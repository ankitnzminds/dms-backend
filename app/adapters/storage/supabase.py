"""Supabase Storage adapter (REST). Uses only the documented Storage API - never SQL on the
``storage`` schema. The service-role key is read server-side and is never sent to clients.

VERIFICATION STATUS: exercised against a mocked transport in unit tests; a run against a real
non-production Supabase project is tracked in docs/implementation-status.md.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO
from urllib.parse import quote

import httpx

from app.adapters.storage.base import (
    ObjectMeta,
    ObjectNotFoundError,
    StorageCapabilities,
    StorageError,
)
from app.core.config import Settings


def _chunks(data: BinaryIO, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    while chunk := data.read(chunk_size):
        yield chunk


class SupabaseStorageProvider:
    name = "supabase"
    # We stream through the backend so authorization is re-checked on every download.
    capabilities = StorageCapabilities(temporary_download_urls=False, server_side_copy=True)

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if not settings.supabase_url or settings.supabase_service_role_key is None:
            raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required")
        self._base = settings.supabase_url.rstrip("/") + "/storage/v1"
        key = settings.supabase_service_role_key.get_secret_value()
        self._headers = {"Authorization": f"Bearer {key}", "apikey": key}
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=False
        )

    @staticmethod
    def _obj(bucket: str, key: str) -> str:
        return f"{quote(bucket, safe='')}/{quote(key, safe='/')}"

    def _raise(self, response: httpx.Response, what: str) -> None:
        if response.status_code == 404:
            raise ObjectNotFoundError(what)
        if response.status_code >= 400:
            # Do not include the response body: it can echo request details.
            raise StorageError(f"{what} failed with HTTP {response.status_code}")

    def put_object(
        self, bucket: str, key: str, data: BinaryIO, size: int, content_type: str
    ) -> None:
        headers = {
            **self._headers,
            "Content-Type": content_type or "application/octet-stream",
            "Content-Length": str(size),
            "x-upsert": "false",
            "Cache-Control": "private, max-age=0",
        }
        try:
            response = self._client.post(
                f"{self._base}/object/{self._obj(bucket, key)}",
                headers=headers,
                content=_chunks(data),
            )
        except httpx.HTTPError as exc:
            raise StorageError("upload failed (network)") from exc
        self._raise(response, "upload")

    def stream_object(
        self, bucket: str, key: str, chunk_size: int = 1024 * 1024
    ) -> Iterator[bytes]:
        url = f"{self._base}/object/authenticated/{self._obj(bucket, key)}"

        def gen() -> Iterator[bytes]:
            try:
                with self._client.stream("GET", url, headers=self._headers) as response:
                    if response.status_code >= 400:
                        response.read()
                        self._raise(response, "download")
                    yield from response.iter_bytes(chunk_size)
            except httpx.HTTPError as exc:
                raise StorageError("download failed (network)") from exc

        # Resolve 404 eagerly so callers can map it before streaming starts.
        head = self.head_object(bucket, key)
        if head is None:
            raise ObjectNotFoundError(key)
        return gen()

    def head_object(self, bucket: str, key: str) -> ObjectMeta | None:
        try:
            response = self._client.get(
                f"{self._base}/object/info/authenticated/{self._obj(bucket, key)}",
                headers=self._headers,
            )
        except httpx.HTTPError as exc:
            raise StorageError("head failed (network)") from exc
        if response.status_code == 404:
            return None
        self._raise(response, "head")
        info = response.json()
        size = info.get("size")
        if size is None:
            size = (info.get("metadata") or {}).get("size")
        if size is None:
            raise StorageError("storage did not report object size")
        content_type = info.get("content_type") or (info.get("metadata") or {}).get("mimetype")
        return ObjectMeta(size=int(size), content_type=content_type)

    def copy_object(self, bucket: str, source_key: str, destination_key: str) -> None:
        try:
            response = self._client.post(
                f"{self._base}/object/copy",
                headers=self._headers,
                json={
                    "bucketId": bucket,
                    "sourceKey": source_key,
                    "destinationKey": destination_key,
                },
            )
        except httpx.HTTPError as exc:
            raise StorageError("copy failed (network)") from exc
        self._raise(response, "copy")

    def delete_object(self, bucket: str, key: str) -> None:
        try:
            response = self._client.delete(
                f"{self._base}/object/{self._obj(bucket, key)}", headers=self._headers
            )
        except httpx.HTTPError as exc:
            raise StorageError("delete failed (network)") from exc
        if response.status_code != 404:
            self._raise(response, "delete")

    def health_check(self, bucket: str) -> bool:
        try:
            response = self._client.get(
                f"{self._base}/bucket/{quote(bucket, safe='')}", headers=self._headers
            )
        except httpx.HTTPError:
            return False
        if response.status_code != 200:
            return False
        # The bucket MUST be private; a public bucket is a misconfiguration we refuse to use.
        return response.json().get("public") is False
