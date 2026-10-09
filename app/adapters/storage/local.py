"""Filesystem storage. Development and automated tests only (refused in staging/production)."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from app.adapters.storage.base import (
    ObjectMeta,
    ObjectNotFoundError,
    StorageCapabilities,
    StorageError,
)


class LocalStorageProvider:
    name = "local"
    capabilities = StorageCapabilities(temporary_download_urls=False, server_side_copy=True)

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, bucket: str, key: str) -> Path:
        path = (self.root / bucket / key).resolve()
        # Path traversal guard: the resolved path must stay inside root/bucket.
        if not str(path).startswith(str((self.root / bucket).resolve())):
            raise StorageError("invalid object key")
        return path

    def put_object(
        self, bucket: str, key: str, data: BinaryIO, size: int, content_type: str
    ) -> None:
        path = self._path(bucket, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise StorageError("object already exists")
        written = 0
        with path.open("xb") as out:
            while chunk := data.read(1024 * 1024):
                written += len(chunk)
                out.write(chunk)
        if written != size:
            path.unlink(missing_ok=True)
            raise StorageError("size mismatch while storing object")

    def stream_object(
        self, bucket: str, key: str, chunk_size: int = 1024 * 1024
    ) -> Iterator[bytes]:
        path = self._path(bucket, key)
        if not path.is_file():
            raise ObjectNotFoundError(key)

        def gen() -> Iterator[bytes]:
            with path.open("rb") as handle:
                while chunk := handle.read(chunk_size):
                    yield chunk

        return gen()

    def head_object(self, bucket: str, key: str) -> ObjectMeta | None:
        path = self._path(bucket, key)
        return ObjectMeta(size=path.stat().st_size) if path.is_file() else None

    def copy_object(self, bucket: str, source_key: str, destination_key: str) -> None:
        src, dst = self._path(bucket, source_key), self._path(bucket, destination_key)
        if not src.is_file():
            raise ObjectNotFoundError(source_key)
        if dst.exists():
            raise StorageError("destination already exists")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    def delete_object(self, bucket: str, key: str) -> None:
        self._path(bucket, key).unlink(missing_ok=True)

    def health_check(self, bucket: str) -> bool:
        return self.root.is_dir()
