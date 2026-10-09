"""Directory providers: static snapshot (JSON import), Microsoft Entra ID (Graph) and LDAP(S).

VERIFICATION STATUS: the static provider and the sync engine are covered by integration tests.
The Entra adapter is tested against a mocked Graph transport and the LDAP adapter against a fake
connection; neither has been run against a live tenant/directory (see implementation-status.md).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx

from app.adapters.directory.base import (
    DirectoryError,
    DirGroup,
    DirSnapshot,
    DirUser,
    resolve_secret,
)

GRAPH_HOST = "graph.microsoft.com"
LOGIN_HOST = "login.microsoftonline.com"
MAX_PAGES = 500


class StaticDirectory:
    """Snapshot stored in the source config (admin-uploaded export or SCIM/CSV bridge)."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    def fetch(self) -> DirSnapshot:
        try:
            users = [
                DirUser(
                    str(u["external_id"]),
                    str(u["email"]).strip().lower(),
                    u.get("display_name"),
                    bool(u.get("active", True)),
                )
                for u in self._config.get("users", [])
            ]
            groups = [
                DirGroup(
                    str(g["external_id"]),
                    str(g["name"]),
                    frozenset(str(m) for m in g.get("member_ids", [])),
                )
                for g in self._config.get("groups", [])
            ]
        except (KeyError, TypeError) as exc:
            raise DirectoryError("stored snapshot is malformed") from exc
        return DirSnapshot(users, groups)


class EntraDirectory:
    """Microsoft Graph with application permissions (User.Read.All, Group.Read.All)."""

    def __init__(
        self, config: dict[str, Any], secret_ref: str | None, client: httpx.Client | None = None
    ) -> None:
        self.tenant = str(config.get("tenant_id", ""))
        self.client_id = str(config.get("client_id", ""))
        self.only_groups = set(config.get("group_ids", []) or [])
        self._secret = resolve_secret(secret_ref)
        if not (self.tenant and self.client_id and self._secret):
            raise DirectoryError("Entra sources need tenant_id, client_id and a secret_ref")
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False
        )

    def _token(self) -> str:
        try:
            r = self._client.post(
                f"https://{LOGIN_HOST}/{self.tenant}/oauth2/v2.0/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self._secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
        except httpx.HTTPError as exc:
            raise DirectoryError("could not reach the identity platform") from exc
        if r.status_code != 200 or "access_token" not in r.json():
            raise DirectoryError(f"token request failed (HTTP {r.status_code})")
        return str(r.json()["access_token"])

    def _pages(self, token: str, url: str):  # noqa: ANN202
        headers = {"Authorization": f"Bearer {token}"}
        for _ in range(MAX_PAGES):
            if urlparse(url).hostname != GRAPH_HOST:  # never follow a link off Graph (SSRF)
                raise DirectoryError("refusing to follow a non-Graph pagination link")
            try:
                r = self._client.get(url, headers=headers)
            except httpx.HTTPError as exc:
                raise DirectoryError("Graph request failed") from exc
            if r.status_code != 200:
                raise DirectoryError(f"Graph returned HTTP {r.status_code}")
            data = r.json()
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")
            if not url:
                return
        raise DirectoryError("too many pages")

    def fetch(self) -> DirSnapshot:
        token = self._token()
        base = f"https://{GRAPH_HOST}/v1.0"
        users = []
        for u in self._pages(
            token,
            f"{base}/users?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999",
        ):
            email = (u.get("mail") or u.get("userPrincipalName") or "").strip().lower()
            if email:
                users.append(
                    DirUser(
                        str(u["id"]),
                        email,
                        u.get("displayName"),
                        bool(u.get("accountEnabled", True)),
                    )
                )
        groups = []
        for g in self._pages(token, f"{base}/groups?$select=id,displayName&$top=999"):
            if self.only_groups and g["id"] not in self.only_groups:
                continue
            members = frozenset(
                str(m["id"])
                for m in self._pages(token, f"{base}/groups/{g['id']}/members?$select=id&$top=999")
                if m.get("@odata.type", "#microsoft.graph.user").endswith(".user")
            )
            groups.append(DirGroup(str(g["id"]), str(g.get("displayName") or g["id"]), members))
        return DirSnapshot(users, groups)


class LdapDirectory:
    """LDAP/Active Directory over TLS only (ldaps:// or StartTLS), least-privilege bind account."""

    def __init__(
        self,
        config: dict[str, Any],
        secret_ref: str | None,
        connection_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.cfg = config
        uri = str(config.get("server_uri", ""))
        if not uri.startswith("ldaps://") and not config.get("start_tls"):
            raise DirectoryError("LDAP sources must use ldaps:// or start_tls=true")
        self._password = resolve_secret(secret_ref)
        if not (config.get("bind_dn") and self._password and config.get("base_dn_users")):
            raise DirectoryError(
                "LDAP sources need server_uri, bind_dn, base_dn_users and a secret_ref"
            )
        self._connect = connection_factory or self._default_connect

    def _default_connect(self):  # noqa: ANN202
        import ssl

        from ldap3 import Connection, Server, Tls

        tls = Tls(validate=ssl.CERT_REQUIRED)
        server = Server(
            self.cfg["server_uri"],
            use_ssl=self.cfg["server_uri"].startswith("ldaps://"),
            tls=tls,
            connect_timeout=15,
        )
        conn = Connection(
            server,
            user=self.cfg["bind_dn"],
            password=self._password,
            receive_timeout=60,
            raise_exceptions=True,
        )
        conn.open()
        if self.cfg.get("start_tls"):
            conn.start_tls()
        conn.bind()
        return conn

    def _search(self, conn: Any, base: str, flt: str, attrs: list[str]):  # noqa: ANN202
        gen = conn.extend.standard.paged_search(
            base, flt, attributes=attrs, paged_size=500, generator=True
        )
        for entry in gen:
            if entry.get("type") == "searchResEntry":
                yield entry["attributes"]

    @staticmethod
    def _first(value: Any) -> str | None:
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        return None if value is None else str(value)

    def fetch(self) -> DirSnapshot:
        c = self.cfg
        id_attr, mail_attr, name_attr = (
            c.get("attr_id", "entryUUID"),
            c.get("attr_mail", "mail"),
            c.get("attr_name", "displayName"),
        )
        member_attr = c.get("attr_member", "member")
        try:
            conn = self._connect()
            try:
                users: list[DirUser] = []
                dn_to_id: dict[str, str] = {}
                for a in self._search(
                    conn,
                    c["base_dn_users"],
                    c.get("user_filter", "(objectClass=person)"),
                    [id_attr, mail_attr, name_attr, "userAccountControl", "distinguishedName"],
                ):
                    email = (self._first(a.get(mail_attr)) or "").strip().lower()
                    uid = self._first(a.get(id_attr))
                    if not (email and uid):
                        continue
                    uac = self._first(a.get("userAccountControl"))
                    active = not (uac and uac.isdigit() and int(uac) & 2)  # AD ACCOUNTDISABLE flag
                    users.append(DirUser(uid, email, self._first(a.get(name_attr)), active))
                    dn = self._first(a.get("distinguishedName"))
                    if dn:
                        dn_to_id[dn.lower()] = uid
                groups: list[DirGroup] = []
                if c.get("base_dn_groups"):
                    for a in self._search(
                        conn,
                        c["base_dn_groups"],
                        c.get("group_filter", "(objectClass=group)"),
                        [id_attr, "cn", member_attr],
                    ):
                        gid = self._first(a.get(id_attr))
                        if not gid:
                            continue
                        raw = a.get(member_attr) or []
                        members = frozenset(
                            dn_to_id[m.lower()]
                            for m in (raw if isinstance(raw, list) else [raw])
                            if m.lower() in dn_to_id
                        )
                        groups.append(DirGroup(gid, self._first(a.get("cn")) or gid, members))
                return DirSnapshot(users, groups)
            finally:
                try:
                    conn.unbind()
                except Exception:  # noqa: BLE001, S110
                    pass
        except DirectoryError:
            raise
        except Exception as exc:
            raise DirectoryError(f"LDAP read failed: {type(exc).__name__}") from exc


def build_provider(kind: str, config: dict[str, Any], secret_ref: str | None):  # noqa: ANN201
    if kind == "static":
        return StaticDirectory(config)
    if kind == "entra":
        return EntraDirectory(config, secret_ref)
    if kind == "ldap":
        return LdapDirectory(config, secret_ref)
    raise DirectoryError(f"unsupported directory kind: {kind}")
