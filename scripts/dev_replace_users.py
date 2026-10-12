"""Replace the seeded LOCAL development users with the ones listed in ``.dev/dev_users.json``.

    uv run python scripts/dev_replace_users.py        (with the dev stack STOPPED)

* Creates (or updates) each listed user: active, local sign-in, own password (scrypt hash), role and group.
* Removes every OTHER member of the development organization the way an administrator's "Delete user" does:
  membership removed, sessions revoked, group memberships dropped, audit event written. Files and folders
  stay in the organization (nothing is erased).

``.dev/`` is git-ignored, so the passwords never enter the repository. Development stack only.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEV_DIR = ROOT / os.environ.get("DEV_STACK_DIR", ".dev")


def main() -> int:
    import pgserver
    from sqlalchemy import delete, select

    spec_path = DEV_DIR / "dev_users.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))

    server = pgserver.get_server(DEV_DIR / "pgdata", cleanup_mode=None)
    os.environ.update(
        {
            "APP_ENV": "development",
            "DATABASE_URL": server.get_uri(),
            "AUTH_PROVIDER": "local",
            "LOCAL_JWT_SECRET": os.environ.get(
                "LOCAL_JWT_SECRET", "dev-only-local-jwt-secret-change-me-0123456789"
            ),
            "STORAGE_PROVIDER": "local",
            "LOCAL_STORAGE_PATH": str(DEV_DIR / "objects"),
            "MALWARE_SCANNER": "eicar",
            "PYTHONUTF8": "1",
        }
    )
    from app.cli import main as cli
    from app.core.config import get_settings
    from app.core.local_password import hash_password
    from app.db.enums import MembershipStatus, UserStatus
    from app.db.models import Group, GroupMembership, Membership, Organization, User
    from app.db.session import get_sessionmaker
    from app.devseed import DEV_ORG_SLUG
    from app.modules.audit import service as audit

    settings = get_settings()
    if settings.is_production_like or settings.auth_provider != "local":
        raise RuntimeError("This script is for the local development stack only.")

    cli(["migrate"])
    keep = {u["email"].strip().lower() for u in spec["users"]}
    with get_sessionmaker()() as db:
        org = db.scalar(select(Organization).where(Organization.slug == DEV_ORG_SLUG))
        if org is None:
            raise RuntimeError(
                "The development organization does not exist yet; start the dev stack once."
            )

        groups: dict[str, Group] = {
            g.name: g for g in db.scalars(select(Group).where(Group.organization_id == org.id))
        }
        actor: User | None = None
        for u in spec["users"]:
            email = u["email"].strip().lower()
            user = db.scalar(select(User).where(User.email == email))
            if user is None:
                user = User(id=uuid.uuid4(), email=email)
                db.add(user)
                db.flush()
            user.display_name = u["name"]
            user.status = UserStatus.ACTIVE.value
            user.identity_provider = "local"
            user.external_subject = f"local-{email.split('@')[0]}"
            user.email_verified = True
            user.local_password_hash = hash_password(u["password"])
            user.sessions_valid_after = None
            m = db.scalar(
                select(Membership).where(
                    Membership.user_id == user.id, Membership.organization_id == org.id
                )
            )
            if m is None:
                m = Membership(id=uuid.uuid4(), organization_id=org.id, user_id=user.id)
                db.add(m)
            m.role = u["role"]
            m.status = MembershipStatus.ACTIVE.value
            if u["role"] == "owner" and actor is None:
                actor = user
            gname = u.get("group")
            if gname:
                g = groups.get(gname)
                if g is None:
                    g = Group(
                        id=uuid.uuid4(), organization_id=org.id, name=gname, kind="department"
                    )
                    db.add(g)
                    db.flush()
                    groups[gname] = g
                has = db.scalar(
                    select(GroupMembership).where(
                        GroupMembership.group_id == g.id, GroupMembership.user_id == user.id
                    )
                )
                if has is None:
                    db.add(GroupMembership(group_id=g.id, user_id=user.id, organization_id=org.id))
        db.flush()
        if actor is None:
            raise RuntimeError("dev_users.json must contain at least one owner.")

        removed = []
        old = db.execute(
            select(User, Membership)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == org.id,
                Membership.status != MembershipStatus.REMOVED.value,
                User.email.notin_(keep),
            )
        ).all()
        for user, m in old:
            m.status = MembershipStatus.REMOVED.value
            user.sessions_valid_after = datetime.now(UTC)
            user.status = UserStatus.DISABLED.value  # cannot sign in to the dev stack any more
            db.execute(
                delete(GroupMembership).where(
                    GroupMembership.organization_id == org.id, GroupMembership.user_id == user.id
                )
            )
            audit.record(
                db,
                organization_id=org.id,
                actor_user_id=actor.id,
                action="member.deleted",
                resource_type="user",
                resource_id=user.id,
                metadata={"files_deleted": False, "reason": "dev user replacement"},
            )
            removed.append(user.email)
        # anyone not listed (including users removed by an earlier run) can no longer sign in
        for stray in db.scalars(
            select(User).where(User.email.notin_(keep), User.identity_provider == "local")
        ):
            stray.status = UserStatus.DISABLED.value
        db.commit()
    print("active users:", ", ".join(sorted(keep)))
    print("removed users:", ", ".join(sorted(removed)) or "(none)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
