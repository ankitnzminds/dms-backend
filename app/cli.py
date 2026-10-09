"""Operator CLI: ``python -m app.cli <command>``.

There is deliberately no HTTP endpoint that creates organizations or administrators; the
first owner of an organization is created here by an operator with server access.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

from sqlalchemy import select


def _alembic_config(url: str | None = None):  # noqa: ANN202
    from alembic.config import Config

    root = Path(__file__).resolve().parents[1]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    if url:
        cfg.cmd_opts = type("o", (), {"x": [f"url={url}"]})()  # type: ignore[attr-defined]
    return cfg


def cmd_migrate(args: argparse.Namespace) -> int:
    from alembic import command

    command.upgrade(_alembic_config(), args.revision)
    print(f"database is at revision: {args.revision}")
    return 0


def cmd_check_migrations(_: argparse.Namespace) -> int:
    """Fails if the SQLAlchemy models and the migrated schema diverge."""
    from alembic import command

    command.check(_alembic_config())
    print("models and migrations are consistent")
    return 0


def cmd_bootstrap_org(args: argparse.Namespace) -> int:
    from app.db.session import get_sessionmaker
    from app.modules.organizations.service import bootstrap_organization

    with get_sessionmaker()() as db:
        org = bootstrap_organization(
            db,
            name=args.name,
            slug=args.slug,
            owner_email=args.owner_email,
            owner_display_name=args.owner_name,
            quota_bytes=args.quota_gb * 1024**3 if args.quota_gb else None,
            member_default_access=not args.no_member_default_access,
        )
        print(
            f"organization {org.slug} created (id={org.id}). The owner activates the account on first sign-in "
            f"with a verified email matching {args.owner_email!r}."
        )
    return 0


def cmd_worker(_: argparse.Namespace) -> int:
    from app.core.config import get_settings
    from app.core.logging import configure_logging
    from app.workers.runner import run_forever

    configure_logging(get_settings().log_level)
    run_forever()
    return 0


def cmd_maintenance(_: argparse.Namespace) -> int:
    from app.db.session import get_sessionmaker
    from app.workers.maintenance import run_maintenance

    print(json.dumps(run_maintenance(get_sessionmaker())))
    return 0


def cmd_quota(args: argparse.Namespace) -> int:
    from app.db.models import Organization
    from app.db.session import get_sessionmaker
    from app.modules.quota.service import reconcile

    with get_sessionmaker()() as db:
        orgs = [args.org] if args.org else [str(i) for i in db.scalars(select(Organization.id))]
        for org_id in orgs:
            report = reconcile(db, uuid.UUID(org_id), fix=args.fix)
            db.commit()
            print(org_id, json.dumps(report))
    return 0


def cmd_openapi(args: argparse.Namespace) -> int:
    from app.main import app

    spec = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(spec)
    else:
        Path(args.output).write_text(spec, encoding="utf-8")
        print(f"wrote {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("migrate", help="apply Alembic migrations")
    p.add_argument("revision", nargs="?", default="head")
    p.set_defaults(func=cmd_migrate)

    sub.add_parser("check-migrations", help="verify models == migrated schema").set_defaults(
        func=cmd_check_migrations
    )

    p = sub.add_parser("bootstrap-org", help="create an organization and its first owner")
    p.add_argument("--name", required=True)
    p.add_argument("--slug", required=True)
    p.add_argument("--owner-email", required=True)
    p.add_argument("--owner-name")
    p.add_argument("--quota-gb", type=int)
    p.add_argument(
        "--no-member-default-access",
        action="store_true",
        help="do not let every member discover the root and create top-level items",
    )
    p.set_defaults(func=cmd_bootstrap_org)

    sub.add_parser("worker", help="run the outbox worker").set_defaults(func=cmd_worker)
    sub.add_parser("maintenance", help="run housekeeping once").set_defaults(func=cmd_maintenance)

    p = sub.add_parser("quota-reconcile", help="compare quota counters with ground truth")
    p.add_argument("--org")
    p.add_argument("--fix", action="store_true")
    p.set_defaults(func=cmd_quota)

    p = sub.add_parser("export-openapi", help="write the OpenAPI document")
    p.add_argument("-o", "--output", default="docs/api/openapi.json")
    p.set_defaults(func=cmd_openapi)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
