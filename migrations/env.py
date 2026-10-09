"""Alembic environment. DMS owns schema ``dms`` only; Supabase-managed schemas are never touched."""

from __future__ import annotations

from alembic import context
from sqlalchemy import text

import app.db.models  # noqa: F401  (register models)
from app.db.base import SCHEMA, Base
from app.db.session import make_engine

config = context.config
target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to):  # noqa: ANN001
    # Only manage objects in the DMS schema.
    if type_ == "table" and getattr(obj, "schema", None) != SCHEMA:
        return False
    return True


def run_migrations_offline() -> None:
    raise RuntimeError("Offline mode is not supported; run against a database.")


def run_migrations_online() -> None:
    url = context.get_x_argument(as_dictionary=True).get("url")
    engine = make_engine(url)
    with engine.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table_schema=SCHEMA,
            include_schemas=True,
            include_object=include_object,
            compare_type=True,
            compare_server_default=False,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
