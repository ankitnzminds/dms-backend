"""granular permissions: new actions backfilled onto existing grants, upload intent

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-10-10 01:10:00
"""
from alembic import op
import sqlalchemy as sa


revision = 'b3c4d5e6f7a8'
down_revision = 'a2b3c4d5e6f7'
branch_labels = None
depends_on = None

# Existing access must not shrink: whoever could do the broad thing keeps the finer-grained rights it
# used to include. (New grants are explicit, so the new rights can be given or withheld one by one.)
#   create_child   -> create_folder, upload, create_file
#   upload_version -> restore_version, lock
#   view           -> view_versions
RULES = [
    ('create_child', ['create_folder', 'upload', 'create_file']),
    ('upload_version', ['restore_version', 'lock']),
    ('view', ['view_versions']),
]
TABLES = ['permission_grants', 'share_grants', 'share_recipients']


def upgrade() -> None:
    op.add_column(
        'upload_sessions',
        sa.Column('intent', sa.String(length=16), server_default='upload', nullable=False),
        schema='dms',
    )
    for table in TABLES:
        for have, add in RULES:
            extra = ', '.join(f"'{a}'" for a in add)
            op.execute(
                f"""
                UPDATE dms.{table}
                   SET actions = ARRAY(
                       SELECT DISTINCT x FROM unnest(actions || ARRAY[{extra}]::varchar[]) AS x
                   )
                 WHERE actions IS NOT NULL AND '{have}' = ANY(actions)
                """
            )


def downgrade() -> None:
    # The finer-grained actions are simply ignored by older code; remove them to restore the old shape.
    new = "ARRAY['create_folder','upload','create_file','view_versions','restore_version','lock']"
    for table in TABLES:
        op.execute(
            f"""
            UPDATE dms.{table}
               SET actions = ARRAY(SELECT x FROM unnest(actions) AS x WHERE x <> ALL({new}))
             WHERE actions IS NOT NULL
            """
        )
    op.drop_column('upload_sessions', 'intent', schema='dms')
