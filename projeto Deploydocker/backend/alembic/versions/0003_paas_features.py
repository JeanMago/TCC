"""replicas horizontais, autoscaling e autenticacao 2FA (TOTP)

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("replicas", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("autoscale_enabled", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("autoscale_min_replicas", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("autoscale_max_replicas", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("autoscale_cpu_target", sa.Integer(), nullable=True))

    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("totp_secret", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("totp_enabled", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("totp_enabled")
        batch.drop_column("totp_secret")

    with op.batch_alter_table("projects") as batch:
        batch.drop_column("autoscale_cpu_target")
        batch.drop_column("autoscale_max_replicas")
        batch.drop_column("autoscale_min_replicas")
        batch.drop_column("autoscale_enabled")
        batch.drop_column("replicas")
