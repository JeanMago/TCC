"""historico persistente de telemetria do host e por conteiner (amostras por minuto)

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "telemetry_samples",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.Float(), nullable=False),
        sa.Column("cpu_host", sa.Float(), nullable=False),
        sa.Column("cpu_host_max", sa.Float(), nullable=False),
        sa.Column("cpu_docker", sa.Float(), nullable=False),
        sa.Column("memory_host_pct", sa.Float(), nullable=False),
        sa.Column("memory_host_used_mb", sa.Float(), nullable=False),
        sa.Column("memory_docker_used_mb", sa.Float(), nullable=False),
        sa.Column("network_rx_mb", sa.Float(), nullable=False),
        sa.Column("network_tx_mb", sa.Float(), nullable=False),
        sa.Column("disk_used_pct", sa.Float(), nullable=False),
        sa.Column("containers_active", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_telemetry_samples_timestamp"), "telemetry_samples", ["timestamp"], unique=False
    )

    op.create_table(
        "container_telemetry_samples",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.Float(), nullable=False),
        sa.Column("container_name", sa.String(length=255), nullable=False),
        sa.Column("cpu_percent", sa.Float(), nullable=False),
        sa.Column("cpu_percent_max", sa.Float(), nullable=False),
        sa.Column("memory_mb", sa.Float(), nullable=False),
        sa.Column("memory_host_pct", sa.Float(), nullable=False),
        sa.Column("network_rx_mb", sa.Float(), nullable=False),
        sa.Column("network_tx_mb", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_container_telemetry_samples_timestamp"),
        "container_telemetry_samples",
        ["timestamp"],
        unique=False,
    )
    op.create_index(
        op.f("ix_container_telemetry_samples_container_name"),
        "container_telemetry_samples",
        ["container_name"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_container_telemetry_samples_container_name"),
        table_name="container_telemetry_samples",
    )
    op.drop_index(
        op.f("ix_container_telemetry_samples_timestamp"), table_name="container_telemetry_samples"
    )
    op.drop_table("container_telemetry_samples")
    op.drop_index(op.f("ix_telemetry_samples_timestamp"), table_name="telemetry_samples")
    op.drop_table("telemetry_samples")
