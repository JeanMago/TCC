"""Garante que as migrações Alembic aplicam do zero e refletem exatamente os modelos."""

import os
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic(args: list[str], db_url: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "DATABASE_URL": db_url}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR, env=env, capture_output=True, text=True, timeout=120,
    )


def test_migrations_upgrade_and_match_models(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/mig.db"
    up = _alembic(["upgrade", "head"], url)
    assert up.returncode == 0, up.stderr
    check = _alembic(["check"], url)
    assert check.returncode == 0, "modelos divergem das migrações: " + check.stderr + check.stdout


def test_migrations_downgrade_to_base(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/mig2.db"
    assert _alembic(["upgrade", "head"], url).returncode == 0
    down = _alembic(["downgrade", "base"], url)
    assert down.returncode == 0, down.stderr
