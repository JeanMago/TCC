"""
Configuração global dos testes.

As variáveis de ambiente são definidas ANTES de importar a aplicação, para que
`app.core.config.settings` use um banco SQLite temporário e segredos de teste.
Nenhum teste depende de um daemon Docker real (serviços são mockados).
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="deploydock-tests-")
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP}/test.db"
os.environ["SECRET_KEY"] = "test-secret-key-with-more-than-32-characters-0123456789"
os.environ["GITHUB_WEBHOOK_SECRET"] = "global-webhook-secret-for-tests"
os.environ["INITIAL_ADMIN_USERNAME"] = "admin"
os.environ["INITIAL_ADMIN_PASSWORD"] = "S3nha-Forte-de-Teste!"
os.environ["INITIAL_ADMIN_EMAIL"] = "admin@test.local"
os.environ["REPOS_BASE_PATH"] = os.path.join(_TMP, "repos")
os.environ["ENVIRONMENT"] = "development"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_USER = os.environ["INITIAL_ADMIN_USERNAME"]
ADMIN_PASS = os.environ["INITIAL_ADMIN_PASSWORD"]


@pytest.fixture(scope="session")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def fresh_security_manager():
    """Estado limpo do WAF/rate limiter para cada teste que o utilize."""
    from app.core.waf import SecurityManager

    return SecurityManager()


@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture()
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
