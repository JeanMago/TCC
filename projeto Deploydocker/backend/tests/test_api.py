"""Testes de integração da API (sem Docker): autenticação, RBAC, WebSocket e métricas."""

import pytest
from starlette.websockets import WebSocketDisconnect

from tests.conftest import ADMIN_PASS, ADMIN_USER


def test_health_and_root(client):
    assert client.get("/health").json() == {"status": "healthy"}
    assert client.get("/").json()["app"] == "DeployDock"


def test_login_success_returns_token_and_user(client):
    r = client.post("/api/v1/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["username"] == ADMIN_USER
    assert body["user"]["role"] == "admin"
    assert "hashed_password" not in body["user"]


def test_login_by_email_is_case_insensitive(client):
    r = client.post("/api/v1/auth/login", json={"username": "ADMIN@test.local", "password": ADMIN_PASS})
    assert r.status_code == 200


def test_login_wrong_password_is_401(client):
    r = client.post(
        "/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": "errada"},
        headers={"X-Forwarded-For": "10.0.0.50"},
    )
    assert r.status_code == 401


def test_login_bruteforce_leads_to_block(client):
    ip = {"X-Forwarded-For": "10.9.9.9"}
    statuses = [
        client.post("/api/v1/auth/login", json={"username": "nobody", "password": "x"}, headers=ip).status_code
        for _ in range(6)
    ]
    assert 429 in statuses
    # IP bloqueado não consegue mais acessar nada
    assert client.get("/health", headers=ip).status_code == 403
    from app.core.waf import security_manager

    security_manager.unblock_ip("10.9.9.9")


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/projects").status_code == 401


def test_protected_route_rejects_invalid_token(client):
    r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer lixo"})
    assert r.status_code == 401


def test_me_with_valid_token(client, auth_headers):
    r = client.get("/api/v1/auth/me", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["username"] == ADMIN_USER


def test_projects_crud_lifecycle(client, auth_headers):
    assert client.get("/api/v1/projects", headers=auth_headers).json() == []
    payload = {
        "name": "meu-app-teste",
        "repo_url": "https://github.com/exemplo/repo.git",
        "branch": "main",
    }
    created = client.post("/api/v1/projects", json=payload, headers=auth_headers)
    assert created.status_code in (200, 201), created.text
    pid = created.json()["id"]

    listed = client.get("/api/v1/projects", headers=auth_headers).json()
    assert [p["name"] for p in listed] == ["meu-app-teste"]

    assert client.get(f"/api/v1/projects/{pid}", headers=auth_headers).status_code == 200
    assert client.delete(f"/api/v1/projects/{pid}", headers=auth_headers).status_code in (200, 204)
    assert client.get(f"/api/v1/projects/{pid}", headers=auth_headers).status_code == 404


def test_waf_blocks_malicious_query_over_http(client):
    r = client.get("/api/v1/projects?name=../../etc/passwd", headers={"X-Forwarded-For": "10.1.1.1"})
    assert r.status_code == 403
    assert "WAF" in r.json()["detail"]


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "x-frame-options" in {k.lower() for k in r.headers}


def test_prometheus_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "deploydock_waf_attacks_blocked_total" in r.text
    assert "# TYPE deploydock_blocked_ips gauge" in r.text


# ── WebSocket exige autenticação ─────────────────────────────────────────

@pytest.mark.parametrize(
    "path",
    ["/ws/containers/abc/logs", "/ws/containers/abc/stats", "/ws/deployments/abc/stream"],
)
def test_websocket_rejects_unauthenticated(client, path):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(path):
            pass


def test_websocket_rejects_invalid_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/deployments/abc/stream?token=invalido"):
            pass


def test_websocket_accepts_valid_token(client, admin_token):
    with client.websocket_connect(f"/ws/deployments/abc/stream?token={admin_token}") as ws:
        ws.send_text("ping")
        assert ws.receive_json() == {"type": "pong"}
