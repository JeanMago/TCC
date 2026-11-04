"""Testes de integração dos endpoints /containers, /projects, /deployments, /security, /system e /auth."""

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.deps import get_docker_service
from app.main import app


@pytest.fixture()
def mock_docker():
    d = MagicMock()
    d.list_containers = AsyncMock(
        return_value=[
            {
                "id": "c123",
                "full_id": "c123full",
                "name": "demo-web",
                "status": "running",
                "image": "nginx:alpine",
                "ports": {},
                "created": "2026-10-29T00:00:00Z",
                "state": "running",
                "labels": {"deploydock.host": "demo.localhost"},
                "public_url": "http://demo.localhost",
            }
        ]
    )
    d.get_container = AsyncMock(
        return_value={
            "id": "c123",
            "full_id": "c123full",
            "name": "demo-web",
            "status": "running",
            "image": "nginx:alpine",
            "ports": {},
            "created": "2026-10-29T00:00:00Z",
            "state": "running",
            "mounts": [],
            "networks": {},
            "env": ["A=1"],
            "config": {},
            "restart_policy": {"Name": "unless-stopped"},
            "memory_limit_mb": 256,
            "cpu_limit_cores": 1.0,
        }
    )
    d.run_quick_container = AsyncMock(
        return_value={"id": "q1", "name": "redis-test", "image": "redis:alpine", "state": "running"}
    )
    d.start_container = AsyncMock(return_value={"id": "c123", "name": "demo-web", "status": "running"})
    d.stop_container = AsyncMock(return_value={"id": "c123", "name": "demo-web", "status": "exited"})
    d.restart_container = AsyncMock(return_value={"id": "c123", "name": "demo-web", "status": "running"})
    d.remove_container = AsyncMock(return_value=None)
    d.update_container_resources = AsyncMock(
        return_value={"id": "c123", "name": "demo-web", "memory_limit_mb": 512, "cpu_limit_cores": 2.0}
    )
    d.get_container_logs = AsyncMock(
        return_value={"container_id": "c123", "container_name": "demo-web", "state": "running", "lines": ["ok"], "logs": "ok", "count": 1}
    )
    d.exec_container_command = AsyncMock(
        return_value={"exit_code": 0, "stdout": "uid=0(root)\n", "stderr": "", "output": "uid=0(root)"}
    )
    d.list_container_files = AsyncMock(return_value={"path": "/", "items": [{"name": "app", "is_dir": True}], "stderr": ""})
    d.read_container_file = AsyncMock(return_value={"path": "/app/main.py", "content": "print(1)", "stderr": "", "exit_code": 0})
    d.write_container_file = AsyncMock(return_value={"path": "/app/main.py", "size_bytes": 8, "restarted": False})
    d.upload_container_file = AsyncMock(return_value={"path": "/app/a.txt", "filename": "a.txt", "size_bytes": 3})
    d.download_container_file = AsyncMock(return_value=(b"abc", "a.txt"))
    d.delete_container_file = AsyncMock(return_value={"deleted": "/app/a.txt", "exit_code": 0})
    d.export_container_db_dump = AsyncMock(return_value=(b"-- sql dump", "dump.sql", "application/sql"))
    d.get_system_info = AsyncMock(
        return_value={
            "docker_version": "27.0",
            "os": "Linux",
            "architecture": "x86_64",
            "cpus": 4,
            "total_memory_gb": 8.0,
            "containers_running": 1,
            "containers_stopped": 0,
            "containers_total": 1,
            "images_total": 2,
        }
    )
    d.get_resources_overview = AsyncMock(return_value={"host": {}, "docker": {}, "storage": {}})
    d.list_images = AsyncMock(return_value=[{"id": "img1", "tags": ["nginx:alpine"], "size_mb": 20.0, "created": "now"}])
    d.remove_image = AsyncMock(return_value=None)
    d.list_volumes = AsyncMock(return_value=[{"name": "v1", "driver": "local", "mountpoint": "/mnt", "created": "now"}])
    d.remove_volume = AsyncMock(return_value=None)
    d.export_volume_backup = AsyncMock(return_value=(b"gzbytes", "vol_v1.tar.gz"))
    d.restore_volume_backup = AsyncMock(return_value={"volume": "v1", "restored_bytes": 100, "status": "restored"})
    d.list_networks = AsyncMock(return_value=[{"id": "n1", "name": "bridge", "driver": "bridge", "scope": "local"}])
    d.prune_system = AsyncMock(
        return_value={"target": "all", "containers_deleted": 1, "images_deleted": 1, "volumes_deleted": 0, "networks_deleted": 0, "reclaimed_space": 1024, "space_reclaimed_mb": 0.01}
    )

    app.dependency_overrides[get_docker_service] = lambda: d
    yield d
    app.dependency_overrides.pop(get_docker_service, None)


# ── /api/v1/containers ───────────────────────────────────────────────────


def test_containers_full_endpoints_flow(client, auth_headers, mock_docker):
    r = client.get("/api/v1/containers", headers=auth_headers)
    assert r.status_code == 200 and r.json()[0]["name"] == "demo-web"

    r = client.post(
        "/api/v1/containers/run",
        json={"image": "redis:alpine", "name": "redis-test", "host_port": 6379, "container_port": 6379, "env_text": "FOO=bar\n# comentario\nBAZ=1"},
        headers=auth_headers,
    )
    assert r.status_code == 200 and r.json()["name"] == "redis-test"

    assert client.post("/api/v1/containers/run", json={"image": "  "}, headers=auth_headers).status_code == 400

    assert client.get("/api/v1/containers/c123", headers=auth_headers).status_code == 200
    assert client.post("/api/v1/containers/c123/start", headers=auth_headers).json()["message"] == "Started"
    assert client.post("/api/v1/containers/c123/stop", headers=auth_headers).json()["message"] == "Stopped"
    assert client.post("/api/v1/containers/c123/restart", headers=auth_headers).json()["message"] == "Restarted"
    assert client.put("/api/v1/containers/c123/resources", json={"memory_limit_mb": 512, "cpu_limit_cores": 2.0}, headers=auth_headers).status_code == 200
    assert client.get("/api/v1/containers/c123/logs?tail=50&search=ok", headers=auth_headers).json()["count"] == 1

    # Exec seguro vs bloqueado pelo WAF
    r = client.post("/api/v1/containers/c123/exec", json={"command": "id"}, headers=auth_headers)
    assert r.status_code == 200 and "uid=0" in r.json()["output"]
    r_bad = client.post("/api/v1/containers/c123/exec", json={"command": "rm -rf /"}, headers=auth_headers)
    assert r_bad.status_code == 403

    # Explorador de arquivos e dump
    assert client.get("/api/v1/containers/c123/files?path=/", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/containers/c123/files/content?path=/app/main.py", headers=auth_headers).json()["content"] == "print(1)"
    assert client.put("/api/v1/containers/c123/files/content", json={"path": "/app/main.py", "content": "print(2)"}, headers=auth_headers).status_code == 200
    b64 = base64.b64encode(b"abc").decode()
    assert client.post("/api/v1/containers/c123/files/upload", json={"dir_path": "/app", "filename": "a.txt", "content_base64": b64}, headers=auth_headers).status_code == 200
    dl = client.get("/api/v1/containers/c123/files/download?path=/app/a.txt", headers=auth_headers)
    assert dl.status_code == 200 and dl.content == b"abc"
    assert client.delete("/api/v1/containers/c123/files?path=/app/a.txt", headers=auth_headers).status_code == 200
    dump = client.get("/api/v1/containers/c123/db-dump", headers=auth_headers)
    assert dump.status_code == 200 and b"sql dump" in dump.content

    assert client.delete("/api/v1/containers/c123", headers=auth_headers).json()["message"] == "Removed"


# ── /api/v1/projects (templates, blue_green, env Fernet, routing, previews) ──


def test_projects_templates_blue_green_and_env_encryption(client, auth_headers, monkeypatch):
    from app.api.v1.endpoints import projects as proj_ep

    monkeypatch.setattr(proj_ep, "_reapply_routing", AsyncMock())
    monkeypatch.setattr(proj_ep, "_trigger_deploy", AsyncMock())

    # Criação com template local + estratégia blue_green + token Git cifrado
    created = client.post(
        "/api/v1/projects",
        json={
            "name": "api-bluegreen",
            "template": "fastapi",
            "deploy_strategy": "blue_green",
            "subdomain": "api-bg",
            "container_port": 8000,
            "memory_limit_mb": 256,
            "cpu_limit_cores": 1.0,
            "git_token": "ghp_secretToken123",
        },
        headers=auth_headers,
    )
    assert created.status_code in (200, 201), created.text
    proj = created.json()
    pid = proj["id"]
    assert proj["deploy_strategy"] == "blue_green"
    assert proj["has_git_token"] is True
    assert proj["public_host"].startswith("api-bg.")

    # Atualização de estratégia e limites
    patched = client.patch(
        f"/api/v1/projects/{pid}",
        json={"deploy_strategy": "recreate", "memory_limit_mb": 512, "custom_domain": "meuapp.exemplo.com"},
        headers=auth_headers,
    )
    assert patched.status_code == 200
    assert patched.json()["deploy_strategy"] == "recreate"
    assert patched.json()["public_host"] == "meuapp.exemplo.com"

    # Variáveis .env: individual secreta (Fernet) + em lote
    r_env = client.post(
        f"/api/v1/projects/{pid}/env",
        json={"key": "DB_PASS", "value": "super-secreta", "is_secret": True},
        headers=auth_headers,
    )
    assert r_env.status_code == 200
    assert r_env.json()[0]["value"] == "super-secreta"

    r_bulk = client.post(
        f"/api/v1/projects/{pid}/env",
        json={"bulk_content": "PORT=8000\n# comentario\nAPI_KEY='xyz'", "is_secret": True, "apply_now": True},
        headers=auth_headers,
    )
    assert r_bulk.status_code == 200
    keys = {item["key"]: item["value"] for item in r_bulk.json()}
    assert keys["PORT"] == "8000" and keys["API_KEY"] == "xyz"

    env_id = r_bulk.json()[0]["id"]
    assert client.delete(f"/api/v1/projects/{pid}/env/{env_id}", headers=auth_headers).status_code == 200
    assert client.post(f"/api/v1/projects/{pid}/env/apply", headers=auth_headers).status_code == 200

    # Rotas auxiliares de projetos
    assert client.get("/api/v1/projects/routing-config", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/projects/uptime/overview", headers=auth_headers).status_code == 200
    assert client.post(f"/api/v1/projects/{pid}/deploy", headers=auth_headers).status_code == 200

    assert client.delete(f"/api/v1/projects/{pid}", headers=auth_headers).status_code == 200


# ── /api/v1/system, /api/v1/security e /api/v1/auth (RBAC) ───────────────


def test_system_security_and_auth_rbac_endpoints(client, auth_headers, mock_docker):
    # System endpoints
    assert client.get("/api/v1/system/info", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/resources", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/images", headers=auth_headers).status_code == 200
    assert client.delete("/api/v1/system/images/img1", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/volumes", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/volumes/v1/backup", headers=auth_headers).status_code == 200
    b64 = base64.b64encode(b"tar").decode()
    assert client.post("/api/v1/system/volumes/v1/restore", json={"archive_base64": b64}, headers=auth_headers).status_code == 200
    assert client.delete("/api/v1/system/volumes/v1", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/networks", headers=auth_headers).status_code == 200
    assert client.post("/api/v1/system/prune", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/production-check", headers=auth_headers).status_code == 200
    assert client.get("/api/v1/system/notifications", headers=auth_headers).status_code == 200

    # Security / WAF endpoints
    assert client.get("/api/v1/security/overview", headers=auth_headers).status_code == 200
    assert client.put("/api/v1/security/config", json={"rate_limit_per_minute": 300}, headers=auth_headers).status_code == 200
    assert client.post("/api/v1/security/block", json={"ip": "203.0.113.9", "reason": "teste", "duration_seconds": 60}, headers=auth_headers).status_code == 200
    assert client.post("/api/v1/security/unblock", json={"ip": "203.0.113.9"}, headers=auth_headers).status_code == 200
    assert client.post("/api/v1/security/simulate-attack", json={"attack_type": "sqli"}, headers=auth_headers).status_code == 200

    # Gestão de usuários e RBAC (viewer não pode criar projeto nem remover recursos)
    u = client.post(
        "/api/v1/auth/users",
        json={"username": "leitor", "email": "leitor@test.local", "password": "Senha123!", "role": "viewer"},
        headers=auth_headers,
    )
    assert u.status_code in (200, 201), u.text
    uid = u.json()["id"]

    viewer_token = client.post("/api/v1/auth/login", json={"username": "leitor", "password": "Senha123!"}).json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer pode listar, mas recebe 403 ao tentar criar projeto ou rodar prune
    assert client.get("/api/v1/projects", headers=viewer_headers).status_code == 200
    assert client.post("/api/v1/projects", json={"name": "proibido", "template": "static"}, headers=viewer_headers).status_code == 403
    assert client.post("/api/v1/system/prune", headers=viewer_headers).status_code == 403

    # Admin promove, alterna status e remove o usuário
    assert client.patch(f"/api/v1/auth/users/{uid}/role", json={"role": "developer"}, headers=auth_headers).status_code == 200
    assert client.patch(f"/api/v1/auth/users/{uid}/toggle", headers=auth_headers).status_code == 200
    assert client.delete(f"/api/v1/auth/users/{uid}", headers=auth_headers).status_code == 200



# ── Cobertura adicional: deployments, webhooks (push/PR/preview), previews e notificações ──


def test_deployments_webhooks_previews_and_notifications_routes(client, auth_headers, mock_docker, monkeypatch):
    import hashlib
    import hmac
    import json
    from app.api.v1.endpoints import deployments as dep_ep
    from app.api.v1.endpoints import projects as proj_ep
    from app.api.v1.endpoints import webhooks as wh_ep
    from app.services import notification_service as notif_mod

    monkeypatch.setattr(proj_ep, "_reapply_routing", AsyncMock())
    monkeypatch.setattr(proj_ep, "_trigger_deploy", AsyncMock())
    monkeypatch.setattr(wh_ep, "_trigger_deploy", AsyncMock())
    monkeypatch.setattr(wh_ep, "_trigger_preview_deploy", AsyncMock())

    # Criar projeto com auto_deploy e preview_deployments_enabled
    created = client.post(
        "/api/v1/projects",
        json={
            "name": "webhook-proj",
            "repo_url": "https://github.com/exemplo/webhook-proj.git",
            "branch": "main",
            "webhook_secret": "segredo-do-projeto-123",
            "auto_deploy": True,
            "preview_deployments_enabled": True,
        },
        headers=auth_headers,
    )
    assert created.status_code in (200, 201), created.text
    proj = created.json()
    pid = proj["id"]

    # Webhook push na branch principal autenticado pelo segredo individual do projeto
    push_main = {
        "ref": "refs/heads/main",
        "after": "a" * 40,
        "repository": {"clone_url": "https://github.com/exemplo/webhook-proj.git"},
    }
    raw_main = json.dumps(push_main).encode()
    sig_main = "sha256=" + hmac.new(b"segredo-do-projeto-123", raw_main, hashlib.sha256).hexdigest()
    r_push = client.post(
        "/api/v1/webhooks/github",
        content=raw_main,
        headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig_main, "Content-Type": "application/json"},
    )
    assert r_push.status_code == 202 and r_push.json()["status"] in ("queued", "deploy_queued")

    # Webhook push em branch secundária -> preview_queued
    push_feat = {
        "ref": "refs/heads/feat-login",
        "after": "b" * 40,
        "repository": {"clone_url": "https://github.com/exemplo/webhook-proj.git"},
    }
    raw_feat = json.dumps(push_feat).encode()
    sig_feat = "sha256=" + hmac.new(b"segredo-do-projeto-123", raw_feat, hashlib.sha256).hexdigest()
    r_feat = client.post(
        "/api/v1/webhooks/github",
        content=raw_feat,
        headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": sig_feat, "Content-Type": "application/json"},
    )
    assert r_feat.status_code == 202 and r_feat.json()["status"] == "preview_queued"

    # Webhook pull_request opened -> preview_queued
    pr_payload = {
        "action": "opened",
        "number": 42,
        "pull_request": {"head": {"ref": "feat-pr"}},
        "repository": {"clone_url": "https://github.com/exemplo/webhook-proj.git"},
    }
    raw_pr = json.dumps(pr_payload).encode()
    sig_pr = "sha256=" + hmac.new(b"segredo-do-projeto-123", raw_pr, hashlib.sha256).hexdigest()
    r_pr = client.post(
        "/api/v1/webhooks/github",
        content=raw_pr,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig_pr, "Content-Type": "application/json"},
    )
    assert r_pr.status_code == 202 and r_pr.json()["status"] == "preview_queued"

    # Rotas de Preview do projeto (/previews GET, POST, DELETE) e healthcheck/uptime
    monkeypatch.setattr(
        proj_ep.DeployOrchestrator,
        "deploy_preview",
        AsyncMock(return_value={"container_id": "p1", "public_url": "http://pr.localhost", "status": "running"}),
    )
    monkeypatch.setattr(
        proj_ep.uptime_monitor,
        "check_single_project",
        AsyncMock(return_value={"project_id": pid, "reachable": True, "uptime_percent": 100.0}),
    )
    monkeypatch.setattr(
        proj_ep.uptime_monitor,
        "check_all_projects",
        AsyncMock(return_value={pid: {"reachable": True}}),
    )

    assert client.get(f"/api/v1/projects/{pid}/healthcheck", headers=auth_headers).status_code == 200
    assert client.post("/api/v1/projects/uptime/check-now", headers=auth_headers).status_code == 200
    assert client.get(f"/api/v1/projects/{pid}/previews", headers=auth_headers).status_code == 200
    assert client.post(f"/api/v1/projects/{pid}/previews", json={"branch": "feat-ui"}, headers=auth_headers).status_code == 200
    assert client.delete(f"/api/v1/projects/{pid}/previews/feat-ui", headers=auth_headers).status_code == 200

    # Rotas de Deployments (/api/v1/deployments) e Notificações (/api/v1/system/notifications)
    assert client.get(f"/api/v1/deployments?project_id={pid}", headers=auth_headers).status_code == 200
    assert client.get(f"/api/v1/deployments/{pid}", headers=auth_headers).status_code == 404

    monkeypatch.setattr(
        dep_ep.DeployOrchestrator,
        "rollback",
        AsyncMock(side_effect=ValueError("Deployment não encontrado")),
    )
    assert client.post(f"/api/v1/deployments/{pid}/rollback", headers=auth_headers).status_code == 400

    assert client.put("/api/v1/system/notifications/config", json={"enabled": True, "cpu_threshold_percent": 90}, headers=auth_headers).status_code == 200
    monkeypatch.setattr(notif_mod.notification_manager, "notify", AsyncMock(return_value={"id": "n1", "channels": ["painel_interno"]}))
    assert client.post("/api/v1/system/notifications/test", json={"title": "Teste", "message": "OK", "severity": "info"}, headers=auth_headers).status_code == 200

    # Alteração de senha do próprio usuário e limpeza de logs de auditoria
    assert client.delete("/api/v1/security/audit-logs", headers=auth_headers).status_code == 200
    assert client.delete(f"/api/v1/projects/{pid}", headers=auth_headers).status_code == 200
