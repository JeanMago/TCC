"""
Testes automatizados para todas as funcionalidades PaaS Avançadas (Dokploy & Ployter, single-host):
- Autenticação em Duas Etapas (2FA / TOTP RFC 6238)
- Webhooks Multi-Provedor (GitLab, Bitbucket e Gitea)
- Builders Zero-Config expandidos (Go, Rust, PHP, Ruby, Java, Bun, .NET, pyproject.toml)
- Escalonamento Horizontal (Réplicas Multi-Contêiner) e Autoscaling por Métricas
- RBAC Granular por Projeto
- Bancos de Dados Gerenciados de 1ª Classe (PostgreSQL, MySQL, MariaDB, MongoDB, Redis)
- Catálogo de Templates 1-Clique
- Backups Agendados (Cron) com envio para S3 / Object Storage (AWS SigV4)
- Cron Jobs Gerenciados por Aplicação
- Container Registries Privados
- Gerenciamento Automático de DNS (Cloudflare API v4)
- Configuração Visual do Traefik & Certificados TLS Customizados
- Diagnóstico Inteligente de Falhas de Build e Deploy
"""

import hashlib
import hmac
import json

import pytest

from app.core.security import build_totp_uri, compute_totp, generate_totp_secret, verify_totp
from app.services.deploy_orchestrator import _ensure_auto_dockerfile


def _auth_headers(client, username="paas_admin", password="StrongPassword123!", role="admin"):
    import asyncio
    from sqlalchemy import select
    from app.core.security import create_access_token, get_password_hash
    from app.db.session import async_session_factory
    from app.models.user import User

    async def _ensure():
        async with async_session_factory() as s:
            existing = (await s.execute(select(User).where(User.username == username))).scalar_one_or_none()
            if not existing:
                u = User(
                    username=username,
                    email=f"{username}@example.com",
                    hashed_password=get_password_hash(password),
                    role=role,
                    is_active=True,
                )
                s.add(u)
                await s.commit()
                await s.refresh(u)
                return u
            return existing

    user = asyncio.run(_ensure())
    tok = create_access_token({"sub": str(user.id), "username": user.username, "role": user.role})
    return {"Authorization": f"Bearer {tok}"}, user


def test_totp_core_and_2fa_endpoints(client):
    secret = generate_totp_secret()
    assert len(secret) >= 16
    code = compute_totp(secret, timestamp=1700000000)
    assert len(code) == 6 and code.isdigit()
    assert verify_totp(secret, code, timestamp=1700000000) is True
    assert verify_totp(secret, "000000", timestamp=1700000000) is False
    assert verify_totp("", code) is False
    assert verify_totp(secret, "abc") is False
    uri = build_totp_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/")

    headers, _user = _auth_headers(client, username="totp_user", password="Password123!")

    # Enable before setup -> 400
    assert client.post("/api/v1/auth/2fa/enable", json={"code": "123456"}, headers=headers).status_code == 400

    # 1. Setup 2FA
    r_setup = client.post("/api/v1/auth/2fa/setup", headers=headers)
    assert r_setup.status_code == 200
    srv_secret = r_setup.json()["secret"]
    assert r_setup.json()["totp_enabled"] is False

    # 2. Enable 2FA with invalid code -> 400
    r_bad = client.post("/api/v1/auth/2fa/enable", json={"code": "000000"}, headers=headers)
    assert r_bad.status_code == 400

    # 3. Enable 2FA with valid TOTP code -> 200
    valid_code = compute_totp(srv_secret)
    r_en = client.post("/api/v1/auth/2fa/enable", json={"code": valid_code}, headers=headers)
    assert r_en.status_code == 200
    assert r_en.json()["totp_enabled"] is True

    # 4. Login without otp_code when 2FA enabled -> 401 (2FA_REQUIRED)
    r_login_no_otp = client.post(
        "/api/v1/auth/login",
        json={"username": "totp_user", "password": "Password123!"},
    )
    assert r_login_no_otp.status_code == 401
    assert "2FA_REQUIRED" in r_login_no_otp.json()["detail"]

    # 5. Login with wrong otp_code -> 401
    r_login_bad_otp = client.post(
        "/api/v1/auth/login",
        json={"username": "totp_user", "password": "Password123!", "otp_code": "000000"},
    )
    assert r_login_bad_otp.status_code == 401

    # 6. Login with valid otp_code -> 200
    r_login_ok = client.post(
        "/api/v1/auth/login",
        json={"username": "totp_user", "password": "Password123!", "otp_code": compute_totp(srv_secret)},
    )
    assert r_login_ok.status_code == 200
    assert r_login_ok.json()["user"]["totp_enabled"] is True

    # Disable with invalid code -> 400
    assert client.post("/api/v1/auth/2fa/disable", json={"code": "000000"}, headers=headers).status_code == 400

    # 7. Disable 2FA
    r_dis = client.post(
        "/api/v1/auth/2fa/disable",
        json={"code": compute_totp(srv_secret)},
        headers=headers,
    )
    assert r_dis.status_code == 200
    assert r_dis.json()["totp_enabled"] is False


@pytest.mark.parametrize(
    "marker_file,expected_image",
    [
        ("bun.lockb", "oven/bun:1-alpine"),
        ("pyproject.toml", "python:3.11-slim"),
        ("go.mod", "golang:1.22-alpine"),
        ("Cargo.toml", "rust:1.77-alpine"),
        ("composer.json", "php:8.3-apache"),
        ("Gemfile", "ruby:3.3-slim"),
        ("pom.xml", "eclipse-temurin:21-jdk-alpine"),
        ("App.csproj", "mcr.microsoft.com/dotnet/sdk:8.0"),
    ],
)
def test_expanded_zero_config_auto_dockerfiles(tmp_path, marker_file, expected_image):
    (tmp_path / marker_file).write_text("# sample manifest", encoding="utf-8")
    _ensure_auto_dockerfile(str(tmp_path), "Dockerfile")
    df_content = (tmp_path / "Dockerfile").read_text(encoding="utf-8")
    assert expected_image in df_content


def test_gitlab_bitbucket_and_gitea_webhooks(client, monkeypatch):
    headers, _ = _auth_headers(client)
    monkeypatch.setattr("app.api.v1.endpoints.webhooks._trigger_deploy", lambda *a, **kw: None)
    monkeypatch.setattr("app.api.v1.endpoints.webhooks._trigger_preview_deploy", lambda *a, **kw: None)

    client.post(
        "/api/v1/projects",
        json={
            "name": "gitlab-app",
            "repo_url": "https://gitlab.com/acme/gitlab-app.git",
            "branch": "main",
            "webhook_secret": "gl-secret-123",
        },
        headers=headers,
    )
    client.post(
        "/api/v1/projects",
        json={
            "name": "bb-app",
            "repo_url": "https://bitbucket.org/acme/bb-app",
            "branch": "main",
            "webhook_secret": "bb-secret-123",
        },
        headers=headers,
    )
    client.post(
        "/api/v1/projects",
        json={
            "name": "gitea-app",
            "repo_url": "https://gitea.example.com/acme/gitea-app.git",
            "branch": "main",
            "webhook_secret": "gt-secret-123",
        },
        headers=headers,
    )

    # Erros de cabeçalho ausente / assinatura inválida
    assert client.post("/api/v1/webhooks/gitlab", json={}).status_code == 401
    assert (
        client.post(
            "/api/v1/webhooks/gitlab",
            json={"project": {"git_http_url": "https://gitlab.com/acme/gitlab-app.git"}},
            headers={"X-Gitlab-Token": "wrong"},
        ).status_code
        == 401
    )
    assert client.post("/api/v1/webhooks/bitbucket", json={}).status_code == 401
    assert client.post("/api/v1/webhooks/gitea", json={}).status_code == 401

    # 1. GitLab Push Hook (main + preview branch + ignored event)
    gl_push = {
        "object_kind": "push",
        "ref": "refs/heads/main",
        "checkout_sha": "abcdef1234567890",
        "project": {"git_http_url": "https://gitlab.com/acme/gitlab-app.git"},
    }
    r_gl = client.post(
        "/api/v1/webhooks/gitlab",
        json=gl_push,
        headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "gl-secret-123"},
    )
    assert r_gl.status_code == 202
    assert r_gl.json()["status"] == "queued"

    gl_preview_push = {
        "object_kind": "push",
        "ref": "refs/heads/feat-branch",
        "checkout_sha": "abcdef1234567890",
        "project": {"git_http_url": "https://gitlab.com/acme/gitlab-app.git"},
    }
    r_gl_pv = client.post(
        "/api/v1/webhooks/gitlab",
        json=gl_preview_push,
        headers={"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "gl-secret-123"},
    )
    assert r_gl_pv.json()["status"] == "preview_queued"

    # GitLab Merge Request Hook (Preview)
    gl_mr = {
        "object_kind": "merge_request",
        "project": {"git_http_url": "https://gitlab.com/acme/gitlab-app.git"},
        "object_attributes": {"action": "open", "iid": 42, "source_branch": "feat-gl"},
    }
    r_gl_mr = client.post(
        "/api/v1/webhooks/gitlab",
        json=gl_mr,
        headers={"X-Gitlab-Event": "Merge Request Hook", "X-Gitlab-Token": "gl-secret-123"},
    )
    assert r_gl_mr.status_code == 202
    assert r_gl_mr.json()["status"] == "preview_queued"

    # 2. Bitbucket repo:push & pullrequest:created
    bb_payload = {
        "repository": {"full_name": "acme/bb-app"},
        "push": {
            "changes": [
                {"new": {"name": "main", "target": {"hash": "112233445566"}}}
            ]
        },
    }
    raw_bb = json.dumps(bb_payload).encode("utf-8")
    sig_bb = "sha256=" + hmac.new(b"bb-secret-123", raw_bb, hashlib.sha256).hexdigest()
    r_bb = client.post(
        "/api/v1/webhooks/bitbucket",
        content=raw_bb,
        headers={
            "Content-Type": "application/json",
            "X-Event-Key": "repo:push",
            "X-Hub-Signature-256": sig_bb,
        },
    )
    assert r_bb.status_code == 202
    assert r_bb.json()["status"] == "queued"

    bb_pr = {
        "repository": {"full_name": "acme/bb-app"},
        "pullrequest": {"id": 9, "source": {"branch": {"name": "feat-bb"}}},
    }
    raw_bb_pr = json.dumps(bb_pr).encode("utf-8")
    sig_bb_pr = "sha256=" + hmac.new(b"bb-secret-123", raw_bb_pr, hashlib.sha256).hexdigest()
    r_bb_pr = client.post(
        "/api/v1/webhooks/bitbucket",
        content=raw_bb_pr,
        headers={
            "Content-Type": "application/json",
            "X-Event-Key": "pullrequest:created",
            "X-Hub-Signature-256": sig_bb_pr,
        },
    )
    assert r_bb_pr.status_code == 202
    assert r_bb_pr.json()["status"] == "preview_queued"

    # 3. Gitea push
    gt_payload = {
        "ref": "refs/heads/main",
        "after": "998877665544",
        "repository": {"clone_url": "https://gitea.example.com/acme/gitea-app.git"},
    }
    raw_gt = json.dumps(gt_payload).encode("utf-8")
    sig_gt = hmac.new(b"gt-secret-123", raw_gt, hashlib.sha256).hexdigest()
    r_gt = client.post(
        "/api/v1/webhooks/gitea",
        content=raw_gt,
        headers={
            "Content-Type": "application/json",
            "X-Gitea-Event": "push",
            "X-Gitea-Signature": sig_gt,
        },
    )
    assert r_gt.status_code == 202
    assert r_gt.json()["status"] == "queued"


def test_project_scaling_autoscaler_and_granular_rbac(client):
    admin_headers, _ = _auth_headers(client, username="rbac_admin", role="admin")
    dev_headers, dev_user = _auth_headers(client, username="rbac_dev1", role="developer")
    other_headers, _ = _auth_headers(client, username="rbac_dev2", role="developer")

    r_proj = client.post(
        "/api/v1/projects",
        json={
            "name": "scalable-api",
            "template": "fastapi",
            "replicas": 2,
            "autoscale_enabled": True,
            "autoscale_min_replicas": 1,
            "autoscale_max_replicas": 4,
            "autoscale_cpu_target": 70,
        },
        headers=admin_headers,
    )
    assert r_proj.status_code == 200
    proj_id = r_proj.json()["id"]
    assert r_proj.json()["replicas"] == 2

    r_scale = client.post(
        f"/api/v1/projects/{proj_id}/scale",
        json={
            "replicas": 3,
            "autoscale_enabled": True,
            "autoscale_min_replicas": 1,
            "autoscale_max_replicas": 5,
            "autoscale_cpu_target": 65,
        },
        headers=admin_headers,
    )
    assert r_scale.status_code == 200
    assert r_scale.json()["replicas"] == 3

    r_auto_up = client.post(
        "/api/v1/paas/autoscaler/evaluate",
        json={"simulated_cpu_by_project": {proj_id: 90.0}},
        headers=admin_headers,
    )
    assert r_auto_up.status_code == 200
    assert len(r_auto_up.json()["scaled_actions"]) == 1
    assert r_auto_up.json()["scaled_actions"][0]["new_replicas"] == 4

    r_auto_down = client.post(
        "/api/v1/paas/autoscaler/evaluate",
        json={"simulated_cpu_by_project": {proj_id: 10.0}},
        headers=admin_headers,
    )
    assert r_auto_down.status_code == 200
    assert r_auto_down.json()["scaled_actions"][0]["new_replicas"] == 3

    # RBAC Granular por Projeto
    r_mem = client.post(
        f"/api/v1/projects/{proj_id}/members",
        json={"user_id": str(dev_user.id), "role": "viewer"},
        headers=admin_headers,
    )
    assert r_mem.status_code == 200
    assert len(client.get(f"/api/v1/projects/{proj_id}/members", headers=admin_headers).json()) == 1

    r_dep_denied = client.post(f"/api/v1/projects/{proj_id}/deploy", headers=dev_headers)
    assert r_dep_denied.status_code == 403
    assert client.delete(f"/api/v1/projects/{proj_id}", headers=dev_headers).status_code == 403

    r_edit_denied = client.patch(
        f"/api/v1/projects/{proj_id}",
        json={"branch": "develop"},
        headers=other_headers,
    )
    assert r_edit_denied.status_code == 403

    # Papel inválido -> 400
    assert (
        client.post(
            f"/api/v1/projects/{proj_id}/members",
            json={"user_id": str(dev_user.id), "role": "invalid_role"},
            headers=admin_headers,
        ).status_code
        == 400
    )

    r_rem = client.delete(
        f"/api/v1/projects/{proj_id}/members/{dev_user.id}",
        headers=admin_headers,
    )
    assert r_rem.status_code == 200


def test_paas_databases_templates_backups_crons_registries_cloudflare_traefik_and_diagnose(client):
    headers, _ = _auth_headers(client)

    # 1. Bancos de Dados Gerenciados (Postgres, MySQL, MariaDB, Redis, MongoDB)
    for eng in ("postgres", "mysql", "mariadb", "redis", "mongodb"):
        r_db = client.post(
            "/api/v1/paas/databases",
            json={"name": f"meu-{eng}", "engine": eng, "memory_limit_mb": 256, "username": "custom_user"},
            headers=headers,
        )
        assert r_db.status_code == 200
        assert r_db.json()["engine"] == eng
        assert "connection_url" in r_db.json()

    assert (
        client.post(
            "/api/v1/paas/databases",
            json={"name": "bad", "engine": "oracle"},
            headers=headers,
        ).status_code
        == 400
    )

    dbs = client.get("/api/v1/paas/databases", headers=headers).json()
    assert len(dbs) >= 5
    del_db = client.delete(f"/api/v1/paas/databases/{dbs[0]['id']}", headers=headers)
    assert del_db.status_code == 200
    assert client.delete("/api/v1/paas/databases/not-found", headers=headers).status_code == 404

    # 2. Catálogo de Templates 1-Clique
    tpls = client.get("/api/v1/paas/templates", headers=headers).json()
    assert len(tpls) >= 8
    r_launch = client.post(
        "/api/v1/paas/templates/n8n/launch",
        json={"app_name": "deploydock_n8n_test", "env_overrides": {"CUSTOM_VAR": "1"}},
        headers=headers,
    )
    assert r_launch.status_code == 200
    assert r_launch.json()["template_id"] == "n8n"
    assert client.post("/api/v1/paas/templates/unknown/launch", json={}, headers=headers).status_code == 404

    # 3. Backups Agendados + S3 Config
    r_s3 = client.put(
        "/api/v1/paas/backups/s3-config",
        json={
            "enabled": True,
            "provider": "cloudflare_r2",
            "endpoint_url": "https://s3.example.com",
            "bucket": "my-backups",
            "region": "auto",
            "access_key": "AKIA_TEST",
            "secret_key": "SECRET_TEST_KEY",
        },
        headers=headers,
    )
    assert r_s3.status_code == 200
    assert r_s3.json()["has_secret_key"] is True

    r_bjob = client.post(
        "/api/v1/paas/backups/jobs",
        json={
            "name": "Backup Diário Postgres",
            "target_type": "database",
            "target_name": "deploydock_db_meu-postgres",
            "cron_expression": "0 3 * * *",
            "s3_upload": True,
            "retention_count": 14,
        },
        headers=headers,
    )
    assert r_bjob.status_code == 200
    job_id = r_bjob.json()["id"]

    r_brun = client.post(f"/api/v1/paas/backups/jobs/{job_id}/run", headers=headers)
    assert r_brun.status_code == 200
    assert r_brun.json()["status"] == "completed"
    assert r_brun.json()["s3_url"].startswith("s3://my-backups/")

    assert client.get("/api/v1/paas/backups", headers=headers).status_code == 200
    assert client.delete(f"/api/v1/paas/backups/jobs/{job_id}", headers=headers).status_code == 200
    assert client.delete(f"/api/v1/paas/backups/jobs/{job_id}", headers=headers).status_code == 404

    # 4. Cron Jobs por Aplicação
    proj = client.post(
        "/api/v1/projects",
        json={"name": "cron-app", "template": "fastapi"},
        headers=headers,
    ).json()
    r_cron = client.post(
        "/api/v1/paas/crons",
        json={
            "project_id": proj["id"],
            "name": "Limpar Sessões Expiradas",
            "command": "python -c 'print(123)'",
            "cron_expression": "*/30 * * * *",
        },
        headers=headers,
    )
    assert r_cron.status_code == 200
    cron_id = r_cron.json()["id"]

    r_crun = client.post(f"/api/v1/paas/crons/{cron_id}/run", headers=headers)
    assert r_crun.status_code == 200
    assert r_crun.json()["last_run_at"] is not None
    assert len(client.get(f"/api/v1/paas/crons?project_id={proj['id']}", headers=headers).json()) == 1
    assert client.delete(f"/api/v1/paas/crons/{cron_id}", headers=headers).status_code == 200

    # 5. Container Registries Privados
    r_reg = client.post(
        "/api/v1/paas/registries",
        json={
            "name": "GitHub Container Registry",
            "server_address": "https://ghcr.io",
            "username": "octocat",
            "password": "ghp_secret_token",
        },
        headers=headers,
    )
    assert r_reg.status_code == 200
    reg_id = r_reg.json()["id"]
    assert len(client.get("/api/v1/paas/registries", headers=headers).json()) >= 1
    assert client.delete(f"/api/v1/paas/registries/{reg_id}", headers=headers).status_code == 200

    # 6. Cloudflare DNS Automático
    r_cf_cfg = client.put(
        "/api/v1/paas/cloudflare/config",
        json={
            "enabled": True,
            "zone_id": "zone_12345",
            "base_domain": "meusaas.com.br",
            "server_ip": "203.0.113.50",
            "proxied_default": True,
            "api_token": "cf_tok_secret",
        },
        headers=headers,
    )
    assert r_cf_cfg.status_code == 200
    assert r_cf_cfg.json()["config"]["has_api_token"] is True

    r_cf_rec = client.post(
        "/api/v1/paas/cloudflare/records",
        json={"type": "CNAME", "name": "app.meusaas.com.br", "content": "meusaas.com.br", "proxied": True},
        headers=headers,
    )
    assert r_cf_rec.status_code == 200

    r_cf_sync = client.post(
        f"/api/v1/paas/cloudflare/sync-project/{proj['id']}",
        headers=headers,
    )
    assert r_cf_sync.status_code == 200
    rec_id = r_cf_sync.json()["id"]
    assert r_cf_sync.json()["content"] == "203.0.113.50"
    assert client.get("/api/v1/paas/cloudflare", headers=headers).status_code == 200
    assert client.delete(f"/api/v1/paas/cloudflare/records/{rec_id}", headers=headers).status_code == 200

    # 7. Traefik Visual Config & Certificados TLS Customizados
    r_tf = client.put(
        "/api/v1/paas/traefik/config",
        json={"acme_email": "ssl@meusaas.com.br", "hsts_enabled": True},
        headers=headers,
    )
    assert r_tf.status_code == 200
    assert r_tf.json()["acme_email"] == "ssl@meusaas.com.br"

    r_cert = client.post(
        "/api/v1/paas/traefik/certificates",
        json={
            "domain": "*.meusaas.com.br",
            "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
            "issuer": "Cloudflare Origin CA",
        },
        headers=headers,
    )
    assert r_cert.status_code == 200
    cert_id = r_cert.json()["id"]
    assert client.get("/api/v1/paas/traefik", headers=headers).status_code == 200
    assert client.delete(f"/api/v1/paas/traefik/certificates/{cert_id}", headers=headers).status_code == 200

    # 8. Diagnóstico Inteligente de Falhas de Build/Deploy (múltiplos padrões)
    for sample_log, expected_cat in [
        ("ModuleNotFoundError: No module named 'psycopg2'", "Python"),
        ("npm ERR! ERESOLVE unable to resolve dependency tree", "Node.js"),
        ("OOMKilled: exit code 137 out of memory", "RAM"),
        ("OperationalError: password authentication failed for user", "Banco de Dados"),
        ("EADDRINUSE: address already in use 0.0.0.0:3000", "Rede"),
    ]:
        r_diag = client.post(
            "/api/v1/paas/diagnose",
            json={"logs": sample_log, "error_message": "Failed", "status": "failed"},
            headers=headers,
        )
        assert r_diag.status_code == 200
        assert expected_cat in r_diag.json()["category"]

    # Healthy e Generic fallback
    r_diag_ok = client.post(
        "/api/v1/paas/diagnose",
        json={"logs": "Build complete", "status": "healthy"},
        headers=headers,
    )
    assert r_diag_ok.json()["status"] == "healthy"

    r_diag_gen = client.post(
        "/api/v1/paas/diagnose",
        json={"logs": "unknown custom crash", "status": "failed"},
        headers=headers,
    )
    assert r_diag_gen.json()["status"] == "failed"

    # Overview completo PaaS
    r_ov = client.get("/api/v1/paas/overview", headers=headers)
    assert r_ov.status_code == 200
    assert "databases" in r_ov.json() and "templates" in r_ov.json()


def test_gateway_proxy_and_deployment_diagnose(client):
    import asyncio
    from unittest.mock import AsyncMock, patch
    import httpx
    from app.api.v1.endpoints.gateway import _inject_gateway_shim, _find_container_host_port
    from app.db.session import async_session_factory
    from app.models.deployment import Deployment

    headers, _ = _auth_headers(client)

    # 1. Gateway HTML shim e redirecionamento raiz
    patched_html = _inject_gateway_shim(
        '<html><head><title>App</title></head><body><a href="/login">Login</a></body></html>',
        "/open/my-app",
    )
    assert '<base href="/open/my-app/">' in patched_html
    assert 'href="/open/my-app/login"' in patched_html

    r_redir = client.get("/open/port-8080?foo=1", follow_redirects=False)
    assert r_redir.status_code == 307
    assert r_redir.headers["location"] == "/open/port-8080/?foo=1"

    assert asyncio.run(_find_container_host_port("port-3005")) == 3005
    assert asyncio.run(_find_container_host_port("4000")) == 4000

    # Proxy request simulada com httpx.AsyncClient.request mockado
    fake_resp = httpx.Response(
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8", "location": "/dash"},
        content=b'<html><head></head><body><a href="/home">Home</a></body></html>',
    )
    with patch("httpx.AsyncClient.request", new=AsyncMock(return_value=fake_resp)):
        r_gw = client.get("/open/my-app/index.html")
        assert r_gw.status_code == 200
        assert "/open/my-app/home" in r_gw.text
        assert r_gw.headers.get("location") == "/open/my-app/dash"

    # 2. Diagnóstico de Deployment específico via /api/v1/deployments/{id}/diagnose
    proj = client.post(
        "/api/v1/projects",
        json={"name": "diag-proj", "template": "html"},
        headers=headers,
    ).json()

    async def _seed_dep():
        import uuid
        async with async_session_factory() as db:
            dep = Deployment(
                project_id=uuid.UUID(proj["id"]),
                commit_sha="12345678",
                commit_message="Fix dockerfile",
                commit_author="admin",
                branch="main",
                status="failed",
                build_logs="ModuleNotFoundError: No module named 'fastapi'",
                error_message="Docker build failed",
            )
            db.add(dep)
            await db.commit()
            await db.refresh(dep)
            return str(dep.id)

    dep_id = asyncio.run(_seed_dep())
    r_dep_diag = client.get(f"/api/v1/deployments/{dep_id}/diagnose", headers=headers)
    assert r_dep_diag.status_code == 200
    assert r_dep_diag.json()["deployment_id"] == dep_id
    assert "Python" in r_dep_diag.json()["category"]
    assert client.get("/api/v1/deployments/00000000-0000-0000-0000-000000000000/diagnose", headers=headers).status_code == 404


def test_github_integration_and_auto_code_auth_inspection(client):
    from unittest.mock import AsyncMock, patch
    import httpx

    headers, _ = _auth_headers(client)

    # 1. Status inicial do GitHub
    r_st = client.get("/api/v1/paas/github", headers=headers)
    assert r_st.status_code == 200
    assert "connected" in r_st.json()

    # 2. Conectar conta GitHub via Token (com mock da API /user do GitHub)
    fake_user_resp = httpx.Response(
        status_code=200,
        headers={"x-oauth-scopes": "repo, read:user, admin:repo_hook"},
        json={"login": "JeanMago", "name": "Jean Mago", "avatar_url": "https://avatars.githubusercontent.com/u/1"},
    )
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=fake_user_resp)):
        r_conn = client.post(
            "/api/v1/paas/github/connect",
            json={
                "token": "ghp_test_token_123456",
                "auto_inject_git_token": True,
                "auto_create_webhook": True,
                "auto_import_env_example": True,
            },
            headers=headers,
        )
        assert r_conn.status_code == 200
        assert r_conn.json()["connected"] is True
        assert r_conn.json()["username"] == "JeanMago"
        assert r_conn.json()["has_token"] is True

    # 3. OAuth Device Flow (start + poll)
    fake_device_start = httpx.Response(
        status_code=200,
        json={
            "user_code": "ABCD-1234",
            "verification_uri": "https://github.com/login/device",
            "device_code": "dev_code_xyz",
            "expires_in": 900,
            "interval": 5,
        },
    )
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_device_start)):
        r_dev = client.post("/api/v1/paas/github/device/start", json={}, headers=headers)
        assert r_dev.status_code == 200
        assert r_dev.json()["user_code"] == "ABCD-1234"

    fake_device_poll = httpx.Response(
        status_code=200,
        json={"access_token": "gho_oauth_device_token_999"},
    )
    with (
        patch("httpx.AsyncClient.post", new=AsyncMock(return_value=fake_device_poll)),
        patch("httpx.AsyncClient.get", new=AsyncMock(return_value=fake_user_resp)),
    ):
        r_poll = client.post("/api/v1/paas/github/device/poll", headers=headers)
        assert r_poll.status_code == 200
        assert r_poll.json()["status"] == "connected"
        assert r_poll.json()["github"]["auth_mode"] == "oauth_device"

    # 4. Listagem de repositórios autenticados
    fake_repos_resp = httpx.Response(
        status_code=200,
        json=[
            {
                "id": 101,
                "name": "DeployDock",
                "full_name": "JeanMago/DeployDock",
                "owner": {"login": "JeanMago"},
                "private": True,
                "html_url": "https://github.com/JeanMago/DeployDock",
                "clone_url": "https://github.com/JeanMago/DeployDock.git",
                "default_branch": "main",
                "language": "Python",
                "description": "PaaS GitOps",
                "updated_at": "2026-11-01T19:00:00Z",
            }
        ],
    )
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=fake_repos_resp)):
        r_repos = client.get("/api/v1/paas/github/repos", headers=headers)
        assert r_repos.status_code == 200
        assert len(r_repos.json()) == 1
        assert r_repos.json()[0]["full_name"] == "JeanMago/DeployDock"

    # 5. Inspeção automática de código, branches, Dockerfile e .env.example no GitHub
    async def _mock_github_inspect_get(url, **kwargs):
        if url.endswith("/repos/JeanMago/DeployDock"):
            return httpx.Response(
                200,
                json={
                    "default_branch": "main",
                    "private": True,
                    "clone_url": "https://github.com/JeanMago/DeployDock.git",
                    "language": "Python",
                },
            )
        if "/branches" in url:
            return httpx.Response(200, json=[{"name": "main"}, {"name": "develop"}])
        if url.endswith("/contents?ref=main"):
            return httpx.Response(
                200,
                json=[
                    {"name": "Dockerfile"},
                    {"name": ".env.example"},
                    {"name": "requirements.txt"},
                ],
            )
        if "/contents/.env.example" in url:
            return httpx.Response(
                200,
                text="SECRET_KEY=changeme\nAPP_PORT=8080\nDATABASE_URL=postgresql://user:pass@db:5432/app\n",
            )
        if "/contents/Dockerfile" in url:
            return httpx.Response(200, text="FROM python:3.12-slim\nEXPOSE 8080\n")
        return httpx.Response(404)

    with patch("httpx.AsyncClient.get", side_effect=_mock_github_inspect_get):
        r_insp = client.post(
            "/api/v1/paas/github/inspect",
            json={"repo_or_url": "https://github.com/JeanMago/DeployDock.git"},
            headers=headers,
        )
        assert r_insp.status_code == 200
        insp_data = r_insp.json()
        assert insp_data["full_name"] == "JeanMago/DeployDock"
        assert insp_data["detected_port"] == 8080
        assert insp_data["env_file_found"] == ".env.example"
        assert len(insp_data["discovered_env_vars"]) == 3
        assert insp_data["using_saved_github_token"] is True

    # 6. Criação de projeto GitHub sem passar git_token manual — herda automaticamente a credencial global e importa .env.example
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=httpx.Response(201, json={"id": 555}))):
        r_proj = client.post(
            "/api/v1/projects",
            json={
                "name": "auto-auth-gh-app",
                "repo_url": "https://github.com/JeanMago/DeployDock.git",
                "branch": "main",
                "initial_env_vars": insp_data["discovered_env_vars"],
            },
            headers=headers,
        )
        assert r_proj.status_code == 200
        assert r_proj.json()["has_git_token"] is True

        r_envs = client.get(f"/api/v1/projects/{r_proj.json()['id']}/env", headers=headers)
        assert r_envs.status_code == 200
        assert len(r_envs.json()) == 3

        r_wh = client.post(
            "/api/v1/paas/github/webhook",
            json={
                "repo_or_url": "JeanMago/DeployDock",
                "webhook_url": "http://localhost:8000/api/v1/webhooks/github",
                "webhook_secret": "sec123",
            },
            headers=headers,
        )
        assert r_wh.status_code == 200
        assert r_wh.json()["created"] is True

    # 7. Atualizar preferências e desconectar
    assert (
        client.patch(
            "/api/v1/paas/github/preferences",
            json={"auto_create_webhook": False},
            headers=headers,
        ).status_code
        == 200
    )
    r_disc = client.delete("/api/v1/paas/github/disconnect", headers=headers)
    assert r_disc.status_code == 200
    assert r_disc.json()["connected"] is False


def test_account_oauth_git_google_admin_access_and_email_notifications(client):
    admin_headers, _ = _auth_headers(client, username="access_admin", role="admin")

    # 1. Provedores públicos OAuth na tela de Login
    r_prov = client.get("/api/v1/auth/oauth/providers")
    assert r_prov.status_code == 200
    assert r_prov.json()["allow_github_login"] is True
    assert r_prov.json()["allow_google_login"] is True

    # 2. Login via Conta Git (GitHub) criando/vinculando conta automaticamente
    r_gh_login = client.post(
        "/api/v1/auth/oauth/github",
        json={
            "username": "JeanMagoGit",
            "email": "jeanmago@github.example.com",
            "name": "Jean Mago Git",
        },
    )
    assert r_gh_login.status_code == 200
    gh_user = r_gh_login.json()["user"]
    gh_token = r_gh_login.json()["access_token"]
    assert gh_user["github_linked"] is True
    assert gh_user["github_username"] == "JeanMagoGit"
    assert gh_user["last_login_provider"] == "github"

    # 3. Login via Conta Google
    r_gg_login = client.post(
        "/api/v1/auth/oauth/google",
        json={
            "email": "jean.google@gmail.com",
            "name": "Jean Google",
        },
    )
    assert r_gg_login.status_code == 200
    gg_user = r_gg_login.json()["user"]
    assert gg_user["google_linked"] is True
    assert gg_user["google_email"] == "jean.google@gmail.com"
    assert gg_user["last_login_provider"] == "google"

    # 4. Tela de Minha Conta (/api/v1/auth/account): vincular Google na conta Git (tornando-a híbrida)
    user_headers = {"Authorization": f"Bearer {gh_token}"}
    r_link_gg = client.post(
        "/api/v1/auth/account/link/google",
        json={"email": "jeanmago.linked@gmail.com", "name": "Jean Linked"},
        headers=user_headers,
    )
    assert r_link_gg.status_code == 200
    assert r_link_gg.json()["user"]["account_type"] == "hybrid"

    r_acc = client.get("/api/v1/auth/account", headers=user_headers)
    assert r_acc.status_code == 200
    assert r_acc.json()["user"]["github_linked"] is True
    assert r_acc.json()["user"]["google_linked"] is True

    # 5. Página de Controle de Acessos & Contas Logadas para Admins (/api/v1/auth/admin/access)
    r_adm = client.get("/api/v1/auth/admin/access", headers=admin_headers)
    assert r_adm.status_code == 200
    adm_data = r_adm.json()
    assert adm_data["stats"]["github_linked_count"] >= 1
    assert adm_data["stats"]["google_linked_count"] >= 2
    assert len(adm_data["sessions"]) >= 2

    # Admin altera políticas e nível de acesso da conta OAuth
    r_pol = client.put(
        "/api/v1/auth/admin/access/policies",
        json={"default_oauth_role": "viewer", "allowed_email_domains": "*"},
        headers=admin_headers,
    )
    assert r_pol.status_code == 200
    assert r_pol.json()["policies"]["default_oauth_role"] == "viewer"

    r_upd_acc = client.patch(
        f"/api/v1/auth/admin/users/{gh_user['id']}/access",
        json={"role": "admin", "email_notifications": True},
        headers=admin_headers,
    )
    assert r_upd_acc.status_code == 200
    assert r_upd_acc.json()["role"] == "admin"

    r_rev = client.post(
        f"/api/v1/auth/admin/users/{gh_user['id']}/revoke-sessions",
        headers=admin_headers,
    )
    assert r_rev.status_code == 200
    assert r_rev.json()["revoked_sessions"] >= 1

    # 6. Notificação por E-mail na parte de Mensagens (/api/v1/system/notifications)
    r_notif_cfg = client.put(
        "/api/v1/system/notifications/config",
        json={
            "email_enabled": True,
            "email_recipients": "alertas@deploydock.local, devops@gmail.com",
            "notify_logged_users_emails": True,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
        },
        headers=admin_headers,
    )
    assert r_notif_cfg.status_code == 200
    assert "email" in r_notif_cfg.json()["overview"]["channels_configured"]

    r_test_notif = client.post(
        "/api/v1/system/notifications/test",
        json={
            "title": "Deploy Concluído",
            "message": "Notificação por e-mail ativa!",
            "severity": "success",
            "email_to": "teste@deploydock.local",
        },
        headers=admin_headers,
    )
    assert r_test_notif.status_code == 200
    assert "email" in r_test_notif.json()["channels"]





