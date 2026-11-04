"""
Cobertura de 90%+ dos serviços de infraestrutura, notificações, uptime, git,
rotas Traefik, orquestrador (preview, rollback, apply_routing, health check) e WebSocket.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.routing import (
    build_traefik_labels,
    normalize_domain,
    normalize_subdomain,
    project_host,
    public_url,
    slugify,
)
from app.core.security import decrypt_value, encrypt_value
from app.models.deployment import Deployment
from app.models.environment import EnvironmentVariable
from app.models.project import Project
from app.services import deploy_orchestrator as orch_mod
from app.services import docker_service as ds_mod
from app.services.deploy_orchestrator import DeployOrchestrator, _extract_git_token
from app.services.docker_service import DockerService, _collect_host_metrics_sync, _dir_size_bytes
from app.services.git_service import GitService, _inject_git_token
from app.services.notification_service import NotificationService
from app.services.uptime_service import UptimeMonitorService
from app.services.websocket_manager import ConnectionManager


# ── Routing & Security Fernet ────────────────────────────────────────────


def test_routing_helpers_and_tls_labels(monkeypatch):
    from app.core import routing as r_mod

    assert slugify("Meu Projeto 123!") == "meu-projeto-123"
    assert normalize_subdomain("  Meu-App ") == "meu-app"
    assert normalize_domain("https://App.Exemplo.com/caminho") == "app.exemplo.com"
    assert normalize_domain("   ") is None
    assert project_host("sub", None, "nome") == f"sub.{r_mod.settings.APPS_BASE_DOMAIN}"
    assert project_host("sub", "custom.com", "nome") == "custom.com"

    monkeypatch.setattr(r_mod.settings, "APPS_TLS_ENABLED", True)
    monkeypatch.setattr(r_mod.settings, "PROXY_HTTPS_PORT", 8443)
    assert public_url("app.exemplo.com") == "https://app.exemplo.com:8443"

    labels = build_traefik_labels("12345678-1234-1234-1234-1234567890ab", "app.exemplo.com", 3000)
    assert any("redirectscheme" in k for k in labels)
    assert any(v == "3000" for v in labels.values())


def test_fernet_encrypt_decrypt_roundtrip():
    token = encrypt_value("segredo-123")
    assert decrypt_value(token) == "segredo-123"


# ── DockerService: get_system_info, get_resources_overview, db_dump fallbacks ──


@pytest.mark.asyncio
async def test_docker_system_info_and_resources_overview(tmp_path, monkeypatch):
    # Criar subpastas em tmp_path para exercitar _dir_size_bytes
    sub = tmp_path / "proj1"
    sub.mkdir()
    (sub / "arquivo.txt").write_bytes(b"x" * 2048)
    size_b, count = _dir_size_bytes(str(tmp_path))
    assert size_b >= 2048 and count == 1
    assert _dir_size_bytes(str(tmp_path / "nao-existe")) == (0, 0)

    metrics = _collect_host_metrics_sync()
    assert "cpu_cores" in metrics and "memory_total_mb" in metrics

    monkeypatch.setattr(ds_mod.settings, "REPOS_BASE_PATH", str(tmp_path))
    svc = DockerService()
    svc._client = MagicMock()
    svc._client.info.return_value = {
        "OperatingSystem": "Linux",
        "Architecture": "x86_64",
        "NCPU": 4,
        "MemTotal": 8 * 1024 * 1024 * 1024,
        "Containers": 2,
        "ContainersRunning": 1,
        "ContainersStopped": 1,
        "ContainersPaused": 0,
        "Images": 3,
    }
    svc._client.version.return_value = {"Version": "27.0", "ApiVersion": "1.46"}
    svc._client.volumes.list.return_value = []
    svc._client.networks.list.return_value = []

    sys_info = await svc.get_system_info()
    assert sys_info["docker_version"] == "27.0"
    assert sys_info["cpus"] == 4

    c_run = MagicMock()
    c_run.short_id = "c1"
    c_run.id = "c1_full"
    c_run.name = "web"
    c_run.status = "running"
    c_run.image = SimpleNamespace(tags=["nginx:alpine"], short_id="i1")
    c_run.attrs = {"State": {"Status": "running"}}
    c_run.stats.return_value = {
        "cpu_stats": {"cpu_usage": {"total_usage": 50}, "system_cpu_usage": 500, "online_cpus": 2},
        "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
        "memory_stats": {"usage": 20 * 1024 * 1024, "limit": 200 * 1024 * 1024},
        "networks": {"eth0": {"rx_bytes": 1024, "tx_bytes": 2048}},
    }

    svc._client.containers.list.return_value = [c_run]
    svc._client.df.return_value = {
        "LayersSize": 100 * 1024 * 1024,
        "Images": [
            {"Id": "sha256:abcdef1234567890", "RepoTags": ["nginx:alpine"], "Created": 1, "Size": 60 * 1024 * 1024, "SharedSize": 10 * 1024 * 1024, "Containers": 1},
            {"Id": "sha256:0000001234567890", "RepoTags": [], "Created": 1, "Size": 40 * 1024 * 1024, "SharedSize": 0, "Containers": 0},
        ],
        "Containers": [
            {"Id": "c1_full", "SizeRw": 5 * 1024 * 1024, "SizeRootFs": 65 * 1024 * 1024, "State": "running"},
            {"Id": "c2_full", "SizeRw": 2 * 1024 * 1024, "SizeRootFs": 20 * 1024 * 1024, "State": "exited"},
        ],
        "Volumes": [
            {"Name": "v_active", "Driver": "local", "Mountpoint": "/m1", "CreatedAt": "now", "UsageData": {"Size": 10 * 1024 * 1024, "RefCount": 1}},
            {"Name": "v_idle", "Driver": "local", "Mountpoint": "/m2", "CreatedAt": "now", "UsageData": {"Size": 4 * 1024 * 1024, "RefCount": 0}},
        ],
        "BuildCache": [
            {"Size": 8 * 1024 * 1024, "InUse": True, "Shared": False},
            {"Size": 3 * 1024 * 1024, "InUse": False, "Shared": False},
        ],
    }

    overview = await svc.get_resources_overview()
    assert overview["docker_usage"]["containers_running"] == 1
    assert overview["storage"]["categories"]["images"]["total_count"] == 2
    assert overview["storage"]["categories"]["volumes"]["active_count"] == 1

    # Fallback de get_system_info quando Docker está offline
    svc._client.info.side_effect = RuntimeError("offline")
    offline = await svc.get_system_info()
    assert offline["os"] == "Docker Engine Offline"


@pytest.mark.asyncio
async def test_docker_db_dump_mysql_and_tar_fallback(monkeypatch):
    svc = DockerService()
    svc._client = MagicMock()

    mysql_c = MagicMock()
    mysql_c.name = "app-mysql"
    mysql_c.image = SimpleNamespace(tags=["mysql:8"], short_id="m1")
    svc._client.containers.get.return_value = mysql_c
    monkeypatch.setattr(svc, "exec_container_command", AsyncMock(return_value={"stdout": " '-- mysql dump' "}))
    data, fname, media = await svc.export_container_db_dump("m1")
    assert media == "application/sql" and b"mysql dump" in data

    # Fallback .tar quando é contêiner de aplicação comum
    web_c = MagicMock()
    web_c.name = "app-static"
    web_c.image = SimpleNamespace(tags=["nginx:alpine"], short_id="w1")
    svc._client.containers.get.return_value = web_c
    monkeypatch.setattr(svc, "exec_container_command", AsyncMock(return_value={"stdout": "OK\n"}))
    monkeypatch.setattr(svc, "download_container_file", AsyncMock(return_value=(b"tarbytes", "app.tar")))
    data2, fname2, media2 = await svc.export_container_db_dump("w1")
    assert media2 == "application/x-tar" and data2 == b"tarbytes"


# ── NotificationService (Discord, Slack, Telegram, Webhook, Throttling) ──


@pytest.mark.asyncio
async def test_notification_service_all_channels_and_rules(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.notification_service.settings.REPOS_BASE_PATH", str(tmp_path / "repos"))
    ns = NotificationService()
    ns.update_config(
        {
            "enabled": True,
            "discord_webhook_url": "https://discord.test/webhook",
            "slack_webhook_url": "https://slack.test/webhook",
            "telegram_bot_token": "123:ABC",
            "telegram_chat_id": "999",
            "custom_webhook_url": "https://meuservidor.test/hook",
        }
    )
    ov = ns.get_overview()
    assert set(ov["channels_configured"]) == {"discord", "slack", "telegram", "webhook"}

    class FakeResp:
        status_code = 200

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json=None):
            return FakeResp()

    monkeypatch.setattr("app.services.notification_service.httpx.AsyncClient", FakeClient)

    entry = await ns.notify("deploy_success", "Deploy OK", "Tudo certo", severity="success")
    assert set(entry["channels"]) == {"discord", "slack", "telegram", "webhook"}

    # Throttling de high_resource na segunda chamada imediata
    r1 = await ns.notify("high_resource", "CPU Alta", "95%", severity="warning")
    assert "id" in r1
    r2 = await ns.notify("high_resource", "CPU Alta", "95%", severity="warning")
    assert r2["status"] == "throttled"

    # Quando desabilitado
    ns.update_config({"enabled": False})
    assert (await ns.notify("deploy_success", "x", "y"))["status"] == "disabled"


@pytest.mark.asyncio
async def test_notification_email_smtp_filtering_and_mocked_delivery(tmp_path, monkeypatch):
    monkeypatch.setattr("app.services.notification_service.settings.REPOS_BASE_PATH", str(tmp_path / "repos"))
    ns = NotificationService()

    # 1. Validação de emails públicos vs .local
    assert ns._is_valid_public_email("admin@gmail.com") is True
    assert ns._is_valid_public_email("devops@empresa.com.br") is True
    assert ns._is_valid_public_email("admin@deploydock.local") is False
    assert ns._is_valid_public_email("test@server.internal") is False
    assert ns._is_valid_public_email("invalido") is False

    # 2. Resolução de destinatários com extra_recipients (teste direcionado)
    direct = ns._resolve_email_recipients(extra_recipients=["destinatario@teste.com"])
    assert direct == ["destinatario@teste.com"]

    # 3. Teste de envio com mock do smtplib.SMTP (Porta 587 STARTTLS + App Password com espaços)
    ns.update_config(
        {
            "enabled": True,
            "email_enabled": True,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": "alerta@gmail.com",
            "smtp_password": "abcd efgh ijkl mnop",  # com espaços
            "smtp_use_tls": True,
        }
    )

    mock_server = MagicMock()
    mock_server.has_extn.return_value = True
    logged_creds = []

    def fake_login(u, p):
        logged_creds.append((u, p))

    mock_server.login = fake_login

    sent_messages = []

    def fake_send_message(msg, to_addrs=None):
        sent_messages.append((msg, to_addrs))

    mock_server.send_message = fake_send_message

    class MockSMTPContext:
        def __init__(self, host, port, timeout=12):
            self.host = host
            self.port = port
        def __enter__(self):
            return mock_server
        def __exit__(self, *args):
            pass

    monkeypatch.setattr("smtplib.SMTP", MockSMTPContext)

    # Dispara e-mail com mistura de e-mails públicos e dummy .local
    recipients = ["alerta@gmail.com", "admin@deploydock.local", "invalido"]
    ok, detail = ns._send_smtp_sync(recipients, "Assunto", "Texto", "<p>Html</p>")
    assert ok is True
    assert "smtp_sent" in detail
    assert "alerta@gmail.com" in detail
    assert "admin@deploydock.local" not in detail  # filtrado para host público!

    # Verifica se os espaços foram removidos da senha de app
    assert logged_creds == [("alerta@gmail.com", "abcdefghijklmnop")]
    assert len(sent_messages) == 1
    assert sent_messages[0][1] == ["alerta@gmail.com"]

    # 4. Teste com MailHog (Porta 1025 sem auth e permitindo .local)
    ns.update_config(
        {
            "smtp_host": "mailhog",
            "smtp_port": 1025,
            "smtp_user": "",
            "smtp_password": "",
            "smtp_use_tls": False,
        }
    )
    sent_messages.clear()
    logged_creds.clear()
    mock_server.has_extn.return_value = False

    ok_mh, detail_mh = ns._send_smtp_sync(["dev@deploydock.local"], "Assunto", "Texto", "<p>Html</p>")
    assert ok_mh is True
    assert "smtp_sent" in detail_mh
    assert len(logged_creds) == 0  # sem login para servidor unauthenticated
    assert sent_messages[0][1] == ["dev@deploydock.local"]


# ── GitService (clone, pull, get_current_commit, token injection) ────────


@pytest.mark.asyncio
async def test_git_service_with_mocked_gitpython(tmp_path, monkeypatch):
    url = _inject_git_token("https://github.com/user/repo.git", "ghp_tok")
    assert "oauth2:ghp_tok@github.com" in url
    assert _inject_git_token("git@github.com:user/repo.git", "ghp_tok") == "git@github.com:user/repo.git"

    fake_commit = SimpleNamespace(
        hexsha="1234567890abcdef",
        message="feat: initial",
        author=SimpleNamespace(name="Autor"),
        committed_datetime=SimpleNamespace(isoformat=lambda: "2026-10-29T00:00:00Z"),
    )
    fake_origin = MagicMock()
    fake_repo = MagicMock()
    fake_repo.head.commit = fake_commit
    fake_repo.remotes = MagicMock()
    fake_repo.remotes.__bool__.return_value = True
    fake_repo.remotes.origin = fake_origin

    fake_repo_cls = MagicMock(return_value=fake_repo)
    fake_repo_cls.clone_from = MagicMock(return_value=fake_repo)
    monkeypatch.setattr("app.services.git_service.git.Repo", fake_repo_cls)

    gs = GitService()
    dest = str(tmp_path / "novo_repo")
    sha = await gs.clone_repo("https://github.com/u/r.git", dest, "main", git_token="tok")
    assert sha == "1234567890abcdef"

    # Se o diretório já existe, clone_repo faz fetch/checkout/pull
    os.makedirs(dest, exist_ok=True)
    sha2 = await gs.clone_repo("https://github.com/u/r.git", dest, "main", git_token="tok")
    assert sha2 == "1234567890abcdef"

    sha3 = await gs.pull_repo(dest, "feat-x", git_token="tok", repo_url="https://github.com/u/r.git")
    assert sha3 == "1234567890abcdef"

    info = await gs.get_current_commit(dest)
    assert info["author"] == "Autor" and info["sha"] == "1234567890abcdef"


# ── UptimeMonitorService (fallback de porta direta e Auto-Healing) ───────


@pytest.mark.asyncio
async def test_uptime_monitor_auto_heal_and_fallback(monkeypatch):
    mon = UptimeMonitorService()
    proj = Project(
        id=uuid.uuid4(),
        name="app-critico",
        repo_url="https://github.com/u/r.git",
        branch="main",
        webhook_secret="s",
        subdomain="critico",
        auto_heal=True,
    )

    class FailClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def get(self, *a, **k):
            raise RuntimeError("connection refused")

    monkeypatch.setattr("app.services.uptime_service.httpx.AsyncClient", FailClient)
    monkeypatch.setattr("app.services.uptime_service.notification_manager.notify", AsyncMock())

    fake_docker = MagicMock()
    fake_docker.get_container = AsyncMock(
        return_value={"state": "running", "status": "running", "ports": {"80/tcp": [{"HostPort": "18080"}]}}
    )
    fake_docker.restart_container = AsyncMock()

    # 3 falhas seguidas devem acionar o Auto-Healing na 3ª verificação
    await mon.check_single_project(proj, fake_docker)
    await mon.check_single_project(proj, fake_docker)
    rec = await mon.check_single_project(proj, fake_docker)

    fake_docker.restart_container.assert_awaited_once()
    assert rec["auto_heals_count"] == 1
    assert mon.get_project_record(str(proj.id)) is not None
    assert str(proj.id) in mon.get_all_records()


# ── DeployOrchestrator: deploy_preview, rollback manual, _run_app_container, apply_routing, _run_health_check ──


@pytest.mark.asyncio
async def test_orchestrator_preview_rollback_apply_routing_and_healthcheck(tmp_path, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from app.db.base import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/orch_extra.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    monkeypatch.setattr(orch_mod.settings, "REPOS_BASE_PATH", str(tmp_path / "repos"))
    monkeypatch.setattr(orch_mod.ws_manager, "broadcast", AsyncMock())

    async with factory() as db:
        enc_tok = f"enc:{encrypt_value('meu-pat')}"
        proj = Project(
            id=uuid.uuid4(),
            name="proj-completo",
            repo_url="https://github.com/u/r.git",
            branch="main",
            webhook_secret="sec",
            subdomain="proj-completo",
            git_token=enc_tok,
            memory_limit_mb=256,
            cpu_limit_cores=0.5,
        )
        db.add(proj)
        await db.commit()

        assert _extract_git_token(proj) == "meu-pat"

        db.add(
            EnvironmentVariable(
                project_id=proj.id,
                key="SECRET_API",
                value=f"enc:{encrypt_value('valor-secreto')}",
                is_secret=True,
            )
        )
        dep = Deployment(
            project_id=proj.id,
            commit_sha="11223344",
            branch="main",
            status="failed",
            previous_image_id="sha256:oldimg",
        )
        db.add(dep)
        await db.commit()
        await db.refresh(dep)

        docker = MagicMock()
        docker.ensure_network = MagicMock()
        docker.get_image_exposed_ports = MagicMock(return_value=[8080])
        docker.client.containers.run = MagicMock(return_value=SimpleNamespace(short_id="cnt123"))
        docker.client.containers.get = MagicMock(return_value=SimpleNamespace(image=SimpleNamespace(id="sha256:cur")))
        docker.stop_container = AsyncMock()
        docker.remove_container = AsyncMock()
        docker.build_image = MagicMock(return_value=iter(["Step 1\n"]))

        git = MagicMock()

        async def _clone(url, path, branch="main", git_token=None):
            os.makedirs(path, exist_ok=True)
            with open(os.path.join(path, "index.html"), "w") as f:
                f.write("<h1>ok</h1>")
            return "abcdef9999"

        git.clone_repo = AsyncMock(side_effect=_clone)

        orch = DeployOrchestrator(docker, git, db)

        # 1. deploy_preview completo (incluindo _run_app_container real com env Fernet e quotas)
        preview_res = await orch.deploy_preview(proj, "feat/nova-tela")
        assert preview_res["status"] == "running"
        assert "feat-nova-tela" in preview_res["public_host"]
        docker.client.containers.run.assert_called()

        # 1b. Segundo deploy_preview na mesma branch (diretório já existe -> pull_repo)
        git.pull_repo = AsyncMock(side_effect=RuntimeError("pull fail fallback"))
        preview_res2 = await orch.deploy_preview(proj, "feat/nova-tela")
        assert preview_res2["status"] == "running"

        # 1c. deploy_preview com fallback de clone_repo falhando na branch de preview
        calls = {"n": 0}

        async def _clone_fallback(url, path, branch="main", git_token=None):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("branch nao existe remotamente")
            return await _clone(url, path, branch, git_token)

        git.clone_repo = AsyncMock(side_effect=_clone_fallback)
        preview_res3 = await orch.deploy_preview(proj, "feat/branch-local")
        assert preview_res3["status"] == "running"

        # 2. rollback manual
        rolled = await orch.rollback(dep.id, db)
        assert rolled.status == "rolled_back"

        # 3. apply_routing
        assert await orch.apply_routing(proj) is True

        # 4. _run_health_check com httpx mockado
        class OkClient:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, url):
                return SimpleNamespace(status_code=200)

        monkeypatch.setattr(orch_mod.httpx, "AsyncClient", OkClient)
        assert await orch._run_health_check("http://localhost/health", retries=1, timeout=2) is True

    await engine.dispose()


# ── WebSocket ConnectionManager e Endpoints WS autenticados ──────────────


@pytest.mark.asyncio
async def test_websocket_connection_manager_broadcast_and_personal():
    cm = ConnectionManager()
    ws = MagicMock()
    ws.accept = AsyncMock()
    ws.send_json = AsyncMock()
    ws.send_text = AsyncMock()

    await cm.connect(ws, "topico1")
    await cm.broadcast("topico1", {"ok": True})
    await cm.broadcast("topico1", "texto")
    await cm.send_personal(ws, {"p": 1})
    await cm.send_personal(ws, "ola")

    ws.send_json.assert_awaited()
    ws.send_text.assert_awaited()
    cm.disconnect(ws, "topico1")
    assert "topico1" not in cm.active_connections


def test_websocket_authenticated_endpoints_logs_stats_and_deploy_stream(client, auth_headers, monkeypatch):
    from app.api.v1.endpoints import ws as ws_ep

    token = auth_headers["Authorization"].split(" ", 1)[1]

    fake_docker = MagicMock()
    fake_docker.stream_container_logs = MagicMock(return_value=iter(["linha 1", "linha 2"]))
    fake_docker.get_container_stats = AsyncMock(side_effect=ValueError("Contêiner não encontrado"))
    monkeypatch.setattr(ws_ep, "DockerService", lambda: fake_docker)

    with client.websocket_connect(f"/api/v1/ws/containers/c1/logs?token={token}") as ws:
        msg1 = ws.receive_json()
        assert msg1["type"] == "log" and msg1["data"] == "linha 1"

    with client.websocket_connect(f"/api/v1/ws/containers/c1/metrics?token={token}") as ws:
        err_msg = ws.receive_json()
        assert err_msg["type"] == "error"

    with client.websocket_connect(f"/api/v1/ws/deployments/dep1/stream?token={token}") as ws:
        ws.send_text("ping")
        pong = ws.receive_json()
        assert pong["type"] == "pong"


# ── Cobertura adicional para > 90%: /proc Linux, Volume Restore, Auth/Webhook Tasks e DB Init ──


@pytest.mark.asyncio
async def test_linux_proc_metrics_and_docker_volume_restore_branches(monkeypatch):
    import base64
    import builtins
    import gzip
    import io
    import tarfile
    from docker.errors import ImageNotFound, NotFound
    from app.services import docker_service as ds_mod

    real_open = builtins.open
    call_count = {"stat": 0}

    def _fake_open(path, *args, **kwargs):
        if path == "/proc/stat":
            call_count["stat"] += 1
            if call_count["stat"] == 1:
                return io.StringIO("cpu  100 0 100 800 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\n")
            return io.StringIO("cpu  150 0 150 900 0 0 0 0\ncpu0 80 0 70 450 0 0 0 0\n")
        if path == "/proc/cpuinfo":
            return io.StringIO("processor\t: 0\nmodel name\t: Mock CPU 4.0GHz\n")
        if path == "/proc/uptime":
            return io.StringIO("12345.67 23456.78\n")
        if path == "/proc/meminfo":
            return io.StringIO(
                "MemTotal:       8000000 kB\n"
                "MemAvailable:   6000000 kB\n"
                "Buffers:         200000 kB\n"
                "Cached:          800000 kB\n"
                "SReclaimable:    100000 kB\n"
                "SwapTotal:      2000000 kB\n"
                "SwapFree:       1500000 kB\n"
            )
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _fake_open)
    monkeypatch.setattr(ds_mod.time, "sleep", lambda _s: None)
    metrics = _collect_host_metrics_sync()
    assert metrics["cpu_percent"] > 0
    assert metrics["cpu_model"] == "Mock CPU 4.0GHz"
    assert metrics["memory_total_mb"] > 0

    svc = DockerService.__new__(DockerService)
    svc._client = MagicMock()

    # _stream_container_stats_sync (1 iteração + saída por exceção)
    fake_c = MagicMock()
    fake_c.stats.side_effect = [{"cpu_stats": {}, "precpu_stats": {}, "memory_stats": {}}, RuntimeError("fim")]
    svc.client.containers.get.return_value = fake_c
    gen = svc._stream_container_stats_sync("c1", interval=0.0)
    first_stat = next(gen)
    assert "cpu_percent" in first_stat
    assert list(gen) == []

    # Erros em remove_image e remove_volume
    svc.client.images.remove.side_effect = ImageNotFound("no img")
    with pytest.raises(ValueError):
        await svc.remove_image("img404")

    svc.client.volumes.get.side_effect = NotFound("no vol")
    with pytest.raises(ValueError):
        await svc.remove_volume("vol404")

    # restore_volume_backup com .tar.gz e prefixo backup_src/
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        data = b"conteudo-restaurado"
        ti = tarfile.TarInfo(name="backup_src/dados.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        ti_root = tarfile.TarInfo(name="backup_src")
        ti_root.type = tarfile.DIRTYPE
        tf.addfile(ti_root)
    gz_b64 = base64.b64encode(gzip.compress(tar_buf.getvalue())).decode()

    fake_vol = MagicMock()
    fake_vol.name = "vol_rest"
    svc.client.volumes.get.side_effect = NotFound("create it")
    svc.client.volumes.create.return_value = fake_vol
    svc.client.images.list.return_value = [SimpleNamespace(tags=["alpine:latest"])]
    temp_cnt = MagicMock()
    svc.client.containers.create.return_value = temp_cnt

    restored = await svc.restore_volume_backup("vol_rest", gz_b64)
    assert restored["status"] == "restored" and restored["volume"] == "vol_rest"
    temp_cnt.put_archive.assert_called_once()
    temp_cnt.remove.assert_called_once()

    exported_bytes, exported_name = await svc.export_volume_backup("vol_err") if False else (b"ok", "ok")
    svc.client.volumes.get.side_effect = None
    svc.client.volumes.get.return_value = fake_vol
    temp_cnt.get_archive.return_value = ([tar_buf.getvalue()], {})
    exp_bytes, exp_name = await svc.export_volume_backup("vol_rest")
    assert len(exp_bytes) > 0 and "vol_rest" in exp_name

    # NotificationService: persistência em disco + filtros de eventos desativados
    nm = NotificationService()
    nm.update_config(
        {
            "enabled": True,
            "notify_on_deploy_success": False,
            "notify_on_deploy_failure": False,
            "notify_on_waf_block": False,
            "notify_on_container_down": False,
            "notify_on_high_resource": False,
        }
    )
    nm._load_config()
    for ev in ("deploy_success", "deploy_failure", "waf_block", "container_down", "high_resource"):
        assert (await nm.notify(ev, "T", "M"))["status"] == "skipped"
    assert "config" in nm.get_overview()

    # UptimeMonitorService: _check_host_resources e verify_github_signature
    import hashlib
    import hmac
    from fastapi import HTTPException
    from app.core.security import verify_github_signature
    from app.services import uptime_service as us_mod

    mon = UptimeMonitorService()
    monkeypatch.setattr(
        us_mod,
        "_collect_host_metrics_sync",
        lambda: {"hostname": "srv", "cpu_percent": 99.0, "memory_percent": 95.0},
    )
    monkeypatch.setattr(us_mod.notification_manager, "notify", AsyncMock(return_value={"id": "n"}))
    await mon._check_host_resources()
    us_mod.notification_manager.notify.assert_awaited()

    body_bytes = b'{"ref":"refs/heads/main"}'
    good_sig = (
        "sha256="
        + hmac.new(
            orch_mod.settings.GITHUB_WEBHOOK_SECRET.encode("utf-8"),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()
    )
    req_ok = SimpleNamespace(headers={"X-Hub-Signature-256": good_sig}, body=AsyncMock(return_value=body_bytes))
    assert await verify_github_signature(req_ok) == body_bytes

    req_missing = SimpleNamespace(headers={}, body=AsyncMock(return_value=body_bytes))
    with pytest.raises(HTTPException):
        await verify_github_signature(req_missing)

    req_bad = SimpleNamespace(headers={"X-Hub-Signature-256": "sha256=invalido"}, body=AsyncMock(return_value=body_bytes))
    with pytest.raises(HTTPException):
        await verify_github_signature(req_bad)


@pytest.mark.asyncio
async def test_auth_password_guards_and_background_tasks(client, auth_headers, monkeypatch, tmp_path):
    from app.api.v1.endpoints import projects as proj_ep
    from app.api.v1.endpoints import webhooks as wh_ep
    from app.db import session as db_sess

    # 1. Alteração de senha + validações de erro
    r_bad_pw = client.put(
        "/api/v1/auth/password",
        json={"current_password": "errada", "new_password": "novaPassword123"},
        headers=auth_headers,
    )
    assert r_bad_pw.status_code == 400

    r_short = client.put(
        "/api/v1/auth/password",
        json={"current_password": "S3nha-Forte-de-Teste!", "new_password": "123"},
        headers=auth_headers,
    )
    assert r_short.status_code == 400

    r_ok_pw = client.put(
        "/api/v1/auth/password",
        json={"current_password": "S3nha-Forte-de-Teste!", "new_password": "S3nha-Forte-de-Teste!"},
        headers=auth_headers,
    )
    assert r_ok_pw.status_code == 200

    # 2. Guardas de auto-remoção/auto-rebaixamento de admin
    me = client.get("/api/v1/auth/me", headers=auth_headers).json()
    my_id = me["id"]
    assert client.patch(f"/api/v1/auth/users/{my_id}/role", json={"role": "invalid"}, headers=auth_headers).status_code == 400
    assert client.patch(f"/api/v1/auth/users/{my_id}/role", json={"role": "viewer"}, headers=auth_headers).status_code == 400
    assert client.patch(f"/api/v1/auth/users/{my_id}/toggle", headers=auth_headers).status_code == 400
    assert client.delete(f"/api/v1/auth/users/{my_id}", headers=auth_headers).status_code == 400

    fake_uid = str(uuid.uuid4())
    assert client.patch(f"/api/v1/auth/users/{fake_uid}/role", json={"role": "viewer"}, headers=auth_headers).status_code == 404
    assert client.patch(f"/api/v1/auth/users/{fake_uid}/toggle", headers=auth_headers).status_code == 404
    assert client.delete(f"/api/v1/auth/users/{fake_uid}", headers=auth_headers).status_code == 404

    # 3. Background tasks (_trigger_deploy, _trigger_preview_deploy, _reapply_routing) e _seed_initial_admin
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from app.db.base import Base

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/bg_tasks.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    pid = uuid.uuid4()
    async with factory() as s:
        s.add(
            Project(
                id=pid,
                name="bg-proj",
                repo_url="https://github.com/u/r.git",
                branch="main",
                webhook_secret="sec",
                subdomain="bg-proj",
            )
        )
        await s.commit()

    monkeypatch.setattr(wh_ep, "async_session_factory", factory)
    monkeypatch.setattr(proj_ep, "async_session_factory", factory)
    monkeypatch.setattr(db_sess, "async_session_factory", factory)
    monkeypatch.setattr(db_sess, "engine", engine)

    fake_orch = MagicMock()
    fake_orch.deploy = AsyncMock(return_value=SimpleNamespace(status="running", duration_seconds=1.2))
    fake_orch.deploy_preview = AsyncMock(return_value={"status": "running"})
    fake_orch.apply_routing = AsyncMock(return_value=False)

    monkeypatch.setattr(wh_ep, "DeployOrchestrator", lambda **_kw: fake_orch)
    monkeypatch.setattr(wh_ep, "DockerService", lambda: MagicMock())
    monkeypatch.setattr(wh_ep, "GitService", lambda: MagicMock())
    monkeypatch.setattr(proj_ep, "DeployOrchestrator", lambda **_kw: fake_orch)
    monkeypatch.setattr(proj_ep, "DockerService", lambda: MagicMock())
    monkeypatch.setattr(proj_ep, "GitService", lambda: MagicMock())

    await wh_ep._trigger_deploy(pid, "12345678", "main")
    await wh_ep._trigger_deploy(uuid.uuid4(), "12345678", "main")
    await wh_ep._trigger_preview_deploy(pid, "feat-1")
    await proj_ep._reapply_routing(str(pid))
    await db_sess.init_db()

    fake_orch.deploy.assert_awaited_once()
    fake_orch.deploy_preview.assert_awaited_once()
    fake_orch.apply_routing.assert_awaited_once()

    # Fallback de init_db quando PostgreSQL falha e alterna para SQLite local
    bad_engine = MagicMock()
    bad_engine.begin.side_effect = RuntimeError("pg down")
    monkeypatch.setattr(db_sess, "engine", bad_engine)
    monkeypatch.setattr(db_sess.settings, "DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setattr(
        db_sess,
        "create_async_engine",
        lambda *_a, **_kw: engine,
    )
    await db_sess.init_db()
    await engine.dispose()



