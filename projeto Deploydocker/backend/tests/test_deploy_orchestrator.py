"""RF de deploy contínuo: pipeline do DeployOrchestrator com Docker/Git mockados."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.models.project import Project
from app.services import deploy_orchestrator as orch_module
from app.services.deploy_orchestrator import DeployOrchestrator, _ensure_auto_dockerfile


@pytest_asyncio.fixture()
async def db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/orch.db")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture(autouse=True)
def quiet_side_effects(monkeypatch, tmp_path):
    monkeypatch.setattr(orch_module.ws_manager, "broadcast", AsyncMock())
    monkeypatch.setattr(orch_module.notification_manager, "notify", AsyncMock())
    monkeypatch.setattr(orch_module.settings, "REPOS_BASE_PATH", str(tmp_path / "repos"))


def make_project(**kw) -> Project:
    return Project(
        id=uuid.uuid4(),
        name=kw.pop("name", "demo"),
        repo_url="https://github.com/exemplo/demo.git",
        branch="main",
        webhook_secret="s",
        health_check_url=kw.pop("health_check_url", None),
        **kw,
    )


def make_services(build_ok=True, previous_image=None):
    docker = MagicMock()
    if build_ok:
        docker.build_image = MagicMock(return_value=iter(["Step 1/2\n", "Successfully built\n"]))
    else:
        def boom(**_kw):
            raise RuntimeError("erro no Dockerfile")
            yield  # pragma: no cover
        docker.build_image = boom
    if previous_image:
        docker.get_container = AsyncMock(return_value={"image": previous_image})
    else:
        docker.get_container = AsyncMock(side_effect=ValueError("não existe"))
    docker.stop_container = AsyncMock()
    docker.remove_container = AsyncMock()

    git = MagicMock()
    git.clone_repo = AsyncMock(side_effect=lambda url, path, *a, **k: _fake_clone(path))
    git.pull_repo = AsyncMock()
    git.get_current_commit = AsyncMock(
        return_value={"sha": "abcdef1234567890", "message": "feat: x", "author": "Dev"}
    )
    return docker, git


def _fake_clone(path):
    import os

    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "Dockerfile"), "w") as f:
        f.write("FROM scratch\n")


async def run_deploy(db, project, docker, git, monkeypatch, healthy=True):
    db.add(project)
    await db.commit()
    orch = DeployOrchestrator(docker, git, db)
    monkeypatch.setattr(orch, "_run_app_container", AsyncMock(return_value=SimpleNamespace(short_id="c0ffee")))
    monkeypatch.setattr(orch, "_run_health_check", AsyncMock(return_value=healthy))
    rollback = AsyncMock()
    monkeypatch.setattr(orch, "_perform_rollback", rollback)
    deployment = await orch.deploy(project, "abcdef12", "main")
    return deployment, orch, rollback


@pytest.mark.asyncio
async def test_successful_deploy_reaches_healthy(db, monkeypatch):
    docker, git = make_services()
    dep, orch, rollback = await run_deploy(db, make_project(), docker, git, monkeypatch)
    assert dep.status == "healthy"
    assert dep.commit_sha == "abcdef1234567890"
    assert dep.duration_seconds is not None
    assert "Successfully built" in dep.build_logs
    orch._run_app_container.assert_awaited_once()
    rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_build_failure_marks_failed_without_rollback_when_no_previous(db, monkeypatch):
    docker, git = make_services(build_ok=False)
    dep, orch, rollback = await run_deploy(db, make_project(), docker, git, monkeypatch)
    assert dep.status == "failed"
    assert "erro no Dockerfile" in dep.error_message
    orch._run_app_container.assert_not_awaited()
    rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_health_check_triggers_automatic_rollback(db, monkeypatch):
    docker, git = make_services(previous_image="sha256:imagem-anterior")
    project = make_project(health_check_url="http://demo.localhost/health")
    dep, orch, rollback = await run_deploy(db, project, docker, git, monkeypatch, healthy=False)
    assert dep.status == "rolled_back"
    assert dep.previous_image_id == "sha256:imagem-anterior"
    assert "Health check falhou" in dep.error_message
    rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_old_container_is_replaced(db, monkeypatch):
    docker, git = make_services(previous_image="sha256:old")
    await run_deploy(db, make_project(), docker, git, monkeypatch)
    docker.stop_container.assert_awaited_once()
    docker.remove_container.assert_awaited_once()


# ── Auto-detecção de stack ───────────────────────────────────────────────

@pytest.mark.parametrize(
    "marker,expected",
    [
        ("index.html", "nginx"),
        ("package.json", "node"),
        ("requirements.txt", "python"),
    ],
)
def test_auto_dockerfile_detects_stack(tmp_path, marker, expected):
    (tmp_path / marker).write_text("x")
    _ensure_auto_dockerfile(str(tmp_path), "Dockerfile")
    assert expected in (tmp_path / "Dockerfile").read_text().lower()


def test_auto_dockerfile_keeps_existing(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM custom\n")
    (tmp_path / "index.html").write_text("x")
    _ensure_auto_dockerfile(str(tmp_path), "Dockerfile")
    assert (tmp_path / "Dockerfile").read_text() == "FROM custom\n"


def test_auto_dockerfile_fails_for_unknown_stack(tmp_path):
    with pytest.raises(RuntimeError):
        _ensure_auto_dockerfile(str(tmp_path), "Dockerfile")


# ── Estratégia blue/green ────────────────────────────────────────────────

def bg_services(old_image="sha256:old", candidate_running=True):
    """Docker mockado que registra a ordem das operações em `docker.calls`."""
    docker, git = make_services(previous_image=old_image)
    docker.calls = []

    async def get_container(name):
        if "-bg-" in name:
            return {"status": "running" if candidate_running else "exited", "image": "novo"}
        if old_image is None:
            raise ValueError("não existe")
        return {"status": "running", "image": old_image}

    def rec(label):
        async def _fn(*a, **k):
            docker.calls.append((label, a[0] if a else None))
        return _fn

    docker.get_container = get_container
    docker.stop_container = rec("stop")
    docker.remove_container = rec("remove")
    docker.rename_container = rec("rename")
    return docker, git


async def run_bg(db, project, docker, git, monkeypatch, healthy=True):
    monkeypatch.setattr(orch_module.settings, "BLUE_GREEN_DRAIN_SECONDS", 0)
    monkeypatch.setattr(orch_module.settings, "BLUE_GREEN_MIN_UPTIME_SECONDS", 0)
    db.add(project)
    await db.commit()
    orch = DeployOrchestrator(docker, git, db)

    async def run_container(proj, image, name, *a, **k):
        docker.calls.append(("run", name))
        return SimpleNamespace(short_id="c0ffee")

    monkeypatch.setattr(orch, "_run_app_container", run_container)
    monkeypatch.setattr(orch, "_resolve_port", lambda p, i: 8080)
    health = AsyncMock(return_value=healthy)
    monkeypatch.setattr(orch, "_run_health_check", health)
    rollback = AsyncMock()
    monkeypatch.setattr(orch, "_perform_rollback", rollback)
    dep = await orch.deploy(project, "abcdef12", "main")
    return dep, health, rollback


@pytest.mark.asyncio
async def test_blue_green_starts_new_version_before_removing_old(db, monkeypatch):
    docker, git = bg_services()
    project = make_project(deploy_strategy="blue_green", health_check_url="http://demo.localhost/health")
    dep, health, rollback = await run_bg(db, project, docker, git, monkeypatch)

    assert dep.status == "healthy"
    labels = [c[0] for c in docker.calls]
    i_stop = labels.index("stop")
    assert labels.index("run") < i_stop < labels.index("remove", i_stop) < labels.index("rename")
    run_name = next(n for c, n in docker.calls if c == "run")
    assert "-bg-" in run_name
    assert ("rename", run_name) in docker.calls
    assert dep.previous_image_id == "sha256:old"
    rollback.assert_not_awaited()
    # validação interna do candidato pela rede Docker (nome do contêiner + porta + path)
    assert health.await_args_list[0].args[0] == f"http://{run_name}:8080/health"


@pytest.mark.asyncio
async def test_blue_green_failed_candidate_keeps_old_version_running(db, monkeypatch):
    docker, git = bg_services()
    project = make_project(deploy_strategy="blue_green", health_check_url="http://demo.localhost/health")
    dep, _, rollback = await run_bg(db, project, docker, git, monkeypatch, healthy=False)

    assert dep.status == "failed"
    assert "versão anterior mantida no ar" in dep.error_message
    assert not any(c == "stop" for c, _ in docker.calls), "a versão antiga não pode ser parada"
    removed = [n for c, n in docker.calls if c == "remove"]
    assert removed and all("-bg-" in n for n in removed), "somente o candidato deve ser removido"
    rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_blue_green_rejects_candidate_that_exited(db, monkeypatch):
    docker, git = bg_services(candidate_running=False)
    dep, _, rollback = await run_bg(db, make_project(deploy_strategy="blue_green"), docker, git, monkeypatch)
    assert dep.status == "failed"
    assert "não está em execução" in dep.error_message
    assert not any(c == "stop" for c, _ in docker.calls)
    rollback.assert_not_awaited()


@pytest.mark.asyncio
async def test_blue_green_first_deploy_has_nothing_to_remove(db, monkeypatch):
    docker, git = bg_services(old_image=None)
    dep, _, _ = await run_bg(db, make_project(deploy_strategy="blue_green"), docker, git, monkeypatch)
    assert dep.status == "healthy"
    labels = [c for c, _ in docker.calls]
    assert "stop" not in labels
    assert labels[-1] == "rename"


@pytest.mark.asyncio
async def test_recreate_strategy_stops_old_before_starting_new(db, monkeypatch):
    """Contraste com blue/green: no recreate a versão antiga cai antes da nova subir."""
    docker, git = bg_services()
    project = make_project(deploy_strategy="recreate")
    db.add(project)
    await db.commit()
    orch = DeployOrchestrator(docker, git, db)

    async def run_container(proj, image, name, *a, **k):
        docker.calls.append(("run", name))
        return SimpleNamespace(short_id="x")

    monkeypatch.setattr(orch, "_run_app_container", run_container)
    await orch.deploy(project, "abcdef12", "main")
    labels = [c for c, _ in docker.calls]
    assert labels.index("stop") < labels.index("run")


@pytest.mark.asyncio
async def test_legacy_null_strategy_behaves_as_recreate(db, monkeypatch):
    docker, git = bg_services()
    project = make_project()
    project.deploy_strategy = None
    db.add(project)
    await db.commit()
    orch = DeployOrchestrator(docker, git, db)

    async def run_container(proj, image, name, *a, **k):
        docker.calls.append(("run", name))
        return SimpleNamespace(short_id="x")

    monkeypatch.setattr(orch, "_run_app_container", run_container)
    await orch.deploy(project, "abcdef12", "main")
    assert not any(n and "-bg-" in n for _, n in docker.calls)
