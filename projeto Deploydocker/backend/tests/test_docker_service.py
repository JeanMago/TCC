"""Testes unitários de DockerService (SDK do Docker inteiramente mockado)."""

import base64
import gzip
import io
import tarfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from docker.errors import ImageNotFound, NotFound

from app.services.docker_service import DockerService


def _fake_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _fake_container(
    short_id="abc123",
    name="app-web",
    status="running",
    tags=("nginx:alpine",),
    labels=None,
    mem_bytes=256 * 1024 * 1024,
    cpu_quota=150000,
    cpu_period=100000,
):
    c = MagicMock()
    c.short_id = short_id
    c.id = f"{short_id}_full"
    c.name = name
    c.status = status
    c.ports = {"80/tcp": [{"HostPort": "8080"}]}
    c.labels = labels if labels is not None else {"deploydock.host": "app.localhost"}
    c.image = SimpleNamespace(tags=list(tags), short_id="img123")
    c.attrs = {
        "Created": "2026-10-29T00:00:00Z",
        "State": {"Status": status},
        "HostConfig": {
            "Memory": mem_bytes,
            "NanoCpus": 0,
            "CpuQuota": cpu_quota,
            "CpuPeriod": cpu_period,
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "Mounts": [],
        "NetworkSettings": {"Networks": {"bridge": {}}},
        "Config": {"Env": ["ENV=prod"]},
    }
    return c


@pytest.fixture()
def svc():
    s = DockerService()
    s._client = MagicMock()
    return s


# ── Contêineres: listagem, inspeção e ciclo de vida ───────────────────────


@pytest.mark.asyncio
async def test_list_containers_builds_public_url(svc):
    svc._client.containers.list.return_value = [
        _fake_container(short_id="c1", name="web1", labels={"deploydock.host": "site.localhost"}),
        _fake_container(short_id="c2", name="worker", tags=(), labels={}),
    ]
    items = await svc.list_containers(all=True)
    assert len(items) == 2
    assert items[0]["public_url"] == "http://site.localhost"
    assert items[1]["public_url"] is None
    assert items[1]["image"] == "img123"


@pytest.mark.asyncio
async def test_list_containers_returns_empty_on_error(svc):
    svc._client.containers.list.side_effect = RuntimeError("daemon down")
    assert await svc.list_containers() == []


@pytest.mark.asyncio
async def test_get_container_extracts_quotas(svc):
    svc._client.containers.get.return_value = _fake_container(
        mem_bytes=512 * 1024 * 1024, cpu_quota=200000, cpu_period=100000
    )
    info = await svc.get_container("abc123")
    assert info["memory_limit_mb"] == 512
    assert info["cpu_limit_cores"] == 2.0


@pytest.mark.asyncio
async def test_get_container_not_found_raises_value_error(svc):
    svc._client.containers.get.side_effect = NotFound("no such container")
    with pytest.raises(ValueError, match="não encontrado"):
        await svc.get_container("inexistente")


def test_ensure_network_creates_when_missing(svc):
    svc._client.networks.get.side_effect = NotFound("missing")
    svc.ensure_network("deploydock-apps")
    svc._client.networks.create.assert_called_once_with("deploydock-apps", driver="bridge")


def test_get_image_exposed_ports_parses_tcp_ports(svc):
    img = SimpleNamespace(attrs={"Config": {"ExposedPorts": {"8080/tcp": {}, "53/udp": {}, "80/tcp": {}}}})
    svc._client.images.get.return_value = img
    assert svc.get_image_exposed_ports("myimg:latest") == [80, 8080]

    svc._client.images.get.side_effect = ImageNotFound("no img")
    assert svc.get_image_exposed_ports("missing") == []


@pytest.mark.asyncio
async def test_lifecycle_start_stop_restart_remove_rename(svc):
    c = _fake_container()
    svc._client.containers.get.return_value = c

    assert (await svc.start_container("abc123"))["status"] == "running"
    c.start.assert_called_once()

    assert (await svc.stop_container("abc123", timeout=5))["id"] == "abc123"
    c.stop.assert_called_once_with(timeout=5)

    assert (await svc.restart_container("abc123", timeout=3))["name"] == "app-web"
    c.restart.assert_called_once_with(timeout=3)

    await svc.rename_container("abc123", "novo-nome")
    c.rename.assert_called_once_with("novo-nome")

    await svc.remove_container("abc123", force=True)
    c.remove.assert_called_once_with(force=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["start_container", "stop_container", "restart_container", "remove_container", "rename_container"])
async def test_lifecycle_not_found_raises_value_error(svc, method):
    svc._client.containers.get.side_effect = NotFound("missing")
    fn = getattr(svc, method)
    args = ("id", "new") if method == "rename_container" else ("id",)
    with pytest.raises(ValueError):
        await fn(*args)


# ── Logs, Exec e Stats ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_container_logs_filters_by_search(svc):
    c = _fake_container()
    c.logs.return_value = b"2026-01-01 INFO boot ok\n2026-01-01 ERROR db timeout\n2026-01-01 WARN slow\n"
    svc._client.containers.get.return_value = c

    res = await svc.get_container_logs("abc123", tail=100, since_seconds=60, search="error")
    assert res["count"] == 1
    assert "ERROR db timeout" in res["logs"]


def test_stream_container_logs_yields_lines(svc):
    c = _fake_container()
    c.logs.return_value = iter([b"linha 1\nlin", b"ha 2\r\nfinal"])
    svc._client.containers.get.return_value = c

    lines = list(svc.stream_container_logs("abc123", tail=10, since=1000))
    assert lines == ["linha 1", "linha 2", "final"]


@pytest.mark.asyncio
async def test_exec_container_command_demuxes_output(svc):
    c = _fake_container(status="running")
    c.exec_run.return_value = (0, (b"hello\n", b"warn\n"))
    svc._client.containers.get.return_value = c

    res = await svc.exec_container_command("abc123", "echo hello", workdir="/app")
    assert res["exit_code"] == 0
    assert res["stdout"] == "hello\n"
    assert res["stderr"] == "warn\n"
    assert "hello" in res["output"] and "warn" in res["output"]


@pytest.mark.asyncio
async def test_exec_container_command_rejects_stopped_container(svc):
    svc._client.containers.get.return_value = _fake_container(status="exited")
    with pytest.raises(RuntimeError, match="em execução"):
        await svc.exec_container_command("abc123", "ls")


def test_parse_raw_container_stats_computes_percentages():
    raw = {
        "cpu_stats": {"cpu_usage": {"total_usage": 200_000_000}, "system_cpu_usage": 1_000_000_000, "online_cpus": 2},
        "precpu_stats": {"cpu_usage": {"total_usage": 100_000_000}, "system_cpu_usage": 500_000_000},
        "memory_stats": {
            "usage": 150 * 1024 * 1024,
            "limit": 300 * 1024 * 1024,
            "stats": {"inactive_file": 50 * 1024 * 1024},
        },
        "networks": {"eth0": {"rx_bytes": 2 * 1024 * 1024, "tx_bytes": 4 * 1024 * 1024}},
    }
    parsed = DockerService._parse_raw_container_stats(raw)
    assert parsed["cpu_percent"] == 40.0
    assert parsed["memory_usage_mb"] == 100.0
    assert parsed["memory_limit_mb"] == 300.0
    assert parsed["network_rx_mb"] == 2.0
    assert parsed["network_tx_mb"] == 4.0


@pytest.mark.asyncio
async def test_get_container_stats(svc):
    c = _fake_container()
    c.stats.return_value = {
        "cpu_stats": {"cpu_usage": {"total_usage": 10}, "system_cpu_usage": 100, "online_cpus": 1},
        "precpu_stats": {"cpu_usage": {"total_usage": 0}, "system_cpu_usage": 0},
        "memory_stats": {"usage": 10 * 1024 * 1024, "limit": 100 * 1024 * 1024},
        "networks": {},
    }
    svc._client.containers.get.return_value = c
    stats = await svc.get_container_stats("abc123")
    assert stats["cpu_percent"] == 10.0
    assert stats["memory_percent"] == 10.0


# ── Build, Imagens, Volumes, Redes e Prune ───────────────────────────────


def test_build_image_streams_and_raises_on_error(svc):
    svc._client.api.build.return_value = iter([{"stream": "Step 1\n"}, {"stream": "Done\n"}])
    assert list(svc.build_image("/tmp/repo", "tag:1")) == ["Step 1\n", "Done\n"]

    svc._client.api.build.return_value = iter([{"error": "boom", "errorDetail": {"message": "syntax error"}}])
    with pytest.raises(RuntimeError, match="syntax error"):
        list(svc.build_image("/tmp/repo", "tag:1"))


@pytest.mark.asyncio
async def test_images_volumes_networks_and_prune(svc):
    svc._client.images.list.return_value = [
        SimpleNamespace(short_id="img1", tags=["app:1"], attrs={"Size": 50 * 1024 * 1024, "Created": "now"})
    ]
    imgs = await svc.list_images()
    assert imgs[0]["size_mb"] == 50.0

    await svc.remove_image("img1", force=True)
    svc._client.images.remove.assert_called_once_with("img1", force=True)

    vol = MagicMock()
    vol.name = "pg_data"
    vol.attrs = {"Driver": "local", "Mountpoint": "/var/lib/docker/volumes/pg", "CreatedAt": "now"}
    svc._client.volumes.list.return_value = [vol]
    assert (await svc.list_volumes())[0]["name"] == "pg_data"

    svc._client.volumes.get.return_value = vol
    await svc.remove_volume("pg_data")
    vol.remove.assert_called_once()

    net = SimpleNamespace(
        short_id="n1",
        name="deploydock-apps",
        attrs={"Driver": "bridge", "Scope": "local", "Internal": False, "IPAM": {"Config": [{"Subnet": "172.18.0.0/16"}]}, "Containers": {}},
    )
    svc._client.networks.list.return_value = [net]
    nets = await svc.list_networks()
    assert nets[0]["name"] == "deploydock-apps"

    svc._client.containers.prune.return_value = {"ContainersDeleted": ["c1", "c2"], "SpaceReclaimed": 10 * 1024 * 1024}
    svc._client.images.prune.return_value = {"ImagesDeleted": ["i1"], "SpaceReclaimed": 20 * 1024 * 1024}
    svc._client.volumes.prune.return_value = {"VolumesDeleted": ["v1"], "SpaceReclaimed": 5 * 1024 * 1024}
    svc._client.networks.prune.return_value = {"NetworksDeleted": ["n1"]}

    pruned = await svc.prune_system("all")
    assert pruned["containers_deleted"] == 2
    assert pruned["images_deleted"] == 1
    assert pruned["volumes_deleted"] == 1
    assert pruned["networks_deleted"] == 1
    assert pruned["space_reclaimed_mb"] == 35.0


# ── Quick container, explorador de arquivos, quotas e backups ────────────


@pytest.mark.asyncio
async def test_run_quick_container_pulls_when_missing(svc):
    svc._client.images.get.side_effect = ImageNotFound("pull me")
    svc._client.containers.run.return_value = _fake_container(short_id="q1", name="redis-quick")
    res = await svc.run_quick_container(
        image="redis:alpine", name="redis-quick", ports={"6379/tcp": 6379}, env={"A": "1"}
    )
    svc._client.images.pull.assert_called_once_with("redis:alpine")
    assert res["name"] == "redis-quick"


@pytest.mark.asyncio
async def test_list_and_read_and_delete_container_files(svc, monkeypatch):
    ls_out = (
        "total 8\n"
        "drwxr-xr-x 2 root root 4096 Oct 29 00:00 .\n"
        "drwxr-xr-x 1 root root 4096 Oct 29 00:00 ..\n"
        "drwxr-xr-x 2 root root 4096 Oct 29 00:00 conf.d\n"
        "-rw-r--r-- 1 root root  123 Oct 29 00:00 nginx.conf\n"
        "lrwxrwxrwx 1 root root   11 Oct 29 00:00 link.conf -> nginx.conf\n"
    )

    async def fake_exec(cid, cmd, workdir=None):
        if cmd.startswith("ls -la"):
            return {"exit_code": 0, "stdout": ls_out, "stderr": "", "output": ls_out}
        if cmd.startswith("head -c"):
            return {"exit_code": 0, "stdout": "server {}", "stderr": "", "output": "server {}"}
        return {"exit_code": 0, "stdout": "", "stderr": "", "output": ""}

    monkeypatch.setattr(svc, "exec_container_command", fake_exec)

    listing = await svc.list_container_files("c1", "/etc/nginx")
    names = [i["name"] for i in listing["items"]]
    assert names[0] == "conf.d" and "nginx.conf" in names and "link.conf" in names

    content = await svc.read_container_file("c1", "/etc/nginx/nginx.conf")
    assert content["content"] == "server {}"

    deleted = await svc.delete_container_file("c1", "/tmp/lixo.txt")
    assert deleted["deleted"] == "/tmp/lixo.txt"

    with pytest.raises(ValueError, match="não é permitida"):
        await svc.delete_container_file("c1", "/etc")


@pytest.mark.asyncio
async def test_write_upload_download_container_file_and_update_resources(svc):
    c = _fake_container()
    svc._client.containers.get.return_value = c

    written = await svc.write_container_file("c1", "/app/config.env", "PORT=8080\n", restart=True)
    assert written["size_bytes"] == 10
    assert written["restarted"] is True
    c.put_archive.assert_called()
    c.restart.assert_called_once()

    b64 = base64.b64encode(b"conteudo-binario").decode()
    uploaded = await svc.upload_container_file("c1", "/app", "dados.bin", b64)
    assert uploaded["path"] == "/app/dados.bin"
    assert uploaded["size_bytes"] == 16

    c.get_archive.return_value = ([_fake_tar({"dados.bin": b"conteudo-binario"})], {})
    raw, fname = await svc.download_container_file("c1", "/app/dados.bin")
    assert raw == b"conteudo-binario"
    assert fname == "dados.bin"

    updated = await svc.update_container_resources("c1", memory_limit_mb=512, cpu_limit_cores=1.5)
    c.update.assert_called_once_with(
        mem_limit=512 * 1024 * 1024,
        memswap_limit=1024 * 1024 * 1024,
        cpu_period=100000,
        cpu_quota=150000,
    )
    assert updated["memory_limit_mb"] == 512


@pytest.mark.asyncio
async def test_volume_backup_and_restore_and_db_dump(svc, monkeypatch):
    vol = MagicMock()
    vol.name = "meus_dados"
    svc._client.volumes.get.return_value = vol
    svc._client.images.list.return_value = [SimpleNamespace(tags=["alpine:latest"])]

    temp_c = MagicMock()
    temp_c.get_archive.return_value = ([_fake_tar({"backup_src/hello.txt": b"oi"})], {})
    svc._client.containers.create.return_value = temp_c

    gz_bytes, filename = await svc.export_volume_backup("meus_dados")
    assert filename.startswith("volume_meus_dados_") and filename.endswith(".tar.gz")
    assert gzip.decompress(gz_bytes)
    temp_c.remove.assert_called_once_with(force=True)

    b64_archive = base64.b64encode(gz_bytes).decode()
    restored = await svc.restore_volume_backup("meus_dados", b64_archive)
    assert restored["status"] == "restored"
    temp_c.put_archive.assert_called_once()

    # DB dump para contêiner PostgreSQL
    pg_container = _fake_container(name="app-postgres-db", tags=("postgres:16-alpine",))
    svc._client.containers.get.return_value = pg_container
    monkeypatch.setattr(
        svc,
        "exec_container_command",
        lambda cid, cmd, workdir=None: _async_return({"exit_code": 0, "stdout": "CREATE TABLE t();", "stderr": ""}),
    )
    dump_bytes, dump_name, media = await svc.export_container_db_dump("pg1")
    assert media == "application/sql"
    assert dump_name.endswith(".sql")
    assert b"CREATE TABLE" in dump_bytes


async def _async_return(val):
    return val
