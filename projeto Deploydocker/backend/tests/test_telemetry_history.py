"""Testes do histórico de telemetria (janelas em dias, agregação e persistência)."""

import asyncio
import time

import pytest

from app.services.telemetry_service import (
    TelemetryPoint,
    TelemetryService,
    aggregate_points,
    parse_range,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("15m", ("15m", 900)),
        ("6h", ("6h", 21600)),
        ("7d", ("7d", 7 * 86400)),
        ("30D", ("30d", 30 * 86400)),
        ("999d", ("90d", 90 * 86400)),
        ("abc", ("15m", 900)),
        ("", ("15m", 900)),
    ],
)
def test_parse_range(raw, expected):
    assert parse_range(raw) == expected


def test_aggregate_points_averages_and_keeps_peak():
    pts = [
        TelemetryPoint(timestamp=120, cpu_host=10, memory_host_pct=40),
        TelemetryPoint(timestamp=150, cpu_host=30, memory_host_pct=60),
        TelemetryPoint(timestamp=185, cpu_host=50, memory_host_pct=50),
    ]
    out = aggregate_points(pts, 60)
    assert [p.timestamp for p in out] == [120, 180]
    assert out[0].cpu_host == 20
    assert out[0].cpu_host_max == 30
    assert out[0].memory_host_pct == 50
    assert out[1].cpu_host == 50


def test_minute_rollup_emits_completed_bucket():
    svc = TelemetryService()
    base = 60 * 1000
    for i, cpu in enumerate([10, 20, 30]):
        p = svc.record_point(cpu, 1, 50, 500, 100, 1, 1, 20, 3, timestamp=base + i * 3)
        assert svc._take_completed_minute(p) is None
    nxt = svc.record_point(90, 1, 50, 500, 100, 1, 1, 20, 3, timestamp=base + 60)
    done = svc._take_completed_minute(nxt)
    assert done is not None
    assert done.timestamp == base
    assert done.cpu_host == 20
    assert done.cpu_host_max == 30


def test_history_combines_persisted_days_and_memory(client):
    svc = TelemetryService()
    now = time.time()

    async def scenario():
        # Duas amostras persistidas de dias anteriores
        await svc._persist(TelemetryPoint(timestamp=now - 3 * 86400, cpu_host=42, memory_host_pct=55))
        await svc._persist(TelemetryPoint(timestamp=now - 1 * 86400, cpu_host=64, memory_host_pct=65))
        # Uma amostra muito antiga, fora da janela de 2 dias
        await svc._persist(TelemetryPoint(timestamp=now - 10 * 86400, cpu_host=99))
        svc.record_point(12, 2, 30, 300, 80, 1, 1, 20, 4, timestamp=now - 5)
        return await svc.get_history("2d"), await svc.get_history("7d")

    two_days, seven_days = asyncio.run(scenario())

    assert two_days["range"] == "2d"
    assert two_days["window_seconds"] == 2 * 86400
    assert two_days["bucket_seconds"] == 2 * 86400 // TelemetryService.TARGET_POINTS
    cpus = [p["cpu_host"] for p in two_days["points"]]
    assert 64 in cpus and 12 in cpus
    assert 42 not in cpus and 99 not in cpus

    cpus7 = [p["cpu_host"] for p in seven_days["points"]]
    assert 42 in cpus7 and 99 not in cpus7


def test_metrics_history_endpoint_accepts_days(client, auth_headers):
    resp = client.get("/api/v1/system/metrics/history?range=7d", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["range"] == "7d"
    assert body["window_seconds"] == 7 * 86400
    assert "bucket_seconds" in body
    assert isinstance(body["points"], list)


def test_container_rollup_and_history_filter(client):
    from app.services.telemetry_service import ContainerPoint

    svc = TelemetryService()
    now = time.time()
    base = (int(now // 60) - 5) * 60  # minuto fechado recente

    # Minuto 1: dois contêineres
    svc._rollup(base)
    svc.record_container_point("api", ContainerPoint(timestamp=base, cpu_percent=10, memory_mb=100))
    svc.record_container_point("api", ContainerPoint(timestamp=base + 3, cpu_percent=30, memory_mb=120))
    svc.record_container_point("db", ContainerPoint(timestamp=base, cpu_percent=5, memory_mb=300))

    # Virada de minuto fecha as médias por contêiner
    _, done = svc._rollup(base + 60)
    assert set(done) == {"api", "db"}
    assert done["api"].cpu_percent == 20
    assert done["api"].cpu_percent_max == 30
    assert done["api"].memory_mb == 110

    async def scenario():
        # Histórico antigo persistido apenas para o "api" (3 dias atrás)
        await svc._persist(None, {"api": ContainerPoint(timestamp=now - 3 * 86400, cpu_percent=77)})
        return (
            await svc.get_history("7d", container="api"),
            await svc.get_history("7d", container="db"),
            await svc.get_history("7d"),
            await svc.list_containers("7d"),
        )

    api_hist, db_hist, host_hist, names = asyncio.run(scenario())

    assert api_hist["scope"] == "container" and api_hist["container"] == "api"
    api_cpus = [p["cpu_percent"] for p in api_hist["points"]]
    assert 77 in api_cpus
    assert "memory_mb" in api_hist["points"][0]
    assert all(p["cpu_percent"] != 77 for p in db_hist["points"])
    assert host_hist["scope"] == "host" and host_hist["container"] is None
    assert {"api", "db"} <= set(names)


def test_metrics_history_endpoint_filters_container(client, auth_headers):
    resp = client.get(
        "/api/v1/system/metrics/history?range=1d&container=inexistente", headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scope"] == "container"
    assert body["container"] == "inexistente"
    assert body["points"] == []

    listed = client.get("/api/v1/system/metrics/containers?range=7d", headers=auth_headers)
    assert listed.status_code == 200, listed.text
    assert isinstance(listed.json()["containers"], list)


def test_system_processes_endpoint_requires_admin(client, auth_headers):
    # auth_headers is admin token
    resp = client.get("/api/v1/system/processes", headers=auth_headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "processes" in data
    assert isinstance(data["processes"], list)


def test_system_processes_endpoint_forbidden_for_non_admin(client):
    # Unauthenticated
    resp = client.get("/api/v1/system/processes")
    assert resp.status_code in (401, 403)


def test_manually_stopped_containers_are_not_restarted_by_auto_heal():
    from app.services.uptime_service import uptime_monitor

    c_name = "deploydock_testapp_stopped"
    uptime_monitor.mark_manually_stopped(c_name)
    assert uptime_monitor.is_manually_stopped(c_name) is True
    # Check that unprefixed works too
    assert uptime_monitor.is_manually_stopped("testapp_stopped") is True

    # Starting clears the stop flag
    uptime_monitor.clear_manually_stopped("testapp_stopped")
    assert uptime_monitor.is_manually_stopped(c_name) is False
    assert uptime_monitor.is_manually_stopped("testapp_stopped") is False
