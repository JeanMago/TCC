import asyncio
import logging
import re
import time
from collections import deque
from typing import Any, ClassVar, Deque, Dict, List, Optional, Sequence, Tuple, Type, TypeVar

logger = logging.getLogger(__name__)

# Campos numéricos de cada ponto de telemetria do host (ordem usada nas agregações)
METRIC_FIELDS: Tuple[str, ...] = (
    "cpu_host",
    "cpu_docker",
    "memory_host_pct",
    "memory_host_used_mb",
    "memory_docker_used_mb",
    "network_rx_mb",
    "network_tx_mb",
    "disk_used_pct",
    "containers_active",
)

# Campos numéricos de cada ponto de telemetria de contêiner
CONTAINER_FIELDS: Tuple[str, ...] = (
    "cpu_percent",
    "memory_mb",
    "memory_host_pct",
    "network_rx_mb",
    "network_tx_mb",
)

_RANGE_RE = re.compile(r"^\s*(\d+)\s*(m|h|d)\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def parse_range(range_key: str) -> Tuple[str, int]:
    """
    Converte uma janela textual em segundos. Aceita minutos (`15m`), horas (`6h`)
    e dias (`7d`). Valores inválidos caem no padrão de 15 minutos; a janela é
    limitada entre 1 minuto e o período de retenção do histórico.
    """
    match = _RANGE_RE.match(range_key or "")
    if not match:
        return "15m", 900
    amount = max(1, int(match.group(1)))
    unit = match.group(2).lower()
    seconds = amount * _UNIT_SECONDS[unit]
    max_seconds = TelemetryService.RETENTION_DAYS * 86400
    if seconds > max_seconds:
        return f"{TelemetryService.RETENTION_DAYS}d", max_seconds
    return f"{amount}{unit}", max(60, seconds)


class _BasePoint:
    """Ponto genérico de série temporal: campos médios + campos de pico."""

    FIELDS: ClassVar[Tuple[str, ...]] = ()
    # campo_de_pico -> campo_base (ex.: cpu_host_max -> cpu_host)
    PEAKS: ClassVar[Dict[str, str]] = {}
    ROUNDING: ClassVar[Dict[str, int]] = {}
    INT_FIELDS: ClassVar[Tuple[str, ...]] = ()

    __slots__ = ("timestamp",)

    def __init__(self, timestamp: float, **values: float):
        self.timestamp = float(timestamp)
        for f in self.FIELDS:
            setattr(self, f, float(values.get(f, 0.0) or 0.0))
        for peak, base in self.PEAKS.items():
            v = values.get(peak)
            setattr(self, peak, float(v if v is not None else getattr(self, base)))

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"timestamp": round(self.timestamp, 3)}
        for f in (*self.FIELDS, *self.PEAKS):
            v = getattr(self, f)
            out[f] = int(round(v)) if f in self.INT_FIELDS else round(v, self.ROUNDING.get(f, 1))
        return out


class TelemetryPoint(_BasePoint):
    FIELDS = METRIC_FIELDS
    PEAKS = {"cpu_host_max": "cpu_host"}
    ROUNDING = {"network_rx_mb": 2, "network_tx_mb": 2}
    INT_FIELDS = ("containers_active",)
    __slots__ = ("cpu_host_max", *METRIC_FIELDS)


class ContainerPoint(_BasePoint):
    FIELDS = CONTAINER_FIELDS
    PEAKS = {"cpu_percent_max": "cpu_percent"}
    ROUNDING = {"cpu_percent": 2, "cpu_percent_max": 2, "network_rx_mb": 2, "network_tx_mb": 2,
                "memory_host_pct": 2}
    __slots__ = ("cpu_percent_max", *CONTAINER_FIELDS)


P = TypeVar("P", bound=_BasePoint)


def aggregate_points(points: Sequence[P], bucket_seconds: int) -> List[P]:
    """
    Agrupa os pontos em baldes de tempo alinhados ao epoch (média de cada métrica
    e máximo dos campos de pico). O alinhamento permite que o frontend continue
    preenchendo o mesmo balde com leituras ao vivo.
    """
    if not points:
        return []
    if bucket_seconds <= 1:
        return sorted(points, key=lambda p: p.timestamp)

    cls: Type[P] = type(points[0])
    buckets: Dict[int, List[P]] = {}
    for p in points:
        buckets.setdefault(int(p.timestamp // bucket_seconds), []).append(p)

    result: List[P] = []
    for key in sorted(buckets):
        group = buckets[key]
        n = len(group)
        values: Dict[str, float] = {f: sum(getattr(p, f) for p in group) / n for f in cls.FIELDS}
        for peak in cls.PEAKS:
            values[peak] = max(getattr(p, peak) for p in group)
        result.append(cls(timestamp=key * bucket_seconds, **values))
    return result


class TelemetryService:
    """
    Telemetria contínua do host, do Docker Engine e de cada contêiner.

    - Amostra a cada `SAMPLE_INTERVAL` segundos e mantém as últimas horas em
      memória (ring buffer) para o gráfico em tempo real.
    - Persiste no banco a média de cada minuto (host e por contêiner), com
      retenção de `RETENTION_DAYS`, permitindo consultar vários dias de histórico.
    """

    SAMPLE_INTERVAL = 3.0
    MEMORY_WINDOW_SECONDS = 2 * 3600
    MAX_POINTS = int(MEMORY_WINDOW_SECONDS / SAMPLE_INTERVAL)
    PERSIST_BUCKET_SECONDS = 60
    RETENTION_DAYS = 90
    PURGE_INTERVAL_SECONDS = 3600
    TARGET_POINTS = 180

    def __init__(self) -> None:
        self._buffer: Deque[TelemetryPoint] = deque(maxlen=self.MAX_POINTS)
        self._container_buffers: Dict[str, Deque[ContainerPoint]] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._last_snapshot: Optional[TelemetryPoint] = None
        self._pending: List[TelemetryPoint] = []
        self._pending_containers: Dict[str, List[ContainerPoint]] = {}
        self._pending_bucket: Optional[int] = None
        self._last_purge = 0.0

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._collector_loop())
            logger.info("TelemetryService de métricas do sistema iniciado.")

    def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("TelemetryService de métricas do sistema parado.")

    # ------------------------------------------------------------------ coleta

    def record_point(
        self,
        cpu_host: float,
        cpu_docker: float,
        memory_host_pct: float,
        memory_host_used_mb: float,
        memory_docker_used_mb: float,
        network_rx_mb: float,
        network_tx_mb: float,
        disk_used_pct: float,
        containers_active: int,
        timestamp: Optional[float] = None,
    ) -> TelemetryPoint:
        point = TelemetryPoint(
            timestamp=timestamp if timestamp is not None else time.time(),
            cpu_host=cpu_host,
            cpu_docker=cpu_docker,
            memory_host_pct=memory_host_pct,
            memory_host_used_mb=memory_host_used_mb,
            memory_docker_used_mb=memory_docker_used_mb,
            network_rx_mb=network_rx_mb,
            network_tx_mb=network_tx_mb,
            disk_used_pct=disk_used_pct,
            containers_active=containers_active,
        )
        self._buffer.append(point)
        self._last_snapshot = point
        return point

    def record_container_point(self, name: str, point: ContainerPoint) -> None:
        buf = self._container_buffers.get(name)
        if buf is None:
            buf = self._container_buffers[name] = deque(maxlen=self.MAX_POINTS)
        buf.append(point)
        self._pending_containers.setdefault(name, []).append(point)

    def _prune_container_buffers(self, now: float) -> None:
        """Descarta buffers de contêineres que não reportam há mais que a janela em memória."""
        stale = [
            name for name, buf in self._container_buffers.items()
            if not buf or now - buf[-1].timestamp > self.MEMORY_WINDOW_SECONDS
        ]
        for name in stale:
            del self._container_buffers[name]

    def _rollup(self, ts: float) -> Tuple[Optional[TelemetryPoint], Dict[str, ContainerPoint]]:
        """
        Fecha o minuto pendente quando `ts` pertence a um novo minuto, devolvendo as
        médias do host e de cada contêiner a serem persistidas.
        """
        bucket = int(ts // self.PERSIST_BUCKET_SECONDS)
        host_done: Optional[TelemetryPoint] = None
        containers_done: Dict[str, ContainerPoint] = {}
        if self._pending_bucket is not None and bucket != self._pending_bucket:
            if self._pending:
                host_done = aggregate_points(self._pending, self.PERSIST_BUCKET_SECONDS)[0]
            for name, pts in self._pending_containers.items():
                if pts:
                    containers_done[name] = aggregate_points(pts, self.PERSIST_BUCKET_SECONDS)[0]
            self._pending = []
            self._pending_containers = {}
        self._pending_bucket = bucket
        return host_done, containers_done

    def _take_completed_minute(self, point: TelemetryPoint) -> Optional[TelemetryPoint]:
        """Acumula o ponto do host no minuto corrente e devolve a média do minuto anterior quando ele fecha."""
        host_done, _ = self._rollup(point.timestamp)
        self._pending.append(point)
        return host_done

    async def _persist(
        self,
        point: Optional[TelemetryPoint],
        containers: Optional[Dict[str, ContainerPoint]] = None,
    ) -> None:
        import app.db.session as db_session
        from app.models.telemetry import ContainerTelemetrySample, TelemetrySample

        rows: List[Any] = []
        if point is not None:
            rows.append(
                TelemetrySample(
                    timestamp=point.timestamp,
                    cpu_host_max=point.cpu_host_max,
                    **{f: getattr(point, f) for f in METRIC_FIELDS if f != "containers_active"},
                    containers_active=int(round(point.containers_active)),
                )
            )
        for name, cp in (containers or {}).items():
            rows.append(
                ContainerTelemetrySample(
                    timestamp=cp.timestamp,
                    container_name=name[:255],
                    cpu_percent_max=cp.cpu_percent_max,
                    **{f: getattr(cp, f) for f in CONTAINER_FIELDS},
                )
            )
        if not rows:
            return
        async with db_session.async_session_factory() as session:
            session.add_all(rows)
            await session.commit()

    async def _purge_old(self, now: float) -> None:
        if now - self._last_purge < self.PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        from sqlalchemy import delete

        import app.db.session as db_session
        from app.models.telemetry import ContainerTelemetrySample, TelemetrySample

        cutoff = now - self.RETENTION_DAYS * 86400
        async with db_session.async_session_factory() as session:
            await session.execute(delete(TelemetrySample).where(TelemetrySample.timestamp < cutoff))
            await session.execute(
                delete(ContainerTelemetrySample).where(ContainerTelemetrySample.timestamp < cutoff)
            )
            await session.commit()

    async def _collector_loop(self) -> None:
        from app.services.docker_service import DockerService

        docker = DockerService()
        while self._running:
            try:
                overview = await docker.get_resources_overview()
                host = overview.get("host", {}) or {}
                d_usage = overview.get("docker_usage", {}) or {}
                disks = host.get("disks") or []
                disk_pct = host.get("disk_percent")
                if disk_pct is None:
                    disk_pct = disks[0].get("percent", 0.0) if disks else 0.0

                now = time.time()
                host_done, containers_done = self._rollup(now)

                point = self.record_point(
                    cpu_host=host.get("cpu_percent", 0.0) or 0.0,
                    cpu_docker=d_usage.get("cpu_normalized_percent", 0.0) or 0.0,
                    memory_host_pct=host.get("memory_percent", 0.0) or 0.0,
                    memory_host_used_mb=host.get("memory_used_mb", 0.0) or 0.0,
                    memory_docker_used_mb=d_usage.get("memory_used_mb", 0.0) or 0.0,
                    network_rx_mb=d_usage.get("network_rx_mb", 0.0) or 0.0,
                    network_tx_mb=d_usage.get("network_tx_mb", 0.0) or 0.0,
                    disk_used_pct=disk_pct or 0.0,
                    containers_active=d_usage.get("containers_running", 0) or 0,
                    timestamp=now,
                )
                self._pending.append(point)

                for c in d_usage.get("containers") or []:
                    name = c.get("name")
                    if not name or c.get("state") != "running":
                        continue
                    self.record_container_point(
                        name,
                        ContainerPoint(
                            timestamp=now,
                            cpu_percent=c.get("cpu_percent", 0.0),
                            memory_mb=c.get("memory_usage_mb", 0.0),
                            memory_host_pct=c.get("memory_host_percent", 0.0),
                            network_rx_mb=c.get("network_rx_mb", 0.0),
                            network_tx_mb=c.get("network_tx_mb", 0.0),
                        ),
                    )
                self._prune_container_buffers(now)

                if host_done is not None or containers_done:
                    await self._persist(host_done, containers_done)
                await self._purge_old(point.timestamp)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Amostragem de telemetria omitida: {e}")

            try:
                await asyncio.sleep(self.SAMPLE_INTERVAL)
            except asyncio.CancelledError:
                break

    # ---------------------------------------------------------------- consulta

    async def _load_persisted(self, start: float, end: float) -> List[TelemetryPoint]:
        from sqlalchemy import select

        import app.db.session as db_session
        from app.models.telemetry import TelemetrySample as T

        stmt = (
            select(T.timestamp, T.cpu_host_max, *(getattr(T, f) for f in METRIC_FIELDS))
            .where(T.timestamp >= start, T.timestamp < end)
            .order_by(T.timestamp)
        )
        async with db_session.async_session_factory() as session:
            rows = (await session.execute(stmt)).all()

        return [
            TelemetryPoint(timestamp=ts, cpu_host_max=cpu_max, **dict(zip(METRIC_FIELDS, values)))
            for ts, cpu_max, *values in rows
        ]

    async def _load_persisted_container(
        self, name: str, start: float, end: float
    ) -> List[ContainerPoint]:
        from sqlalchemy import select

        import app.db.session as db_session
        from app.models.telemetry import ContainerTelemetrySample as C

        stmt = (
            select(C.timestamp, C.cpu_percent_max, *(getattr(C, f) for f in CONTAINER_FIELDS))
            .where(C.container_name == name, C.timestamp >= start, C.timestamp < end)
            .order_by(C.timestamp)
        )
        async with db_session.async_session_factory() as session:
            rows = (await session.execute(stmt)).all()

        return [
            ContainerPoint(timestamp=ts, cpu_percent_max=cpu_max, **dict(zip(CONTAINER_FIELDS, values)))
            for ts, cpu_max, *values in rows
        ]

    async def get_history(self, range_key: str = "15m", container: Optional[str] = None) -> Dict[str, Any]:
        """
        Retorna a série temporal da janela pedida (`30m`, `6h`, `7d`...), agregada em
        baldes de tempo para manter ~`TARGET_POINTS` pontos no gráfico.
        Combina o buffer em memória (alta resolução) com o histórico persistido.
        Com `container`, retorna a série daquele contêiner específico.
        """
        normalized, window_seconds = parse_range(range_key)
        now = time.time()
        start = now - window_seconds
        bucket_seconds = max(int(self.SAMPLE_INTERVAL), int(window_seconds // self.TARGET_POINTS))
        container = (container or "").strip() or None

        memory_source: Sequence[_BasePoint]
        if container:
            memory_source = self._container_buffers.get(container) or ()
        else:
            memory_source = self._buffer
        memory_points = [p for p in memory_source if p.timestamp >= start]
        cutoff = memory_points[0].timestamp if memory_points else now

        persisted: List[Any] = []
        if cutoff - start > self.PERSIST_BUCKET_SECONDS:
            end = cutoff - self.PERSIST_BUCKET_SECONDS
            try:
                if container:
                    persisted = await self._load_persisted_container(container, start, end)
                else:
                    persisted = await self._load_persisted(start, end)
            except Exception as e:
                logger.warning(f"Falha ao ler histórico de telemetria persistido: {e}")

        points = aggregate_points([*persisted, *memory_points], bucket_seconds)
        oldest = points[0].timestamp if points else None

        return {
            "range": normalized,
            "scope": "container" if container else "host",
            "container": container,
            "window_seconds": window_seconds,
            "bucket_seconds": bucket_seconds,
            "sample_interval_seconds": self.SAMPLE_INTERVAL,
            "retention_days": self.RETENTION_DAYS,
            "oldest_timestamp": oldest,
            "total_points": len(points),
            "points": [p.to_dict() for p in points],
        }

    async def list_containers(self, range_key: str = "24h") -> List[str]:
        """Nomes de contêineres com histórico disponível na janela (inclui removidos)."""
        _, window_seconds = parse_range(range_key)
        start = time.time() - window_seconds
        names = {
            name for name, buf in self._container_buffers.items()
            if buf and buf[-1].timestamp >= start
        }
        try:
            from sqlalchemy import select

            import app.db.session as db_session
            from app.models.telemetry import ContainerTelemetrySample as C

            stmt = select(C.container_name).where(C.timestamp >= start).distinct()
            async with db_session.async_session_factory() as session:
                names.update(r[0] for r in (await session.execute(stmt)).all())
        except Exception as e:
            logger.warning(f"Falha ao listar contêineres com histórico: {e}")
        return sorted(names)


telemetry_service = TelemetryService()
