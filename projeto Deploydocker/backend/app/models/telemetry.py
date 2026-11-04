from sqlalchemy import Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class TelemetrySample(Base):
    """
    Amostra agregada (média por minuto) de uso de recursos do host e do Docker.

    Persistida para permitir a visualização do histórico por vários dias no
    gráfico do Monitor de Recursos, mesmo após reinícios do backend.
    """

    __tablename__ = "telemetry_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Epoch em segundos (UTC) do início do minuto agregado
    timestamp: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    cpu_host: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cpu_host_max: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cpu_docker: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_host_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_host_used_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_docker_used_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    network_rx_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    network_tx_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    disk_used_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    containers_active: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ContainerTelemetrySample(Base):
    """
    Amostra agregada (média por minuto) de uso de recursos de um contêiner Docker.

    Indexada pelo nome do contêiner (estável entre redeploys, ao contrário do ID),
    permitindo filtrar o gráfico de histórico por contêiner.
    """

    __tablename__ = "container_telemetry_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    container_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    # CPU no padrão `docker stats` (100% = 1 núcleo; pode passar de 100% em multi-core)
    cpu_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cpu_percent_max: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    memory_host_pct: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    network_rx_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    network_tx_mb: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
