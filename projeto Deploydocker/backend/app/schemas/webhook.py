from typing import Optional

from pydantic import BaseModel


class WebhookResponse(BaseModel):
    status: str
    branch: Optional[str] = None
    commit: Optional[str] = None
    delivery: Optional[str] = None


class SystemInfo(BaseModel):
    """
    Schema alinhado com o retorno de DockerService.get_system_info().

    Campos retornados pelo serviço:
        docker_version, api_version, os, architecture, cpus,
        memory_total_mb, containers_count, containers_running,
        containers_stopped, containers_paused, images_count,
        volumes_count, networks_count
    """
    docker_version: Optional[str] = None
    api_version: Optional[str] = None
    os: Optional[str] = None
    architecture: Optional[str] = None
    cpus: Optional[int] = None
    memory_total_mb: Optional[float] = None
    containers_count: Optional[int] = None
    containers_running: Optional[int] = None
    containers_stopped: Optional[int] = None
    containers_paused: Optional[int] = None
    images_count: Optional[int] = None
    volumes_count: Optional[int] = None
    networks_count: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    uptime_seconds: Optional[float] = None
