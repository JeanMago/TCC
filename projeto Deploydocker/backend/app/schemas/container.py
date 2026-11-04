from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ContainerSummary(BaseModel):
    id: str
    name: str
    status: str
    image: str
    ports: Optional[Dict[str, Any]] = None
    created: Optional[str] = None
    state: Optional[str] = None
    labels: Optional[Dict[str, str]] = None
    public_url: Optional[str] = None


class ContainerDetail(ContainerSummary):
    mounts: Optional[List[Dict[str, Any]]] = None
    networks: Optional[Dict[str, Any]] = None
    env: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None
    restart_policy: Optional[Dict[str, Any]] = None
    memory_limit_mb: Optional[int] = None
    cpu_limit_cores: Optional[float] = None


class ContainerStats(BaseModel):
    cpu_percent: float
    memory_usage_mb: float
    memory_limit_mb: float
    memory_percent: float
    network_rx_mb: float
    network_tx_mb: float


class ContainerAction(BaseModel):
    action: str
