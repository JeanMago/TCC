import uuid
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.routing import normalize_domain, normalize_subdomain


class RoutingFieldsMixin(BaseModel):
    """Validação compartilhada dos campos de URL pública."""

    @field_validator("subdomain", mode="before", check_fields=False)
    @classmethod
    def _validate_subdomain(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        return normalize_subdomain(v)

    @field_validator("custom_domain", mode="before", check_fields=False)
    @classmethod
    def _validate_custom_domain(cls, v):
        return normalize_domain(v) if isinstance(v, str) else v


class ProjectBase(BaseModel):
    name: str
    repo_url: Optional[str] = None
    git_url: Optional[str] = None
    branch: str = "main"
    webhook_secret: Optional[str] = None
    docker_compose_path: Optional[str] = "docker-compose.yml"
    dockerfile_path: Optional[str] = "Dockerfile"
    auto_deploy: bool = True
    health_check_url: Optional[str] = None
    health_check_interval: int = 30
    subdomain: Optional[str] = None
    custom_domain: Optional[str] = None
    container_port: Optional[int] = Field(default=None, ge=1, le=65535)
    preview_deployments_enabled: Optional[bool] = True
    memory_limit_mb: Optional[int] = Field(default=None, ge=32, le=65536)
    cpu_limit_cores: Optional[float] = Field(default=None, ge=0.1, le=64.0)
    auto_heal: Optional[bool] = True
    auto_heal_enabled: Optional[bool] = None
    deploy_strategy: Optional[Literal["recreate", "blue_green"]] = "recreate"
    replicas: Optional[int] = Field(default=1, ge=1, le=10)
    autoscale_enabled: Optional[bool] = False
    autoscale_min_replicas: Optional[int] = Field(default=1, ge=1, le=10)
    autoscale_max_replicas: Optional[int] = Field(default=3, ge=1, le=10)
    autoscale_cpu_target: Optional[int] = Field(default=75, ge=10, le=99)

    @model_validator(mode="before")
    @classmethod
    def _remap_project_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "git_url" in data and not data.get("repo_url"):
                data["repo_url"] = data["git_url"]
            if "auto_heal_enabled" in data and "auto_heal" not in data:
                data["auto_heal"] = data["auto_heal_enabled"]
        return data


class ProjectCreate(RoutingFieldsMixin, ProjectBase):
    template: Optional[str] = None
    dockerfile_content: Optional[str] = None
    git_token: Optional[str] = None
    initial_env_vars: Optional[list[dict]] = None


class ProjectUpdate(RoutingFieldsMixin, BaseModel):
    name: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    webhook_secret: Optional[str] = None
    docker_compose_path: Optional[str] = None
    dockerfile_path: Optional[str] = None
    auto_deploy: Optional[bool] = None
    health_check_url: Optional[str] = None
    health_check_interval: Optional[int] = None
    subdomain: Optional[str] = None
    custom_domain: Optional[str] = None
    container_port: Optional[int] = Field(default=None, ge=1, le=65535)
    git_token: Optional[str] = None
    preview_deployments_enabled: Optional[bool] = None
    memory_limit_mb: Optional[int] = Field(default=None, ge=32, le=65536)
    cpu_limit_cores: Optional[float] = Field(default=None, ge=0.1, le=64.0)
    auto_heal: Optional[bool] = None
    deploy_strategy: Optional[Literal["recreate", "blue_green"]] = None
    replicas: Optional[int] = Field(default=None, ge=1, le=10)
    autoscale_enabled: Optional[bool] = None
    autoscale_min_replicas: Optional[int] = Field(default=None, ge=1, le=10)
    autoscale_max_replicas: Optional[int] = Field(default=None, ge=1, le=10)
    autoscale_cpu_target: Optional[int] = Field(default=None, ge=10, le=99)


class ProjectRead(ProjectBase):
    id: uuid.UUID
    public_host: str
    public_url: str
    has_git_token: bool = False
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectList(BaseModel):
    id: uuid.UUID
    name: str
    repo_url: str
    branch: str
    auto_deploy: bool
    webhook_secret: Optional[str] = None
    subdomain: Optional[str] = None
    custom_domain: Optional[str] = None
    container_port: Optional[int] = None
    public_host: str
    public_url: str
    last_deploy_status: Optional[str] = None
    container_id: Optional[str] = None
    has_git_token: bool = False
    preview_deployments_enabled: Optional[bool] = True
    memory_limit_mb: Optional[int] = None
    cpu_limit_cores: Optional[float] = None
    auto_heal: Optional[bool] = True
    deploy_strategy: Optional[str] = "recreate"
    replicas: Optional[int] = 1
    autoscale_enabled: Optional[bool] = False
    autoscale_min_replicas: Optional[int] = 1
    autoscale_max_replicas: Optional[int] = 3
    autoscale_cpu_target: Optional[int] = 75

    model_config = ConfigDict(from_attributes=True)


class RoutingConfig(BaseModel):
    """Configuração de URLs exposta ao frontend (pré-visualização dos links)."""
    base_domain: str
    tls_enabled: bool
    scheme: str
    port_suffix: str
    traefik_enabled: bool = True
