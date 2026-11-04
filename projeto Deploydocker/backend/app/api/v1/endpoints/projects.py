import logging
import os
import secrets
import shutil
import uuid
from typing import List
from typing import Optional as _Optional

import git
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel as _BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, get_docker_service, require_role
from app.api.v1.endpoints.webhooks import _trigger_deploy
from app.core.config import settings
from app.core.routing import public_url as build_public_url
from app.core.routing import slugify
from app.core.security import decrypt_value, encrypt_value
from app.core.waf import security_manager, validate_safe_git_url
from app.db.session import async_session_factory
from app.models.deployment import Deployment
from app.models.environment import EnvironmentVariable
from app.models.project import Project
from app.models.user import User
from app.schemas.deployment import DeploymentList
from app.schemas.project import ProjectCreate, ProjectList, ProjectRead, ProjectUpdate, RoutingConfig
from app.services.deploy_orchestrator import DeployOrchestrator
from app.services.docker_service import DockerService
from app.services.git_service import GitService
from app.services.paas_service import paas_manager
from app.services.uptime_service import uptime_monitor

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(get_current_user)])

RESERVED_SUBDOMAINS = {"admin", "api", "painel", "traefik", "dashboard", "auth", "mail", "smtp", "status", "system"}


@router.post("/validate-subdomain")
@router.get("/validate-subdomain")
async def validate_subdomain_route(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Verifica e reserva subdomínios, prevenindo colisões e route hijacking (HTTP 409)."""
    sub = ""
    cust = ""
    if request.method == "POST":
        try:
            body = await request.json()
            sub = (body.get("subdomain") or "").strip().lower()
            cust = (body.get("custom_domain") or "").strip().lower()
        except Exception:
            pass
    else:
        sub = (request.query_params.get("subdomain") or "").strip().lower()
        cust = (request.query_params.get("custom_domain") or "").strip().lower()

    if sub in RESERVED_SUBDOMAINS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"O subdomínio '{sub}' é reservado pelo sistema DeployDock.",
        )

    if sub:
        exists = (
            await db.execute(select(Project.id).where(Project.subdomain == sub))
        ).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"O subdomínio '{sub}' já está em uso por outro projeto.",
            )

    if cust:
        exists_c = (
            await db.execute(select(Project.id).where(Project.custom_domain == cust))
        ).first()
        if exists_c:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"O domínio customizado '{cust}' já está em uso por outro projeto.",
            )

    return {
        "available": True,
        "subdomain": sub,
        "custom_domain": cust,
        "message": "Subdomínio/domínio disponível para roteamento.",
    }


@router.get("/routing-config", response_model=RoutingConfig)
async def get_routing_config():
    """Retorna configurações de domínio e TLS para ajudar o frontend a exibir prévias das URLs."""
    if settings.APPS_TLS_ENABLED:
        scheme = "https"
        port_suffix = "" if settings.PROXY_HTTPS_PORT == 443 else f":{settings.PROXY_HTTPS_PORT}"
    else:
        scheme = "http"
        port_suffix = "" if settings.PROXY_HTTP_PORT == 80 else f":{settings.PROXY_HTTP_PORT}"

    return RoutingConfig(
        base_domain=settings.APPS_BASE_DOMAIN,
        tls_enabled=settings.APPS_TLS_ENABLED,
        scheme=scheme,
        port_suffix=port_suffix,
        traefik_enabled=True,
    )


@router.get("/uptime/overview")
async def get_uptime_overview():
    """Retorna métricas de Uptime, histórico de latência e contadores de Auto-Healing de todos os projetos."""
    records = uptime_monitor.get_all_records()
    if not records:
        records = await uptime_monitor.check_all_projects()
    return {
        "total_auto_heals": uptime_monitor.total_auto_heals,
        "projects": records,
    }


@router.post("/uptime/check-now")
async def trigger_uptime_check_now():
    """Executa verificação imediata de Uptime/Latência em todos os projetos."""
    records = await uptime_monitor.check_all_projects()
    return {
        "total_auto_heals": uptime_monitor.total_auto_heals,
        "projects": records,
    }


TEMPLATES = {
    "fastapi": {
        "Dockerfile": """FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY main.py .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
""",
        "main.py": """from fastapi import FastAPI

app = FastAPI(title="Minha API")

@app.get("/")
def home():
    return {"status": "online", "message": "DeployDock - API FastAPI em execução!"}

@app.get("/health")
def health():
    return {"status": "healthy"}
""",
    },
    "express": {
        "Dockerfile": """FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY index.js .
EXPOSE 3000
CMD ["node", "index.js"]
""",
        "package.json": """{
  "name": "minha-api-node",
  "version": "1.0.0",
  "main": "index.js",
  "dependencies": {
    "express": "^4.19.2"
  }
}
""",
        "index.js": """const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({ status: 'online', message: 'DeployDock - Aplicação Node.js em execução!' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy' });
});

app.listen(port, () => console.log(`Rodando na porta ${port}`));
""",
    },
    "static": {
        "Dockerfile": """FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
""",
        "index.html": """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>DeployDock App</title>
  <style>
    body { font-family: sans-serif; background: #0b0f19; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #131b2e; padding: 2rem; border-radius: 12px; border: 1px solid #1e2a45; text-align: center; }
    h1 { color: #0ea5e9; }
  </style>
</head>
<body>
  <div class="card">
    <h1>DeployDock</h1>
    <p>Site estático publicado com sucesso!</p>
  </div>
</body>
</html>
""",
    },
    "flask": {
        "Dockerfile": """FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask gunicorn
COPY app.py .
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
""",
        "app.py": """from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify(service="flask-microservice", status="online", env=os.getenv("APP_ENV", "production"))

@app.route("/health")
def health():
    return jsonify(status="healthy")
""",
    },
    "adminer": {
        "Dockerfile": """FROM adminer:latest
EXPOSE 8080
""",
    },
    "status_page": {
        "Dockerfile": """FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
""",
        "index.html": """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Status dos Serviços</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0d0f12; color: #e4e7ec; margin: 0; padding: 3rem 1rem; }
    .wrap { max-width: 640px; margin: 0 auto; background: #13161b; border: 1px solid #232830; border-radius: 8px; padding: 1.5rem; }
    .badge { display: inline-block; background: #065f46; color: #34d399; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .row { display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid #1e232b; font-size: 14px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem">
      <h2 style="margin:0;font-size:18px">Status Operacional</h2>
      <span class="badge">Todos os Sistemas Operacionais</span>
    </div>
    <div class="row"><span>API Gateway (Traefik)</span><span style="color:#34d399">100% Online</span></div>
    <div class="row"><span>Container Engine</span><span style="color:#34d399">100% Online</span></div>
    <div class="row" style="border:none"><span>Banco de Dados</span><span style="color:#34d399">100% Online</span></div>
  </div>
</body>
</html>
""",
    },
}


@router.get("", response_model=List[ProjectList])
async def list_projects(db: AsyncSession = Depends(get_db)):
    from app.models.deployment import Deployment

    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    projects = result.scalars().all()

    dep_res = await db.execute(select(Deployment).order_by(Deployment.started_at.desc()))
    latest_by_project: dict[uuid.UUID, str] = {}
    for d in dep_res.scalars().all():
        if d.project_id not in latest_by_project:
            latest_by_project[d.project_id] = d.status

    container_map: dict[str, tuple[str, str]] = {}
    try:
        docker_svc = DockerService()
        for c in await docker_svc.list_containers(all=True):
            container_map[c["name"].lower()] = (c["id"], c.get("state") or c.get("status") or "")
    except Exception:
        pass

    out: list[dict] = []
    for p in projects:
        c_name = f"deploydock_{p.name.lower()}"
        c_info = container_map.get(c_name)
        status = latest_by_project.get(p.id)
        if c_info and c_info[1] == "running":
            status = status or "running"
        out.append(
            {
                "id": p.id,
                "name": p.name,
                "repo_url": p.repo_url,
                "branch": p.branch,
                "auto_deploy": p.auto_deploy,
                "webhook_secret": p.webhook_secret,
                "subdomain": p.subdomain,
                "custom_domain": p.custom_domain,
                "container_port": p.container_port,
                "public_host": p.public_host,
                "public_url": p.public_url,
                "last_deploy_status": status or ("running" if c_info else "pending"),
                "container_id": c_info[0] if c_info else None,
                "has_git_token": p.has_git_token,
                "preview_deployments_enabled": (
                    True if p.preview_deployments_enabled is None else p.preview_deployments_enabled
                ),
                "memory_limit_mb": p.memory_limit_mb,
                "cpu_limit_cores": p.cpu_limit_cores,
                "auto_heal": True if p.auto_heal is None else p.auto_heal,
                "deploy_strategy": p.deploy_strategy or "recreate",
                "replicas": p.replicas or 1,
                "autoscale_enabled": bool(p.autoscale_enabled),
                "autoscale_min_replicas": p.autoscale_min_replicas or 1,
                "autoscale_max_replicas": p.autoscale_max_replicas or 3,
                "autoscale_cpu_target": p.autoscale_cpu_target or 75,
            }
        )
    return out


async def _ensure_routing_available(
    db: AsyncSession,
    subdomain: str | None,
    custom_domain: str | None,
    exclude_id: uuid.UUID | None = None,
) -> None:
    """Garante que subdomínio/domínio não estejam em uso por outro projeto (HTTP 409)."""
    checks = [
        (Project.subdomain, subdomain, "subdomínio"),
        (Project.custom_domain, custom_domain, "domínio"),
    ]
    for column, value, label in checks:
        if not value:
            continue
        query = select(Project.id).where(column == value)
        if exclude_id:
            query = query.where(Project.id != exclude_id)
        if (await db.execute(query)).first():
            raise HTTPException(
                status_code=409, detail=f"O {label} '{value}' já está em uso por outro projeto."
            )


async def _unique_subdomain(db: AsyncSession, base: str) -> str:
    """Gera um subdomínio livre a partir do nome (meu-site, meu-site-2, ...)."""
    candidate, n = base, 2
    while (await db.execute(select(Project.id).where(Project.subdomain == candidate))).first():
        suffix = f"-{n}"
        candidate = f"{base[:63 - len(suffix)]}{suffix}"
        n += 1
    return candidate


@router.post("", response_model=ProjectRead, dependencies=[Depends(require_role("admin", "developer"))])
async def create_project(
    project_in: ProjectCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project_id = uuid.uuid4()
    webhook_secret = project_in.webhook_secret or secrets.token_hex(16)
    repo_url = (project_in.repo_url or "").strip()
    branch = project_in.branch or "main"

    subdomain = project_in.subdomain or await _unique_subdomain(db, slugify(project_in.name))
    await _ensure_routing_available(db, subdomain, project_in.custom_domain)

    if not repo_url or repo_url.startswith("local:") or project_in.template:
        repo_dir = os.path.abspath(os.path.join(settings.REPOS_BASE_PATH, str(project_id)))
        os.makedirs(repo_dir, exist_ok=True)

        template_key = project_in.template or "static"
        template_files = TEMPLATES.get(template_key, TEMPLATES["static"]).copy()

        if project_in.dockerfile_content:
            template_files["Dockerfile"] = project_in.dockerfile_content

        for filename, content in template_files.items():
            file_path = os.path.join(repo_dir, filename)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

        try:
            repo = git.Repo.init(repo_dir)
            repo.git.checkout("-b", branch)
            repo.git.add(A=True)
            repo.git.commit("-m", f"Initial commit for {project_in.name}")
        except Exception:
            pass

        repo_url = repo_dir
    else:
        repo_url = validate_safe_git_url(repo_url)

    encrypted_git_token = None
    if project_in.git_token and project_in.git_token.strip():
        encrypted_git_token = f"enc:{encrypt_value(project_in.git_token.strip())}"
    elif "github.com" in repo_url.lower():
        auto_gh_tok = paas_manager.get_decrypted_github_token()
        if auto_gh_tok:
            encrypted_git_token = f"enc:{encrypt_value(auto_gh_tok)}"

    db_obj = Project(
        id=project_id,
        name=project_in.name,
        repo_url=repo_url,
        branch=branch,
        webhook_secret=webhook_secret,
        docker_compose_path=project_in.docker_compose_path or "docker-compose.yml",
        dockerfile_path=project_in.dockerfile_path or "Dockerfile",
        auto_deploy=project_in.auto_deploy,
        health_check_url=project_in.health_check_url,
        health_check_interval=project_in.health_check_interval or 30,
        subdomain=subdomain,
        custom_domain=project_in.custom_domain,
        container_port=project_in.container_port,
        git_token=encrypted_git_token,
        preview_deployments_enabled=(
            True
            if project_in.preview_deployments_enabled is None
            else project_in.preview_deployments_enabled
        ),
        memory_limit_mb=project_in.memory_limit_mb,
        cpu_limit_cores=project_in.cpu_limit_cores,
        auto_heal=True if project_in.auto_heal is None else project_in.auto_heal,
        deploy_strategy=project_in.deploy_strategy or "recreate",
        replicas=project_in.replicas or 1,
        autoscale_enabled=bool(project_in.autoscale_enabled),
        autoscale_min_replicas=project_in.autoscale_min_replicas or 1,
        autoscale_max_replicas=project_in.autoscale_max_replicas or 3,
        autoscale_cpu_target=project_in.autoscale_cpu_target or 75,
    )
    db.add(db_obj)

    # Se foram detectadas/informadas variáveis iniciais (.env.example do GitHub), salva automaticamente
    if project_in.initial_env_vars:
        for item in project_in.initial_env_vars:
            if not isinstance(item, dict):
                continue
            k = str(item.get("key") or "").strip()
            if not k:
                continue
            v = str(item.get("value") or "")
            is_sec = bool(item.get("is_secret", False))
            stored_val = encrypt_value(v) if is_sec else v
            db.add(
                EnvironmentVariable(
                    project_id=project_id,
                    key=k,
                    value=stored_val,
                    is_secret=is_sec,
                )
            )

    await db.commit()
    await db.refresh(db_obj)

    # Auto-registro de Webhook no GitHub se a integração estiver ativa
    if (
        "github.com" in repo_url.lower()
        and project_in.auto_deploy
        and paas_manager.github_config.get("auto_create_webhook", True)
        and paas_manager.get_decrypted_github_token(force=True)
    ):
        webhook_target = f"{str(request.base_url).rstrip('/')}/api/v1/webhooks/github"
        background_tasks.add_task(
            paas_manager.create_github_repo_webhook,
            repo_url,
            webhook_target,
            webhook_secret,
        )

    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path="/api/v1/projects",
        detail=f"Projeto '{db_obj.name}' criado ({db_obj.public_url})",
        user=current_user.username,
    )
    return db_obj


@router.get("/{project_id}", response_model=ProjectRead)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Projeto não encontrado")
    return project


@router.get("/{project_id}/deployments", response_model=List[DeploymentList])
async def list_project_deployments(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Retorna o histórico auditável de deployments do projeto."""
    await get_project(project_id, db)
    q = select(Deployment).where(Deployment.project_id == project_id).order_by(Deployment.started_at.desc())
    result = await db.execute(q)
    return result.scalars().all()


ROUTING_FIELDS = (
    "subdomain",
    "custom_domain",
    "container_port",
    "memory_limit_mb",
    "cpu_limit_cores",
)


async def _reapply_routing(project_id: str) -> None:
    """Background task: recria o contêiner com a nova URL pública e limites (sem rebuild)."""
    async with async_session_factory() as session:
        project = (
            await session.execute(select(Project).where(Project.id == uuid.UUID(project_id)))
        ).scalar_one_or_none()
        if not project:
            return
        orchestrator = DeployOrchestrator(
            docker_service=DockerService(), git_service=GitService(), db_session=session
        )
        try:
            applied = await orchestrator.apply_routing(project)
            if not applied:
                logger.info(
                    f"[Routing] {project.name} sem contêiner ativo; URL será usada no próximo deploy."
                )
        except Exception as e:
            logger.error(f"[Routing] Falha ao reaplicar URL de {project.name}: {e}")


@router.put(
    "/{project_id}",
    response_model=ProjectRead,
    dependencies=[Depends(require_role("admin", "developer"))],
)
@router.patch(
    "/{project_id}",
    response_model=ProjectRead,
    dependencies=[Depends(require_role("admin", "developer"))],
)
async def update_project(
    project_id: uuid.UUID,
    project_in: ProjectUpdate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await get_project(project_id, db)
    if not paas_manager.check_project_permission(
        str(current_user.id), current_user.role, str(project.id), ("admin", "developer")
    ):
        raise HTTPException(status_code=403, detail="Sem permissão para editar este projeto.")
    update_data = project_in.model_dump(exclude_unset=True)

    if "subdomain" in update_data and not update_data["subdomain"]:
        base = slugify(update_data.get("name") or project.name)
        update_data["subdomain"] = (
            project.subdomain if project.subdomain == base else await _unique_subdomain(db, base)
        )

    await _ensure_routing_available(
        db, update_data.get("subdomain"), update_data.get("custom_domain"), exclude_id=project.id
    )

    if "git_token" in update_data:
        raw_tok = update_data.pop("git_token")
        if raw_tok is not None:
            project.git_token = (
                f"enc:{encrypt_value(raw_tok.strip())}" if raw_tok.strip() else None
            )

    routing_changed = any(
        k in update_data and update_data[k] != getattr(project, k) for k in ROUTING_FIELDS
    )
    for k, v in update_data.items():
        setattr(project, k, v)
    await db.commit()
    await db.refresh(project)

    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}",
        detail=f"Configurações do projeto '{project.name}' atualizadas",
        user=current_user.username,
    )

    if routing_changed:
        background_tasks.add_task(_reapply_routing, str(project.id))
    return project


@router.delete("/{project_id}", dependencies=[Depends(require_role("admin", "developer"))])
async def delete_project(
    project_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await get_project(project_id, db)
    if not paas_manager.check_project_permission(
        str(current_user.id), current_user.role, str(project.id), ("admin",)
    ):
        raise HTTPException(status_code=403, detail="Apenas administradores do projeto podem excluí-lo.")
    p_name = project.name
    await db.delete(project)
    await db.commit()
    security_manager.log_event(
        event_type="deploy",
        severity="medium",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}",
        detail=f"Projeto '{p_name}' excluído",
        user=current_user.username,
    )
    return {"message": "Projeto excluído com sucesso"}


@router.post("/{project_id}/deploy", dependencies=[Depends(require_role("admin", "developer"))])
async def deploy_project(
    project_id: uuid.UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await get_project(project_id, db)
    if not paas_manager.check_project_permission(
        str(current_user.id), current_user.role, str(project.id), ("admin", "developer")
    ):
        raise HTTPException(status_code=403, detail="Sem permissão de deploy neste projeto.")
    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/deploy",
        detail=f"Deploy iniciado para o projeto '{project.name}' ({project.branch})",
        user=current_user.username,
        blocked=False,
    )
    background_tasks.add_task(_trigger_deploy, str(project.id), "manual", project.branch)
    return {"message": "Deploy iniciado com sucesso"}


@router.post("/{project_id}/stop", dependencies=[Depends(require_role("admin", "developer"))])
async def stop_project(
    project_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    docker: DockerService = Depends(get_docker_service),
):
    """Interrompe intencionalmente a execução dos contêineres do projeto e suspende auto-heal."""
    project = await get_project(project_id, db)
    if not paas_manager.check_project_permission(
        str(current_user.id), current_user.role, str(project.id), ("admin", "developer")
    ):
        raise HTTPException(status_code=403, detail="Sem permissão para gerenciar este projeto.")

    container_name = f"deploydock_{project.name.lower()}"
    uptime_monitor.mark_manually_stopped(container_name)
    uptime_monitor.mark_manually_stopped(project.name)

    stopped_count = 0
    try:
        await docker.stop_container(container_name)
        stopped_count += 1
    except ValueError:
        pass
    except Exception as e:
        logger.warning(f"Erro ao parar contêiner principal {container_name}: {e}")

    for rep in range(2, 11):
        rep_name = f"{container_name}_rep{rep}"
        uptime_monitor.mark_manually_stopped(rep_name)
        try:
            await docker.stop_container(rep_name)
            stopped_count += 1
        except Exception:
            pass

    security_manager.log_event(
        event_type="project_stop",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/stop",
        detail=f"Projeto '{project.name}' parado intencionalmente pelo usuário",
        user=current_user.username,
        blocked=False,
    )
    return {"message": f"Projeto '{project.name}' interrompido com sucesso.", "stopped_containers": stopped_count}


@router.post("/{project_id}/start", dependencies=[Depends(require_role("admin", "developer"))])
async def start_project(
    project_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    docker: DockerService = Depends(get_docker_service),
):
    """Inicia a execução dos contêineres do projeto e reabilita o monitoramento de saúde."""
    project = await get_project(project_id, db)
    if not paas_manager.check_project_permission(
        str(current_user.id), current_user.role, str(project.id), ("admin", "developer")
    ):
        raise HTTPException(status_code=403, detail="Sem permissão para gerenciar este projeto.")

    container_name = f"deploydock_{project.name.lower()}"
    uptime_monitor.clear_manually_stopped(container_name)
    uptime_monitor.clear_manually_stopped(project.name)

    try:
        await docker.start_container(container_name)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"Contêiner '{container_name}' não encontrado no Docker Engine. Faça um novo Deploy."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao iniciar contêiner: {e}")

    for rep in range(2, (project.replicas or 1) + 1):
        rep_name = f"{container_name}_rep{rep}"
        uptime_monitor.clear_manually_stopped(rep_name)
        try:
            await docker.start_container(rep_name)
        except Exception:
            pass

    security_manager.log_event(
        event_type="project_start",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/start",
        detail=f"Projeto '{project.name}' iniciado pelo usuário",
        user=current_user.username,
        blocked=False,
    )
    return {"message": f"Projeto '{project.name}' iniciado com sucesso."}


@router.post("/{project_id}/toggle-auto-heal", dependencies=[Depends(require_role("admin", "developer"))])
async def toggle_project_auto_heal(
    project_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Ativa ou desativa o Auto-Healing automático para o projeto."""
    project = await get_project(project_id, db)
    current_val = getattr(project, "auto_heal", True)
    if current_val is None:
        current_val = True
    new_val = not current_val
    project.auto_heal = new_val
    await db.commit()
    await db.refresh(project)
    return {"project_id": str(project.id), "auto_heal": new_val}


# ----------------------------------------------------------------
# Escalonamento Horizontal (Réplicas) & Autoscaling (Dokploy & Ployter)
# ----------------------------------------------------------------


class ProjectScalePayload(_BaseModel):
    replicas: int = 1
    autoscale_enabled: _Optional[bool] = None
    autoscale_min_replicas: _Optional[int] = None
    autoscale_max_replicas: _Optional[int] = None
    autoscale_cpu_target: _Optional[int] = None
    auto_heal: _Optional[bool] = None


@router.post("/{project_id}/scale", dependencies=[Depends(require_role("admin", "developer"))])
async def scale_project_replicas(
    project_id: uuid.UUID,
    payload: ProjectScalePayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Escala horizontalmente o número de réplicas de contêineres do projeto e configura o Autoscaler."""
    project = await get_project(project_id, db)
    replicas = max(1, min(10, int(payload.replicas)))
    project.replicas = replicas
    if payload.autoscale_enabled is not None:
        project.autoscale_enabled = payload.autoscale_enabled
    if payload.autoscale_min_replicas is not None:
        project.autoscale_min_replicas = max(1, min(10, int(payload.autoscale_min_replicas)))
    if payload.autoscale_max_replicas is not None:
        project.autoscale_max_replicas = max(1, min(10, int(payload.autoscale_max_replicas)))
    if payload.autoscale_cpu_target is not None:
        project.autoscale_cpu_target = max(10, min(99, int(payload.autoscale_cpu_target)))
    if payload.auto_heal is not None:
        project.auto_heal = payload.auto_heal


@router.post("/{project_id}/scale", dependencies=[Depends(require_role("admin", "developer"))])
async def scale_project_replicas(
    project_id: uuid.UUID,
    payload: ProjectScalePayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Escala horizontalmente o número de réplicas de contêineres do projeto e configura o Autoscaler."""
    project = await get_project(project_id, db)
    replicas = max(1, min(10, int(payload.replicas)))
    project.replicas = replicas
    if payload.autoscale_enabled is not None:
        project.autoscale_enabled = payload.autoscale_enabled
    if payload.autoscale_min_replicas is not None:
        project.autoscale_min_replicas = max(1, min(10, int(payload.autoscale_min_replicas)))
    if payload.autoscale_max_replicas is not None:
        project.autoscale_max_replicas = max(1, min(10, int(payload.autoscale_max_replicas)))
    if payload.autoscale_cpu_target is not None:
        project.autoscale_cpu_target = max(10, min(99, int(payload.autoscale_cpu_target)))

    await db.commit()
    await db.refresh(project)

    orchestrator = DeployOrchestrator(
        docker_service=DockerService(),
        git_service=GitService(),
        db_session=db,
    )
    res = await orchestrator.scale_project(project, replicas)
    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/scale",
        detail=(
            f"Projeto '{project.name}' escalado para {replicas} réplica(s) "
            f"(autoscale={'ON' if project.autoscale_enabled else 'OFF'})"
        ),
        user=current_user.username,
    )
    return {
        **res,
        "autoscale_enabled": bool(project.autoscale_enabled),
        "autoscale_min_replicas": project.autoscale_min_replicas or 1,
        "autoscale_max_replicas": project.autoscale_max_replicas or 3,
        "autoscale_cpu_target": project.autoscale_cpu_target or 75,
    }


# ----------------------------------------------------------------
# RBAC Granular por Projeto (Permissões de Membros por Projeto)
# ----------------------------------------------------------------


class ProjectMemberPayload(_BaseModel):
    user_id: uuid.UUID
    role: str = "developer"  # 'admin' | 'developer' | 'viewer'


@router.get("/{project_id}/members")
async def list_project_members(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Lista os membros e papéis granulares atribuídos a este projeto."""
    await get_project(project_id, db)
    return paas_manager.list_project_members(str(project_id))


@router.post("/{project_id}/members", dependencies=[Depends(require_role("admin"))])
async def add_project_member(
    project_id: uuid.UUID,
    payload: ProjectMemberPayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Atribui permissão granular (admin, developer, viewer) a um usuário em um projeto específico."""
    project = await get_project(project_id, db)
    user = (
        await db.execute(select(User).where(User.id == payload.user_id))
    ).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    try:
        member = paas_manager.set_project_member(
            str(project.id), str(user.id), user.username, payload.role
        )
        security_manager.log_event(
            event_type="rbac",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/projects/{project_id}/members",
            detail=f"RBAC por projeto: '{user.username}' definido como '{payload.role}' em '{project.name}'",
            user=current_user.username,
        )
        return member
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{project_id}/members/{user_id}", dependencies=[Depends(require_role("admin"))])
async def remove_project_member(
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a permissão granular de um usuário em um projeto específico."""
    await get_project(project_id, db)
    try:
        res = paas_manager.remove_project_member(str(project_id), str(user_id))
        security_manager.log_event(
            event_type="rbac",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/projects/{project_id}/members/{user_id}",
            detail=f"Membro {user_id} removido do projeto {project_id}",
            user=current_user.username,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{project_id}/healthcheck")
async def check_project_health(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Testa conectividade HTTP ao vivo e retorna métricas de Uptime, histórico de latência e Auto-Heal."""
    project = await get_project(project_id, db)
    return await uptime_monitor.check_single_project(project)


# ----------------------------------------------------------------
# Preview Deployments por Branch / Pull Request (Feature 5)
# ----------------------------------------------------------------

class PreviewCreatePayload(_BaseModel):
    branch: str


@router.get("/{project_id}/previews")
async def list_project_previews(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Lista todos os ambientes de Preview ativos para este projeto."""
    project = await get_project(project_id, db)
    docker = DockerService()
    containers = await docker.list_containers(all=True)
    prefix = f"deploydock_preview_{slugify(project.name)}_"

    previews = []
    for c in containers:
        labels = c.get("labels") or {}
        if c["name"].lower().startswith(prefix) or (
            labels.get("deploydock.preview") == "true"
            and labels.get("deploydock.project_name") == project.name
        ):
            branch_slug = labels.get("deploydock.preview_slug") or c["name"][len(prefix):]
            branch_name = labels.get("deploydock.preview_branch") or branch_slug
            host = labels.get("deploydock.host") or f"{branch_slug}-{project.subdomain}.{settings.APPS_BASE_DOMAIN}"
            previews.append(
                {
                    "container_id": c["id"],
                    "container_name": c["name"],
                    "branch": branch_name,
                    "branch_slug": branch_slug,
                    "status": c.get("state") or c.get("status") or "running",
                    "public_host": host,
                    "public_url": c.get("public_url") or build_public_url(host),
                    "created": c.get("created"),
                }
            )
    return previews


@router.post(
    "/{project_id}/previews",
    dependencies=[Depends(require_role("admin", "developer"))],
)
async def create_project_preview(
    project_id: uuid.UUID,
    payload: PreviewCreatePayload,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cria ou atualiza um ambiente isolado de Preview para uma branch ou Pull Request."""
    project = await get_project(project_id, db)
    branch_name = (payload.branch or "").strip()
    if not branch_name:
        raise HTTPException(status_code=400, detail="Informe o nome da branch ou PR (ex: feat-login, pr-12).")

    orchestrator = DeployOrchestrator(
        docker_service=DockerService(),
        git_service=GitService(),
        db_session=db,
    )
    try:
        res = await orchestrator.deploy_preview(project, branch_name)
        security_manager.log_event(
            event_type="deploy",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/projects/{project_id}/previews",
            detail=f"Preview Deployment criado para '{project.name}' branch '{branch_name}' → {res.get('public_url')}",
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Falha ao criar Preview Deployment: {e}")


@router.delete(
    "/{project_id}/previews/{branch_slug}",
    dependencies=[Depends(require_role("admin", "developer"))],
)
async def delete_project_preview(
    project_id: uuid.UUID,
    branch_slug: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Encerra e remove um ambiente de Preview."""
    project = await get_project(project_id, db)
    clean_slug = slugify(branch_slug)[:28]
    container_name = f"deploydock_preview_{slugify(project.name)}_{clean_slug}"
    docker = DockerService()
    try:
        await docker.stop_container(container_name, timeout=8)
    except Exception:
        pass
    try:
        await docker.remove_container(container_name, force=True)
    except Exception:
        pass

    preview_repo_path = os.path.join(settings.REPOS_BASE_PATH, f"{project.id}_preview_{clean_slug}")
    if os.path.exists(preview_repo_path):
        shutil.rmtree(preview_repo_path, ignore_errors=True)

    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/previews/{branch_slug}",
        detail=f"Ambiente de Preview '{branch_slug}' encerrado em '{project.name}'",
        user=current_user.username,
    )
    return {"deleted": branch_slug}


# ----------------------------------------------------------------
# Variáveis de Ambiente (.env)
# ----------------------------------------------------------------

class EnvVarCreatePayload(_BaseModel):
    key: _Optional[str] = None
    value: _Optional[str] = None
    is_secret: bool = False
    bulk_content: _Optional[str] = None
    apply_now: bool = False


def _decrypt_if_needed(val: str, is_secret: bool) -> str:
    if is_secret and val.startswith("enc:"):
        try:
            return decrypt_value(val[4:])
        except Exception:
            return val
    return val


@router.get("/{project_id}/env")
async def list_env(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    await get_project(project_id, db)
    res = await db.execute(
        select(EnvironmentVariable)
        .where(EnvironmentVariable.project_id == project_id)
        .order_by(EnvironmentVariable.key.asc())
    )
    items = res.scalars().all()
    vars_list = [
        {
            "id": str(item.id),
            "project_id": str(item.project_id),
            "key": item.key,
            "value": _decrypt_if_needed(item.value, item.is_secret),
            "is_secret": item.is_secret,
            "created_at": item.created_at,
        }
        for item in items
    ]
    raw_lines = [f"{item.key}={_decrypt_if_needed(item.value, item.is_secret)}" for item in items]
    env_content_str = "\n".join(raw_lines)
    if env_content_str:
        env_content_str += "\n"

    return {
        "env_content": env_content_str,
        "variables": vars_list,
    }


@router.put("/{project_id}/env", dependencies=[Depends(require_role("admin", "developer"))])
async def put_env_content(
    project_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Atualiza em lote o arquivo .env com criptografia Fernet AES-128 em repouso."""
    project = await get_project(project_id, db)
    try:
        body = await request.json()
    except Exception:
        body = {}

    raw_content = body.get("env_content") or body.get("bulk_content") or ""
    pairs: list[tuple[str, str, bool]] = []
    for raw_line in raw_content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k:
            is_sec = any(s in k.lower() for s in ("secret", "key", "password", "token", "pwd", "auth", "database_url"))
            pairs.append((k, v, is_sec))

    existing_res = await db.execute(
        select(EnvironmentVariable).where(EnvironmentVariable.project_id == project_id)
    )
    existing_map = {e.key: e for e in existing_res.scalars().all()}

    for k, v, secret in pairs:
        stored_val = f"enc:{encrypt_value(v)}" if secret else v
        if k in existing_map:
            existing_map[k].value = stored_val
            existing_map[k].is_secret = secret
        else:
            db.add(
                EnvironmentVariable(
                    project_id=project_id,
                    key=k,
                    value=stored_val,
                    is_secret=secret,
                )
            )
    await db.commit()
    return {
        "status": "updated",
        "count": len(pairs),
        "env_content": raw_content,
    }


@router.post("/{project_id}/env", dependencies=[Depends(require_role("admin", "developer"))])
async def add_env(
    project_id: uuid.UUID,
    payload: EnvVarCreatePayload,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    project = await get_project(project_id, db)

    pairs: list[tuple[str, str, bool]] = []
    if payload.bulk_content and payload.bulk_content.strip():
        for raw_line in payload.bulk_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                pairs.append((k, v, payload.is_secret))
    elif payload.key and payload.key.strip():
        pairs.append((payload.key.strip(), payload.value or "", payload.is_secret))
    else:
        raise HTTPException(status_code=400, detail="Informe a chave/valor ou cole o conteúdo .env.")

    existing_res = await db.execute(
        select(EnvironmentVariable).where(EnvironmentVariable.project_id == project_id)
    )
    existing_map = {e.key: e for e in existing_res.scalars().all()}

    for k, v, secret in pairs:
        stored_val = f"enc:{encrypt_value(v)}" if secret else v
        if k in existing_map:
            existing_map[k].value = stored_val
            existing_map[k].is_secret = secret
        else:
            db.add(
                EnvironmentVariable(
                    project_id=project_id,
                    key=k,
                    value=stored_val,
                    is_secret=secret,
                )
            )

    await db.commit()
    security_manager.log_event(
        event_type="env_change",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/projects/{project_id}/env",
        detail=f"{len(pairs)} variável(is) .env atualizada(s) em '{project.name}' (Fernet AES-128 ativo)",
        user=current_user.username,
        blocked=False,
    )
    if payload.apply_now:
        background_tasks.add_task(_reapply_routing, str(project.id))

    return await list_env(project_id, db)


@router.delete("/{project_id}/env/{env_id}", dependencies=[Depends(require_role("admin", "developer"))])
async def delete_env(
    project_id: uuid.UUID,
    env_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    apply_now: bool = False,
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(EnvironmentVariable).where(
            EnvironmentVariable.id == env_id,
            EnvironmentVariable.project_id == project_id,
        )
    )
    env_obj = res.scalar_one_or_none()
    if not env_obj:
        raise HTTPException(status_code=404, detail="Variável não encontrada")
    await db.delete(env_obj)
    await db.commit()
    if apply_now:
        background_tasks.add_task(_reapply_routing, str(project_id))
    return {"message": "Deleted"}


@router.post("/{project_id}/env/apply", dependencies=[Depends(require_role("admin", "developer"))])
async def apply_env_to_container(
    project_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    project = await get_project(project_id, db)
    background_tasks.add_task(_reapply_routing, str(project.id))
    return {"message": f"Variáveis aplicadas ao contêiner de {project.name}."}
