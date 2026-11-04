"""
Orquestrador de Deploy.

Implementa o pipeline completo de deploy automático:
Webhook → Clone/Pull (com suporte a Token Git Privado) → Build → Deploy (com Quotas de CPU/RAM e Réplicas)
→ Health Check → Rollback (em caso de falha) + Notificações Multicanal + Preview Deployments.
"""

import asyncio
import logging
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.routing import build_traefik_labels, slugify
from app.core.routing import public_url as build_public_url
from app.core.security import decrypt_value
from app.models.deployment import Deployment
from app.models.project import Project
from app.services.docker_service import DockerService
from app.services.git_service import GitService
from app.services.notification_service import notification_manager
from app.services.websocket_manager import ws_manager

logger = logging.getLogger(__name__)


def _extract_git_token(project: Project) -> str | None:
    raw = getattr(project, "git_token", None)
    if raw and raw.strip():
        if raw.startswith("enc:"):
            try:
                return decrypt_value(raw[4:])
            except Exception:
                return None
        return raw.strip()
    repo_url = (getattr(project, "repo_url", "") or "").lower()
    if "github.com" in repo_url:
        try:
            from app.services.paas_service import paas_manager

            return paas_manager.get_decrypted_github_token()
        except Exception:
            return None
    return None


def _ensure_auto_dockerfile(repo_path: str, dockerfile_rel_path: str) -> None:
    """
    Auto-detecta stack (Zero-Config estilo Nixpacks/Railpack) se o repositório não tiver Dockerfile:
    HTML/Nginx, Bun, Node.js, Python (requirements.txt / pyproject.toml / Pipfile),
    Go, Rust, PHP/Laravel, Ruby/Rails, Java (Maven/Gradle) e .NET (C#).
    """
    dockerfile_full_path = os.path.join(repo_path, dockerfile_rel_path)
    if os.path.exists(dockerfile_full_path):
        return

    has_csproj = False
    try:
        has_csproj = any(f.endswith(".csproj") for f in os.listdir(repo_path))
    except Exception:
        pass

    if os.path.exists(os.path.join(repo_path, "index.html")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM nginx:alpine\n"
                "COPY . /usr/share/nginx/html\n"
                "EXPOSE 80\n"
                'CMD ["nginx", "-g", "daemon off;"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "bun.lockb")) or os.path.exists(
        os.path.join(repo_path, "bunfig.toml")
    ):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM oven/bun:1-alpine\n"
                "WORKDIR /app\n"
                "COPY . .\n"
                "RUN bun install --production\n"
                "EXPOSE 3000\n"
                'CMD ["bun", "run", "start"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "package.json")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM node:20-alpine\n"
                "WORKDIR /app\n"
                "COPY package*.json ./\n"
                "RUN npm install --production\n"
                "COPY . .\n"
                "EXPOSE 3000\n"
                'CMD ["npm", "start"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "requirements.txt")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM python:3.11-slim\n"
                "WORKDIR /app\n"
                "COPY requirements.txt .\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n"
                "COPY . .\n"
                "EXPOSE 8000\n"
                'CMD ["python", "main.py"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "pyproject.toml")) or os.path.exists(
        os.path.join(repo_path, "Pipfile")
    ):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM python:3.11-slim\n"
                "WORKDIR /app\n"
                "COPY . .\n"
                "RUN pip install --no-cache-dir .\n"
                "EXPOSE 8000\n"
                'CMD ["python", "main.py"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "go.mod")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM golang:1.22-alpine AS builder\n"
                "WORKDIR /src\n"
                "COPY go.* ./\n"
                "RUN go mod download\n"
                "COPY . .\n"
                "RUN CGO_ENABLED=0 GOOS=linux go build -o /app/server .\n"
                "FROM alpine:3.19\n"
                "WORKDIR /app\n"
                "COPY --from=builder /app/server ./server\n"
                "EXPOSE 8080\n"
                'CMD ["./server"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "Cargo.toml")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM rust:1.77-alpine AS builder\n"
                "WORKDIR /src\n"
                "COPY . .\n"
                "RUN cargo build --release\n"
                "EXPOSE 8080\n"
                'CMD ["cargo", "run", "--release"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "composer.json")) or os.path.exists(
        os.path.join(repo_path, "index.php")
    ):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM php:8.3-apache\n"
                "WORKDIR /var/www/html\n"
                "COPY . /var/www/html\n"
                "EXPOSE 80\n"
                'CMD ["apache2-foreground"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "Gemfile")):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM ruby:3.3-slim\n"
                "WORKDIR /app\n"
                "COPY Gemfile* ./\n"
                "RUN bundle install\n"
                "COPY . .\n"
                "EXPOSE 3000\n"
                'CMD ["bundle", "exec", "ruby", "app.rb"]\n'
            )
    elif os.path.exists(os.path.join(repo_path, "pom.xml")) or os.path.exists(
        os.path.join(repo_path, "build.gradle")
    ):
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM eclipse-temurin:21-jdk-alpine\n"
                "WORKDIR /app\n"
                "COPY . .\n"
                "EXPOSE 8080\n"
                'CMD ["./mvnw", "spring-boot:run"]\n'
            )
    elif has_csproj:
        with open(dockerfile_full_path, "w", encoding="utf-8") as f:
            f.write(
                "FROM mcr.microsoft.com/dotnet/sdk:8.0\n"
                "WORKDIR /app\n"
                "COPY . .\n"
                "RUN dotnet publish -c Release -o out\n"
                "EXPOSE 8080\n"
                'CMD ["dotnet", "run", "--urls", "http://0.0.0.0:8080"]\n'
            )
    else:
        raise RuntimeError(
            f"Arquivo '{dockerfile_rel_path}' não foi encontrado na raiz do repositório."
        )


class CandidateRejected(RuntimeError):
    """Candidato blue/green reprovado antes do corte de tráfego (versão antiga intacta)."""


class DeployOrchestrator:
    """Orquestra o ciclo completo de deploy, réplicas horizontais e preview environments de um projeto."""

    def __init__(
        self,
        docker_service: DockerService,
        git_service: GitService,
        db_session: AsyncSession,
    ) -> None:
        self.docker = docker_service
        self.git = git_service
        self.db = db_session

    async def deploy(self, project: Project, commit_sha: str, branch: str) -> Deployment:
        """
        Executa o pipeline de deploy completo:
        1. Cria registro de deployment
        2. Clone/Pull do repositório (suporta PAT para repositórios privados)
        3. Docker build com streaming de logs
        4. Para contêiner antigo e inicia o novo (aplicando Quotas de CPU, RAM e Réplicas Horizontais)
        5. Executa health check
        6. Em caso de falha, faz rollback automático e envia alerta
        """
        deployment = Deployment(
            project_id=project.id,
            commit_sha=commit_sha,
            branch=branch,
            status="pending",
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(deployment)
        await self.db.commit()
        await self.db.refresh(deployment)

        deploy_topic = f"deploy_{deployment.id}"
        start_time = time.monotonic()
        container_name = f"deploydock_{project.name.lower()}"
        git_token = _extract_git_token(project)

        try:
            # ── Etapa 1: Clonar / Atualizar repositório ──
            deployment.status = "cloning"
            await self.db.commit()
            await ws_manager.broadcast(deploy_topic, {"status": "cloning", "step": 1})
            logger.info(f"[Deploy {deployment.id}] Clonando {project.repo_url}@{branch}")

            repo_path = os.path.join(settings.REPOS_BASE_PATH, str(project.id))

            if os.path.exists(repo_path):
                try:
                    await self.git.pull_repo(
                        repo_path, branch, git_token=git_token, repo_url=project.repo_url
                    )
                except Exception as e:
                    logger.warning(
                        f"Git pull falhou ({e}). Tentando sincronizar com clone limpo..."
                    )
                    try:
                        shutil.rmtree(repo_path, ignore_errors=True)
                        await self.git.clone_repo(
                            project.repo_url, repo_path, branch, git_token=git_token
                        )
                    except Exception as clone_err:
                        logger.warning(
                            f"Falha ao reclonar repositório ({clone_err}). Prosseguindo com estado local."
                        )
            else:
                await self.git.clone_repo(
                    project.repo_url, repo_path, branch, git_token=git_token
                )

            try:
                commit_info = await self.git.get_current_commit(repo_path)
                deployment.commit_sha = commit_info.get("sha", commit_sha or "initial")
                deployment.commit_message = commit_info.get("message", "Deploy inicial")
                deployment.commit_author = commit_info.get("author", "DeployDock")
            except Exception:
                commit_info = {}
                deployment.commit_sha = commit_sha or "initial"
                deployment.commit_message = "Deploy manual"
                deployment.commit_author = "DeployDock"
            await self.db.commit()
            await ws_manager.broadcast(
                deploy_topic,
                {
                    "status": "cloning",
                    "step": 1,
                    "commit": commit_info,
                },
            )

            # ── Etapa 2: Docker Build ──
            deployment.status = "building"
            await self.db.commit()
            await ws_manager.broadcast(deploy_topic, {"status": "building", "step": 2})
            logger.info(f"[Deploy {deployment.id}] Construindo imagem...")

            dockerfile_rel_path = project.dockerfile_path or "Dockerfile"
            _ensure_auto_dockerfile(repo_path, dockerfile_rel_path)

            image_tag = f"deploydock-{project.name.lower()}:{deployment.commit_sha[:8]}"
            build_logs: list[str] = []

            log_queue: asyncio.Queue[str | None] = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def _build_worker():
                try:
                    for line in self.docker.build_image(
                        path=repo_path,
                        tag=image_tag,
                        dockerfile=dockerfile_rel_path,
                    ):
                        loop.call_soon_threadsafe(log_queue.put_nowait, line)
                    loop.call_soon_threadsafe(log_queue.put_nowait, None)
                except Exception as exc:
                    loop.call_soon_threadsafe(log_queue.put_nowait, f"BUILD_ERROR: {exc}")
                    loop.call_soon_threadsafe(log_queue.put_nowait, None)

            build_thread = threading.Thread(target=_build_worker, daemon=True)
            build_thread.start()

            while True:
                line = await log_queue.get()
                if line is None:
                    break
                if line.startswith("BUILD_ERROR:"):
                    raise RuntimeError(line)
                build_logs.append(line)
                await ws_manager.broadcast(deploy_topic, {"log": line, "step": 2})

            deployment.build_logs = "".join(build_logs)
            await self.db.commit()

            # ── Etapa 3: Deploy (Container Swap + Réplicas Horizontais) ──
            deployment.status = "deploying"
            await self.db.commit()
            await ws_manager.broadcast(deploy_topic, {"status": "deploying", "step": 3})
            logger.info(f"[Deploy {deployment.id}] Substituindo contêiner...")

            strategy = getattr(project, "deploy_strategy", None) or "recreate"
            if strategy == "blue_green":
                new_container = await self._swap_blue_green(
                    project, image_tag, container_name, deployment, deploy_topic
                )
            else:
                try:
                    old_container = await self.docker.get_container(container_name)
                    deployment.previous_image_id = old_container.get("image")
                    await self.db.commit()
                    await self.docker.stop_container(container_name, timeout=15)
                    await self.docker.remove_container(container_name, force=True)
                    logger.info(f"[Deploy {deployment.id}] Contêiner anterior removido.")
                except (ValueError, Exception):
                    logger.info(f"[Deploy {deployment.id}] Nenhum contêiner anterior encontrado.")

                new_container = await self._run_app_container(project, image_tag, container_name)

            # Sincronizar réplicas horizontais extras se project.replicas > 1
            target_replicas = int(getattr(project, "replicas", None) or 1)
            if target_replicas > 1:
                await self._sync_extra_replicas(project, image_tag, container_name, target_replicas)

            logger.info(
                f"[Deploy {deployment.id}] Novo contêiner iniciado: {new_container.short_id} "
                f"→ {project.public_url} (replicas={target_replicas})"
            )

            # ── Etapa 4: Health Check ──
            if project.health_check_url:
                await ws_manager.broadcast(deploy_topic, {"status": "health_check", "step": 4})
                logger.info(
                    f"[Deploy {deployment.id}] Executando health check: {project.health_check_url}"
                )

                healthy = await self._run_health_check(
                    project.health_check_url,
                    retries=settings.HEALTH_CHECK_RETRIES,
                    timeout=settings.HEALTH_CHECK_TIMEOUT,
                )
                if not healthy:
                    raise RuntimeError(
                        f"Health check falhou após {settings.HEALTH_CHECK_RETRIES} tentativas "
                        f"em {project.health_check_url}"
                    )

            # ── Sucesso ──
            deployment.status = "healthy"
            deployment.finished_at = datetime.now(timezone.utc)
            deployment.duration_seconds = round(time.monotonic() - start_time, 2)
            await self.db.commit()
            await ws_manager.broadcast(
                deploy_topic,
                {
                    "status": "healthy",
                    "step": 5,
                    "duration": deployment.duration_seconds,
                },
            )
            logger.info(
                f"[Deploy {deployment.id}] ✅ Deploy concluído em {deployment.duration_seconds}s"
            )

            try:
                await notification_manager.notify(
                    event_type="deploy_success",
                    title=f"Deploy Concluído: {project.name}",
                    message=(
                        f"O projeto **{project.name}** (`{branch}` @ `{deployment.commit_sha[:7]}`) "
                        f"foi publicado com sucesso em {deployment.duration_seconds}s.\n"
                        f"URL: {project.public_url}"
                    ),
                    severity="success",
                    metadata={
                        "project": project.name,
                        "branch": branch,
                        "commit": deployment.commit_sha[:8],
                        "duration": deployment.duration_seconds,
                        "url": project.public_url,
                    },
                )
            except Exception:
                pass

        except Exception as e:
            # ── Falha — Rollback automático ──
            logger.error(f"[Deploy {deployment.id}] ❌ Falha: {e}")

            deployment.status = "failed"
            deployment.error_message = str(e)
            deployment.finished_at = datetime.now(timezone.utc)
            deployment.duration_seconds = round(time.monotonic() - start_time, 2)
            await self.db.commit()

            if isinstance(e, CandidateRejected):
                deployment.error_message = f"{e} (versão anterior mantida no ar)"
                await self.db.commit()
            elif deployment.previous_image_id:
                try:
                    await self._perform_rollback(
                        project, deployment.previous_image_id, container_name, deploy_topic
                    )
                    deployment.status = "rolled_back"
                    await self.db.commit()
                except Exception as rollback_err:
                    logger.error(f"[Deploy {deployment.id}] Rollback também falhou: {rollback_err}")

            await ws_manager.broadcast(
                deploy_topic,
                {
                    "status": deployment.status,
                    "error": str(e),
                    "step": -1,
                },
            )

            try:
                await notification_manager.notify(
                    event_type="deploy_failure",
                    title=f"Falha no Deploy: {project.name}",
                    message=(
                        f"O deploy do projeto **{project.name}** (`{branch}`) falhou após "
                        f"{deployment.duration_seconds}s.\n"
                        f"Status final: `{deployment.status}`\n"
                        f"Erro: {str(e)[:250]}"
                    ),
                    severity="error",
                    metadata={
                        "project": project.name,
                        "branch": branch,
                        "status": deployment.status,
                        "error": str(e),
                    },
                )
            except Exception:
                pass

        return deployment

    # ----------------------------------------------------------------
    # Escalonamento Horizontal (Réplicas Multi-Contêiner com Traefik LB)
    # ----------------------------------------------------------------

    async def _sync_extra_replicas(
        self,
        project: Project,
        image: str,
        base_container_name: str,
        target_replicas: int,
    ) -> list[str]:
        """
        Garante que as réplicas extras `deploydock_<name>_r2` .. `deploydock_<name>_r{N}`
        estejam em execução com as mesmas labels do Traefik (Load Balancing automático)
        e remove réplicas excedentes.
        """
        active_names = [base_container_name]
        for idx in range(2, max(1, target_replicas) + 1):
            r_name = f"{base_container_name}_r{idx}"
            await self._discard_container(r_name)
            try:
                await self._run_app_container(
                    project,
                    image,
                    r_name,
                    extra_labels={
                        "deploydock.replica": str(idx),
                        "deploydock.project_name": project.name,
                    },
                )
                active_names.append(r_name)
            except Exception as exc:
                logger.warning(f"[Scale] Falha ao iniciar réplica {r_name}: {exc}")

        # Remover réplicas excedentes (ex: se escalou de 4 para 2)
        for idx in range(max(1, target_replicas) + 1, 11):
            r_name = f"{base_container_name}_r{idx}"
            await self._discard_container(r_name)

        return active_names

    async def scale_project(self, project: Project, target_replicas: int) -> dict[str, Any]:
        """Escala horizontalmente o número de réplicas de um projeto em execução."""
        replicas = max(1, min(10, int(target_replicas)))
        base_container_name = f"deploydock_{project.name.lower()}"
        image_tag = f"deploydock-{project.name.lower()}:latest"
        try:
            current = await self.docker.get_container(base_container_name)
            image_tag = current.get("image") or image_tag
        except Exception:
            pass

        active_containers = await self._sync_extra_replicas(
            project, image_tag, base_container_name, replicas
        )
        return {
            "project_id": str(project.id),
            "project_name": project.name,
            "replicas": replicas,
            "containers": active_containers,
            "load_balancer_url": project.public_url,
        }

    # ----------------------------------------------------------------
    # Preview Deployments por Branch / Pull Request (Feature 5)
    # ----------------------------------------------------------------

    async def deploy_preview(self, project: Project, branch_name: str) -> dict[str, Any]:
        """
        Cria ou atualiza um ambiente isolado de Preview para uma branch ou Pull Request.
        Gera URL exclusiva: <branch>-<subdomain>.<APPS_BASE_DOMAIN>
        """
        branch_slug = slugify(branch_name)[:28] or "preview"
        preview_sub = f"{branch_slug}-{project.subdomain or slugify(project.name)}"[:63]
        preview_host = f"{preview_sub}.{settings.APPS_BASE_DOMAIN}"
        preview_url = build_public_url(preview_host)
        container_name = f"deploydock_preview_{slugify(project.name)}_{branch_slug}"
        image_tag = f"deploydock-preview-{slugify(project.name)}:{branch_slug}"
        git_token = _extract_git_token(project)

        base_repo_path = os.path.join(settings.REPOS_BASE_PATH, str(project.id))
        preview_repo_path = os.path.join(
            settings.REPOS_BASE_PATH, f"{project.id}_preview_{branch_slug}"
        )

        # Clonar ou copiar do repositório principal
        if os.path.exists(base_repo_path) and (
            not project.repo_url.startswith(("http://", "https://"))
            or os.path.abspath(project.repo_url) == os.path.abspath(base_repo_path)
        ):
            if os.path.exists(preview_repo_path):
                shutil.rmtree(preview_repo_path, ignore_errors=True)
            await asyncio.to_thread(shutil.copytree, base_repo_path, preview_repo_path)
            commit_sha = "preview"
        else:
            if os.path.exists(preview_repo_path):
                try:
                    commit_sha = await self.git.pull_repo(
                        preview_repo_path,
                        branch_name,
                        git_token=git_token,
                        repo_url=project.repo_url,
                    )
                except Exception:
                    try:
                        shutil.rmtree(preview_repo_path, ignore_errors=True)
                        commit_sha = await self.git.clone_repo(
                            project.repo_url,
                            preview_repo_path,
                            branch=branch_name,
                            git_token=git_token,
                        )
                    except Exception:
                        commit_sha = "preview"
            else:
                try:
                    commit_sha = await self.git.clone_repo(
                        project.repo_url,
                        preview_repo_path,
                        branch=branch_name,
                        git_token=git_token,
                    )
                except Exception:
                    if os.path.exists(base_repo_path):
                        await asyncio.to_thread(
                            shutil.copytree, base_repo_path, preview_repo_path
                        )
                    else:
                        await self.git.clone_repo(
                            project.repo_url,
                            preview_repo_path,
                            branch=project.branch,
                            git_token=git_token,
                        )
                    commit_sha = "preview"

        dockerfile_rel_path = project.dockerfile_path or "Dockerfile"
        _ensure_auto_dockerfile(preview_repo_path, dockerfile_rel_path)

        def _build_sync():
            for _ in self.docker.build_image(
                path=preview_repo_path,
                tag=image_tag,
                dockerfile=dockerfile_rel_path,
            ):
                pass

        await asyncio.to_thread(_build_sync)

        # Remover preview anterior da mesma branch se existir
        try:
            await self.docker.stop_container(container_name, timeout=8)
            await self.docker.remove_container(container_name, force=True)
        except Exception:
            pass

        extra_labels = {
            "deploydock.preview": "true",
            "deploydock.preview_branch": branch_name,
            "deploydock.preview_slug": branch_slug,
            "deploydock.project_name": project.name,
        }
        c = await self._run_app_container(
            project,
            image_tag,
            container_name,
            custom_host=preview_host,
            extra_labels=extra_labels,
        )
        return {
            "container_id": c.short_id,
            "container_name": container_name,
            "project_id": str(project.id),
            "project_name": project.name,
            "branch": branch_name,
            "branch_slug": branch_slug,
            "commit_sha": commit_sha[:8],
            "public_host": preview_host,
            "public_url": preview_url,
            "status": "running",
        }

    async def rollback(self, deployment_id: str, db: AsyncSession) -> Deployment:
        """Rollback manual para a versão anterior de um deployment."""
        result = await db.execute(
            select(Deployment).where(Deployment.id == deployment_id)
        )
        deployment = result.scalar_one_or_none()
        if not deployment:
            raise ValueError(f"Deployment '{deployment_id}' não encontrado.")

        if not deployment.previous_image_id:
            raise ValueError("Sem imagem anterior disponível para rollback.")

        project_result = await db.execute(
            select(Project).where(Project.id == deployment.project_id)
        )
        project = project_result.scalar_one()

        container_name = f"deploydock_{project.name.lower()}"
        deploy_topic = f"deploy_{deployment.id}"

        await self._perform_rollback(
            project, deployment.previous_image_id, container_name, deploy_topic
        )

        deployment.status = "rolled_back"
        await db.commit()
        return deployment

    async def _perform_rollback(
        self, project: Project, previous_image: str, container_name: str, topic: str
    ) -> None:
        """Executa o rollback: para contêiner atual e reinicia com imagem anterior."""
        logger.info(f"[Rollback] Revertendo para imagem: {previous_image}")
        await ws_manager.broadcast(topic, {"status": "rolling_back"})

        try:
            await self.docker.stop_container(container_name, timeout=10)
            await self.docker.remove_container(container_name, force=True)
        except Exception:
            pass

        await self._run_app_container(project, previous_image, container_name)

        await ws_manager.broadcast(topic, {"status": "rolled_back"})
        logger.info("[Rollback] ✅ Rollback concluído com sucesso.")

    async def _run_app_container(
        self,
        project: Project,
        image: str,
        container_name: str,
        custom_host: str | None = None,
        extra_labels: dict[str, str] | None = None,
    ):
        """
        Inicia o contêiner da aplicação já registrado no proxy reverso (Traefik):
        conectado à rede compartilhada, com variáveis de ambiente do projeto,
        limites de CPU/RAM (Quotas), hardening de segurança e labels de roteamento.
        """
        from app.core.waf import security_manager
        from app.models.environment import EnvironmentVariable

        env_vars: dict[str, str] = {}
        try:
            env_res = await self.db.execute(
                select(EnvironmentVariable).where(EnvironmentVariable.project_id == project.id)
            )
            for item in env_res.scalars().all():
                val = item.value
                if item.is_secret and val.startswith("enc:"):
                    try:
                        val = decrypt_value(val[4:])
                    except Exception:
                        pass
                env_vars[item.key] = val
        except Exception:
            pass

        def _run():
            self.docker.ensure_network(settings.APPS_NETWORK)
            port = project.container_port
            if not port:
                exposed = self.docker.get_image_exposed_ports(image)
                port = exposed[0] if exposed else 80

            target_host = custom_host or project.public_host
            router_id = (
                f"{project.id}-{extra_labels.get('deploydock.preview_slug', '')}"
                if extra_labels and "deploydock.preview_slug" in extra_labels
                else str(project.id)
            )
            labels = build_traefik_labels(router_id, target_host, port)
            if extra_labels:
                labels.update(extra_labels)

            sec_opts = (
                ["no-new-privileges:true"]
                if security_manager.config.get("container_no_new_privileges", True)
                else None
            )

            run_kwargs: dict[str, Any] = {
                "name": container_name,
                "detach": True,
                "restart_policy": {"Name": "unless-stopped"},
                "publish_all_ports": True,
                "network": settings.APPS_NETWORK,
                "labels": labels,
                "environment": env_vars if env_vars else None,
                "security_opt": sec_opts,
                "pids_limit": 256,
            }

            # Quotas de Recursos (CPU & RAM) configuradas no projeto
            mem_mb = getattr(project, "memory_limit_mb", None)
            if mem_mb and int(mem_mb) >= 32:
                run_kwargs["mem_limit"] = f"{int(mem_mb)}m"

            cpu_cores = getattr(project, "cpu_limit_cores", None)
            if cpu_cores and float(cpu_cores) > 0:
                run_kwargs["cpu_period"] = 100000
                run_kwargs["cpu_quota"] = int(float(cpu_cores) * 100000)

            return self.docker.client.containers.run(image, **run_kwargs)

        return await asyncio.to_thread(_run)

    # ----------------------------------------------------------------
    # Estratégia Blue/Green (sobreposição sem janela de indisponibilidade)
    # ----------------------------------------------------------------

    async def _swap_blue_green(
        self,
        project: Project,
        image_tag: str,
        container_name: str,
        deployment: Deployment,
        deploy_topic: str,
    ):
        """
        Troca de versão sem derrubar a anterior antes da hora:

        1. sobe o candidato com um nome temporário e as MESMAS labels do Traefik (o proxy passa a
           balancear entre a versão antiga e a nova, pois o serviço é identificado pela label);
        2. valida o candidato (health check pela rede interna ou estabilidade em execução);
        3. se reprovado, descarta o candidato e mantém a versão antiga (`CandidateRejected`);
        4. se aprovado, aguarda o período de drenagem, remove a versão antiga e renomeia o candidato.
        """
        has_old = False
        try:
            old_container = await self.docker.get_container(container_name)
            deployment.previous_image_id = old_container.get("image")
            await self.db.commit()
            has_old = True
        except (ValueError, Exception):
            logger.info(f"[Deploy {deployment.id}] Nenhum contêiner anterior; blue/green sem sobreposição.")

        candidate_name = f"{container_name}-bg-{str(deployment.id)[:8]}"
        await self._discard_container(candidate_name)

        await ws_manager.broadcast(deploy_topic, {"status": "deploying", "step": 3, "strategy": "blue_green"})
        candidate = await self._run_app_container(project, image_tag, candidate_name)
        logger.info(f"[Deploy {deployment.id}] Candidato blue/green iniciado: {candidate_name}")

        try:
            await self._wait_candidate_ready(project, image_tag, candidate_name)
        except Exception as exc:
            await self._discard_container(candidate_name)
            raise CandidateRejected(f"Candidato blue/green reprovado: {exc}") from exc

        if has_old:
            await asyncio.sleep(settings.BLUE_GREEN_DRAIN_SECONDS)
            try:
                await self.docker.stop_container(container_name, timeout=15)
            except Exception as exc:
                logger.warning(f"[Deploy {deployment.id}] Falha ao parar versão anterior: {exc}")
            await self.docker.remove_container(container_name, force=True)
            logger.info(f"[Deploy {deployment.id}] Versão anterior removida após corte blue/green.")

        await self.docker.rename_container(candidate_name, container_name)
        return candidate

    async def _discard_container(self, name: str) -> None:
        """Remove um contêiner (ignora se não existir)."""
        try:
            await self.docker.remove_container(name, force=True)
        except Exception:
            pass

    async def _wait_candidate_ready(self, project: Project, image: str, name: str) -> None:
        """Valida o candidato; levanta RuntimeError se ele não estiver saudável."""
        if project.health_check_url:
            port = await asyncio.to_thread(self._resolve_port, project, image)
            parsed = urlparse(project.health_check_url)
            path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
            internal_url = f"http://{name}:{port}{path}"
            healthy = await self._run_health_check(
                internal_url,
                retries=settings.HEALTH_CHECK_RETRIES,
                timeout=settings.HEALTH_CHECK_TIMEOUT,
            )
            if not healthy:
                raise RuntimeError(f"health check interno falhou em {internal_url}")
        else:
            await asyncio.sleep(settings.BLUE_GREEN_MIN_UPTIME_SECONDS)

        info = await self.docker.get_container(name)
        if info.get("status") != "running":
            raise RuntimeError(f"contêiner candidato não está em execução (status={info.get('status')})")

    def _resolve_port(self, project: Project, image: str) -> int:
        port = project.container_port
        if not port:
            exposed = self.docker.get_image_exposed_ports(image)
            port = exposed[0] if exposed else 80
        return port

    async def apply_routing(self, project: Project) -> bool:
        """
        Reaplica a URL pública, limites de CPU/RAM e variáveis de ambiente de um projeto
        já implantado recriando o contêiner com a mesma imagem.
        """
        container_name = f"deploydock_{project.name.lower()}"
        try:
            current = await asyncio.to_thread(self.docker.client.containers.get, container_name)
        except Exception:
            return False

        image = current.image.id
        await self.docker.stop_container(container_name, timeout=10)
        await self.docker.remove_container(container_name, force=True)
        await self._run_app_container(project, image, container_name)
        target_replicas = int(getattr(project, "replicas", None) or 1)
        if target_replicas > 1:
            await self._sync_extra_replicas(project, image, container_name, target_replicas)
        logger.info(f"[Routing/Env] {project.name} atualizado em {project.public_url}")
        return True

    async def _run_health_check(self, url: str, retries: int, timeout: int) -> bool:
        """
        Verifica se o serviço está respondendo com status 200.
        Tenta `retries` vezes com intervalo de 3 segundos.
        """
        async with httpx.AsyncClient(timeout=timeout) as client:
            for attempt in range(1, retries + 1):
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        logger.info(f"[Health Check] ✅ Tentativa {attempt}: OK")
                        return True
                    logger.warning(
                        f"[Health Check] Tentativa {attempt}: status {response.status_code}"
                    )
                except Exception as e:
                    logger.warning(f"[Health Check] Tentativa {attempt}: {e}")
                await asyncio.sleep(3)
        return False
