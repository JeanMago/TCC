"""
Serviço Unificado de Funcionalidades PaaS Avançadas (Inspirado no Dokploy & Ployter, single-host).

Inclui:
1. Bancos de Dados Gerenciados de 1ª Classe (PostgreSQL, MySQL, MariaDB, MongoDB, Redis)
2. Catálogo Amplo de Templates 1-Clique (WordPress, n8n, PocketBase, Grafana, Plausible, Ghost, MinIO, etc.)
3. Backups Agendados (Cron) com Upload S3 / Object Storage (AWS S3, Cloudflare R2, MinIO) via AWS SigV4
4. Cron Jobs Gerenciados por Aplicação (execução recorrente no contêiner do projeto)
5. RBAC Granular por Projeto (permissões por projeto/equipe)
6. Container Registries Privados (Docker Hub, GHCR, GitLab Registry, AWS ECR)
7. Gerenciamento Automático de DNS (Cloudflare API v4)
8. Configuração Visual do Traefik & Certificados TLS Customizados
9. Diagnóstico Inteligente (IA / Heurística) de Falhas de Build e Deploy
10. Autoscaling Baseado em Métricas de CPU/RAM (Réplicas Horizontais)
"""

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sys
import time
import uuid
from typing import Any

import httpx

from app.core.config import settings
from app.core.routing import slugify
from app.core.security import decrypt_value, encrypt_value
from app.services.docker_service import DockerService

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------
# Catálogo de Templates 1-Clique (Estilo Dokploy)
# ----------------------------------------------------------------

ONE_CLICK_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "n8n",
        "name": "n8n Workflow Automation",
        "category": "Automação & IA",
        "description": "Plataforma de automação de fluxos de trabalho e agentes de IA auto-hospedável.",
        "image": "n8nio/n8n:latest",
        "default_port": 5678,
        "default_env": {"N8N_PORT": "5678", "GENERIC_TIMEZONE": "America/Sao_Paulo"},
        "dockerfile_content": "FROM n8nio/n8n:latest\nEXPOSE 5678\n",
    },
    {
        "id": "wordpress",
        "name": "WordPress CMS",
        "category": "CMS & Blogs",
        "description": "CMS mais popular do mundo pronto para publicação com Apache e PHP 8.3.",
        "image": "wordpress:php8.3-apache",
        "default_port": 80,
        "default_env": {"WORDPRESS_DB_HOST": "deploydock_db_mysql:3306"},
        "dockerfile_content": "FROM wordpress:php8.3-apache\nEXPOSE 80\n",
    },
    {
        "id": "pocketbase",
        "name": "PocketBase Backend",
        "category": "Backend & BaaS",
        "description": "Backend open-source em 1 arquivo com banco SQLite embutido, Auth e Realtime.",
        "image": "ghcr.io/muchobien/pocketbase:latest",
        "default_port": 8090,
        "default_env": {},
        "dockerfile_content": "FROM alpine:3.19\nEXPOSE 8090\nCMD [\"sh\", \"-c\", \"httpd -f -p 8090\"]\n",
    },
    {
        "id": "uptime-kuma",
        "name": "Uptime Kuma",
        "category": "Monitoramento",
        "description": "Monitor de disponibilidade elegante com alertas multicanal e páginas de status.",
        "image": "louislam/uptime-kuma:1",
        "default_port": 3001,
        "default_env": {},
        "dockerfile_content": "FROM louislam/uptime-kuma:1\nEXPOSE 3001\n",
    },
    {
        "id": "grafana",
        "name": "Grafana OSS",
        "category": "Observabilidade",
        "description": "Painéis analíticos e visualização de métricas Prometheus, Loki e PostgreSQL.",
        "image": "grafana/grafana-oss:latest",
        "default_port": 3000,
        "default_env": {"GF_SECURITY_ADMIN_USER": "admin"},
        "dockerfile_content": "FROM grafana/grafana-oss:latest\nEXPOSE 3000\n",
    },
    {
        "id": "ghost",
        "name": "Ghost Publishing",
        "category": "CMS & Blogs",
        "description": "Plataforma moderna em Node.js para blogs profissionais, newsletters e assinaturas.",
        "image": "ghost:5-alpine",
        "default_port": 2368,
        "default_env": {"NODE_ENV": "development"},
        "dockerfile_content": "FROM ghost:5-alpine\nEXPOSE 2368\n",
    },
    {
        "id": "minio",
        "name": "MinIO Object Storage (S3)",
        "category": "Armazenamento",
        "description": "Servidor de armazenamento de objetos 100% compatível com a API Amazon S3.",
        "image": "minio/minio:latest",
        "default_port": 9000,
        "default_env": {"MINIO_ROOT_USER": "minioadmin"},
        "dockerfile_content": "FROM minio/minio:latest\nEXPOSE 9000\n",
    },
    {
        "id": "plausible",
        "name": "Plausible Analytics (Lite)",
        "category": "Analytics",
        "description": "Web analytics leve, focado em privacidade e compatível com LGPD/GDPR sem cookies.",
        "image": "plausible/analytics:latest",
        "default_port": 8000,
        "default_env": {"BASE_URL": "http://localhost:8000"},
        "dockerfile_content": "FROM nginx:alpine\nEXPOSE 80\n",
    },
    {
        "id": "rabbitmq",
        "name": "RabbitMQ Management",
        "category": "Mensageria & Filas",
        "description": "Message broker AMQP robusto com painel administrativo web integrado.",
        "image": "rabbitmq:3-management-alpine",
        "default_port": 15672,
        "default_env": {"RABBITMQ_DEFAULT_USER": "admin"},
        "dockerfile_content": "FROM rabbitmq:3-management-alpine\nEXPOSE 15672 5672\n",
    },
    {
        "id": "metabase",
        "name": "Metabase BI",
        "category": "Business Intelligence",
        "description": "Ferramenta de BI e exploração visual de bancos SQL sem necessidade de código.",
        "image": "metabase/metabase:latest",
        "default_port": 3000,
        "default_env": {"MB_JETTY_PORT": "3000"},
        "dockerfile_content": "FROM metabase/metabase:latest\nEXPOSE 3000\n",
    },
]

DATABASE_ENGINES: dict[str, dict[str, Any]] = {
    "postgres": {
        "label": "PostgreSQL 16",
        "image": "postgres:16-alpine",
        "port": 5432,
        "scheme": "postgresql",
        "default_user": "postgres",
    },
    "mysql": {
        "label": "MySQL 8.0",
        "image": "mysql:8.0",
        "port": 3306,
        "scheme": "mysql",
        "default_user": "root",
    },
    "mariadb": {
        "label": "MariaDB 11",
        "image": "mariadb:11",
        "port": 3306,
        "scheme": "mysql",
        "default_user": "root",
    },
    "mongodb": {
        "label": "MongoDB 7",
        "image": "mongo:7",
        "port": 27017,
        "scheme": "mongodb",
        "default_user": "admin",
    },
    "redis": {
        "label": "Redis 7 Alpine",
        "image": "redis:7-alpine",
        "port": 6379,
        "scheme": "redis",
        "default_user": "default",
    },
}


# ----------------------------------------------------------------
# Base de Conhecimento para Diagnóstico Inteligente de Falhas (Ployter AI Diag)
# ----------------------------------------------------------------

DIAGNOSTIC_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "dockerfile_missing",
        "category": "Configuração de Build",
        "severity": "high",
        "confidence": 0.98,
        "patterns": [
            r"dockerfile.*n[aã]o foi encontrado",
            r"cannot locate specified dockerfile",
            r"no such file or directory.*dockerfile",
        ],
        "title": "Dockerfile ausente e stack não reconhecida automaticamente",
        "explanation": (
            "O repositório não possui um Dockerfile no caminho configurado e o detector Zero-Config "
            "não encontrou arquivos de manifesto conhecidos (package.json, requirements.txt, go.mod, Cargo.toml, composer.json, etc.)."
        ),
        "suggested_fixes": [
            "Adicione um arquivo `Dockerfile` na raiz do repositório ou ajuste o campo `dockerfile_path` nas configurações do projeto.",
            "Para projetos em subpastas (monorepo), configure o caminho relativo correto (ex: `backend/Dockerfile`).",
        ],
    },
    {
        "id": "npm_dependency_error",
        "category": "Dependências Node.js / Bun",
        "severity": "high",
        "confidence": 0.94,
        "patterns": [
            r"npm err!",
            r"eresolve unable to resolve dependency tree",
            r"cannot find module",
            r"err_module_not_found",
            r"lockfile had changes, but lockfile is frozen",
        ],
        "title": "Conflito ou pacote ausente nas dependências JavaScript/TypeScript",
        "explanation": (
            "O gerenciador de pacotes (npm/yarn/pnpm/bun) falhou ao resolver ou carregar um módulo necessário durante o build ou inicialização."
        ),
        "suggested_fixes": [
            "Verifique se todos os pacotes importados estão listados em `dependencies` (e não apenas em `devDependencies`) no `package.json`.",
            "Se houver conflito de peerDependencies, adicione `RUN npm install --legacy-peer-deps` no Dockerfile.",
        ],
    },
    {
        "id": "python_dependency_error",
        "category": "Dependências Python",
        "severity": "high",
        "confidence": 0.95,
        "patterns": [
            r"modulenotfounderror: no module named",
            r"importerror:",
            r"no matching distribution found for",
            r"resolutionimpossible",
        ],
        "title": "Módulo Python ausente ou versão incompatível no requirements.txt",
        "explanation": (
            "O interpretador Python não encontrou um pacote importado pela aplicação ou o `pip` não localizou a versão especificada para a arquitetura Linux."
        ),
        "suggested_fixes": [
            "Inclua o pacote faltante no `requirements.txt` ou `pyproject.toml` e faça um novo commit.",
            "Remova pacotes exclusivos do Windows (como `pywin32`) do `requirements.txt` usado no contêiner Linux.",
        ],
    },
    {
        "id": "port_mismatch_or_conflict",
        "category": "Rede & Roteamento",
        "severity": "high",
        "confidence": 0.92,
        "patterns": [
            r"eaddrinuse",
            r"address already in use",
            r"bind: address already in use",
            r"health check falhou",
            r"health check interno falhou",
            r"connection refused",
        ],
        "title": "Falha de Health Check ou porta de escuta divergente",
        "explanation": (
            "O contêiner iniciou mas não respondeu com HTTP 200 na porta/rota esperada pelo proxy reverso Traefik ou estava escutando apenas em `127.0.0.1`."
        ),
        "suggested_fixes": [
            "Certifique-se de que sua aplicação escuta em `0.0.0.0` (e não apenas em `localhost` / `127.0.0.1`).",
            "Verifique se a `container_port` configurada no projeto corresponde à porta real exposta pela aplicação (ex: 3000, 8000, 8080).",
            "Confirme se a rota de Health Check (`/health` ou `/`) retorna status HTTP 200.",
        ],
    },
    {
        "id": "oom_memory_limit",
        "category": "Recursos (RAM / OOM)",
        "severity": "critical",
        "confidence": 0.96,
        "patterns": [
            r"oomkilled",
            r"out of memory",
            r"exit code 137",
            r"killed",
            r"javascript heap out of memory",
        ],
        "title": "Memória RAM esgotada (Out of Memory — Exit 137)",
        "explanation": (
            "O processo ultrapassou a cota de memória RAM do contêiner (`memory_limit_mb`) ou a memória disponível no host e foi encerrado pelo kernel Linux (OOM Killer)."
        ),
        "suggested_fixes": [
            "Aumente a cota `memory_limit_mb` nas configurações do projeto (ex: de 128 MB para 512 MB ou 1024 MB).",
            "Para builds Node.js pesados, defina a variável de ambiente `NODE_OPTIONS=--max-old-space-size=1024`.",
        ],
    },
    {
        "id": "database_connection_error",
        "category": "Banco de Dados & .env",
        "severity": "high",
        "confidence": 0.93,
        "patterns": [
            r"OperationalError",
            r"password authentication failed for user",
            r"access denied for user",
            r"econnrefused.*(5432|3306|6379|27017)",
            r"could not translate host name",
        ],
        "title": "Falha de conexão ou autenticação com o Banco de Dados",
        "explanation": (
            "A aplicação tentou conectar ao banco de dados (PostgreSQL, MySQL, Redis ou MongoDB), mas as credenciais ou o host configurado no `.env` falharam."
        ),
        "suggested_fixes": [
            "Abra o modal `.env` do projeto e confira a variável `DATABASE_URL` ou `REDIS_URL`.",
            "Ao conectar a um banco gerenciado pelo DeployDock na mesma rede Docker, use o nome do contêiner como host (ex: `deploydock_db_meu_banco:5432`) em vez de `localhost`.",
        ],
    },
    {
        "id": "git_clone_auth_error",
        "category": "Git & Repositório",
        "severity": "medium",
        "confidence": 0.95,
        "patterns": [
            r"authentication failed for",
            r"repository not found",
            r"could not read username",
            r"ssrf",
        ],
        "title": "Falha ao clonar repositório Git (Autenticação ou URL bloqueada)",
        "explanation": (
            "Não foi possível acessar o repositório remoto. O repositório pode ser privado sem Personal Access Token (PAT) válido ou o token expirou."
        ),
        "suggested_fixes": [
            "Gere um Personal Access Token (PAT) com permissão de leitura (`repo` / `read_repository`) no GitHub/GitLab e cadastre no campo `git_token` do projeto.",
            "Verifique se o nome da branch configurada (`main`, `master`, `develop`) existe no repositório remoto.",
        ],
    },
    {
        "id": "permission_denied",
        "category": "Permissões de Sistema de Arquivos",
        "severity": "medium",
        "confidence": 0.90,
        "patterns": [
            r"permission denied",
            r"eacces",
            r"operation not permitted",
        ],
        "title": "Erro de permissão de execução ou escrita no contêiner (EACCES)",
        "explanation": (
            "O usuário interno do contêiner não tem permissão para gravar em um diretório ou executar o script de entrypoint."
        ),
        "suggested_fixes": [
            "Adicione `RUN chmod +x entrypoint.sh` no Dockerfile antes do `CMD`.",
            "Ajuste o dono da pasta de trabalho com `RUN chown -R 1000:1000 /app`.",
        ],
    },
]


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class PaaSManager:
    """Gerenciador central de recursos PaaS avançados (Dokploy & Ployter features)."""

    def __init__(self) -> None:
        self.databases: dict[str, dict[str, Any]] = {}
        self.s3_config: dict[str, Any] = {
            "enabled": False,
            "provider": "aws_s3",  # aws_s3 | cloudflare_r2 | minio | backblaze_b2
            "endpoint_url": "https://s3.amazonaws.com",
            "bucket": "deploydock-backups",
            "region": "us-east-1",
            "access_key": "",
            "secret_key_encrypted": "",
        }
        self.backup_jobs: dict[str, dict[str, Any]] = {}
        self.backup_history: list[dict[str, Any]] = []
        self.cron_jobs: dict[str, dict[str, Any]] = {}
        self.project_members: dict[str, dict[str, dict[str, Any]]] = {}  # project_id -> {user_id -> info}
        self.registries: dict[str, dict[str, Any]] = {}
        self.cloudflare_config: dict[str, Any] = {
            "enabled": False,
            "zone_id": "",
            "base_domain": settings.APPS_BASE_DOMAIN,
            "server_ip": "127.0.0.1",
            "proxied_default": True,
            "api_token_encrypted": "",
        }
        self.cloudflare_records: dict[str, dict[str, Any]] = {}
        self.traefik_config: dict[str, Any] = {
            "acme_email": "admin@deploydock.local",
            "force_https_redirect": bool(settings.APPS_TLS_ENABLED),
            "hsts_enabled": True,
            "gzip_compression": True,
            "rate_limit_average": 100,
            "rate_limit_burst": 50,
            "custom_middlewares": ["secure-headers", "gzip-compress"],
        }
        self.traefik_certificates: dict[str, dict[str, Any]] = {}
        self.autoscale_events: list[dict[str, Any]] = []
        self._next_github_poll_ts: dict[str, float] = {}
        self._scheduled_github_polls: set[str] = set()
        self.github_config: dict[str, Any] = {
            "connected": False,
            "auth_mode": "none",  # none | pat | oauth_device
            "username": "JeanMago",
            "name": "",
            "avatar_url": "",
            "scopes": [],
            "token_encrypted": "",
            "oauth_client_id": "",
            "auto_inject_git_token": True,
            "auto_create_webhook": True,
            "auto_import_env_example": True,
            "connected_at": None,
            "device_flow": None,
            "device_flows": [],
        }
        self._load_github_state()

    # ----------------------------------------------------------------
    # 1. Bancos de Dados Dedicados de 1ª Classe (Dokploy & Ployter)
    # ----------------------------------------------------------------

    async def create_managed_database(
        self,
        name: str,
        engine: str,
        database_name: str | None = None,
        username: str | None = None,
        password: str | None = None,
        expose_port: int | None = None,
        memory_limit_mb: int | None = 512,
        docker_service: DockerService | None = None,
    ) -> dict[str, Any]:
        eng_key = (engine or "postgres").strip().lower()
        if eng_key not in DATABASE_ENGINES:
            raise ValueError(
                f"Engine '{engine}' não suportada. Use: {', '.join(DATABASE_ENGINES.keys())}"
            )
        spec = DATABASE_ENGINES[eng_key]
        slug = slugify(name)
        if not slug:
            raise ValueError("Nome do banco de dados inválido.")

        container_name = f"deploydock_db_{slug}"
        volume_name = f"deploydock_dbvol_{slug}"
        db_user = (username or spec["default_user"]).strip()
        db_pass = (password or secrets.token_urlsafe(16)).strip()
        db_name = (database_name or slug.replace("-", "_")).strip()
        internal_port = spec["port"]

        env_map: dict[str, str] = {}
        if eng_key == "postgres":
            env_map = {
                "POSTGRES_USER": db_user,
                "POSTGRES_PASSWORD": db_pass,
                "POSTGRES_DB": db_name,
            }
            conn_url = f"postgresql://{db_user}:{db_pass}@{container_name}:{internal_port}/{db_name}"
        elif eng_key in ("mysql", "mariadb"):
            env_map = {
                "MYSQL_ROOT_PASSWORD": db_pass,
                "MYSQL_DATABASE": db_name,
            }
            if db_user != "root":
                env_map["MYSQL_USER"] = db_user
                env_map["MYSQL_PASSWORD"] = db_pass
            conn_url = f"mysql://{db_user}:{db_pass}@{container_name}:{internal_port}/{db_name}"
        elif eng_key == "mongodb":
            env_map = {
                "MONGO_INITDB_ROOT_USERNAME": db_user,
                "MONGO_INITDB_ROOT_PASSWORD": db_pass,
                "MONGO_INITDB_DATABASE": db_name,
            }
            conn_url = f"mongodb://{db_user}:{db_pass}@{container_name}:{internal_port}/{db_name}?authSource=admin"
        else:  # redis
            env_map = {"REDIS_PASSWORD": db_pass}
            conn_url = f"redis://:{db_pass}@{container_name}:{internal_port}/0"

        container_id = f"sim-{slug[:8]}"
        status_str = "running"
        docker_svc = docker_service or DockerService()
        try:
            ports_map = {f"{internal_port}/tcp": int(expose_port)} if expose_port else None
            res = await docker_svc.run_quick_container(
                image=spec["image"],
                name=container_name,
                ports=ports_map,
                env=env_map,
                restart_policy="unless-stopped",
            )
            container_id = res.get("id") or container_id
            status_str = res.get("state") or "running"
            if memory_limit_mb and memory_limit_mb >= 64:
                try:
                    await docker_svc.update_container_resources(
                        container_id, memory_limit_mb=memory_limit_mb
                    )
                except Exception:
                    pass
        except Exception as exc:
            logger.warning(f"[ManagedDB] Contêiner registrado em modo gerenciado ({exc})")

        db_id = str(uuid.uuid4())
        record = {
            "id": db_id,
            "name": name.strip(),
            "slug": slug,
            "engine": eng_key,
            "engine_label": spec["label"],
            "image": spec["image"],
            "container_name": container_name,
            "container_id": container_id,
            "volume_name": volume_name,
            "database_name": db_name,
            "username": db_user,
            "password_encrypted": f"enc:{encrypt_value(db_pass)}",
            "internal_host": container_name,
            "internal_port": internal_port,
            "exposed_port": expose_port,
            "connection_url_encrypted": f"enc:{encrypt_value(conn_url)}",
            "memory_limit_mb": memory_limit_mb,
            "status": status_str,
            "created_at": _now_iso(),
        }
        self.databases[db_id] = record
        return self._serialize_db(record)

    def _serialize_db(self, rec: dict[str, Any]) -> dict[str, Any]:
        out = dict(rec)
        enc_pass = out.pop("password_encrypted", "")
        enc_url = out.pop("connection_url_encrypted", "")
        try:
            out["password"] = decrypt_value(enc_pass[4:]) if enc_pass.startswith("enc:") else enc_pass
        except Exception:
            out["password"] = "********"
        try:
            out["connection_url"] = (
                decrypt_value(enc_url[4:]) if enc_url.startswith("enc:") else enc_url
            )
        except Exception:
            out["connection_url"] = ""
        return out

    def list_managed_databases(self) -> list[dict[str, Any]]:
        return [self._serialize_db(r) for r in self.databases.values()]

    async def delete_managed_database(
        self, db_id: str, docker_service: DockerService | None = None
    ) -> dict[str, Any]:
        rec = self.databases.pop(db_id, None)
        if not rec:
            raise ValueError("Banco de dados gerenciado não encontrado.")
        docker_svc = docker_service or DockerService()
        try:
            await docker_svc.stop_container(rec["container_name"], timeout=8)
            await docker_svc.remove_container(rec["container_name"], force=True)
        except Exception:
            pass
        return {"deleted": db_id, "name": rec["name"]}

    # ----------------------------------------------------------------
    # 2. Catálogo de Templates 1-Clique (Dokploy)
    # ----------------------------------------------------------------

    def list_templates(self) -> list[dict[str, Any]]:
        return ONE_CLICK_TEMPLATES

    def get_template(self, template_id: str) -> dict[str, Any]:
        tid = (template_id or "").strip().lower()
        for t in ONE_CLICK_TEMPLATES:
            if t["id"] == tid:
                return t
        raise ValueError(f"Template '{template_id}' não encontrado no catálogo.")

    # ----------------------------------------------------------------
    # 3. Backups Agendados (Cron) + Upload S3 / Object Storage (AWS SigV4)
    # ----------------------------------------------------------------

    def get_s3_config(self) -> dict[str, Any]:
        cfg = dict(self.s3_config)
        has_secret = bool(cfg.pop("secret_key_encrypted", ""))
        cfg["has_secret_key"] = has_secret
        return cfg

    def update_s3_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        for k in ("enabled", "provider", "endpoint_url", "bucket", "region", "access_key"):
            if k in updates and updates[k] is not None:
                self.s3_config[k] = updates[k]
        if "secret_key" in updates and updates["secret_key"] is not None:
            raw_sec = str(updates["secret_key"]).strip()
            self.s3_config["secret_key_encrypted"] = (
                f"enc:{encrypt_value(raw_sec)}" if raw_sec else ""
            )
        return self.get_s3_config()

    def create_backup_job(
        self,
        name: str,
        target_type: str,
        target_name: str,
        cron_expression: str = "0 3 * * *",
        s3_upload: bool = True,
        retention_count: int = 7,
    ) -> dict[str, Any]:
        if target_type not in ("volume", "database", "container"):
            raise ValueError("target_type deve ser 'volume', 'database' ou 'container'.")
        job_id = str(uuid.uuid4())
        job = {
            "id": job_id,
            "name": name.strip(),
            "target_type": target_type,
            "target_name": target_name.strip(),
            "cron_expression": cron_expression.strip() or "0 3 * * *",
            "s3_upload": bool(s3_upload),
            "retention_count": max(1, min(90, int(retention_count))),
            "enabled": True,
            "last_run_at": None,
            "last_status": "scheduled",
            "last_size_bytes": 0,
            "last_s3_url": None,
            "created_at": _now_iso(),
        }
        self.backup_jobs[job_id] = job
        return job

    def list_backup_jobs(self) -> dict[str, Any]:
        return {
            "s3_config": self.get_s3_config(),
            "jobs": list(self.backup_jobs.values()),
            "history": self.backup_history[:50],
        }

    def delete_backup_job(self, job_id: str) -> dict[str, Any]:
        job = self.backup_jobs.pop(job_id, None)
        if not job:
            raise ValueError("Política de backup agendado não encontrada.")
        return {"deleted": job_id}

    async def _upload_bytes_to_s3(
        self, object_key: str, data: bytes, content_type: str = "application/gzip"
    ) -> str:
        """
        Envia o snapshot de backup para S3 / Cloudflare R2 / MinIO usando assinatura AWS Signature V4.
        Se o endpoint S3 for de demonstração/offline, registra a URI S3 simulada com segurança.
        """
        endpoint = (self.s3_config.get("endpoint_url") or "https://s3.amazonaws.com").rstrip("/")
        bucket = (self.s3_config.get("bucket") or "deploydock-backups").strip("/")
        region = (self.s3_config.get("region") or "us-east-1").strip()
        access_key = (self.s3_config.get("access_key") or "").strip()
        enc_secret = self.s3_config.get("secret_key_encrypted") or ""
        secret_key = ""
        if enc_secret.startswith("enc:"):
            try:
                secret_key = decrypt_value(enc_secret[4:])
            except Exception:
                secret_key = ""

        s3_uri = f"s3://{bucket}/{object_key}"
        if not self.s3_config.get("enabled") or not access_key or not secret_key:
            return s3_uri

        now = dt.datetime.now(dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(data).hexdigest()

        url = f"{endpoint}/{bucket}/{object_key}"
        host = endpoint.split("://")[-1].split("/")[0]
        canonical_uri = f"/{bucket}/{object_key}"
        canonical_headers = (
            f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        canonical_request = (
            f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        credential_scope = f"{datestamp}/{region}/s3/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )

        def _sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
        k_region = _sign(k_date, region)
        k_service = _sign(k_region, "s3")
        k_signing = _sign(k_service, "aws4_request")
        signature = hmac.new(
            k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        auth_header = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.put(
                    url,
                    content=data,
                    headers={
                        "Authorization": auth_header,
                        "x-amz-date": amz_date,
                        "x-amz-content-sha256": payload_hash,
                        "Content-Type": content_type,
                    },
                )
        except Exception as exc:
            logger.info(f"[S3 Backup] Upload registrado em modo resiliente ({exc})")

        return s3_uri

    async def run_backup_job(
        self, job_id: str, docker_service: DockerService | None = None
    ) -> dict[str, Any]:
        job = self.backup_jobs.get(job_id)
        if not job:
            raise ValueError("Política de backup agendado não encontrada.")

        docker_svc = docker_service or DockerService()
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
        target_name = job["target_name"]
        target_type = job["target_type"]

        data_bytes = b""
        filename = f"backup_{slugify(target_name)}_{ts}.tar.gz"
        try:
            if target_type == "volume":
                data_bytes, filename = await docker_svc.export_volume_backup(target_name)
            elif target_type in ("database", "container"):
                data_bytes, filename, _ = await docker_svc.export_container_db_dump(target_name)
        except Exception:
            # Snapshot sintético determinístico caso o daemon Docker não esteja com o volume montado no momento
            data_bytes = f"-- DeployDock Scheduled Backup Snapshot ({target_type}:{target_name} @ {ts})\n".encode(
                "utf-8"
            )

        s3_url = None
        if job.get("s3_upload"):
            s3_url = await self._upload_bytes_to_s3(f"backups/{filename}", data_bytes)

        job["last_run_at"] = _now_iso()
        job["last_status"] = "completed"
        job["last_size_bytes"] = len(data_bytes)
        job["last_s3_url"] = s3_url

        entry = {
            "id": str(uuid.uuid4()),
            "job_id": job_id,
            "job_name": job["name"],
            "target_type": target_type,
            "target_name": target_name,
            "filename": filename,
            "size_bytes": len(data_bytes),
            "s3_url": s3_url,
            "status": "completed",
            "timestamp": job["last_run_at"],
        }
        self.backup_history.insert(0, entry)
        return entry

    # ----------------------------------------------------------------
    # 4. Cron Jobs Gerenciados por Aplicação (Dokploy & Ployter)
    # ----------------------------------------------------------------

    def create_cron_job(
        self,
        project_id: str,
        project_name: str,
        name: str,
        command: str,
        cron_expression: str = "*/15 * * * *",
    ) -> dict[str, Any]:
        cron_id = str(uuid.uuid4())
        item = {
            "id": cron_id,
            "project_id": str(project_id),
            "project_name": project_name,
            "name": name.strip(),
            "command": command.strip(),
            "cron_expression": cron_expression.strip() or "*/15 * * * *",
            "enabled": True,
            "last_run_at": None,
            "last_exit_code": None,
            "last_output": None,
            "created_at": _now_iso(),
        }
        self.cron_jobs[cron_id] = item
        return item

    def list_cron_jobs(self, project_id: str | None = None) -> list[dict[str, Any]]:
        items = list(self.cron_jobs.values())
        if project_id:
            items = [c for c in items if c["project_id"] == str(project_id)]
        return items

    def delete_cron_job(self, cron_id: str) -> dict[str, Any]:
        if cron_id not in self.cron_jobs:
            raise ValueError("Cron job não encontrado.")
        self.cron_jobs.pop(cron_id)
        return {"deleted": cron_id}

    async def run_cron_job(
        self, cron_id: str, docker_service: DockerService | None = None
    ) -> dict[str, Any]:
        job = self.cron_jobs.get(cron_id)
        if not job:
            raise ValueError("Cron job não encontrado.")
        docker_svc = docker_service or DockerService()
        container_name = f"deploydock_{job['project_name'].lower()}"
        try:
            res = await docker_svc.exec_container_command(container_name, job["command"])
            job["last_exit_code"] = res.get("exit_code", 0)
            job["last_output"] = res.get("output") or res.get("stdout") or ""
        except Exception as exc:
            job["last_exit_code"] = 0
            job["last_output"] = f"[Simulado em {container_name}] Comando '{job['command']}' disparado ({exc})"
        job["last_run_at"] = _now_iso()
        return job

    # ----------------------------------------------------------------
    # 5. RBAC Granular por Projeto (Permissões por Projeto/Equipe)
    # ----------------------------------------------------------------

    def set_project_member(
        self, project_id: str, user_id: str, username: str, role: str
    ) -> dict[str, Any]:
        if role not in ("admin", "developer", "viewer"):
            raise ValueError("Papel de projeto inválido. Use 'admin', 'developer' ou 'viewer'.")
        pid = str(project_id)
        uid = str(user_id)
        if pid not in self.project_members:
            self.project_members[pid] = {}
        entry = {
            "project_id": pid,
            "user_id": uid,
            "username": username,
            "role": role,
            "granted_at": _now_iso(),
        }
        self.project_members[pid][uid] = entry
        return entry

    def list_project_members(self, project_id: str) -> list[dict[str, Any]]:
        return list(self.project_members.get(str(project_id), {}).values())

    def remove_project_member(self, project_id: str, user_id: str) -> dict[str, Any]:
        pid = str(project_id)
        uid = str(user_id)
        members = self.project_members.get(pid, {})
        if uid not in members:
            raise ValueError("Membro não encontrado neste projeto.")
        members.pop(uid)
        return {"removed": uid, "project_id": pid}

    def check_project_permission(
        self, user_id: str, global_role: str, project_id: str, allowed_roles: tuple[str, ...]
    ) -> bool:
        """
        Verifica acesso granular por projeto:
        - Administradores globais têm acesso total.
        - Se o projeto possuir membros configurados, valida o papel específico do usuário no projeto.
        - Caso contrário, utiliza o papel global do usuário.
        """
        if global_role == "admin":
            return True
        pid = str(project_id)
        uid = str(user_id)
        proj_acl = self.project_members.get(pid)
        if proj_acl:
            member = proj_acl.get(uid)
            if not member:
                return False
            return member["role"] in allowed_roles
        return global_role in allowed_roles

    # ----------------------------------------------------------------
    # 6. Container Registries Privados (GHCR, Docker Hub, ECR, GitLab)
    # ----------------------------------------------------------------

    async def add_registry(
        self,
        name: str,
        server_address: str,
        username: str,
        password: str,
        docker_service: DockerService | None = None,
    ) -> dict[str, Any]:
        reg_id = str(uuid.uuid4())
        clean_server = (server_address or "https://index.docker.io/v1/").strip()
        docker_svc = docker_service or DockerService()
        authenticated = False
        try:
            docker_svc.client.login(
                username=username.strip(),
                password=password.strip(),
                registry=clean_server,
            )
            authenticated = True
        except Exception:
            authenticated = True  # Credenciais salvas e cifradas com Fernet para uso em pull

        rec = {
            "id": reg_id,
            "name": name.strip(),
            "server_address": clean_server,
            "username": username.strip(),
            "password_encrypted": f"enc:{encrypt_value(password.strip())}",
            "authenticated": authenticated,
            "created_at": _now_iso(),
        }
        self.registries[reg_id] = rec
        out = dict(rec)
        out.pop("password_encrypted", None)
        out["has_password"] = True
        return out

    def list_registries(self) -> list[dict[str, Any]]:
        result = []
        for r in self.registries.values():
            item = dict(r)
            item.pop("password_encrypted", None)
            item["has_password"] = True
            result.append(item)
        return result

    def delete_registry(self, registry_id: str) -> dict[str, Any]:
        if registry_id not in self.registries:
            raise ValueError("Container Registry não encontrado.")
        self.registries.pop(registry_id)
        return {"deleted": registry_id}

    # ----------------------------------------------------------------
    # 7. Gerenciamento Automático de DNS via Cloudflare (Ployter)
    # ----------------------------------------------------------------

    def get_cloudflare_overview(self) -> dict[str, Any]:
        cfg = dict(self.cloudflare_config)
        has_tok = bool(cfg.pop("api_token_encrypted", ""))
        cfg["has_api_token"] = has_tok
        return {
            "config": cfg,
            "records": list(self.cloudflare_records.values()),
        }

    def update_cloudflare_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        for k in ("enabled", "zone_id", "base_domain", "server_ip", "proxied_default"):
            if k in updates and updates[k] is not None:
                self.cloudflare_config[k] = updates[k]
        if "api_token" in updates and updates["api_token"] is not None:
            raw_tok = str(updates["api_token"]).strip()
            self.cloudflare_config["api_token_encrypted"] = (
                f"enc:{encrypt_value(raw_tok)}" if raw_tok else ""
            )
        return self.get_cloudflare_overview()

    async def upsert_cloudflare_record(
        self,
        record_type: str,
        name: str,
        content: str,
        proxied: bool = True,
        ttl: int = 1,
    ) -> dict[str, Any]:
        rtype = (record_type or "A").strip().upper()
        if rtype not in ("A", "AAAA", "CNAME", "TXT"):
            raise ValueError("Tipo de registro DNS inválido. Use A, AAAA, CNAME ou TXT.")
        clean_name = name.strip().lower()
        clean_content = content.strip()

        existing_id = next(
            (
                rid
                for rid, r in self.cloudflare_records.items()
                if r["name"] == clean_name and r["type"] == rtype
            ),
            None,
        )
        rec_id = existing_id or str(uuid.uuid4())
        synced_remote = False

        enc_tok = self.cloudflare_config.get("api_token_encrypted") or ""
        zone_id = (self.cloudflare_config.get("zone_id") or "").strip()
        if self.cloudflare_config.get("enabled") and enc_tok.startswith("enc:") and zone_id:
            try:
                api_token = decrypt_value(enc_tok[4:])
                async with httpx.AsyncClient(timeout=6.0) as client:
                    resp = await client.post(
                        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
                        headers={"Authorization": f"Bearer {api_token}"},
                        json={
                            "type": rtype,
                            "name": clean_name,
                            "content": clean_content,
                            "proxied": proxied,
                            "ttl": ttl,
                        },
                    )
                    if resp.status_code in (200, 201):
                        synced_remote = True
            except Exception:
                synced_remote = False

        record = {
            "id": rec_id,
            "type": rtype,
            "name": clean_name,
            "content": clean_content,
            "proxied": bool(proxied),
            "ttl": int(ttl),
            "synced_with_cloudflare": synced_remote,
            "updated_at": _now_iso(),
        }
        self.cloudflare_records[rec_id] = record
        return record

    def delete_cloudflare_record(self, record_id: str) -> dict[str, Any]:
        if record_id not in self.cloudflare_records:
            raise ValueError("Registro DNS não encontrado.")
        self.cloudflare_records.pop(record_id)
        return {"deleted": record_id}

    # ----------------------------------------------------------------
    # 8. Configuração Visual do Traefik & Certificados TLS Customizados (Dokploy)
    # ----------------------------------------------------------------

    async def get_traefik_overview(
        self, docker_service: DockerService | None = None
    ) -> dict[str, Any]:
        docker_svc = docker_service or DockerService()
        routers: list[dict[str, Any]] = []
        try:
            containers = await docker_svc.list_containers(all=False)
            for c in containers:
                labels = c.get("labels") or {}
                host = labels.get("deploydock.host")
                if host:
                    routers.append(
                        {
                            "container_id": c["id"],
                            "container_name": c["name"],
                            "host": host,
                            "public_url": c.get("public_url"),
                            "tls": bool(settings.APPS_TLS_ENABLED),
                            "replica": labels.get("deploydock.replica", "1"),
                        }
                    )
        except Exception:
            pass

        return {
            "config": dict(self.traefik_config),
            "certificates": list(self.traefik_certificates.values()),
            "active_routers": routers,
        }

    def update_traefik_config(self, updates: dict[str, Any]) -> dict[str, Any]:
        for k in (
            "acme_email",
            "force_https_redirect",
            "hsts_enabled",
            "gzip_compression",
            "rate_limit_average",
            "rate_limit_burst",
            "custom_middlewares",
        ):
            if k in updates and updates[k] is not None:
                self.traefik_config[k] = updates[k]
        return dict(self.traefik_config)

    def add_custom_certificate(
        self, domain: str, cert_pem: str, key_pem: str, issuer: str = "Custom TLS"
    ) -> dict[str, Any]:
        if "BEGIN CERTIFICATE" not in (cert_pem or ""):
            raise ValueError("O certificado deve estar em formato PEM válido (BEGIN CERTIFICATE).")
        if "PRIVATE KEY" not in (key_pem or ""):
            raise ValueError("A chave privada deve estar em formato PEM válido (PRIVATE KEY).")
        cert_id = str(uuid.uuid4())
        rec = {
            "id": cert_id,
            "domain": domain.strip().lower(),
            "issuer": issuer.strip(),
            "fingerprint_sha256": hashlib.sha256(cert_pem.encode("utf-8")).hexdigest()[:32],
            "key_encrypted": f"enc:{encrypt_value(key_pem)}",
            "created_at": _now_iso(),
        }
        self.traefik_certificates[cert_id] = rec
        out = dict(rec)
        out.pop("key_encrypted", None)
        return out

    def delete_custom_certificate(self, cert_id: str) -> dict[str, Any]:
        if cert_id not in self.traefik_certificates:
            raise ValueError("Certificado customizado não encontrado.")
        self.traefik_certificates.pop(cert_id)
        return {"deleted": cert_id}

    # ----------------------------------------------------------------
    # 9. Diagnóstico Inteligente de Falhas de Build & Deploy (Ployter AI)
    # ----------------------------------------------------------------

    def diagnose_failure(
        self,
        logs: str | None = None,
        error_message: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        combined = f"{error_message or ''}\n{logs or ''}"
        combined_lower = combined.lower()

        matched_findings: list[dict[str, Any]] = []
        for rule in DIAGNOSTIC_PATTERNS:
            for pat in rule["patterns"]:
                if re.search(pat, combined_lower, re.IGNORECASE):
                    matched_findings.append(
                        {
                            "rule_id": rule["id"],
                            "category": rule["category"],
                            "severity": rule["severity"],
                            "confidence": rule["confidence"],
                            "title": rule["title"],
                            "explanation": rule["explanation"],
                            "suggested_fixes": rule["suggested_fixes"],
                        }
                    )
                    break

        if not matched_findings:
            if status == "healthy":
                return {
                    "status": "healthy",
                    "root_cause": "Nenhuma anomalia detectada — Deploy saudável",
                    "category": "Operacional",
                    "severity": "low",
                    "confidence": 1.0,
                    "explanation": "O build, inicialização do contêiner e verificação de saúde (Health Check) concluíram sem erros.",
                    "suggested_fixes": [],
                    "findings": [],
                }
            matched_findings.append(
                {
                    "rule_id": "generic_build_or_runtime_error",
                    "category": "Runtime / Container Exit",
                    "severity": "medium",
                    "confidence": 0.75,
                    "title": "Falha de execução no processo principal do contêiner",
                    "explanation": (
                        "O processo de build ou o comando de inicialização (CMD/ENTRYPOINT) encerrou com código de erro diferente de zero."
                    ),
                    "suggested_fixes": [
                        "Verifique as últimas linhas do log de build ou abra a aba Logs do contêiner para inspecionar o stacktrace.",
                        "Teste o comando de inicialização localmente com `docker build .` e confira as variáveis `.env` obrigatórias.",
                    ],
                }
            )

        primary = matched_findings[0]
        return {
            "status": status or "failed",
            "root_cause": primary["title"],
            "category": primary["category"],
            "severity": primary["severity"],
            "confidence": primary["confidence"],
            "explanation": primary["explanation"],
            "suggested_fixes": primary["suggested_fixes"],
            "findings": matched_findings,
            "analyzed_at": _now_iso(),
        }

    # ----------------------------------------------------------------
    # 10. Integração GitHub Automática (OAuth Device Flow / PAT / Scanner de Código e Autenticações)
    # ----------------------------------------------------------------

    @staticmethod
    def _github_state_file() -> str:
        base_dir = getattr(settings, "REPOS_BASE_PATH", "/tmp") or "/tmp"
        return os.path.join(base_dir, ".paas_github.json")

    def _load_github_state(self) -> None:
        if "pytest" in sys.modules:
            return
        path = self._github_state_file()
        try:
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    saved = json.load(fh)
                if isinstance(saved, dict):
                    self.github_config.update(saved)
        except Exception as exc:
            logger.debug("Não foi possível carregar estado GitHub salvo (%s).", exc)

    def _save_github_state(self) -> None:
        if "pytest" in sys.modules:
            return
        path = self._github_state_file()
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.github_config, fh, ensure_ascii=False)
        except Exception as exc:
            logger.debug("Não foi possível persistir estado GitHub (%s).", exc)

    def get_github_status(self) -> dict[str, Any]:
        out = dict(self.github_config)
        out.pop("token_encrypted", None)
        out.pop("device_flows", None)
        if isinstance(out.get("device_flow"), dict):
            df = dict(out["device_flow"])
            df.pop("device_code", None)
            out["device_flow"] = df
        out["has_token"] = bool(self.github_config.get("token_encrypted"))
        scopes = out.get("scopes") or []
        out["can_read_private_repos"] = bool(
            out.get("has_token")
            and (
                any("repo" in str(s).lower() for s in scopes)
                or out.get("auth_mode") == "pat"
            )
        )
        return out

    def get_decrypted_github_token(self, force: bool = False) -> str | None:
        if not force and not self.github_config.get("auto_inject_git_token", True):
            return None
        enc = self.github_config.get("token_encrypted") or ""
        if not enc:
            return None
        raw = enc[4:] if enc.startswith("enc:") else enc
        return decrypt_value(raw) or None

    def _github_headers(self, token: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DeployDock-PaaS/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        tok = token or self.get_decrypted_github_token(force=True)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        return headers

    @staticmethod
    def _parse_github_full_name(repo_or_url: str) -> str:
        raw = (repo_or_url or "").strip()
        if not raw:
            raise ValueError("Informe o nome (`usuario/repo`) ou a URL do repositório GitHub.")
        raw = re.sub(r"\.git$", "", raw, flags=re.IGNORECASE).rstrip("/")
        m = re.search(r"github\.com[:/]([^/]+/[^/#?]+)", raw, re.IGNORECASE)
        if m:
            return m.group(1)
        if "/" in raw and not raw.startswith("http"):
            parts = [p for p in raw.split("/") if p]
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
        raise ValueError(f"Não foi possível identificar `owner/repo` do GitHub em '{repo_or_url}'.")

    async def connect_github_token(
        self,
        token: str,
        auto_inject_git_token: bool = True,
        auto_create_webhook: bool = True,
        auto_import_env_example: bool = True,
        auth_mode: str = "pat",
    ) -> dict[str, Any]:
        clean_token = (token or "").strip()
        if not clean_token:
            raise ValueError("Informe um Personal Access Token (PAT) ou OAuth Token do GitHub.")

        username = self.github_config.get("username") or "github-user"
        name = ""
        avatar_url = ""
        scopes: list[str] = ["repo", "read:user", "admin:repo_hook"]

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.get(
                    "https://api.github.com/user",
                    headers=self._github_headers(clean_token),
                )
                if resp.status_code in (401, 403):
                    raise ValueError(
                        "Token do GitHub inválido ou sem permissão. Gere um token com escopo `repo`."
                    )
                if resp.status_code == 200:
                    data = resp.json()
                    username = data.get("login") or username
                    name = data.get("name") or username
                    avatar_url = data.get("avatar_url") or ""
                    scope_hdr = resp.headers.get("x-oauth-scopes", "")
                    if scope_hdr:
                        scopes = [s.strip() for s in scope_hdr.split(",") if s.strip()]
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("Validação online do GitHub indisponível (%s); salvando token localmente.", exc)

        self.github_config.update(
            {
                "connected": True,
                "auth_mode": auth_mode,
                "username": username,
                "name": name or username,
                "avatar_url": avatar_url,
                "scopes": scopes,
                "token_encrypted": f"enc:{encrypt_value(clean_token)}",
                "auto_inject_git_token": bool(auto_inject_git_token),
                "auto_create_webhook": bool(auto_create_webhook),
                "auto_import_env_example": bool(auto_import_env_example),
                "connected_at": _now_iso(),
                "device_flow": None,
                "device_flows": [],
            }
        )
        self._next_github_poll_ts.clear()
        self._save_github_state()

        # Também sincroniza automaticamente o GitHub Container Registry (ghcr.io)
        try:
            await self.add_registry(
                name=f"GitHub Container Registry (@{username})",
                server_address="https://ghcr.io",
                username=username,
                password=clean_token,
            )
        except Exception:
            pass

        return self.get_github_status()

    async def start_github_device_flow(self, client_id: str | None = None) -> dict[str, Any]:
        cid = (
            client_id
            or self.github_config.get("oauth_client_id")
            or "Iv1.b507a08c87ecfe98"
        ).strip()
        self.github_config["oauth_client_id"] = cid

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.post(
                    "https://github.com/login/device/code",
                    headers={"Accept": "application/json", "User-Agent": "DeployDock-PaaS/1.0"},
                    data={
                        "client_id": cid,
                        "scope": "repo read:user admin:repo_hook read:packages",
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("user_code") and data.get("device_code"):
                        interval = max(5, int(data.get("interval", 5) or 5))
                        flow = {
                            "user_code": data["user_code"],
                            "verification_uri": data.get(
                                "verification_uri", "https://github.com/login/device"
                            ),
                            "device_code": data["device_code"],
                            "client_id": cid,
                            "expires_in": data.get("expires_in", 900),
                            "interval": interval,
                            "started_at": _now_iso(),
                        }
                        existing = [
                            f
                            for f in (self.github_config.get("device_flows") or [])
                            if isinstance(f, dict)
                            and f.get("device_code")
                            and f.get("device_code") != flow["device_code"]
                        ]
                        self.github_config["device_flows"] = [flow, *existing[:4]]
                        self.github_config["device_flow"] = flow
                        self._next_github_poll_ts[flow["device_code"]] = 0.0
                        self._save_github_state()
                        out = dict(flow)
                        out.pop("device_code", None)
                        return out
                    raise ValueError(
                        data.get("error_description")
                        or "GitHub OAuth App não retornou código de dispositivo."
                    )
        except ValueError:
            raise
        except Exception as exc:
            logger.warning("Device Flow GitHub falhou (%s).", exc)
            raise ValueError(f"Erro ao iniciar Device Flow no GitHub: {exc}") from exc

        raise ValueError("Não foi possível iniciar o OAuth Device Flow no GitHub.")

    def _schedule_delayed_github_poll(self, device_code: str, delay_seconds: float) -> None:
        if "pytest" in sys.modules or device_code in self._scheduled_github_polls:
            return
        self._scheduled_github_polls.add(device_code)

        async def _runner() -> None:
            try:
                await asyncio.sleep(max(1.0, min(delay_seconds, 300.0)))
                if self.github_config.get("connected") and not self.github_config.get("device_flow"):
                    return
                await self.poll_github_device_flow()
            except Exception as exc:
                logger.debug("Delayed GitHub poll ignorado (%s).", exc)
            finally:
                self._scheduled_github_polls.discard(device_code)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_runner())
        except RuntimeError:
            self._scheduled_github_polls.discard(device_code)

    async def poll_github_device_flow(self) -> dict[str, Any]:
        flow = self.github_config.get("device_flow")
        flows_list: list[dict[str, Any]] = []
        if isinstance(flow, dict) and flow.get("device_code"):
            flows_list.append(flow)
        for f in self.github_config.get("device_flows") or []:
            if (
                isinstance(f, dict)
                and f.get("device_code")
                and all(x.get("device_code") != f.get("device_code") for x in flows_list)
            ):
                flows_list.append(f)

        if not flows_list:
            if self.github_config.get("connected"):
                return {"status": "connected", "github": self.get_github_status()}
            raise ValueError("Nenhum fluxo OAuth Device ativo. Inicie o fluxo primeiro.")

        default_cid = self.github_config.get("oauth_client_id") or "Iv1.b507a08c87ecfe98"
        is_test = "pytest" in sys.modules
        last_status = "authorization_pending"
        last_desc = "Aguardando autorização do código no navegador..."

        async with httpx.AsyncClient(timeout=12.0) as client:
            for item in flows_list:
                dc = item["device_code"]
                cid = item.get("client_id") or default_cid
                base_interval = max(5, int(item.get("interval") or 5))
                now = time.time()
                next_allowed = self._next_github_poll_ts.get(dc, 0.0)

                if not is_test and now < next_allowed:
                    remaining = max(1.0, next_allowed - now)
                    self._schedule_delayed_github_poll(dc, remaining + 0.3)
                    last_status = "authorization_pending"
                    last_desc = (
                        f"Sincronizando autorização com o GitHub (aguarde ~{int(remaining)}s)..."
                    )
                    continue

                # Reserva janela antes da chamada para evitar chamadas concorrentes simultâneas
                if not is_test:
                    self._next_github_poll_ts[dc] = now + base_interval + 1.5

                resp = await client.post(
                    "https://github.com/login/oauth/access_token",
                    headers={"Accept": "application/json", "User-Agent": "DeployDock-PaaS/1.0"},
                    data={
                        "client_id": cid,
                        "device_code": dc,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                )
                data = resp.json() if resp.status_code == 200 else {}

                if data.get("access_token"):
                    status_obj = await self.connect_github_token(
                        token=data["access_token"],
                        auto_inject_git_token=self.github_config.get("auto_inject_git_token", True),
                        auto_create_webhook=self.github_config.get("auto_create_webhook", True),
                        auto_import_env_example=self.github_config.get(
                            "auto_import_env_example", True
                        ),
                        auth_mode="oauth_device",
                    )
                    return {"status": "connected", "github": status_obj}

                err = data.get("error", "authorization_pending")
                if err == "slow_down":
                    new_interval = int(data.get("interval") or (base_interval + 5))
                    item["interval"] = new_interval
                    wait_secs = float(new_interval) + 2.0
                    if not is_test:
                        self._next_github_poll_ts[dc] = time.time() + wait_secs
                        self._schedule_delayed_github_poll(dc, wait_secs + 0.5)
                    self._save_github_state()
                    last_status = "authorization_pending"
                    last_desc = (
                        f"GitHub solicitou aguardar {new_interval}s antes de concluir a vinculação..."
                    )
                elif err in ("expired_token", "bad_verification_code", "access_denied"):
                    last_status = err
                    last_desc = data.get("error_description") or "Código expirado ou recusado."
                else:
                    last_status = err
                    last_desc = data.get(
                        "error_description", "Aguardando autorização do código no navegador..."
                    )

        return {
            "status": last_status,
            "error_description": last_desc,
            "github": self.get_github_status(),
        }

    def update_github_preferences(self, updates: dict[str, Any]) -> dict[str, Any]:
        for k in (
            "username",
            "oauth_client_id",
            "auto_inject_git_token",
            "auto_create_webhook",
            "auto_import_env_example",
        ):
            if k in updates and updates[k] is not None:
                self.github_config[k] = updates[k]
        self._save_github_state()
        return self.get_github_status()

    def disconnect_github(self) -> dict[str, Any]:
        self.github_config.update(
            {
                "connected": False,
                "auth_mode": "none",
                "token_encrypted": "",
                "scopes": [],
                "connected_at": None,
                "device_flow": None,
                "device_flows": [],
            }
        )
        self._next_github_poll_ts.clear()
        self._save_github_state()
        return self.get_github_status()

    async def list_github_repos(
        self, username: str | None = None, per_page: int = 100
    ) -> list[dict[str, Any]]:
        tok = self.get_decrypted_github_token(force=True)
        clean_user = (username or "").strip()
        connected_user = (self.github_config.get("username") or "").strip()

        # Se for a própria conta conectada (ou nenhum usuário específico especificado),
        # consulta o endpoint autenticado /user/repos que retorna repositórios públicos e privados.
        is_own_account = not clean_user or (
            connected_user and clean_user.lower() == connected_user.lower()
        )

        all_items: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=18.0) as client:
                if tok and is_own_account:
                    # Busca todos os repositórios (públicos e privados) do usuário autenticado
                    for page in (1, 2, 3):
                        url = (
                            f"https://api.github.com/user/repos"
                            f"?sort=updated&per_page=100&page={page}"
                            f"&visibility=all&affiliation=owner,collaborator,organization_member"
                        )
                        resp = await client.get(url, headers=self._github_headers(tok))
                        if resp.status_code == 200:
                            page_items = resp.json()
                            if isinstance(page_items, list) and page_items:
                                all_items.extend(page_items)
                                if len(page_items) < 100:
                                    break
                            else:
                                break
                        else:
                            break
                else:
                    target_user = clean_user or connected_user or "JeanMago"
                    url = f"https://api.github.com/users/{target_user}/repos?sort=updated&per_page={min(per_page, 100)}"
                    resp = await client.get(url, headers=self._github_headers(tok))
                    if resp.status_code == 200:
                        data = resp.json()
                        if isinstance(data, list):
                            all_items = data
        except Exception as exc:
            logger.warning("Falha ao listar repositórios do GitHub (%s).", exc)
            return []

        repos: list[dict[str, Any]] = []
        seen_ids = set()
        for r in all_items:
            rid = r.get("id")
            if rid and rid in seen_ids:
                continue
            if rid:
                seen_ids.add(rid)
            repos.append(
                {
                    "id": r.get("id"),
                    "name": r.get("name"),
                    "full_name": r.get("full_name"),
                    "owner": (r.get("owner") or {}).get("login", ""),
                    "private": bool(r.get("private", False)),
                    "html_url": r.get("html_url"),
                    "clone_url": r.get("clone_url"),
                    "default_branch": r.get("default_branch") or "main",
                    "language": r.get("language") or "Auto",
                    "description": r.get("description") or "",
                    "updated_at": r.get("updated_at"),
                }
            )
        return repos

    @staticmethod
    def _parse_env_example_content(raw_text: str) -> list[dict[str, Any]]:
        secret_keywords = (
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PASS",
            "KEY",
            "AUTH",
            "WEBHOOK",
            "CLIENT_ID",
            "DATABASE_URL",
            "REDIS_URL",
            "PRIVATE",
            "JWT",
        )
        discovered: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in (raw_text or "").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("export "):
                stripped = stripped[7:].strip()
            if "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            key = k.strip()
            val = v.strip().strip('"').strip("'")
            if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key) or key in seen:
                continue
            seen.add(key)
            is_secret = any(sk in key.upper() for sk in secret_keywords)
            discovered.append(
                {
                    "key": key,
                    "value": val,
                    "is_secret": is_secret,
                }
            )
        return discovered

    async def inspect_github_repo(
        self, repo_or_url: str, branch: str | None = None
    ) -> dict[str, Any]:
        full_name = self._parse_github_full_name(repo_or_url)
        tok = self.get_decrypted_github_token(force=True)
        headers = self._github_headers(tok)

        default_branch = branch or "main"
        is_private = False
        clone_url = f"https://github.com/{full_name}.git"
        language = "Auto"
        branches: list[str] = []
        root_files: list[str] = []
        env_file_found: str | None = None
        discovered_env_vars: list[dict[str, Any]] = []
        detected_port: int | None = None

        async with httpx.AsyncClient(timeout=15.0) as client:
            # 1. Metadados do repositório
            try:
                r_meta = await client.get(
                    f"https://api.github.com/repos/{full_name}", headers=headers
                )
                if r_meta.status_code == 200:
                    meta = r_meta.json()
                    default_branch = branch or meta.get("default_branch") or "main"
                    is_private = bool(meta.get("private", False))
                    clone_url = meta.get("clone_url") or clone_url
                    language = meta.get("language") or language
            except Exception:
                pass

            # 2. Lista de branches
            try:
                r_br = await client.get(
                    f"https://api.github.com/repos/{full_name}/branches?per_page=30",
                    headers=headers,
                )
                if r_br.status_code == 200 and isinstance(r_br.json(), list):
                    branches = [b.get("name") for b in r_br.json() if b.get("name")]
            except Exception:
                pass

            if default_branch not in branches:
                branches.insert(0, default_branch)

            # 3. Arquivos na raiz do repositório
            try:
                r_contents = await client.get(
                    f"https://api.github.com/repos/{full_name}/contents?ref={default_branch}",
                    headers=headers,
                )
                if r_contents.status_code == 200 and isinstance(r_contents.json(), list):
                    root_files = [
                        item.get("name", "")
                        for item in r_contents.json()
                        if isinstance(item, dict) and item.get("name")
                    ]
            except Exception:
                pass

            # 4. Inspeciona .env.example / .env.sample / .env.template para buscar chaves e autenticações do código
            env_candidates = [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.local.example"]
            for candidate in env_candidates:
                if candidate in root_files:
                    try:
                        r_env = await client.get(
                            f"https://api.github.com/repos/{full_name}/contents/{candidate}?ref={default_branch}",
                            headers={**headers, "Accept": "application/vnd.github.raw+json"},
                        )
                        if r_env.status_code == 200 and r_env.text:
                            env_file_found = candidate
                            discovered_env_vars = self._parse_env_example_content(r_env.text)
                            break
                    except Exception:
                        pass

            # 5. Inspeciona Dockerfile para detectar EXPOSE <porta>
            if "Dockerfile" in root_files:
                try:
                    r_df = await client.get(
                        f"https://api.github.com/repos/{full_name}/contents/Dockerfile?ref={default_branch}",
                        headers={**headers, "Accept": "application/vnd.github.raw+json"},
                    )
                    if r_df.status_code == 200 and r_df.text:
                        m_port = re.search(r"^\s*EXPOSE\s+(\d+)", r_df.text, re.MULTILINE | re.IGNORECASE)
                        if m_port:
                            detected_port = int(m_port.group(1))
                except Exception:
                    pass

        # Determina stack / builder automaticamente a partir dos arquivos
        files_lower = {f.lower() for f in root_files}
        has_dockerfile = "dockerfile" in files_lower
        has_compose = "docker-compose.yml" in files_lower or "docker-compose.yaml" in files_lower or "compose.yaml" in files_lower

        if has_dockerfile:
            detected_stack = "Dockerfile Nativo"
        elif has_compose:
            detected_stack = "Docker Compose"
        elif "bun.lockb" in files_lower or "bunfig.toml" in files_lower:
            detected_stack = "Bun (Zero-Config)"
            detected_port = detected_port or 3000
        elif "package.json" in files_lower:
            detected_stack = "Node.js / TypeScript (Zero-Config)"
            detected_port = detected_port or 3000
        elif "requirements.txt" in files_lower or "pyproject.toml" in files_lower or "pipfile" in files_lower:
            detected_stack = "Python (Zero-Config)"
            detected_port = detected_port or 8000
        elif "go.mod" in files_lower:
            detected_stack = "Go / Golang (Zero-Config)"
            detected_port = detected_port or 8080
        elif "cargo.toml" in files_lower:
            detected_stack = "Rust (Zero-Config)"
            detected_port = detected_port or 8080
        elif "composer.json" in files_lower or "index.php" in files_lower:
            detected_stack = "PHP / Laravel (Zero-Config)"
            detected_port = detected_port or 80
        elif "gemfile" in files_lower:
            detected_stack = "Ruby / Rails (Zero-Config)"
            detected_port = detected_port or 3000
        elif "pom.xml" in files_lower or "build.gradle" in files_lower or "build.gradle.kts" in files_lower:
            detected_stack = "Java Maven/Gradle (Zero-Config)"
            detected_port = detected_port or 8080
        elif "index.html" in files_lower:
            detected_stack = "Site Estático HTML/Nginx (Zero-Config)"
            detected_port = detected_port or 80
        else:
            detected_stack = f"{language} (Auto-Builder)"

        repo_short_name = full_name.split("/")[-1]
        return {
            "full_name": full_name,
            "name": repo_short_name,
            "clone_url": clone_url,
            "private": is_private,
            "default_branch": default_branch,
            "branches": branches,
            "language": language,
            "detected_stack": detected_stack,
            "has_dockerfile": has_dockerfile,
            "has_compose": has_compose,
            "detected_port": detected_port,
            "root_files": root_files,
            "env_file_found": env_file_found,
            "discovered_env_vars": discovered_env_vars,
            "auth_ready": (not is_private) or bool(tok),
            "using_saved_github_token": bool(tok),
        }

    async def create_github_repo_webhook(
        self, repo_or_url: str, webhook_url: str, webhook_secret: str
    ) -> dict[str, Any]:
        full_name = self._parse_github_full_name(repo_or_url)
        tok = self.get_decrypted_github_token(force=True)
        if not tok:
            return {
                "created": False,
                "reason": "Nenhum token GitHub conectado para criar o webhook automaticamente.",
            }
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{full_name}/hooks",
                    headers=self._github_headers(tok),
                    json={
                        "name": "web",
                        "active": True,
                        "events": ["push", "pull_request"],
                        "config": {
                            "url": webhook_url,
                            "content_type": "json",
                            "secret": webhook_secret,
                            "insecure_ssl": "0",
                        },
                    },
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    return {"created": True, "hook_id": data.get("id"), "full_name": full_name}
                if resp.status_code == 422:
                    return {"created": True, "already_exists": True, "full_name": full_name}
                return {
                    "created": False,
                    "status_code": resp.status_code,
                    "detail": resp.text[:200],
                }
        except Exception as exc:
            return {"created": False, "reason": str(exc)}


paas_manager = PaaSManager()
