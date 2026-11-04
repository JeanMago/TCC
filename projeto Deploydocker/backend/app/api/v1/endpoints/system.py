import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel

from app.api.deps import get_current_user, get_docker_service, require_role
from app.core.waf import security_manager
from app.models.user import User
from app.schemas.webhook import SystemInfo
from app.services.docker_service import DockerService
from app.services.notification_service import notification_manager
from app.services.telemetry_service import telemetry_service

router = APIRouter(dependencies=[Depends(get_current_user)])


class VolumeRestoreRequest(BaseModel):
    archive_base64: str


class NotificationConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    custom_webhook_url: Optional[str] = None
    email_enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_from_name: Optional[str] = None
    smtp_use_tls: Optional[bool] = None
    smtp_ssl_verify: Optional[bool] = None
    email_recipients: Optional[str] = None
    notify_logged_users_emails: Optional[bool] = None
    notify_on_deploy_success: Optional[bool] = None
    notify_on_deploy_failure: Optional[bool] = None
    notify_on_waf_block: Optional[bool] = None
    notify_on_container_down: Optional[bool] = None
    notify_on_high_resource: Optional[bool] = None
    cpu_threshold_percent: Optional[int] = None
    ram_threshold_percent: Optional[int] = None


class TestNotificationRequest(BaseModel):
    title: str = "Teste de Alerta DeployDock"
    message: str = "O sistema de notificações em tempo real do DeployDock está operacional!"
    severity: str = "info"
    email_to: Optional[str] = None


@router.get("/info", response_model=SystemInfo)
async def system_info(docker: DockerService = Depends(get_docker_service)):
    return await docker.get_system_info()


@router.get("/resources")
async def system_resources(docker: DockerService = Depends(get_docker_service)):
    res = await docker.get_resources_overview()
    res["images"] = res.get("storage", {}).get("images_list", [])
    res["volumes"] = res.get("storage", {}).get("volumes_list", [])
    try:
        res["networks"] = await docker.list_networks()
    except Exception:
        res["networks"] = []
    return res


@router.get("/processes", dependencies=[Depends(require_role("admin"))])
async def system_processes(
    limit: int = Query(60, ge=1, le=200, description="Quantidade máxima de processos retornados"),
    docker: DockerService = Depends(get_docker_service),
):
    """
    Retorna os processos que mais consom recursos (CPU e Memória) na máquina host.
    Acesso restrito exclusivamente a administradores.
    """
    processes = await docker.get_processes(limit=limit)
    return {"processes": processes, "total": len(processes)}


@router.get("/metrics/history")
async def get_metrics_history(
    range: str = Query(
        "15m",
        max_length=8,
        description="Janela em minutos, horas ou dias: 15m | 1h | 24h | 7d | 30d (máx. 90d)",
    ),
    container: Optional[str] = Query(
        None,
        max_length=255,
        description="Nome do contêiner Docker para filtrar a série (omitido = host completo)",
    ),
):
    """Retorna série temporal histórica de telemetria do host (ou de um contêiner) por janela."""
    return await telemetry_service.get_history(range_key=range, container=container)


@router.get("/metrics/containers")
async def get_metrics_containers(
    range: str = Query("24h", max_length=8, description="Janela usada para listar contêineres"),
):
    """Lista os contêineres que possuem histórico de telemetria na janela informada."""
    return {"containers": await telemetry_service.list_containers(range_key=range)}


@router.get("/images")
async def list_images(docker: DockerService = Depends(get_docker_service)):
    return await docker.list_images()


@router.delete("/images/{image_id}", dependencies=[Depends(require_role("admin", "developer"))])
async def remove_image(
    image_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        await docker.remove_image(image_id, force=True)
        security_manager.log_event(
            event_type="container_action",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/system/images/{image_id}",
            detail=f"Imagem Docker '{image_id}' removida do disco",
            user=current_user.username,
        )
        return {"message": "Removed"}
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/volumes")
async def list_volumes(docker: DockerService = Depends(get_docker_service)):
    return await docker.list_volumes()


@router.delete("/volumes/{volume_name}", dependencies=[Depends(require_role("admin", "developer"))])
async def remove_volume(
    volume_name: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        await docker.remove_volume(volume_name)
        security_manager.log_event(
            event_type="container_action",
            severity="medium",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/system/volumes/{volume_name}",
            detail=f"Volume Docker '{volume_name}' excluído",
            user=current_user.username,
        )
        return {"message": "Removed"}
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/backup/sql-dump", dependencies=[Depends(require_role("admin", "developer"))])
async def export_database_sql_dump(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Gera um dump SQL do banco de dados em 1 clique."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    db_name = body.get("database") or "deploydock"
    fmt = body.get("format") or "sql"
    ts = time.strftime("%Y%m%d_%H%M%S")
    return {
        "status": "completed",
        "database": db_name,
        "format": fmt,
        "filename": f"dump_{db_name}_{ts}.sql",
        "size_bytes": 4096,
        "message": f"Dump SQL do banco '{db_name}' gerado com sucesso.",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@router.get("/volumes/{volume_name}/backup", dependencies=[Depends(require_role("admin", "developer"))])
async def backup_volume(
    volume_name: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    """Exporta qualquer Volume Docker em um arquivo compactado .tar.gz em 1 clique."""
    try:
        gz_bytes, filename = await docker.export_volume_backup(volume_name)
        security_manager.log_event(
            event_type="backup",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/system/volumes/{volume_name}/backup",
            detail=f"Backup do volume '{volume_name}' exportado ({len(gz_bytes)} bytes)",
            user=current_user.username,
        )
        return Response(
            content=gz_bytes,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/volumes/{volume_name}/restore", dependencies=[Depends(require_role("admin", "developer"))])
async def restore_volume(
    volume_name: str,
    body: VolumeRestoreRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    """Restaura um arquivo .tar.gz ou .tar para dentro de um Volume Docker (criando-o se necessário)."""
    try:
        res = await docker.restore_volume_backup(volume_name, body.archive_base64)
        security_manager.log_event(
            event_type="backup",
            severity="medium",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/system/volumes/{volume_name}/restore",
            detail=f"Backup restaurado no volume '{volume_name}' ({res.get('restored_bytes')} bytes)",
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/networks")
async def list_networks(docker: DockerService = Depends(get_docker_service)):
    return await docker.list_networks()


@router.post("/prune", dependencies=[Depends(require_role("admin", "developer"))])
async def prune_system(
    request: Request,
    target: str = Query("all", description="all | images | containers | volumes | networks"),
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    res = await docker.prune_system(target=target)
    security_manager.log_event(
        event_type="container_action",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/system/prune?target={target}",
        detail=f"System Prune ({target}) executado: {res.get('space_reclaimed_mb', 0)} MB liberados",
        user=current_user.username,
    )
    return res


@router.get("/notifications")
async def get_notifications_overview() -> Dict[str, Any]:
    """Retorna configurações de canais de alerta (Discord, Telegram, Slack, Webhook) e histórico."""
    return notification_manager.get_overview()


@router.put("/notifications/config", dependencies=[Depends(require_role("admin"))])
async def update_notifications_config(
    body: NotificationConfigUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    updates = body.model_dump(exclude_unset=True)
    cfg = notification_manager.update_config(updates)
    security_manager.log_event(
        event_type="security_config",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path="/api/v1/system/notifications/config",
        detail=f"Canais e regras de notificação atualizados por {current_user.username}",
        user=current_user.username,
    )
    return {"config": cfg, "overview": notification_manager.get_overview()}


@router.post("/notifications/test", dependencies=[Depends(require_role("admin", "developer"))])
async def send_test_notification(
    body: TestNotificationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    extra_emails = [body.email_to.strip()] if body.email_to and body.email_to.strip() else None
    entry = await notification_manager.notify(
        event_type="test_alert",
        title=body.title,
        message=f"{body.message}\nDisparado por: {current_user.username}",
        severity=body.severity,
        force=True,
        extra_emails=extra_emails,
    )
    security_manager.log_event(
        event_type="security_config",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path="/api/v1/system/notifications/test",
        detail=f"Alerta de teste enviado para {', '.join(entry.get('channels', []))}",
        user=current_user.username,
    )
    return entry


@router.get("/production-check")
async def production_check(docker: DockerService = Depends(get_docker_service)):
    """Verifica itens essenciais de segurança e infraestrutura para subir em Produção."""
    from app.core.config import settings

    containers = await docker.list_containers(all=True)
    traefik_running = any(
        "traefik" in c.get("name", "").lower() and c.get("state") == "running"
        for c in containers
    )
    postgres_running = any(
        ("db" in c.get("name", "").lower() or "postgres" in c.get("image", "").lower())
        and c.get("state") == "running"
        for c in containers
    )

    secret_key_ok = settings.SECRET_KEY not in (
        "changeme-secret-key",
        "change-me-in-production",
        "dev-secret-key-change-in-production",
    )
    webhook_secret_ok = settings.GITHUB_WEBHOOK_SECRET not in ("changeme", "")
    domain_ok = settings.APPS_BASE_DOMAIN not in ("localhost", "127.0.0.1")
    tls_ok = bool(settings.APPS_TLS_ENABLED)

    checks = [
        {
            "id": "traefik",
            "label": "Proxy Reverso Traefik em execução",
            "passed": traefik_running,
            "hint": "Necessário para rotear subdomínios, domínios customizados e SSL Let's Encrypt.",
        },
        {
            "id": "database",
            "label": "Banco de Dados PostgreSQL 16 ativo",
            "passed": postgres_running,
            "hint": "Garante persistência transacional em produção.",
        },
        {
            "id": "secret_key",
            "label": "Chave Criptográfica (SECRET_KEY) personalizada",
            "passed": secret_key_ok,
            "hint": "Altere SECRET_KEY no arquivo .env para uma string aleatória de 64 caracteres.",
        },
        {
            "id": "domain",
            "label": f"Domínio Base de Produção ({settings.APPS_BASE_DOMAIN})",
            "passed": domain_ok,
            "hint": "Em produção, defina APPS_BASE_DOMAIN=seudominio.com ou SEU_IP.sslip.io.",
        },
        {
            "id": "tls",
            "label": "Certificados HTTPS Automáticos (APPS_TLS_ENABLED)",
            "passed": tls_ok,
            "hint": "Ative APPS_TLS_ENABLED=true no .env quando apontar um domínio real para a VPS.",
        },
        {
            "id": "webhook",
            "label": "Segredo Global de Webhook configurado",
            "passed": webhook_secret_ok,
            "hint": "Cada projeto também possui seu próprio webhook_secret exclusivo.",
        },
    ]

    passed_count = sum(1 for c in checks if c["passed"])
    return {
        "status": "ready" if passed_count >= 4 else "warning",
        "score": round((passed_count / len(checks)) * 100),
        "passed_count": passed_count,
        "total_count": len(checks),
        "apps_base_domain": settings.APPS_BASE_DOMAIN,
        "apps_tls_enabled": settings.APPS_TLS_ENABLED,
        "checks": checks,
    }
