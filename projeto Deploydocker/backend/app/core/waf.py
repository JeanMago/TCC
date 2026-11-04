"""
Módulo de Segurança Ativa, WAF (Web Application Firewall), Rate Limiting,
Prevenção de Brute-Force, Anti-SSRF e Auditoria de Eventos.
"""

import ipaddress
import re
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional
from urllib.parse import unquote, urlparse

from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class SecurityAuditEntry:
    def __init__(
        self,
        event_type: str,
        severity: str,
        ip: str,
        path: str,
        detail: str,
        user: Optional[str] = None,
        blocked: bool = False,
    ):
        self.id = f"evt-{int(time.time() * 1000)}-{id(self) % 10000}"
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.event_type = event_type  # waf_block, rate_limit, auth_fail, auth_success, container_exec, deploy, env_change, manual_block
        self.severity = severity      # low, medium, high, critical
        self.ip = ip
        self.path = path
        self.detail = detail
        self.user = user or "anonymous"
        self.blocked = blocked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "ip": self.ip,
            "path": self.path,
            "detail": self.detail,
            "user": self.user,
            "blocked": self.blocked,
        }


class SecurityManager:
    """Gerencia Rate Limiting, WAF, IPs bloqueados e Log de Auditoria em memória."""

    def __init__(self) -> None:
        # Histórico dos últimos 300 eventos de segurança/auditoria
        self.audit_logs: Deque[SecurityAuditEntry] = deque(maxlen=300)

        # IPs bloqueados: ip -> {"reason": str, "blocked_at": str, "expires_at": float | None}
        self.blocked_ips: Dict[str, Dict[str, Any]] = {}

        # Contadores de requisições por IP (janela deslizante 60s)
        self.request_timestamps: Dict[str, Deque[float]] = {}

        # Falhas de login por IP (janela deslizante 300s)
        self.login_failures: Dict[str, Deque[float]] = {}

        # Configurações de proteção
        self.config = {
            "waf_enabled": True,
            "rate_limit_enabled": True,
            "rate_limit_per_minute": 240,
            "login_max_attempts": 5,
            "login_lockout_seconds": 300,
            "ssrf_protection": True,
            "container_no_new_privileges": True,
            "security_headers": True,
        }

        # Métricas acumuladas
        self.stats = {
            "total_requests_inspected": 0,
            "waf_attacks_blocked": 0,
            "rate_limits_triggered": 0,
            "brute_force_blocks": 0,
        }

        # Padrões de assinatura WAF (SQLi, XSS, Path Traversal, Command Injection em URL/Query)
        self._waf_patterns = [
            (
                "Path Traversal",
                re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|c:\\windows\\system32)", re.IGNORECASE),
            ),
            (
                "SQL Injection",
                re.compile(
                    r"(union\s+all\s+select|union\s+select|information_schema|sleep\(\d+\)|benchmark\(\d+|'\s*or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|or\s+1\s*=\s*1)",
                    re.IGNORECASE,
                ),
            ),
            (
                "Cross-Site Scripting (XSS)",
                re.compile(r"(<script\b[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|<iframe\b)", re.IGNORECASE),
            ),
            (
                "Remote Code Execution / Shell Probe",
                re.compile(r"(\$\{jndi:|(/bin/)?bash\s+-i|/dev/tcp/|;?\s*curl\s+http|\|\s*nc\s+-e)", re.IGNORECASE),
            ),
        ]

    def get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "127.0.0.1"

    def log_event(
        self,
        event_type: str,
        severity: str,
        ip: str,
        path: str,
        detail: str,
        user: Optional[str] = None,
        blocked: bool = False,
    ) -> SecurityAuditEntry:
        entry = SecurityAuditEntry(
            event_type=event_type,
            severity=severity,
            ip=ip,
            path=path,
            detail=detail,
            user=user,
            blocked=blocked,
        )
        self.audit_logs.appendleft(entry)

        if blocked and event_type in ("waf_block", "manual_block", "auth_fail"):
            try:
                import asyncio

                from app.services.notification_service import notification_manager

                loop = asyncio.get_running_loop()
                loop.create_task(
                    notification_manager.notify(
                        event_type="waf_block",
                        title=f"Escudo WAF Bloqueou Ameaça ({event_type})",
                        message=f"IP: `{ip}` • Rota: `{path}` • Usuário: `{user or 'anonymous'}`\nDetalhe: {detail}",
                        severity="critical" if severity == "critical" else "warning",
                        metadata={"ip": ip, "path": path, "event_type": event_type},
                    )
                )
            except Exception:
                pass

        return entry

    def is_ip_blocked(self, ip: str) -> Optional[Dict[str, Any]]:
        info = self.blocked_ips.get(ip)
        if not info:
            return None
        expires_at = info.get("expires_at")
        if expires_at and time.time() > expires_at:
            del self.blocked_ips[ip]
            return None
        return info

    def block_ip(self, ip: str, reason: str, duration_seconds: Optional[int] = 900) -> Dict[str, Any]:
        now = time.time()
        expires_at = (now + duration_seconds) if duration_seconds else None
        self.blocked_ips[ip] = {
            "ip": ip,
            "reason": reason,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at,
            "permanent": duration_seconds is None,
        }
        return self.blocked_ips[ip]

    def unblock_ip(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            return True
        return False

    def record_login_failure(self, ip: str, username: str) -> bool:
        """Registra falha de login e bloqueia o IP se ultrapassar o limite."""
        now = time.time()
        q = self.login_failures.setdefault(ip, deque())
        while q and now - q[0] > self.config["login_lockout_seconds"]:
            q.popleft()
        q.append(now)

        attempts = len(q)
        max_attempts = self.config["login_max_attempts"]
        self.log_event(
            event_type="auth_fail",
            severity="medium" if attempts < max_attempts else "high",
            ip=ip,
            path="/api/v1/auth/login",
            detail=f"Tentativa de login inválida para '{username}' ({attempts}/{max_attempts})",
            user=username,
            blocked=attempts >= max_attempts,
        )

        if attempts >= max_attempts:
            self.stats["brute_force_blocks"] += 1
            self.block_ip(
                ip,
                reason=f"Brute-force detectado ({attempts} falhas de login para '{username}')",
                duration_seconds=self.config["login_lockout_seconds"],
            )
            return True
        return False

    def record_login_success(self, ip: str, username: str) -> None:
        if ip in self.login_failures:
            self.login_failures[ip].clear()
        self.log_event(
            event_type="auth_success",
            severity="low",
            ip=ip,
            path="/api/v1/auth/login",
            detail=f"Login autenticado com sucesso ({username})",
            user=username,
            blocked=False,
        )

    def check_rate_limit(self, ip: str, path: str) -> bool:
        """Retorna True se excedeu o rate limit."""
        if not self.config["rate_limit_enabled"]:
            return False
        now = time.time()
        q = self.request_timestamps.setdefault(ip, deque())
        while q and now - q[0] > 60.0:
            q.popleft()
        q.append(now)

        if len(q) > self.config["rate_limit_per_minute"]:
            self.stats["rate_limits_triggered"] += 1
            self.log_event(
                event_type="rate_limit",
                severity="medium",
                ip=ip,
                path=path,
                detail=f"Limite de requisições excedido ({len(q)} req/min)",
                blocked=True,
            )
            return True
        return False

    def inspect_request(self, ip: str, path: str, query_string: str) -> Optional[str]:
        """Inspeciona URL e Query String contra assinaturas de ataque WAF."""
        if not self.config["waf_enabled"]:
            return None

        target = unquote(f"{path}?{query_string}" if query_string else path)
        for attack_name, pattern in self._waf_patterns:
            if pattern.search(target):
                self.stats["waf_attacks_blocked"] += 1
                self.log_event(
                    event_type="waf_block",
                    severity="critical",
                    ip=ip,
                    path=path,
                    detail=f"Ataque {attack_name} bloqueado pelo WAF na requisição",
                    blocked=True,
                )
                return attack_name
        return None


security_manager = SecurityManager()


def validate_safe_git_url(repo_url: str) -> str:
    """
    Valida URLs de repositórios Git contra SSRF, Local File Inclusion (file://)
    e injeção de argumentos Git (--upload-pack, ext::).
    """
    url = (repo_url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL do repositório não pode ser vazia.")

    if url.startswith("-"):
        raise HTTPException(status_code=400, detail="URL inválida: flag de linha de comando detectada.")

    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise HTTPException(
            status_code=400,
            detail="Segurança Anti-SSRF: Apenas repositórios com protocolo HTTP ou HTTPS são permitidos.",
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname inválido na URL do repositório.")

    if security_manager.config["ssrf_protection"]:
        blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"}
        if hostname in blocked_hosts:
            security_manager.log_event(
                event_type="waf_block",
                severity="critical",
                ip="internal",
                path="/api/v1/projects",
                detail=f"Tentativa de SSRF bloqueada para host restrito: {hostname}",
                blocked=True,
            )
            raise HTTPException(
                status_code=400,
                detail=f"Segurança Anti-SSRF: O host '{hostname}' não é permitido para clonagem Git.",
            )
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if (
                ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_private
                or ip_obj.is_unspecified
                or ip_obj.is_reserved
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Segurança Anti-SSRF: Endereços de loopback/link-local/rede privada são bloqueados.",
                )
        except ValueError:
            # É um domínio normal (ex: github.com, gitlab.com)
            pass

    return url


def validate_safe_container_command(command: str, user: str = "admin", ip: str = "127.0.0.1") -> str:
    """
    Bloqueia comandos maliciosos ou fork bombs na execução de terminal de contêiner
    e registra no log de auditoria.
    """
    cmd = (command or "").strip()
    dangerous_patterns = [
        (r":\(\)\s*\{\s*:\|\:&\s*\}\s*;?\s*:", "Fork Bomb detectada"),
        (r"/var/run/docker\.sock", "Acesso direto ao socket Docker bloqueado"),
        (r"rm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/(?:\s|$)", "Destruição da raiz do sistema bloqueada"),
        (r"rm\s+-rf\s+/", "Destruição da raiz do sistema bloqueada"),
        (r"mkfs\.", "Formatação de bloco bloqueada"),
    ]
    for pat, reason in dangerous_patterns:
        if re.search(pat, cmd, re.IGNORECASE):
            security_manager.stats["waf_attacks_blocked"] += 1
            security_manager.log_event(
                event_type="waf_block",
                severity="critical",
                ip=ip,
                path="/api/v1/containers/exec",
                detail=f"Comando bloqueado no container ({reason}): {cmd[:80]}",
                user=user,
                blocked=True,
            )
            raise HTTPException(status_code=403, detail=f"Bloqueado pela política de segurança: {reason}")

    security_manager.log_event(
        event_type="container_exec",
        severity="low",
        ip=ip,
        path="/api/v1/containers/exec",
        detail=f"Comando executado em container: {cmd[:80]}",
        user=user,
        blocked=False,
    )
    return cmd


class SecurityShieldMiddleware(BaseHTTPMiddleware):
    """Middleware global de proteção HTTP, WAF, Rate Limiting e Security Headers."""

    async def dispatch(self, request: Request, call_next) -> Response:
        security_manager.stats["total_requests_inspected"] += 1
        ip = security_manager.get_client_ip(request)
        path = request.url.path
        query = request.url.query

        # 1. Verifica se o IP está bloqueado (exceto se for a própria rota de desbloqueio pelo admin local)
        block_info = security_manager.is_ip_blocked(ip)
        if block_info and not path.startswith("/api/v1/security/unblock"):
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Acesso bloqueado pelo Firewall DeployDock: {block_info['reason']}",
                    "blocked_ip": ip,
                },
            )

        # 2. Inspeção WAF em URL e Query
        attack_detected = security_manager.inspect_request(ip, path, query)
        if attack_detected:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"Requisição bloqueada pelo WAF DeployDock: Padrão de {attack_detected} detectado.",
                },
            )

        # 3. Rate Limiting por IP
        if security_manager.check_rate_limit(ip, path):
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Muitas requisições em curto período (Rate Limit atingido). Aguarde alguns segundos.",
                },
            )

        response = await call_next(request)

        # 4. Injeção de Security Headers HTTP
        if security_manager.config["security_headers"]:
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "SAMEORIGIN"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
            response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
            response.headers["X-DeployDock-Shield"] = "active"

        return response
