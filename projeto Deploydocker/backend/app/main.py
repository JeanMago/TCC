import logging
import os
import shutil

# Auto-detect git executable if not in system PATH
if not shutil.which("git"):
    candidates = [
        "C:\\Program Files\\Git\\cmd\\git.exe",
        "C:\\Program Files (x86)\\Git\\cmd\\git.exe",
    ]
    gh_desktop = os.path.expanduser("~\\AppData\\Local\\GitHubDesktop")
    if os.path.exists(gh_desktop):
        for entry in sorted(os.listdir(gh_desktop), reverse=True):
            candidate = os.path.join(gh_desktop, entry, "resources", "app", "git", "cmd", "git.exe")
            if os.path.isfile(candidate):
                candidates.insert(0, candidate)

    for c in candidates:
        if os.path.isfile(c):
            os.environ["GIT_PYTHON_GIT_EXECUTABLE"] = c
            git_dir = os.path.dirname(c)
            if git_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = git_dir + os.pathsep + os.environ.get("PATH", "")
            break

os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from app.api.v1.endpoints import gateway, ws
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.waf import SecurityShieldMiddleware, security_manager
from app.db.session import engine, init_db
from app.services.telemetry_service import telemetry_service
from app.services.uptime_service import uptime_monitor

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.enforce_production_security()
    for problem in settings.insecure_settings():
        logging.getLogger("deploydock").warning("[Segurança] %s", problem)
    await init_db()
    uptime_monitor.start()
    telemetry_service.start()
    yield
    telemetry_service.stop()
    uptime_monitor.stop()
    await engine.dispose()


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

app.add_middleware(SecurityShieldMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")
app.include_router(ws.router, prefix="/ws", tags=["websocket"])
app.include_router(gateway.router, prefix="/open", tags=["gateway"])


@app.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
async def prometheus_metrics() -> str:
    """Métricas do WAF em formato texto Prometheus (backend exposto apenas em 127.0.0.1 por padrão)."""
    stats = security_manager.stats
    lines = []
    for key, help_text in (
        ("total_requests_inspected", "Total de requisições inspecionadas pelo escudo de segurança"),
        ("waf_attacks_blocked", "Ataques bloqueados pelo WAF"),
        ("rate_limits_triggered", "Bloqueios por rate limiting"),
        ("brute_force_blocks", "Bloqueios por brute-force de login"),
    ):
        lines += [
            f"# HELP deploydock_{key}_total {help_text}",
            f"# TYPE deploydock_{key}_total counter",
            f"deploydock_{key}_total {stats.get(key, 0)}",
        ]
    lines += [
        "# HELP deploydock_blocked_ips IPs atualmente bloqueados",
        "# TYPE deploydock_blocked_ips gauge",
        f"deploydock_blocked_ips {len(security_manager.blocked_ips)}",
    ]
    return "\n".join(lines) + "\n"


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.get("/")
async def root():
    return {"app": settings.APP_NAME, "version": "1.0.0"}
