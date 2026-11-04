from fastapi import APIRouter

from app.api.v1.endpoints import auth, containers, deployments, paas, projects, security, system, webhooks, ws

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(containers.router, prefix="/containers", tags=["containers"])
api_router.include_router(projects.router, prefix="/projects", tags=["projects"])
api_router.include_router(deployments.router, prefix="/deployments", tags=["deployments"])
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])
api_router.include_router(system.router, prefix="/system", tags=["system"])
api_router.include_router(security.router, prefix="/security", tags=["security"])
api_router.include_router(paas.router, prefix="/paas", tags=["paas"])
api_router.include_router(ws.router, prefix="/ws", tags=["websocket"])
