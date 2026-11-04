import posixpath
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, model_validator

from app.api.deps import get_current_user, get_docker_service, require_role
from app.core.waf import security_manager, validate_safe_container_command
from app.models.user import User
from app.schemas.container import ContainerDetail, ContainerSummary
from app.services.docker_service import DockerService
from app.services.uptime_service import uptime_monitor

router = APIRouter(dependencies=[Depends(get_current_user)])


class ContainerExecRequest(BaseModel):
    command: str
    workdir: Optional[str] = None


class QuickContainerRunRequest(BaseModel):
    image: str
    name: Optional[str] = None
    host_port: Optional[int] = None
    container_port: Optional[int] = None
    env_text: Optional[str] = None
    restart_policy: str = "unless-stopped"


class ContainerFileWriteRequest(BaseModel):
    path: str
    content: str
    restart: bool = False


class ContainerFileUploadRequest(BaseModel):
    path: Optional[str] = None
    dir_path: str = "/"
    filename: Optional[str] = None
    content_base64: str

    @model_validator(mode="before")
    @classmethod
    def _parse_path_fallback(cls, data: Any) -> Any:
        if isinstance(data, dict):
            p = data.get("path")
            if p and not data.get("filename"):
                data["dir_path"] = posixpath.dirname(p) or "/"
                data["filename"] = posixpath.basename(p)
        return data


class ContainerResourceUpdateRequest(BaseModel):
    memory_limit_mb: Optional[int] = None
    cpu_limit_cores: Optional[float] = None


@router.get("", response_model=List[ContainerSummary])
async def list_containers(all: bool = True, docker: DockerService = Depends(get_docker_service)):
    return await docker.list_containers(all=all)


@router.post("/run", dependencies=[Depends(require_role("admin", "developer"))])
async def run_quick_container(
    body: QuickContainerRunRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    image = (body.image or "").strip()
    if not image:
        raise HTTPException(status_code=400, detail="Informe o nome da imagem Docker (ex: redis:alpine).")

    ports_map = None
    if body.host_port and body.container_port:
        ports_map = {f"{body.container_port}/tcp": int(body.host_port)}

    env_map: dict[str, str] = {}
    if body.env_text and body.env_text.strip():
        for line in body.env_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip():
                env_map[k.strip()] = v.strip()

    try:
        res = await docker.run_quick_container(
            image=image,
            name=body.name.strip() if body.name and body.name.strip() else None,
            ports=ports_map,
            env=env_map or None,
            restart_policy=body.restart_policy,
        )
        security_manager.log_event(
            event_type="deploy",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path="/api/v1/containers/run",
            detail=f"Contêiner rápido iniciado a partir de '{image}' ({res.get('name')})",
            user=current_user.username,
            blocked=False,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Falha ao iniciar contêiner: {e}")


@router.get("/{container_id}", response_model=ContainerDetail)
async def get_container(container_id: str, docker: DockerService = Depends(get_docker_service)):
    try:
        return await docker.get_container(container_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{container_id}/start", dependencies=[Depends(require_role("admin", "developer"))])
async def start_container(
    container_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    res = await docker.start_container(container_id)
    c_name = res.get("name", container_id)
    uptime_monitor.clear_manually_stopped(c_name)
    uptime_monitor.clear_manually_stopped(container_id)
    security_manager.log_event(
        event_type="container_action",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/containers/{container_id}/start",
        detail=f"Contêiner '{c_name}' iniciado",
        user=current_user.username,
    )
    return {"message": "Started"}


@router.post("/{container_id}/stop", dependencies=[Depends(require_role("admin", "developer"))])
async def stop_container(
    container_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    res = await docker.stop_container(container_id)
    c_name = res.get("name", container_id)
    uptime_monitor.mark_manually_stopped(c_name)
    uptime_monitor.mark_manually_stopped(container_id)
    security_manager.log_event(
        event_type="container_action",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/containers/{container_id}/stop",
        detail=f"Contêiner '{c_name}' parado intencionalmente",
        user=current_user.username,
    )
    return {"message": "Stopped"}


@router.post("/{container_id}/restart", dependencies=[Depends(require_role("admin", "developer"))])
async def restart_container(
    container_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    res = await docker.restart_container(container_id)
    security_manager.log_event(
        event_type="container_action",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/containers/{container_id}/restart",
        detail=f"Contêiner '{res.get('name', container_id)}' reiniciado",
        user=current_user.username,
    )
    return {"message": "Restarted"}


@router.delete("/{container_id}", dependencies=[Depends(require_role("admin", "developer"))])
async def remove_container(
    container_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    await docker.remove_container(container_id)
    security_manager.log_event(
        event_type="container_action",
        severity="medium",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/containers/{container_id}",
        detail=f"Contêiner '{container_id}' removido",
        user=current_user.username,
    )
    return {"message": "Removed"}


@router.patch("/{container_id}/quotas", dependencies=[Depends(require_role("admin", "developer"))])
@router.put("/{container_id}/resources", dependencies=[Depends(require_role("admin", "developer"))])
async def update_container_resources(
    container_id: str,
    body: ContainerResourceUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        res = await docker.update_container_resources(
            container_id,
            memory_limit_mb=body.memory_limit_mb,
            cpu_limit_cores=body.cpu_limit_cores,
        )
        security_manager.log_event(
            event_type="resource_quota",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/containers/{container_id}/resources",
            detail=(
                f"Limites de recursos atualizados em '{res.get('name')}': "
                f"RAM={body.memory_limit_mb or 'ilimitada'}MB, CPU={body.cpu_limit_cores or 'ilimitada'} vCPU"
            ),
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{container_id}/logs")
async def get_container_logs(
    container_id: str,
    tail: int = Query(250, ge=0, le=10000),
    timestamps: bool = Query(True),
    since_seconds: Optional[int] = Query(None),
    search: Optional[str] = Query(None),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        return await docker.get_container_logs(
            container_id,
            tail=tail,
            timestamps=timestamps,
            since_seconds=since_seconds,
            search=search,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{container_id}/exec", dependencies=[Depends(require_role("admin", "developer"))])
async def exec_in_container(
    container_id: str,
    body: ContainerExecRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    if not body.command or not body.command.strip():
        raise HTTPException(status_code=400, detail="Informe um comando para executar.")
    safe_cmd = validate_safe_container_command(
        body.command,
        user=current_user.username,
        ip=security_manager.get_client_ip(request),
    )
    try:
        return await docker.exec_container_command(
            container_id, safe_cmd, workdir=body.workdir
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{container_id}/files")
async def list_files_in_container(
    container_id: str,
    path: str = Query("/"),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        return await docker.list_container_files(container_id, path=path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{container_id}/files/content")
async def read_file_in_container(
    container_id: str,
    path: str = Query(...),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        return await docker.read_container_file(container_id, file_path=path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{container_id}/files/content", dependencies=[Depends(require_role("admin", "developer"))])
async def write_file_in_container(
    container_id: str,
    body: ContainerFileWriteRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        res = await docker.write_container_file(
            container_id,
            file_path=body.path,
            content=body.content,
            restart=body.restart,
        )
        security_manager.log_event(
            event_type="file_edit",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/containers/{container_id}/files/content",
            detail=f"Arquivo '{body.path}' editado no contêiner {container_id} ({res.get('size_bytes')} bytes)",
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{container_id}/files/upload", dependencies=[Depends(require_role("admin", "developer"))])
async def upload_file_to_container(
    container_id: str,
    body: ContainerFileUploadRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        target_dir = body.dir_path or "/"
        target_name = body.filename or "upload.bin"
        res = await docker.upload_container_file(
            container_id,
            dir_path=target_dir,
            filename=target_name,
            content_base64=body.content_base64,
        )
        security_manager.log_event(
            event_type="file_upload",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/containers/{container_id}/files/upload",
            detail=f"Upload do arquivo '{body.filename}' para '{body.dir_path}' no contêiner {container_id}",
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{container_id}/files/download")
async def download_file_from_container(
    container_id: str,
    path: str = Query(...),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        file_bytes, filename = await docker.download_container_file(container_id, file_path=path)
        return Response(
            content=file_bytes,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{container_id}/files", dependencies=[Depends(require_role("admin", "developer"))])
async def delete_file_in_container(
    container_id: str,
    request: Request,
    path: str = Query(...),
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        res = await docker.delete_container_file(container_id, file_path=path)
        security_manager.log_event(
            event_type="file_delete",
            severity="medium",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/containers/{container_id}/files",
            detail=f"Arquivo '{path}' excluído no contêiner {container_id}",
            user=current_user.username,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{container_id}/db-dump", dependencies=[Depends(require_role("admin", "developer"))])
async def export_container_database_dump(
    container_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    docker: DockerService = Depends(get_docker_service),
):
    try:
        dump_bytes, filename, media_type = await docker.export_container_db_dump(container_id)
        security_manager.log_event(
            event_type="backup",
            severity="low",
            ip=security_manager.get_client_ip(request),
            path=f"/api/v1/containers/{container_id}/db-dump",
            detail=f"Dump/Backup '{filename}' ({len(dump_bytes)} bytes) exportado do contêiner {container_id}",
            user=current_user.username,
        )
        return Response(
            content=dump_bytes,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
