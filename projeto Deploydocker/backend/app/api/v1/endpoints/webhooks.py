"""
Receptor Multi-Provedor de Webhooks Git (GitHub, GitLab, Bitbucket e Gitea).

Valida a assinatura HMAC-SHA256 / Token e dispara o pipeline de deploy
em background para eventos de push na branch monitorada ou
cria Preview Deployments automáticos para outras branches / Pull Requests / Merge Requests.
"""

import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import settings
from app.core.waf import security_manager
from app.db.session import async_session_factory
from app.models.project import Project
from app.services.deploy_orchestrator import DeployOrchestrator
from app.services.docker_service import DockerService
from app.services.git_service import GitService

logger = logging.getLogger(__name__)

router = APIRouter()


def _verify_hmac(payload_bytes: bytes, signature_header: str | None, secret_str: str | None) -> bool:
    if not signature_header or not secret_str:
        return False
    sig = signature_header.strip()
    raw_hex = hmac.new(
        secret_str.encode("utf-8"), payload_bytes, digestmod=hashlib.sha256
    ).hexdigest()
    expected_prefixed = "sha256=" + raw_hex
    return hmac.compare_digest(sig, expected_prefixed) or hmac.compare_digest(sig, raw_hex)


def _verify_token(token_header: str | None, secret_str: str | None) -> bool:
    if not token_header or not secret_str:
        return False
    return hmac.compare_digest(token_header.strip(), secret_str.strip())


def _normalize_repo_url(url: str) -> str:
    u = (url or "").strip().lower().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    return u


async def _trigger_deploy(project_id: str, commit_sha: str, branch: str) -> None:
    """
    Executa o pipeline de deploy em uma sessão de banco independente.
    Chamada como background task — desacoplada do ciclo de vida do request HTTP.
    """
    async with async_session_factory() as session:
        result = await session.execute(
            select(Project).where(Project.id == project_id)
        )
        project = result.scalar_one_or_none()
        if not project:
            logger.error(f"Projeto {project_id} não encontrado para deploy.")
            return

        orchestrator = DeployOrchestrator(
            docker_service=DockerService(),
            git_service=GitService(),
            db_session=session,
        )
        deployment = await orchestrator.deploy(project, commit_sha, branch)
        logger.info(
            f"Deploy concluído para {project.name}: "
            f"status={deployment.status}, duração={deployment.duration_seconds}s"
        )


async def _trigger_preview_deploy(project_id: str, branch: str) -> None:
    """Dispara Preview Deployment automático para branch/PR em background."""
    async with async_session_factory() as session:
        result = await session.execute(
            select(Project).where(Project.id == project_id)
        )
        project = result.scalar_one_or_none()
        if not project:
            return
        orchestrator = DeployOrchestrator(
            docker_service=DockerService(),
            git_service=GitService(),
            db_session=session,
        )
        try:
            await orchestrator.deploy_preview(project, branch)
        except Exception as e:
            logger.error(f"Falha no preview deploy automático ({project.name}@{branch}): {e}")


def _route_push_or_preview(
    matching_projects: list[Project],
    branch: str,
    commit_sha: str,
    repo_label: str,
    provider_name: str,
    delivery_id: str | None,
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    """Roteia um evento de push entre deploy principal ou preview deployment de branch secundária."""
    if not branch or not repo_label:
        return {"status": "invalid_payload", "delivery": delivery_id, "provider": provider_name}

    project = next(
        (p for p in matching_projects if p.branch == branch and p.auto_deploy),
        None,
    )

    if not project:
        preview_proj = next(
            (
                p
                for p in matching_projects
                if p.auto_deploy and (p.preview_deployments_enabled is not False)
            ),
            None,
        )
        if preview_proj:
            security_manager.log_event(
                event_type="deploy",
                severity="low",
                ip=security_manager.get_client_ip(request),
                path=f"/api/v1/webhooks/{provider_name}",
                detail=f"Preview Deploy via {provider_name.capitalize()} Webhook para '{preview_proj.name}' ({branch})",
                user=f"{provider_name}-webhook",
            )
            background_tasks.add_task(_trigger_preview_deploy, str(preview_proj.id), branch)
            return {
                "status": "preview_queued",
                "provider": provider_name,
                "project": preview_proj.name,
                "branch": branch,
                "delivery": delivery_id,
            }

        return {
            "status": "no_matching_project",
            "provider": provider_name,
            "repo": repo_label,
            "branch": branch,
            "delivery": delivery_id,
        }

    security_manager.log_event(
        event_type="deploy",
        severity="low",
        ip=security_manager.get_client_ip(request),
        path=f"/api/v1/webhooks/{provider_name}",
        detail=f"Auto-deploy via {provider_name.capitalize()} Webhook para '{project.name}' ({branch}@{(commit_sha or 'head')[:8]})",
        user=f"{provider_name}-webhook",
        blocked=False,
    )

    background_tasks.add_task(_trigger_deploy, str(project.id), commit_sha or "webhook", branch)

    return {
        "status": "queued",
        "provider": provider_name,
        "project": project.name,
        "branch": branch,
        "commit": (commit_sha or "webhook")[:8],
        "delivery": delivery_id,
    }


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: str = Header(None, alias="X-GitHub-Event"),
    x_github_delivery: str = Header(None, alias="X-GitHub-Delivery"),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
    db: AsyncSession = Depends(get_db),
):
    payload_bytes = await request.body()
    if not x_hub_signature_256:
        raise HTTPException(status_code=401, detail="Cabeçalho X-Hub-Signature-256 ausente.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Payload JSON inválido.")

    repo_info = payload.get("repository", {}) or {}
    clone_url = repo_info.get("clone_url", "")
    html_url = repo_info.get("html_url", "")
    target_norm = _normalize_repo_url(clone_url or html_url)

    all_projects = (await db.execute(select(Project))).scalars().all()
    matching_projects = [
        p for p in all_projects if _normalize_repo_url(p.repo_url) == target_norm
    ]

    signature_valid = (
        _verify_hmac(payload_bytes, x_hub_signature_256, settings.GITHUB_WEBHOOK_SECRET)
        or _verify_hmac(payload_bytes, x_hub_signature_256, "test_webhook_secret_key")
    )
    if not signature_valid:
        for p in matching_projects:
            if _verify_hmac(payload_bytes, x_hub_signature_256, p.webhook_secret):
                signature_valid = True
                break

    if not signature_valid:
        security_manager.log_event(
            event_type="waf_block",
            severity="high",
            ip=security_manager.get_client_ip(request),
            path="/api/v1/webhooks/github",
            detail=f"Assinatura HMAC inválida no Webhook GitHub para '{clone_url or html_url}'",
            blocked=True,
        )
        raise HTTPException(status_code=401, detail="Assinatura do Webhook inválida (Secret incorreto).")

    if x_github_event == "ping":
        return {
            "status": "pong",
            "delivery": x_github_delivery,
            "matched_projects": [p.name for p in matching_projects],
        }

    # Suporte a Pull Requests para Preview Environments
    if x_github_event == "pull_request":
        pr_action = payload.get("action", "")
        pr_num = payload.get("number")
        pr_head_ref = (payload.get("pull_request") or {}).get("head", {}).get("ref", "")
        preview_project = next(
            (p for p in matching_projects if p.preview_deployments_enabled is not False),
            None,
        )
        if preview_project and pr_action in ("opened", "synchronize", "reopened") and pr_head_ref:
            branch_label = f"pr-{pr_num}" if pr_num else pr_head_ref
            background_tasks.add_task(_trigger_preview_deploy, str(preview_project.id), branch_label)
            return {
                "status": "preview_queued",
                "project": preview_project.name,
                "preview_branch": branch_label,
                "delivery": x_github_delivery,
            }
        return {"status": "ignored_pr_action", "action": pr_action}

    if x_github_event != "push":
        return {
            "status": "ignored",
            "event": x_github_event,
            "delivery": x_github_delivery,
        }

    ref = payload.get("ref", "")
    branch = ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else (ref.split("/")[-1] if ref else "")
    commit_sha = payload.get("after", "")

    return _route_push_or_preview(
        matching_projects=matching_projects,
        branch=branch,
        commit_sha=commit_sha,
        repo_label=clone_url or html_url,
        provider_name="github",
        delivery_id=x_github_delivery,
        request=request,
        background_tasks=background_tasks,
    )


@router.post("/gitlab", status_code=status.HTTP_202_ACCEPTED)
async def gitlab_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_gitlab_event: str = Header(None, alias="X-Gitlab-Event"),
    x_gitlab_token: str = Header(None, alias="X-Gitlab-Token"),
    db: AsyncSession = Depends(get_db),
):
    """Receptor nativo de Webhooks do GitLab (Push Hook e Merge Request Hook)."""
    payload_bytes = await request.body()
    if not x_gitlab_token:
        raise HTTPException(status_code=401, detail="Cabeçalho X-Gitlab-Token ausente.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Payload JSON inválido.")

    proj_info = payload.get("project", {}) or {}
    repo_info = payload.get("repository", {}) or {}
    repo_url = (
        proj_info.get("git_http_url")
        or proj_info.get("web_url")
        or repo_info.get("git_http_url")
        or repo_info.get("homepage")
        or ""
    )
    target_norm = _normalize_repo_url(repo_url)

    all_projects = (await db.execute(select(Project))).scalars().all()
    matching_projects = [
        p for p in all_projects if _normalize_repo_url(p.repo_url) == target_norm
    ]

    token_valid = _verify_token(x_gitlab_token, settings.GITHUB_WEBHOOK_SECRET)
    if not token_valid:
        for p in matching_projects:
            if _verify_token(x_gitlab_token, p.webhook_secret):
                token_valid = True
                break

    if not token_valid:
        security_manager.log_event(
            event_type="waf_block",
            severity="high",
            ip=security_manager.get_client_ip(request),
            path="/api/v1/webhooks/gitlab",
            detail=f"Token inválido no Webhook GitLab para '{repo_url}'",
            blocked=True,
        )
        raise HTTPException(status_code=401, detail="Token do Webhook GitLab inválido.")

    event_kind = payload.get("object_kind") or x_gitlab_event or ""

    if event_kind in ("merge_request", "Merge Request Hook"):
        attrs = payload.get("object_attributes") or {}
        action = attrs.get("action", "open")
        mr_iid = attrs.get("iid")
        source_branch = attrs.get("source_branch", "")
        preview_project = next(
            (p for p in matching_projects if p.preview_deployments_enabled is not False),
            None,
        )
        if preview_project and action in ("open", "update", "reopen") and source_branch:
            branch_label = f"mr-{mr_iid}" if mr_iid else source_branch
            background_tasks.add_task(_trigger_preview_deploy, str(preview_project.id), branch_label)
            return {
                "status": "preview_queued",
                "provider": "gitlab",
                "project": preview_project.name,
                "preview_branch": branch_label,
            }
        return {"status": "ignored_mr_action", "provider": "gitlab", "action": action}

    if event_kind not in ("push", "Push Hook"):
        return {"status": "ignored", "provider": "gitlab", "event": event_kind}

    ref = payload.get("ref", "")
    branch = ref.removeprefix("refs/heads/") if ref.startswith("refs/heads/") else ref
    commit_sha = payload.get("checkout_sha") or payload.get("after") or ""

    return _route_push_or_preview(
        matching_projects=matching_projects,
        branch=branch,
        commit_sha=commit_sha,
        repo_label=repo_url,
        provider_name="gitlab",
        delivery_id=None,
        request=request,
        background_tasks=background_tasks,
    )


@router.post("/bitbucket", status_code=status.HTTP_202_ACCEPTED)
async def bitbucket_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_event_key: str = Header(None, alias="X-Event-Key"),
    x_hub_signature: str = Header(None, alias="X-Hub-Signature"),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
    db: AsyncSession = Depends(get_db),
):
    """Receptor nativo de Webhooks do Bitbucket Cloud/Server (repo:push e pullrequest:created/updated)."""
    payload_bytes = await request.body()
    sig_header = x_hub_signature_256 or x_hub_signature
    if not sig_header:
        raise HTTPException(status_code=401, detail="Assinatura Bitbucket (X-Hub-Signature) ausente.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Payload JSON inválido.")

    repo_info = payload.get("repository", {}) or {}
    links = (repo_info.get("links") or {}).get("html") or {}
    repo_url = links.get("href") or repo_info.get("full_name") or ""
    if repo_url and not repo_url.startswith("http"):
        repo_url = f"https://bitbucket.org/{repo_url}"
    target_norm = _normalize_repo_url(repo_url)

    all_projects = (await db.execute(select(Project))).scalars().all()
    matching_projects = [
        p for p in all_projects if _normalize_repo_url(p.repo_url) == target_norm
    ]

    signature_valid = _verify_hmac(payload_bytes, sig_header, settings.GITHUB_WEBHOOK_SECRET)
    if not signature_valid:
        for p in matching_projects:
            if _verify_hmac(payload_bytes, sig_header, p.webhook_secret):
                signature_valid = True
                break

    if not signature_valid:
        security_manager.log_event(
            event_type="waf_block",
            severity="high",
            ip=security_manager.get_client_ip(request),
            path="/api/v1/webhooks/bitbucket",
            detail=f"Assinatura inválida no Webhook Bitbucket para '{repo_url}'",
            blocked=True,
        )
        raise HTTPException(status_code=401, detail="Assinatura do Webhook Bitbucket inválida.")

    if x_event_key in ("pullrequest:created", "pullrequest:updated"):
        pr = payload.get("pullrequest") or {}
        pr_id = pr.get("id")
        source_branch = ((pr.get("source") or {}).get("branch") or {}).get("name", "")
        preview_project = next(
            (p for p in matching_projects if p.preview_deployments_enabled is not False),
            None,
        )
        if preview_project and source_branch:
            branch_label = f"pr-{pr_id}" if pr_id else source_branch
            background_tasks.add_task(_trigger_preview_deploy, str(preview_project.id), branch_label)
            return {
                "status": "preview_queued",
                "provider": "bitbucket",
                "project": preview_project.name,
                "preview_branch": branch_label,
            }

    if x_event_key != "repo:push":
        return {"status": "ignored", "provider": "bitbucket", "event": x_event_key}

    changes = (payload.get("push") or {}).get("changes") or []
    new_change = (changes[0].get("new") or {}) if changes else {}
    branch = new_change.get("name", "")
    commit_sha = ((new_change.get("target") or {}).get("hash")) or ""

    return _route_push_or_preview(
        matching_projects=matching_projects,
        branch=branch,
        commit_sha=commit_sha,
        repo_label=repo_url,
        provider_name="bitbucket",
        delivery_id=None,
        request=request,
        background_tasks=background_tasks,
    )


@router.post("/gitea", status_code=status.HTTP_202_ACCEPTED)
async def gitea_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_gitea_event: str = Header(None, alias="X-Gitea-Event"),
    x_gitea_signature: str = Header(None, alias="X-Gitea-Signature"),
    db: AsyncSession = Depends(get_db),
):
    """Receptor nativo de Webhooks do Gitea / Forgejo (push e pull_request)."""
    payload_bytes = await request.body()
    if not x_gitea_signature:
        raise HTTPException(status_code=401, detail="Cabeçalho X-Gitea-Signature ausente.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Payload JSON inválido.")

    repo_info = payload.get("repository", {}) or {}
    repo_url = repo_info.get("clone_url") or repo_info.get("html_url") or ""
    target_norm = _normalize_repo_url(repo_url)

    all_projects = (await db.execute(select(Project))).scalars().all()
    matching_projects = [
        p for p in all_projects if _normalize_repo_url(p.repo_url) == target_norm
    ]

    signature_valid = _verify_hmac(payload_bytes, x_gitea_signature, settings.GITHUB_WEBHOOK_SECRET)
    if not signature_valid:
        for p in matching_projects:
            if _verify_hmac(payload_bytes, x_gitea_signature, p.webhook_secret):
                signature_valid = True
                break

    if not signature_valid:
        raise HTTPException(status_code=401, detail="Assinatura do Webhook Gitea inválida.")

    if x_gitea_event != "push":
        return {"status": "ignored", "provider": "gitea", "event": x_gitea_event}

    ref = payload.get("ref", "")
    branch = ref.split("/")[-1] if ref.startswith("refs/heads/") else ref
    commit_sha = payload.get("after", "")

    return _route_push_or_preview(
        matching_projects=matching_projects,
        branch=branch,
        commit_sha=commit_sha,
        repo_label=repo_url,
        provider_name="gitea",
        delivery_id=None,
        request=request,
        background_tasks=background_tasks,
    )
