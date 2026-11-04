"""
Gateway Reverso Integrado (/open/{target}/...) para acesso externo a contêineres e projetos.

Permite abrir qualquer aplicação implantada no DeployDock (via Traefik `.localhost`
ou porta mapeada `localhost:<porta>`) diretamente pelo mesmo túnel externo (Cloudflare,
ngrok, LocalTunnel ou IP da LAN) sem precisar abrir múltiplos túneis ou configurar DNS curinga.
"""

import re
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.services.docker_service import DockerService

router = APIRouter()

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "content-encoding",
    "host",
}

_ATTR_ROOT_RE = re.compile(
    r'(\b(?:href|src|action)\s*=\s*["\'])/(?!/|open/)',
    re.IGNORECASE,
)


def _inject_gateway_shim(html: str, prefix: str) -> str:
    """
    Reescreve atributos HTML absolutos (`href="/..."`, `src="/..."`) e injeta um shim
    leve para que `fetch('/api/...')` e `XMLHttpRequest` dentro do contêiner também
    sejam roteados automaticamente por `/open/{target}/...`.
    """
    rewritten = _ATTR_ROOT_RE.sub(rf"\1{prefix}/", html)
    shim = (
        f'<base href="{prefix}/">'
        "<script>(function(){"
        f"var P={prefix!r};"
        "function rw(u){return (typeof u==='string'&&u.charAt(0)==='/'&&u.charAt(1)!=='/'&&u.indexOf(P+'/')!==0)?P+u:u;}"
        "var oF=window.fetch;"
        "if(oF){window.fetch=function(i,init){return oF.call(this,rw(i),init);};}"
        "var oX=XMLHttpRequest.prototype.open;"
        "XMLHttpRequest.prototype.open=function(m,u){arguments[1]=rw(u);return oX.apply(this,arguments);};"
        "})();</script>"
    )
    if re.search(r"<head[^>]*>", rewritten, re.IGNORECASE):
        return re.sub(
            r"(<head[^>]*>)",
            lambda m: f"{m.group(1)}{shim}",
            rewritten,
            count=1,
            flags=re.IGNORECASE,
        )
    return shim + rewritten


async def _find_container_host_port(target: str) -> Optional[int]:
    """Procura a porta de host mapeada de um contêiner pelo nome, subdomínio ou porta."""
    if target.startswith("port-") and target[5:].isdigit():
        return int(target[5:])
    if target.isdigit():
        return int(target)

    clean = target.strip().lower()
    candidates = {
        clean,
        clean.replace("-", "_"),
        f"deploydock_{clean}",
        f"deploydock_{clean.replace('-', '_')}",
    }
    try:
        docker = DockerService()
        containers = await docker.list_containers(all=False)
        for c in containers:
            cname = (c.get("name") or "").lower()
            labels = c.get("labels") or {}
            host_label = (labels.get("deploydock.host") or "").lower()
            if (
                cname in candidates
                or host_label == f"{clean}.{settings.APPS_BASE_DOMAIN}".lower()
                or cname.endswith(f"_{clean}")
                or cname.endswith(f"_{clean.replace('-', '_')}")
            ):
                ports = c.get("ports") or {}
                for bindings in ports.values():
                    if isinstance(bindings, list):
                        for b in bindings:
                            if isinstance(b, dict) and b.get("HostPort"):
                                return int(b["HostPort"])
    except Exception:
        pass
    return None


@router.api_route(
    "/{target}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def gateway_root(target: str, request: Request) -> Response:
    """Para GET sem barra, redireciona para /{target}/. Para outros métodos HTTP, repassa diretamente."""
    if request.method == "GET":
        qs = f"?{request.url.query}" if request.url.query else ""
        return RedirectResponse(url=f"/open/{target}/{qs}", status_code=307)
    return await gateway_proxy(target=target, subpath="", request=request)


@router.api_route(
    "/{target}/{subpath:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def gateway_proxy(target: str, subpath: str, request: Request) -> Response:
    """Encaminha requisições HTTP para o contêiner/projeto via Traefik ou porta mapeada."""
    query = f"?{request.url.query}" if request.url.query else ""
    body = await request.body()

    fwd_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS and k.lower() != "accept-encoding"
    }
    fwd_headers["accept-encoding"] = "identity"

    upstream_resp: Optional[httpx.Response] = None
    proxy_port = settings.PROXY_HTTP_PORT or 80

    async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
        # 1. Se não for porta explícita, tenta primeiro via Traefik (Host: <target>.<APPS_BASE_DOMAIN>)
        if not target.startswith("port-") and not target.isdigit():
            traefik_host = (
                target
                if "." in target
                else f"{target}.{settings.APPS_BASE_DOMAIN}"
            )
            try:
                resp = await client.request(
                    method=request.method,
                    url=f"http://127.0.0.1:{proxy_port}/{subpath}{query}",
                    headers={**fwd_headers, "Host": traefik_host},
                    content=body,
                )
                if resp.status_code != 404:
                    upstream_resp = resp
            except Exception:
                upstream_resp = None

        # 2. Fallback (ou acesso direto por porta/contêiner) via HostPort mapeada no Docker
        if upstream_resp is None:
            host_port = await _find_container_host_port(target)
            if not host_port:
                raise HTTPException(
                    status_code=502,
                    detail=f"Aplicação ou contêiner '{target}' não encontrado ou sem porta HTTP ativa.",
                )
            
            # Tenta 127.0.0.1 e fallbacks para redes Docker
            candidate_hosts = ["127.0.0.1", "host.docker.internal", "172.17.0.1"]
            last_err = None
            for h in candidate_hosts:
                try:
                    upstream_resp = await client.request(
                        method=request.method,
                        url=f"http://{h}:{host_port}/{subpath}{query}",
                        headers=fwd_headers,
                        content=body,
                    )
                    break
                except Exception as e:
                    last_err = e

            if upstream_resp is None:
                raise HTTPException(
                    status_code=502,
                    detail=f"Erro ao conectar ao contêiner '{target}' na porta {host_port}: {last_err}",
                )

    resp_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }
    prefix = f"/open/{target}"
    if "location" in resp_headers and resp_headers["location"].startswith("/"):
        resp_headers["location"] = f"{prefix}{resp_headers['location']}"

    content_type = upstream_resp.headers.get("content-type", "")
    content_bytes = upstream_resp.content
    if "text/html" in content_type.lower():
        try:
            decoded = content_bytes.decode("utf-8", errors="replace")
            patched = _inject_gateway_shim(decoded, prefix)
            content_bytes = patched.encode("utf-8")
        except Exception:
            pass

    return Response(
        content=content_bytes,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=content_type.split(";")[0].strip() if content_type else None,
    )
