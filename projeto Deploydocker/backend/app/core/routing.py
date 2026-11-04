"""
Roteamento público das aplicações implantadas.

Cada projeto recebe uma URL pública servida pelo proxy reverso (Traefik):
  - subdomínio  -> <subdomain>.<APPS_BASE_DOMAIN>   (ex.: meusite.localhost)
  - domínio próprio (opcional) -> substitui o host padrão (ex.: www.meusite.com.br)

O Traefik descobre os contêineres pelas labels geradas em `build_traefik_labels`.
"""

import re
import unicodedata

from app.core.config import settings

SUBDOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)


def slugify(value: str) -> str:
    """Converte um texto livre em um subdomínio válido (ex.: 'Meu Site!' -> 'meu-site')."""
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:63].strip("-") or "app"


def normalize_subdomain(value: str) -> str:
    value = (value or "").strip().lower()
    if not SUBDOMAIN_RE.match(value):
        raise ValueError(
            "Subdomínio inválido: use apenas letras minúsculas, números e hífens "
            "(1-63 caracteres, sem começar/terminar com hífen)."
        )
    return value


def normalize_domain(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().lower()
    value = re.sub(r"^https?://", "", value).split("/")[0]
    if not value:
        return None
    if not DOMAIN_RE.match(value):
        raise ValueError("Domínio inválido. Exemplo válido: www.meusite.com.br")
    return value


def project_host(subdomain: str | None, custom_domain: str | None, name: str) -> str:
    """Host público do projeto (domínio próprio tem prioridade sobre o subdomínio)."""
    if custom_domain:
        return custom_domain
    return f"{subdomain or slugify(name)}.{settings.APPS_BASE_DOMAIN}"


def public_url(host: str) -> str:
    if settings.APPS_TLS_ENABLED:
        scheme, port, default = "https", settings.PROXY_HTTPS_PORT, 443
    else:
        scheme, port, default = "http", settings.PROXY_HTTP_PORT, 80
    suffix = "" if port == default else f":{port}"
    return f"{scheme}://{host}{suffix}"


def build_traefik_labels(project_id: str, host: str, container_port: int | None) -> dict[str, str]:
    """Labels Docker lidas pelo Traefik para expor o contêiner no host informado (com HTTP->HTTPS em produção)."""
    key = f"dd-{project_id.replace('-', '')[:12]}"
    labels = {
        "traefik.enable": "true",
        "traefik.docker.network": settings.APPS_NETWORK,
        "deploydock.project_id": project_id,
        "deploydock.host": host,
        f"traefik.http.routers.{key}.rule": f"Host(`{host}`)",
    }
    if settings.APPS_TLS_ENABLED:
        labels[f"traefik.http.routers.{key}.entrypoints"] = "websecure"
        labels[f"traefik.http.routers.{key}.tls"] = "true"
        labels[f"traefik.http.routers.{key}.tls.certresolver"] = settings.TRAEFIK_CERT_RESOLVER
        # Router HTTP na porta 80 que redireciona automaticamente para HTTPS (443)
        labels[f"traefik.http.routers.{key}-http.rule"] = f"Host(`{host}`)"
        labels[f"traefik.http.routers.{key}-http.entrypoints"] = "web"
        labels[f"traefik.http.routers.{key}-http.middlewares"] = f"{key}-https-redirect"
        labels[f"traefik.http.middlewares.{key}-https-redirect.redirectscheme.scheme"] = "https"
        labels[f"traefik.http.middlewares.{key}-https-redirect.redirectscheme.permanent"] = "true"
    else:
        labels[f"traefik.http.routers.{key}.entrypoints"] = "web"
    if container_port:
        labels[f"traefik.http.routers.{key}.service"] = key
        labels[f"traefik.http.services.{key}.loadbalancer.server.port"] = str(container_port)
    return labels

