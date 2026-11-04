from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://deploydock:deploydock@localhost:5432/deploydock"
    GITHUB_WEBHOOK_SECRET: str = "changeme"
    SECRET_KEY: str = "changeme-secret-key"
    DOCKER_HOST: str | None = None
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]
    APP_NAME: str = "DeployDock"
    REPOS_BASE_PATH: str = "/app/repos"
    HEALTH_CHECK_TIMEOUT: int = 30
    HEALTH_CHECK_RETRIES: int = 3
    # Blue/green: segundos de sobreposição (old+new no ar) antes de remover a versão anterior.
    BLUE_GREEN_DRAIN_SECONDS: float = 5.0
    # Blue/green sem health_check_url: tempo mínimo que o candidato deve permanecer 'running'.
    BLUE_GREEN_MIN_UPTIME_SECONDS: float = 5.0

    # --- URLs públicas das aplicações (proxy reverso Traefik) ---
    # Domínio base: cada projeto vira "<subdominio>.<APPS_BASE_DOMAIN>".
    #   Local:     localhost  -> http://meusite.localhost
    #   Produção:  seudominio.com -> https://meusite.seudominio.com (requer DNS wildcard *.seudominio.com)
    APPS_BASE_DOMAIN: str = "localhost"
    # Ativa HTTPS (Let's Encrypt via Traefik). Use true em produção.
    APPS_TLS_ENABLED: bool = False
    # Porta pública do proxy (usada apenas para montar o link quando não é 80/443).
    PROXY_HTTP_PORT: int = 80
    PROXY_HTTPS_PORT: int = 443
    # Rede Docker compartilhada entre o Traefik e os contêineres dos projetos.
    APPS_NETWORK: str = "deploydock-apps"
    # Nome do certresolver configurado no Traefik (docker-compose.yml).
    TRAEFIK_CERT_RESOLVER: str = "letsencrypt"

    # --- Autenticação & Admin Inicial ---
    INITIAL_ADMIN_EMAIL: str = "admin@deploydock.local"
    INITIAL_ADMIN_USERNAME: str = "admin"
    INITIAL_ADMIN_PASSWORD: str = "admin123"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 horas

    # --- Ambiente ---
    # "production" ativa o bloqueio de inicialização com segredos/credenciais padrão inseguros.
    ENVIRONMENT: str = "development"

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), env_file_encoding="utf-8", extra="ignore")

    def insecure_settings(self) -> list[str]:
        """Retorna a lista de configurações que ainda usam valores padrão inseguros."""
        problems: list[str] = []
        weak_secrets = {"changeme", "changeme-secret-key", "change-me-in-production", ""}
        if self.SECRET_KEY in weak_secrets or len(self.SECRET_KEY) < 32:
            problems.append("SECRET_KEY padrão ou curta demais (mínimo 32 caracteres)")
        if self.GITHUB_WEBHOOK_SECRET in weak_secrets:
            problems.append("GITHUB_WEBHOOK_SECRET padrão")
        if self.INITIAL_ADMIN_PASSWORD in {"admin123", "admin", "password", ""}:
            problems.append("INITIAL_ADMIN_PASSWORD padrão")
        return problems

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.strip().lower() == "production"

    def enforce_production_security(self) -> None:
        """Em produção, impede a inicialização com configurações inseguras."""
        problems = self.insecure_settings()
        if problems and self.is_production:
            raise RuntimeError(
                "Configuração insegura em produção: " + "; ".join(problems)
                + ". Defina valores fortes no .env (veja .env.example)."
            )

settings = Settings()
