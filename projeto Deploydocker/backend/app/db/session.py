"""
Configuração do banco de dados PostgreSQL com SQLAlchemy 2.0 async.

Utiliza asyncpg como driver assíncrono para PostgreSQL.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

import app.models.deployment  # noqa: F401
import app.models.environment  # noqa: F401

# Importar todos os modelos para que Base.metadata os registre antes do create_all.
# Sem esses imports, o SQLAlchemy não encontra as tabelas ao chamar metadata.create_all().
import app.models.project  # noqa: F401
import app.models.telemetry  # noqa: F401
import app.models.user  # noqa: F401
from app.core.config import settings
from app.db.base import Base

# Engine assíncrona
is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine_kwargs: dict = {"echo": False}
if is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({
        "pool_size": 10,
        "max_overflow": 20,
        "pool_pre_ping": True,
    })

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

# Factory de sessões assíncronas
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Injeção de dependência para rotas FastAPI.
    Gerencia o ciclo de vida da sessão com commit/rollback automático.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def _create_and_migrate(sync_conn) -> None:
    """
    Cria as tabelas e adiciona colunas novas em tabelas já existentes.

    `create_all` não altera tabelas existentes; este passo leve garante que bancos
    criados em versões anteriores recebam as novas colunas (ex.: subdomain).
    Colunas únicas recebem um índice UNIQUE separado (compatível com SQLite).
    """
    from sqlalchemy import inspect, text

    Base.metadata.create_all(sync_conn)
    inspector = inspect(sync_conn)
    preparer = sync_conn.dialect.identifier_preparer

    for table in Base.metadata.sorted_tables:
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            col_type = column.type.compile(dialect=sync_conn.dialect)
            sync_conn.execute(text(
                f"ALTER TABLE {preparer.quote(table.name)} "
                f"ADD COLUMN {preparer.quote(column.name)} {col_type}"
            ))
            if column.unique:
                sync_conn.execute(text(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS "
                    f"{preparer.quote(f'uq_{table.name}_{column.name}')} "
                    f"ON {preparer.quote(table.name)} ({preparer.quote(column.name)})"
                ))


async def _seed_initial_admin() -> None:
    """Garante que as primeiras credenciais de administrador existam no banco."""
    import logging

    from sqlalchemy import select

    from app.core.security import get_password_hash
    from app.models.user import User

    logger = logging.getLogger("deploydock")

    async with async_session_factory() as session:
        result = await session.execute(
            select(User).where(User.username == settings.INITIAL_ADMIN_USERNAME)
        )
        existing_admin = result.scalar_one_or_none()
        if not existing_admin:
            admin = User(
                username=settings.INITIAL_ADMIN_USERNAME,
                email=settings.INITIAL_ADMIN_EMAIL,
                hashed_password=get_password_hash(settings.INITIAL_ADMIN_PASSWORD),
                role="admin",
                is_active=True,
            )
            session.add(admin)
            await session.commit()
            logger.info(
                f"[Segurança] Usuário administrador inicial criado com sucesso: "
                f"username='{settings.INITIAL_ADMIN_USERNAME}', email='{settings.INITIAL_ADMIN_EMAIL}'"
            )


async def init_db() -> None:
    """Cria todas as tabelas no banco de dados se não existirem e semeia admin inicial."""
    global engine, async_session_factory
    try:
        async with engine.begin() as conn:
            await conn.run_sync(_create_and_migrate)
    except Exception as e:
        if "postgresql" in settings.DATABASE_URL:
            import logging
            logger = logging.getLogger("deploydock")
            logger.warning(
                f"PostgreSQL indisponível ({e}). Alternando para SQLite local (deploydock.db)..."
            )
            engine = create_async_engine(
                "sqlite+aiosqlite:///deploydock.db",
                connect_args={"check_same_thread": False},
            )
            async_session_factory = async_sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False,
            )
            async with engine.begin() as conn:
                await conn.run_sync(_create_and_migrate)
        else:
            raise

    # Criar credenciais de admin inicial
    try:
        await _seed_initial_admin()
    except Exception as e:
        import logging
        logging.getLogger("deploydock").warning(f"Erro ao verificar/criar usuário admin: {e}")
