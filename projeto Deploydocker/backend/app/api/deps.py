import uuid

from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.user import User
from app.services.docker_service import DockerService

security_scheme = HTTPBearer(auto_error=False)


async def authenticate_websocket(websocket: WebSocket) -> User | None:
    """
    Autentica uma conexão WebSocket via query string `?token=<JWT>`.

    Navegadores não permitem cabeçalhos customizados em WebSocket, então o JWT
    é enviado como parâmetro. Retorna o usuário ou None (conexão deve ser recusada).
    """
    token = websocket.query_params.get("token")
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        user_id = uuid.UUID(payload.get("sub", ""))
    except (HTTPException, ValueError, TypeError):
        return None
    from app.db import session as db_session  # import tardio: a factory pode ser recriada no fallback SQLite

    async with db_session.async_session_factory() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    if not user or not user.is_active:
        return None
    return user


def get_docker_service() -> DockerService:
    return DockerService()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extrai e valida o usuário a partir do token Bearer JWT."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação necessária. Por favor, faça login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido.",
        )
    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identificador de usuário inválido no token.",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário inativo ou inexistente.",
        )
    return user


def require_role(*allowed_roles: str):
    """
    Dependency factory que exige que o usuário tenha um dos papéis informados.
    Por exemplo: Depends(require_role('admin'))
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permissão insuficiente. Nível exigido: {', '.join(allowed_roles)}. Seu nível atual: {current_user.role}.",
            )
        return current_user

    return role_checker
