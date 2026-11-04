import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request

from app.core.config import settings

JWT_ALGORITHM = "HS256"


def _derive_fernet_key(secret: str) -> bytes:
    """
    Deriva uma chave Fernet de 32 bytes (base64url) a partir do SECRET_KEY.
    """
    key_bytes = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(key_bytes)


fernet = Fernet(_derive_fernet_key(settings.SECRET_KEY))


def get_password_hash(password: str) -> str:
    """Gera hash PBKDF2-HMAC-SHA256 com salt aleatório."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2:sha256:100000${salt.hex()}${dk.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha em texto puro confere com o hash armazenado."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 3:
            return False
        header, salt_hex, hash_hex = parts
        _, _, iterations_str = header.split(":")
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected_dk = bytes.fromhex(hash_hex)
        dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(dk, expected_dk)
    except Exception:
        return False


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Cria um token JWT codificado com expiração."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decodifica e valida o token JWT."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Token inválido ou expirado: {e}")


async def verify_github_signature(request: Request) -> bytes:
    """Valida a assinatura HMAC-SHA256 do webhook do GitHub."""
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature")

    payload_body = await request.body()
    secret = settings.GITHUB_WEBHOOK_SECRET.encode("utf-8")
    expected_signature = (
        "sha256=" + hmac.new(secret, payload_body, digestmod=hashlib.sha256).hexdigest()
    )

    if not hmac.compare_digest(signature_header, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    return payload_body


def encrypt_value(value: str) -> str:
    """Encripta um valor usando Fernet (AES-128-CBC + HMAC-SHA256)."""
    return fernet.encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    """Decripta um valor previamente encriptado com encrypt_value."""
    return fernet.decrypt(encrypted.encode()).decode()


# ----------------------------------------------------------------
# Autenticação em Duas Etapas — 2FA / TOTP (RFC 6238 HMAC-SHA1)
# ----------------------------------------------------------------


def generate_totp_secret(length: int = 20) -> str:
    """Gera um segredo TOTP aleatório codificado em Base32 (compatível com Google Authenticator / Authy)."""
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def compute_totp(
    secret: str,
    timestamp: int | None = None,
    step: int = 30,
    digits: int = 6,
) -> str:
    """Calcula o código TOTP de 6 dígitos para o instante informado (RFC 6238)."""
    clean_secret = (secret or "").strip().upper().replace(" ", "")
    padding = (8 - len(clean_secret) % 8) % 8
    key = base64.b32decode(clean_secret + ("=" * padding), casefold=True)
    ts = int(timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp())
    counter = int(ts // step)
    msg = counter.to_bytes(8, byteorder="big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(code_int % (10**digits)).zfill(digits)


def verify_totp(
    secret: str,
    code: str,
    window: int = 1,
    timestamp: int | None = None,
    step: int = 30,
) -> bool:
    """Valida um código TOTP de 6 dígitos tolerando ±window janelas de 30s em tempo constante."""
    if not secret or not code:
        return False
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit() or len(candidate) != 6:
        return False
    ts = int(timestamp if timestamp is not None else datetime.now(timezone.utc).timestamp())
    for offset in range(-window, window + 1):
        expected = compute_totp(secret, timestamp=ts + (offset * step), step=step)
        if hmac.compare_digest(candidate, expected):
            return True
    return False


def build_totp_uri(secret: str, username: str, issuer: str = "DeployDock") -> str:
    """Gera a URI otpauth:// padrão para leitura via QR Code em apps autenticadores."""
    from urllib.parse import quote

    label = quote(f"{issuer}:{username}")
    issuer_q = quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_q}&algorithm=SHA1&digits=6&period=30"
