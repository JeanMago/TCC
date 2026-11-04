"""RNF de segurança: hash de senhas, JWT e criptografia de segredos."""

from datetime import timedelta

import jwt
import pytest
from fastapi import HTTPException

from app.core.config import Settings, settings
from app.core.security import (
    JWT_ALGORITHM,
    create_access_token,
    decode_access_token,
    get_password_hash,
    verify_password,
)


def test_password_hash_is_salted_and_verifiable():
    h1 = get_password_hash("segredo")
    h2 = get_password_hash("segredo")
    assert h1 != h2, "hashes iguais indicam ausência de salt"
    assert verify_password("segredo", h1)
    assert verify_password("segredo", h2)
    assert not verify_password("outra", h1)


@pytest.mark.parametrize("bad_hash", ["", "texto-puro", "a$b", "pbkdf2:sha256:abc$zz$zz"])
def test_verify_password_rejects_malformed_hash(bad_hash):
    assert verify_password("x", bad_hash) is False


def test_jwt_roundtrip():
    token = create_access_token({"sub": "123", "role": "admin"})
    payload = decode_access_token(token)
    assert payload["sub"] == "123"
    assert payload["role"] == "admin"
    assert "exp" in payload


def test_jwt_expired_is_rejected():
    token = create_access_token({"sub": "1"}, expires_delta=timedelta(seconds=-5))
    with pytest.raises(HTTPException) as exc:
        decode_access_token(token)
    assert exc.value.status_code == 401


def test_jwt_tampered_signature_is_rejected():
    forged = jwt.encode({"sub": "1", "role": "admin"}, "outra-chave-qualquer-0123456789abcdef", algorithm=JWT_ALGORITHM)
    with pytest.raises(HTTPException):
        decode_access_token(forged)


def test_jwt_alg_none_is_rejected():
    forged = jwt.encode({"sub": "1"}, key=None, algorithm="none")
    with pytest.raises(HTTPException):
        decode_access_token(forged)


# ── Guarda de configuração insegura em produção ──────────────────────────

def _settings(**overrides) -> Settings:
    base = dict(
        SECRET_KEY="x" * 40,
        GITHUB_WEBHOOK_SECRET="segredo-forte-webhook",
        INITIAL_ADMIN_PASSWORD="Senha-Forte-123!",
        ENVIRONMENT="production",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_secure_settings_have_no_problems():
    s = _settings()
    assert s.insecure_settings() == []
    s.enforce_production_security()  # não deve lançar


@pytest.mark.parametrize(
    "override",
    [
        {"SECRET_KEY": "changeme-secret-key"},
        {"SECRET_KEY": "curta"},
        {"GITHUB_WEBHOOK_SECRET": "changeme"},
        {"INITIAL_ADMIN_PASSWORD": "admin123"},
    ],
)
def test_production_refuses_insecure_defaults(override):
    s = _settings(**override)
    assert s.insecure_settings()
    with pytest.raises(RuntimeError):
        s.enforce_production_security()


def test_development_tolerates_insecure_defaults():
    s = _settings(SECRET_KEY="changeme", ENVIRONMENT="development")
    assert s.insecure_settings()
    s.enforce_production_security()  # apenas avisa; não lança


def test_test_environment_uses_strong_secret():
    assert len(settings.SECRET_KEY) >= 32
