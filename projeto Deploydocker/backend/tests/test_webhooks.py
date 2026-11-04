"""RF de GitOps: validação HMAC do webhook do GitHub e roteamento de eventos."""

import hashlib
import hmac
import json

import pytest

from app.api.v1.endpoints.webhooks import _normalize_repo_url, _verify_hmac
from app.core.config import settings


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── Unitários ────────────────────────────────────────────────────────────

def test_verify_hmac_accepts_valid_signature():
    body = b'{"a":1}'
    assert _verify_hmac(body, sign(body, "s3"), "s3")


@pytest.mark.parametrize(
    "header,secret",
    [(None, "s"), ("", "s"), ("sha256=abc", "s"), ("sha256=abc", None), ("sha256=abc", "")],
)
def test_verify_hmac_rejects_invalid(header, secret):
    assert _verify_hmac(b"corpo", header, secret) is False


def test_verify_hmac_detects_body_tampering():
    original = b'{"ref":"refs/heads/main"}'
    sig = sign(original, "s3")
    assert not _verify_hmac(b'{"ref":"refs/heads/evil"}', sig, "s3")


@pytest.mark.parametrize(
    "a,b",
    [
        ("https://github.com/User/Repo.git", "https://github.com/user/repo"),
        ("https://github.com/user/repo/", "https://github.com/user/repo.git"),
    ],
)
def test_repo_url_normalization(a, b):
    assert _normalize_repo_url(a) == _normalize_repo_url(b)


# ── Integração via HTTP ──────────────────────────────────────────────────

def _post(client, event, payload, secret=None, signature=None):
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "Content-Type": "application/json"}
    if signature is not None:
        headers["X-Hub-Signature-256"] = signature
    elif secret is not None:
        headers["X-Hub-Signature-256"] = sign(body, secret)
    return client.post("/api/v1/webhooks/github", content=body, headers=headers)


REPO = {"repository": {"clone_url": "https://github.com/exemplo/inexistente.git"}}


def test_webhook_without_signature_is_401(client):
    assert _post(client, "ping", REPO).status_code == 401


def test_webhook_with_wrong_signature_is_401(client):
    assert _post(client, "ping", REPO, secret="segredo-errado").status_code == 401


def test_webhook_with_global_secret_ping_is_pong(client):
    r = _post(client, "ping", REPO, secret=settings.GITHUB_WEBHOOK_SECRET)
    assert r.status_code == 202
    assert r.json()["status"] == "pong"


def test_webhook_push_without_matching_project_is_not_deployed(client):
    payload = {**REPO, "ref": "refs/heads/main", "after": "a" * 40}
    r = _post(client, "push", payload, secret=settings.GITHUB_WEBHOOK_SECRET)
    assert r.status_code == 202
    assert r.json()["status"] == "no_matching_project"


def test_webhook_unhandled_event_is_ignored(client):
    r = _post(client, "issues", REPO, secret=settings.GITHUB_WEBHOOK_SECRET)
    assert r.json()["status"] == "ignored"


def test_webhook_invalid_json_is_400(client):
    r = client.post(
        "/api/v1/webhooks/github",
        content=b"nao-e-json",
        headers={"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=00"},
    )
    assert r.status_code == 400
