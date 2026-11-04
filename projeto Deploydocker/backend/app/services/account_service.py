"""
Serviço de Contas Conectadas (GitHub / Google / Local), Sessões e Controle de Acesso Admin.

Gerencia:
- Login e vinculação de contas Git (GitHub OAuth / PAT / Device Flow) e Google (OAuth2 / ID Token / E-mail)
- Metadados de contas (tipo de conta, provedores vinculados, avatar, último login, preferências de e-mail)
- Políticas administrativas de acesso (quais tipos de conta podem logar, auto-registro OAuth, role padrão, domínios permitidos)
- Registro de sessões ativas e revogação administrativa de acesso
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AccountAccessManager:
    """Gerenciador central de identidades OAuth (Git/Google), sessões e políticas de acesso."""

    def __init__(self) -> None:
        base_dir = getattr(settings, "REPOS_BASE_PATH", "/tmp") or "/tmp"
        self._state_path = os.path.join(base_dir, ".deploydock_accounts.json")
        self.policies: dict[str, Any] = {
            "allow_local_login": True,
            "allow_github_login": True,
            "allow_google_login": True,
            "auto_register_oauth": True,
            "default_oauth_role": "developer",  # 'admin' | 'developer' | 'viewer'
            "require_2fa_for_admins": False,
            "allowed_email_domains": "*",
            "github_oauth_client_id": "Iv1.b507a08c87ecfe98",
            "google_oauth_client_id": "",
        }
        # user_id (str) -> dict com metadados de provedores e preferências
        self.users_meta: dict[str, dict[str, Any]] = {}
        # lista de sessões registradas (mais recentes primeiro)
        self.sessions: list[dict[str, Any]] = []
        self._load_state()

    def _load_state(self) -> None:
        if "pytest" in sys.modules:
            return
        try:
            if os.path.isfile(self._state_path):
                with open(self._state_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    if isinstance(data.get("policies"), dict):
                        self.policies.update(data["policies"])
                    if isinstance(data.get("users_meta"), dict):
                        self.users_meta.update(data["users_meta"])
                    if isinstance(data.get("sessions"), list):
                        self.sessions = data["sessions"][:200]
        except Exception as exc:
            logger.debug("Não foi possível carregar estado de contas (%s).", exc)

    def _save_state(self) -> None:
        if "pytest" in sys.modules:
            return
        try:
            parent = os.path.dirname(self._state_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self._state_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "policies": self.policies,
                        "users_meta": self.users_meta,
                        "sessions": self.sessions[:200],
                    },
                    fh,
                    indent=2,
                    ensure_ascii=False,
                )
        except Exception as exc:
            logger.debug("Não foi possível salvar estado de contas (%s).", exc)

    def get_user_meta(
        self, user_id: str, username: str = "", email: str = ""
    ) -> dict[str, Any]:
        uid = str(user_id)
        if uid not in self.users_meta:
            self.users_meta[uid] = {
                "user_id": uid,
                "username": username,
                "email": email,
                "full_name": username,
                "avatar_url": "",
                "account_type": "local",  # local | github | google | hybrid
                "auth_providers": ["local"],
                "github_linked": False,
                "github_username": None,
                "github_email": None,
                "github_avatar_url": None,
                "github_connected_at": None,
                "google_linked": False,
                "google_email": None,
                "google_name": None,
                "google_avatar_url": None,
                "google_sub": None,
                "google_connected_at": None,
                "email_notifications": True,
                "notify_deploy_email": True,
                "notify_security_email": True,
                "last_login_at": None,
                "last_login_provider": "local",
                "last_login_ip": None,
                "revoked_Before_ts": 0.0,
            }
        meta = self.users_meta[uid]
        if username:
            meta["username"] = username
        if email:
            meta["email"] = email
        self._recompute_account_type(meta)
        return meta

    @staticmethod
    def _recompute_account_type(meta: dict[str, Any]) -> None:
        providers: list[str] = list(meta.get("auth_providers") or ["local"])
        if meta.get("github_linked") and "github" not in providers:
            providers.append("github")
        if meta.get("google_linked") and "google" not in providers:
            providers.append("google")
        if not providers:
            providers = ["local"]
        meta["auth_providers"] = providers

        has_gh = "github" in providers
        has_gg = "google" in providers
        has_local = "local" in providers
        if (has_gh and has_gg) or (has_local and (has_gh or has_gg)):
            meta["account_type"] = "hybrid"
        elif has_gh:
            meta["account_type"] = "github"
        elif has_gg:
            meta["account_type"] = "google"
        else:
            meta["account_type"] = "local"

    def update_user_profile(
        self,
        user_id: str,
        username: str,
        email: str,
        updates: dict[str, Any],
    ) -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        for key in (
            "full_name",
            "avatar_url",
            "email_notifications",
            "notify_deploy_email",
            "notify_security_email",
        ):
            if key in updates and updates[key] is not None:
                meta[key] = updates[key]
        self._recompute_account_type(meta)
        self._save_state()
        return meta

    def link_github_account(
        self,
        user_id: str,
        username: str,
        email: str,
        github_username: str,
        github_email: str | None = None,
        github_avatar_url: str | None = None,
        github_name: str | None = None,
        is_primary_oauth: bool = False,
    ) -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        meta["github_linked"] = True
        meta["github_username"] = github_username.strip()
        meta["github_email"] = (github_email or email or "").strip()
        meta["github_avatar_url"] = github_avatar_url or meta.get("avatar_url") or ""
        meta["github_connected_at"] = _now_iso()
        if github_avatar_url and not meta.get("avatar_url"):
            meta["avatar_url"] = github_avatar_url
        if github_name and (not meta.get("full_name") or meta.get("full_name") == username):
            meta["full_name"] = github_name
        providers = [p for p in (meta.get("auth_providers") or []) if p != "github"]
        if is_primary_oauth and providers == ["local"]:
            providers = ["github"]
        else:
            providers.append("github")
        meta["auth_providers"] = providers
        self._recompute_account_type(meta)
        self._save_state()
        return meta

    def unlink_github_account(self, user_id: str, username: str = "", email: str = "") -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        meta["github_linked"] = False
        meta["github_username"] = None
        meta["github_email"] = None
        meta["github_connected_at"] = None
        meta["auth_providers"] = [p for p in (meta.get("auth_providers") or []) if p != "github"]
        if not meta["auth_providers"]:
            meta["auth_providers"] = ["local"]
        self._recompute_account_type(meta)
        self._save_state()
        return meta

    def link_google_account(
        self,
        user_id: str,
        username: str,
        email: str,
        google_email: str,
        google_name: str | None = None,
        google_avatar_url: str | None = None,
        google_sub: str | None = None,
        is_primary_oauth: bool = False,
    ) -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        meta["google_linked"] = True
        meta["google_email"] = google_email.strip().lower()
        meta["google_name"] = google_name or google_email.split("@")[0]
        meta["google_avatar_url"] = google_avatar_url or meta.get("avatar_url") or ""
        meta["google_sub"] = google_sub or f"google-{google_email.strip().lower()}"
        meta["google_connected_at"] = _now_iso()
        if google_avatar_url and not meta.get("avatar_url"):
            meta["avatar_url"] = google_avatar_url
        if google_name and (not meta.get("full_name") or meta.get("full_name") == username):
            meta["full_name"] = google_name
        providers = [p for p in (meta.get("auth_providers") or []) if p != "google"]
        if is_primary_oauth and providers == ["local"]:
            providers = ["google"]
        else:
            providers.append("google")
        meta["auth_providers"] = providers
        self._recompute_account_type(meta)
        self._save_state()
        return meta

    def unlink_google_account(self, user_id: str, username: str = "", email: str = "") -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        meta["google_linked"] = False
        meta["google_email"] = None
        meta["google_name"] = None
        meta["google_sub"] = None
        meta["google_connected_at"] = None
        meta["auth_providers"] = [p for p in (meta.get("auth_providers") or []) if p != "google"]
        if not meta["auth_providers"]:
            meta["auth_providers"] = ["local"]
        self._recompute_account_type(meta)
        self._save_state()
        return meta

    def find_user_id_by_github(self, github_username: str) -> str | None:
        target = (github_username or "").strip().lower()
        if not target:
            return None
        for uid, meta in self.users_meta.items():
            if meta.get("github_linked") and (meta.get("github_username") or "").lower() == target:
                return uid
        return None

    def find_user_id_by_google(self, google_email: str) -> str | None:
        target = (google_email or "").strip().lower()
        if not target:
            return None
        for uid, meta in self.users_meta.items():
            if meta.get("google_linked") and (meta.get("google_email") or "").lower() == target:
                return uid
        return None

    def record_session_login(
        self,
        user_id: str,
        username: str,
        email: str,
        role: str,
        provider: str,
        ip: str,
        user_agent: str = "",
    ) -> dict[str, Any]:
        meta = self.get_user_meta(user_id, username, email)
        now = _now_iso()
        meta["last_login_at"] = now
        meta["last_login_provider"] = provider
        meta["last_login_ip"] = ip

        session_entry = {
            "session_id": f"sess-{uuid.uuid4().hex[:12]}",
            "user_id": str(user_id),
            "username": username,
            "email": email,
            "role": role,
            "provider": provider,  # 'local' | 'github' | 'google'
            "account_type": meta.get("account_type", "local"),
            "ip": ip,
            "user_agent": (user_agent or "Navegador Web")[:120],
            "logged_in_at": now,
            "active": True,
        }
        self.sessions.insert(0, session_entry)
        self.sessions = self.sessions[:200]
        self._save_state()
        return session_entry

    def get_active_sessions_count(self, user_id: str) -> int:
        uid = str(user_id)
        return sum(1 for s in self.sessions if s.get("user_id") == uid and s.get("active", True))

    def revoke_user_sessions(self, user_id: str) -> int:
        uid = str(user_id)
        revoked = 0
        for s in self.sessions:
            if s.get("user_id") == uid and s.get("active", True):
                s["active"] = False
                s["revoked_at"] = _now_iso()
                revoked += 1
        meta = self.users_meta.get(uid)
        if meta:
            meta["revoked_before_ts"] = time.time()
        self._save_state()
        return revoked

    def revoke_single_session(self, session_id: str) -> bool:
        for s in self.sessions:
            if s.get("session_id") == session_id:
                s["active"] = False
                s["revoked_at"] = _now_iso()
                self._save_state()
                return True
        return False

    def update_policies(self, updates: dict[str, Any]) -> dict[str, Any]:
        for k in (
            "allow_local_login",
            "allow_github_login",
            "allow_google_login",
            "auto_register_oauth",
            "default_oauth_role",
            "require_2fa_for_admins",
            "allowed_email_domains",
            "github_oauth_client_id",
            "google_oauth_client_id",
        ):
            if k in updates and updates[k] is not None:
                self.policies[k] = updates[k]
        self._save_state()
        return self.policies

    def is_email_domain_allowed(self, email: str) -> bool:
        allowed_raw = (self.policies.get("allowed_email_domains") or "*").strip()
        if not allowed_raw or allowed_raw == "*":
            return True
        domains = [
            d.strip().lstrip("@").lower()
            for d in allowed_raw.split(",")
            if d.strip() and d.strip() != "*"
        ]
        if not domains:
            return True
        email_domain = (email or "").split("@")[-1].strip().lower()
        return email_domain in domains

    def get_notifiable_emails(self) -> list[str]:
        emails: list[str] = []
        for meta in self.users_meta.values():
            if not meta.get("email_notifications", True):
                continue
            for candidate in (
                meta.get("email"),
                meta.get("google_email"),
                meta.get("github_email"),
            ):
                clean = (candidate or "").strip().lower()
                if clean and "@" in clean and clean not in emails:
                    emails.append(clean)
        return emails


account_access_manager = AccountAccessManager()
