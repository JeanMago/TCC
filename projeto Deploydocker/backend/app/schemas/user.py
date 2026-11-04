import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


class UserBase(BaseModel):
    username: str
    email: str
    role: str = "developer"  # 'admin' | 'developer' | 'viewer'
    is_active: bool = True


class UserCreate(UserBase):
    password: str
    account_type: Optional[str] = "local"
    github_username: Optional[str] = None
    google_email: Optional[str] = None


class UserRead(UserBase):
    id: uuid.UUID
    totp_enabled: bool = False
    full_name: str = ""
    avatar_url: str = ""
    account_type: str = "local"  # 'local' | 'github' | 'google' | 'hybrid'
    auth_providers: list[str] = ["local"]
    github_linked: bool = False
    github_username: Optional[str] = None
    google_linked: bool = False
    google_email: Optional[str] = None
    email_notifications: bool = True
    last_login_at: Optional[str] = None
    last_login_provider: Optional[str] = None
    last_login_ip: Optional[str] = None
    active_sessions_count: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

    @field_validator("totp_enabled", mode="before")
    @classmethod
    def _coerce_totp_enabled(cls, v):
        return bool(v)


class LoginRequest(BaseModel):
    username: str
    password: str
    otp_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserRead
