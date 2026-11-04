import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class DeploymentBase(BaseModel):
    project_id: uuid.UUID
    commit_sha: str
    branch: str
    status: str = "pending"

class DeploymentRead(DeploymentBase):
    id: uuid.UUID
    commit_message: Optional[str] = None
    commit_author: Optional[str] = None
    build_logs: Optional[str] = None
    error_message: Optional[str] = None
    previous_image_id: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: datetime
    finished_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class DeploymentList(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    commit_sha: str
    commit_message: Optional[str] = None
    commit_author: Optional[str] = None
    branch: str
    status: str
    build_logs: Optional[str] = None
    error_message: Optional[str] = None
    previous_image_id: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: datetime
    finished_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class DeploymentTrigger(BaseModel):
    project_id: uuid.UUID
    commit_sha: Optional[str] = None
    branch: Optional[str] = None

