from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

Severity = Literal["low", "medium", "high", "critical"]

class EventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=80)
    severity: Severity = "low"
    source_ip: IPvAnyAddress | None = None
    message: str = Field(min_length=1, max_length=5000)
    metadata: dict[str, Any] = Field(default_factory=dict)

class EventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: str
    event_type: str
    severity: str
    source_ip: str | None
    message: str
    metadata: dict[str, Any] = Field(validation_alias="event_metadata", serialization_alias="metadata")
    created_at: datetime

class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    event_id: int
    title: str
    description: str
    severity: str
    status: str
    rule_id: str
    created_at: datetime
    acknowledged_at: datetime | None

class SummaryRead(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


class UserRead(BaseModel):
    id: int
    username: str
    role: str
    is_active: bool