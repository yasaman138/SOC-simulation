"""Elastic Common Schema (ECS) Data Models for Telemetry Normalization."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


class EventSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    WEB = "web"
    DATABASE = "database"
    NETWORK = "network"
    PROCESS = "process"
    DIRECTORY_SERVICE = "directory_service"
    SYSTEM = "system"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class HostInfo(BaseModel):
    name: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None


class EndpointInfo(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    domain: Optional[str] = None


class UserInfo(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)


class ProcessInfo(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    command_line: Optional[str] = None
    executable: Optional[str] = None


class HTTPInfo(BaseModel):
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None


class EventMetadata(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str = "event"
    category: EventCategory = EventCategory.SYSTEM
    action: str = "unknown"
    outcome: EventOutcome = EventOutcome.SUCCESS
    severity: EventSeverity = EventSeverity.INFORMATIONAL
    dataset: str = "enterprise.security"


class ECSEvent(BaseModel):
    """Elastic Common Schema (ECS) compliant telemetry event."""

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    event: EventMetadata = Field(default_factory=EventMetadata)
    host: Optional[HostInfo] = None
    source: Optional[EndpointInfo] = None
    destination: Optional[EndpointInfo] = None
    user: Optional[UserInfo] = None
    process: Optional[ProcessInfo] = None
    http: Optional[HTTPInfo] = None
    message: str = ""
    custom: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class EventQuery(BaseModel):
    """Filter parameters for querying stored SIEM events."""

    category: Optional[EventCategory] = None
    action: Optional[str] = None
    severity: Optional[EventSeverity] = None
    host_name: Optional[str] = None
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0
