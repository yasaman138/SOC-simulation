"""Detection Engine & Alerting Domain Models with MITRE ATT&CK Mapping."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class MitreTactic(str, Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class MitreAttackInfo(BaseModel):
    """MITRE ATT&CK technique reference mapping."""

    tactic: MitreTactic = MitreTactic.EXECUTION
    technique_id: str = "T1059"
    technique_name: str = "Command and Scripting Interpreter"
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    url: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AffectedEntities(BaseModel):
    host: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    process: Optional[str] = None


class Alert(BaseModel):
    """Structured Security Alert produced by Detection Rules."""

    id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:10].upper()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    rule_id: str
    rule_name: str
    severity: EventSeverity = EventSeverity.MEDIUM
    mitre_attack: Optional[MitreAttackInfo] = None
    title: str
    description: str
    source_event_ids: List[str] = Field(default_factory=list)
    source_events: List[Dict[str, Any]] = Field(default_factory=list)
    affected_entities: AffectedEntities = Field(
        default_factory=AffectedEntities
    )
    status: AlertStatus = AlertStatus.NEW
    context: Dict[str, Any] = Field(default_factory=dict)
    investigation_hints: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class DetectionRule(BaseModel, ABC):
    """Abstract Base Class defining a Detection Rule specification."""

    id: str
    name: str
    description: str
    severity: EventSeverity = EventSeverity.MEDIUM
    mitre_attack: MitreAttackInfo
    data_sources: List[str] = Field(default_factory=list)
    why: str
    references: List[str] = Field(default_factory=list)
    enabled: bool = True

    @abstractmethod
    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        """Evaluate event against detection logic. Return Alert if matched, None otherwise."""
        pass

    def to_metadata_dict(self) -> Dict[str, Any]:
        """Export declarative rule metadata."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "mitre_attack": self.mitre_attack.to_dict(),
            "data_sources": self.data_sources,
            "why": self.why,
            "references": self.references,
            "enabled": self.enabled,
        }


class AlertQuery(BaseModel):
    """Filter parameters for querying generated security alerts."""

    severity: Optional[EventSeverity] = None
    rule_id: Optional[str] = None
    status: Optional[AlertStatus] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0
