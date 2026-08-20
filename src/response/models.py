"""Incident Response & Investigation Domain Models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.siem.models import EventCategory, EventSeverity


class IncidentStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentDisposition(str, Enum):
    UNRESOLVED = "unresolved"
    TRUE_POSITIVE_MALICIOUS = "true_positive_malicious"
    TRUE_POSITIVE_BENIGN = "true_positive_benign"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"


class ContainmentStatus(str, Enum):
    NOT_CONTAINED = "not_contained"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"


class RemediationStatus(str, Enum):
    NOT_REMEDIATED = "not_remediated"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"


class RecoveryStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    RECOVERED = "recovered"
    VERIFIED = "verified"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    USER = "user"
    HOSTNAME = "hostname"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"
    URL = "url"


class Indicator(BaseModel):
    """Observable Indicator of Compromise (IOC) or suspicious entity."""

    id: str = Field(default_factory=lambda: f"IOC-{uuid4().hex[:8].upper()}")
    type: IndicatorType
    value: str
    context: str = ""
    reputation: str = "suspicious"  # benign, suspicious, malicious, unknown
    confidence: float = 0.8
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class TimelineEntry(BaseModel):
    """Chronological event entry in an incident timeline."""

    id: str = Field(default_factory=lambda: f"TLE-{uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    category: str = "general"
    title: str
    description: str
    source_id: Optional[str] = None
    source_type: str = "event"  # event, alert, analyst_action, forensic_finding
    entities: Dict[str, Any] = Field(default_factory=dict)
    evidence_id: Optional[str] = None
    confidence: float = 1.0
    is_key_event: bool = False
    mitre_technique: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class EvidenceItem(BaseModel):
    """Cryptographically referenced or structured forensic evidence item."""

    id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    evidence_type: str  # log_event, process_dump, network_pcap, registry_export, file_sample
    description: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    source: str = "siem"
    sha256_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class AnalystAction(BaseModel):
    """Documented action taken by a SOC analyst or SOAR automation."""

    id: str = Field(default_factory=lambda: f"ACT-{uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    actor: str  # e.g., "soc_analyst_1", "soar_engine"
    action_type: str  # e.g., "triage", "enrichment", "containment", "manual_investigation"
    description: str
    status: str = "completed"  # pending, in_progress, completed, failed
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class RootCauseAnalysis(BaseModel):
    """Root-cause analysis summary for the incident."""

    summary: str
    initial_vector: str
    attack_path: List[str] = Field(default_factory=list)
    vulnerabilities_exploited: List[str] = Field(default_factory=list)
    impact_assessment: str
    confidence: float = 0.9

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class LessonsLearned(BaseModel):
    """Post-incident review and hardening recommendations."""

    root_cause_summary: str
    detection_gaps: List[str] = Field(default_factory=list)
    preventive_recommendations: List[str] = Field(default_factory=list)
    procedural_improvements: List[str] = Field(default_factory=list)
    hardening_actions: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ResponseActionType(str, Enum):
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    UNISOLATE_ENDPOINT = "unisolate_endpoint"
    BLOCK_IOC = "block_ioc"
    UNBLOCK_IOC = "unblock_ioc"
    TERMINATE_PROCESS = "terminate_process"
    COLLECT_FORENSICS = "collect_forensics"
    REVOKE_SESSIONS = "revoke_sessions"
    RESTORE_BACKUP = "restore_backup"


class ResponseActionResult(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    ALREADY_APPLIED = "already_applied"
    NO_OP = "no_op"


class AuditLogEntry(BaseModel):
    """Immutable audit record for automated and analyst security actions."""

    id: str = Field(default_factory=lambda: f"AUD-{uuid4().hex[:10].upper()}")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    action: ResponseActionType
    actor: str  # User or automated system taking action
    target: str  # Entity being acted upon (user, host, IP, PID)
    reason: str
    result: ResponseActionResult
    details: Dict[str, Any] = Field(default_factory=dict)
    rollback_available: bool = False
    rollback_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class Incident(BaseModel):
    """Structured Security Incident Model across the Incident Response Lifecycle."""

    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid4().hex[:8].upper()}"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.NEW
    title: str
    description: str
    affected_assets: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    indicators: List[Indicator] = Field(default_factory=list)
    detection_source: List[str] = Field(default_factory=list)
    mitre_attack: List[MitreAttackInfo] = Field(default_factory=list)
    timeline: List[TimelineEntry] = Field(default_factory=list)
    analyst_actions: List[AnalystAction] = Field(default_factory=list)
    containment_status: ContainmentStatus = ContainmentStatus.NOT_CONTAINED
    remediation_status: RemediationStatus = RemediationStatus.NOT_REMEDIATED
    recovery_status: RecoveryStatus = RecoveryStatus.PENDING
    evidence_references: List[EvidenceItem] = Field(default_factory=list)
    final_disposition: IncidentDisposition = IncidentDisposition.UNRESOLVED
    root_cause_analysis: Optional[RootCauseAnalysis] = None
    lessons_learned: Optional[LessonsLearned] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def add_timeline_entry(self, entry: TimelineEntry) -> None:
        self.timeline.append(entry)
        self.timeline.sort(key=lambda x: x.timestamp)

    def add_indicator(self, indicator: Indicator) -> None:
        # Deduplicate indicators by type + value
        for existing in self.indicators:
            if existing.type == indicator.type and existing.value == indicator.value:
                existing.last_seen = indicator.last_seen
                return
        self.indicators.append(indicator)

    def add_evidence(self, item: EvidenceItem) -> None:
        self.evidence_references.append(item)

    def log_action(self, action: AnalystAction) -> None:
        self.analyst_actions.append(action)


class IncidentQuery(BaseModel):
    """Filter criteria for querying stored security incidents."""

    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    disposition: Optional[IncidentDisposition] = None
    affected_asset: Optional[str] = None
    affected_user: Optional[str] = None
    search: Optional[str] = None
    limit: int = 100
    offset: int = 0
