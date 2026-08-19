"""Attack Simulation & Detection Validation Domain Models."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from src.core.topology import NetworkZone
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.siem.models import ECSEvent


class ScenarioExecutionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class SimulationTarget(BaseModel):
    """Target descriptor specifying the isolated lab destination."""

    hostname: str
    ip_address: str
    zone: NetworkZone
    service_name: str
    description: Optional[str] = None


class ScenarioResult(BaseModel):
    """Result of an individual scenario execution."""

    scenario_id: str
    scenario_name: str
    status: ScenarioExecutionStatus = ScenarioExecutionStatus.SUCCESS
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    duration_ms: float = 0.0
    generated_events_count: int = 0
    generated_events: List[Dict[str, Any]] = Field(default_factory=list)
    execution_logs: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    cleanup_success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ValidationResult(BaseModel):
    """Validation report comparing simulated telemetry against detection engine alerts."""

    scenario_id: str
    scenario_name: str
    is_benign: bool = False
    passed: bool = True
    matched_telemetry_count: int = 0
    expected_detection_ids: List[str] = Field(default_factory=list)
    triggered_detection_ids: List[str] = Field(default_factory=list)
    missed_detection_ids: List[str] = Field(default_factory=list)
    unexpected_detection_ids: List[str] = Field(default_factory=list)
    generated_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    detection_gap: Optional[str] = None
    validation_notes: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class SimulationContext:
    """Runtime context passed to simulation scenarios."""

    def __init__(
        self,
        siem_collector: Optional[Any] = None,
        event_store: Optional[Any] = None,
        alert_store: Optional[Any] = None,
        detection_engine: Optional[Any] = None,
        ad_server: Optional[Any] = None,
        linux_service: Optional[Any] = None,
        vuln_client: Optional[Any] = None,
        dry_run: bool = False,
        custom_params: Optional[Dict[str, Any]] = None,
    ):
        self.siem_collector = siem_collector
        self.event_store = event_store
        self.alert_store = alert_store
        self.detection_engine = detection_engine
        self.ad_server = ad_server
        self.linux_service = linux_service
        self.vuln_client = vuln_client
        self.dry_run = dry_run
        self.custom_params = custom_params or {}


class BaseScenario(BaseModel, ABC):
    """Abstract Base Class for Enterprise Attack and Benign Scenarios."""

    id: str
    name: str
    description: str
    mitre_attack: MitreAttackInfo
    preconditions: List[str] = Field(default_factory=list)
    lab_target: str
    simulated_behavior: str
    expected_telemetry: List[str] = Field(default_factory=list)
    expected_detections: List[str] = Field(default_factory=list)
    expected_alerts: List[str] = Field(default_factory=list)
    cleanup_requirements: List[str] = Field(default_factory=list)
    is_benign: bool = False

    @abstractmethod
    def execute(self, context: SimulationContext) -> ScenarioResult:
        """Execute the simulated behavior against lab infrastructure and emit telemetry."""
        pass

    def cleanup(self, context: SimulationContext) -> bool:
        """Revert any persistent modifications made during scenario execution."""
        return True

    def validate(
        self,
        events: List[ECSEvent],
        alerts: List[Alert],
    ) -> ValidationResult:
        """Evaluate whether expected telemetry and detection alerts were generated."""
        triggered_rule_ids = list({a.rule_id for a in alerts})

        if self.is_benign:
            # For benign scenarios (negative controls), NO alert should trigger
            unexpected = triggered_rule_ids
            passed = len(unexpected) == 0
            gap = None
            if not passed:
                gap = f"False positive detected: Rules {unexpected} fired on benign activity."

            return ValidationResult(
                scenario_id=self.id,
                scenario_name=self.name,
                is_benign=True,
                passed=passed,
                matched_telemetry_count=len(events),
                expected_detection_ids=[],
                triggered_detection_ids=triggered_rule_ids,
                missed_detection_ids=[],
                unexpected_detection_ids=unexpected,
                generated_alerts=[a.to_dict() for a in alerts],
                detection_gap=gap,
                validation_notes=[
                    f"Benign negative control evaluated with {len(events)} telemetry events.",
                    f"Generated {len(alerts)} alerts (Expected: 0).",
                ],
            )
        else:
            # For attack scenarios, all expected detection rules must trigger
            missed = [
                r_id
                for r_id in self.expected_detections
                if r_id not in triggered_rule_ids
            ]
            passed = len(missed) == 0 and len(events) > 0
            gap = None
            if missed:
                gap = f"Detection gap: Expected rules {missed} did not trigger."

            return ValidationResult(
                scenario_id=self.id,
                scenario_name=self.name,
                is_benign=False,
                passed=passed,
                matched_telemetry_count=len(events),
                expected_detection_ids=self.expected_detections,
                triggered_detection_ids=triggered_rule_ids,
                missed_detection_ids=missed,
                unexpected_detection_ids=[],
                generated_alerts=[a.to_dict() for a in alerts],
                detection_gap=gap,
                validation_notes=[
                    f"Attack scenario generated {len(events)} telemetry events.",
                    f"Detection rules triggered: {triggered_rule_ids}.",
                ],
            )

    def to_metadata_dict(self) -> Dict[str, Any]:
        """Export scenario specification metadata."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mitre_attack": self.mitre_attack.to_dict(),
            "preconditions": self.preconditions,
            "lab_target": self.lab_target,
            "simulated_behavior": self.simulated_behavior,
            "expected_telemetry": self.expected_telemetry,
            "expected_detections": self.expected_detections,
            "expected_alerts": self.expected_alerts,
            "cleanup_requirements": self.cleanup_requirements,
            "is_benign": self.is_benign,
        }


class CoverageItem(BaseModel):
    """Coverage matrix row mapping technique to scenario, rule, and result."""

    technique_id: str
    technique_name: str
    tactic: str
    scenario_id: str
    scenario_name: str
    is_benign: bool
    telemetry_generated: str
    detection_rules: List[str]
    detection_result: str  # "PASS", "FAIL", "FALSE_POSITIVE", "GAP"
    passed: bool
    detection_gaps: Optional[str] = None


class CoverageReport(BaseModel):
    """Comprehensive Detection Coverage and Validation Report."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_scenarios: int
    passed_scenarios: int
    failed_scenarios: int
    attack_scenarios: int
    benign_scenarios: int
    tactics_covered: List[str]
    items: List[CoverageItem]
    summary: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
