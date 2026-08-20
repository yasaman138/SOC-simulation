"""Unit tests for the SOC Metrics Engine."""

from datetime import datetime, timedelta, timezone
from src.core.metrics import SOCMetricsCalculator, SOCMetricsSummary
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.detection.storage import AlertStore
from src.response.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
    TimelineEntry,
)
from src.response.storage import AuditStore, IncidentStore
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventSeverity
from src.siem.storage import EventStore
from src.simulation.models import ValidationResult
from src.simulation.registry import ScenarioRegistry


def test_metrics_calculator_empty_baseline():
    """Verify metrics calculator returns expected defaults on fresh lab baseline."""
    calc = SOCMetricsCalculator()
    summary = calc.calculate_metrics()

    assert isinstance(summary, SOCMetricsSummary)
    assert summary.total_telemetry_events == 0
    assert summary.total_alerts == 0
    assert summary.total_incidents == 0
    assert summary.open_incidents == 0
    assert summary.detection_rate_percent == 100.0
    assert summary.false_positive_rate_percent == 0.0
    assert summary.total_registered_rules >= 30
    assert summary.covered_mitre_techniques >= 20
    assert summary.system_health_score == 100.0


def test_metrics_calculator_with_events_alerts_and_incidents():
    """Verify metrics calculation with simulated event, alert, and incident histories."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    audit_store = AuditStore()

    # Add events
    now = datetime.now(timezone.utc)
    ev1 = ECSEvent(
        timestamp=now - timedelta(seconds=10),
        event=EventMetadata(
            category=EventCategory.AUTHENTICATION,
            action="user.login.failed",
            severity=EventSeverity.HIGH,
        ),
    )
    event_store.add_event(ev1)

    # Add alert with source event for MTTD calculation
    alt1 = Alert(
        rule_id="RULE-AUTH-001",
        rule_name="Brute Force",
        title="Multiple Auth Failures",
        description="Threshold exceeded",
        severity=EventSeverity.HIGH,
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1110",
            technique_name="Brute Force",
        ),
        timestamp=now - timedelta(seconds=8),
        source_events=[ev1.to_dict()],
    )
    alert_store.add_alert(alt1)

    # Add incident with timeline for MTTR calculation
    inc1 = Incident(
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.RECOVERED,
        title="Incident Brute Force",
        description="Investigated and contained",
    )
    inc1.add_timeline_entry(
        TimelineEntry(
            timestamp=now - timedelta(seconds=8),
            title="Alert Fired",
            description="Initial trigger",
        )
    )
    inc1.add_timeline_entry(
        TimelineEntry(
            timestamp=now - timedelta(seconds=2),
            title="Account Disabled",
            description="Contained",
        )
    )
    inc_store.add_incident(inc1)

    calc = SOCMetricsCalculator(
        event_store=event_store,
        alert_store=alert_store,
        incident_store=inc_store,
        audit_store=audit_store,
    )
    summary = calc.calculate_metrics()

    assert summary.total_telemetry_events == 1
    assert summary.total_alerts == 1
    assert summary.total_incidents == 1
    assert summary.resolved_incidents == 1
    assert summary.alerts_by_severity["high"] == 1
    assert summary.alerts_by_tactic["Credential Access"] == 1
    assert summary.mttd_seconds == 2.0  # (now-8s) - (now-10s) = 2.0s
    assert summary.mttr_seconds == 6.0  # (now-2s) - (now-8s) = 6.0s
    assert summary.system_health_score == 100.0


def test_metrics_calculator_with_simulation_results():
    """Verify detection rate and false positive calculations from validation results."""
    calc = SOCMetricsCalculator()

    val_results = [
        ValidationResult(
            scenario_id="SCN-CRED-001",
            scenario_name="Brute Force",
            is_benign=False,
            passed=True,
            matched_telemetry_count=5,
            triggered_detection_ids=["RULE-AUTH-001"],
        ),
        ValidationResult(
            scenario_id="SCN-CRED-002",
            scenario_name="Kerberoasting",
            is_benign=False,
            passed=False,  # Failed detection
            matched_telemetry_count=0,
            triggered_detection_ids=[],
        ),
        ValidationResult(
            scenario_id="SCN-BENIGN-001",
            scenario_name="Legitimate Admin",
            is_benign=True,
            passed=True,  # No alerts (passed)
            matched_telemetry_count=2,
            triggered_detection_ids=[],
        ),
        ValidationResult(
            scenario_id="SCN-BENIGN-002",
            scenario_name="Legitimate Curl",
            is_benign=True,
            passed=False,  # False positive alert!
            matched_telemetry_count=1,
            triggered_detection_ids=["RULE-WEB-001"],
        ),
    ]

    summary = calc.calculate_metrics(validation_results=val_results)

    assert summary.total_attack_scenarios == 2
    assert summary.detected_attack_scenarios == 1
    assert summary.detection_rate_percent == 50.0

    assert summary.total_benign_scenarios == 2
    assert summary.false_positive_alerts == 1
    assert summary.false_positive_rate_percent == 50.0

    assert len(summary.failed_detections) == 1
    assert "SCN-CRED-002" in summary.failed_detections[0]
    # Health score deducted due to detection miss & false positive
    assert summary.system_health_score < 100.0


def test_technique_coverage_matrix():
    """Verify detailed MITRE ATT&CK technique coverage table generation."""
    calc = SOCMetricsCalculator()
    summary = calc.calculate_metrics()

    assert len(summary.technique_coverage) >= 20
    t1110 = next((t for t in summary.technique_coverage if t.technique_id == "T1110"), None)
    assert t1110 is not None
    assert t1110.technique_name == "Brute Force"
    assert t1110.tactic == "Credential Access"
    assert t1110.rules_count >= 1
    assert t1110.has_simulation is True
