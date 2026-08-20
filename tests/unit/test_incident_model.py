"""Unit Tests for Incident Domain Models and Storage."""

from datetime import datetime, timezone
import pytest
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.response.models import (
    AnalystAction,
    AuditLogEntry,
    ContainmentStatus,
    EvidenceItem,
    Incident,
    IncidentDisposition,
    IncidentQuery,
    IncidentSeverity,
    IncidentStatus,
    Indicator,
    IndicatorType,
    LessonsLearned,
    RecoveryStatus,
    RemediationStatus,
    ResponseActionResult,
    ResponseActionType,
    RootCauseAnalysis,
    TimelineEntry,
)
from src.response.storage import AuditStore, IncidentStore
from src.siem.models import EventSeverity


def test_incident_instantiation_defaults():
    inc = Incident(
        title="Unauthorized Admin Logon",
        description="Detection of abnormal administrative logon",
    )
    assert inc.incident_id.startswith("INC-")
    assert inc.status == IncidentStatus.NEW
    assert inc.severity == IncidentSeverity.MEDIUM
    assert inc.containment_status == ContainmentStatus.NOT_CONTAINED
    assert inc.remediation_status == RemediationStatus.NOT_REMEDIATED
    assert inc.recovery_status == RecoveryStatus.PENDING
    assert inc.final_disposition == IncidentDisposition.UNRESOLVED
    assert isinstance(inc.timeline, list)
    assert isinstance(inc.indicators, list)


def test_incident_timeline_addition_and_sorting():
    inc = Incident(title="Test", description="Test")
    t1 = TimelineEntry(
        timestamp=datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc),
        title="Event 1",
        description="First action",
    )
    t2 = TimelineEntry(
        timestamp=datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc),
        title="Event 0",
        description="Initial action",
        is_key_event=True,
    )
    inc.add_timeline_entry(t1)
    inc.add_timeline_entry(t2)

    assert len(inc.timeline) == 2
    # Check sorted oldest first
    assert inc.timeline[0].title == "Event 0"
    assert inc.timeline[1].title == "Event 1"
    assert inc.timeline[0].is_key_event is True


def test_indicator_deduplication():
    inc = Incident(title="Test", description="Test")
    ioc1 = Indicator(
        type=IndicatorType.IP,
        value="198.51.100.42",
        context="Initial C2",
    )
    ioc2 = Indicator(
        type=IndicatorType.IP,
        value="198.51.100.42",
        context="Repeated C2",
    )
    inc.add_indicator(ioc1)
    inc.add_indicator(ioc2)

    assert len(inc.indicators) == 1
    assert inc.indicators[0].value == "198.51.100.42"


def test_incident_serialization_to_dict():
    inc = Incident(
        title="Brute Force Compromise",
        description="Multiple failed logons followed by success",
        severity=IncidentSeverity.HIGH,
        affected_assets=["dc01.corp.enterprise.local"],
        affected_users=["jdoe"],
        root_cause_analysis=RootCauseAnalysis(
            summary="Compromised via credential brute force",
            initial_vector="Password Guessing",
            attack_path=["Step 1", "Step 2"],
            impact_assessment="Single user account compromised",
        ),
    )
    d = inc.to_dict()
    assert d["title"] == "Brute Force Compromise"
    assert d["severity"] == "high"
    assert "dc01.corp.enterprise.local" in d["affected_assets"]
    assert d["root_cause_analysis"]["initial_vector"] == "Password Guessing"


def test_incident_store_crud_and_query():
    store = IncidentStore(max_capacity=100)
    inc1 = Incident(
        title="Critical Malware",
        description="Ransomware attempt",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        affected_assets=["srv01.corp.enterprise.local"],
        affected_users=["sysadmin"],
    )
    inc2 = Incident(
        title="Low Reconnaissance",
        description="Port scanning",
        severity=IncidentSeverity.LOW,
        status=IncidentStatus.CLOSED,
        affected_assets=["wkstn01.corp.enterprise.local"],
    )

    store.add_incident(inc1)
    store.add_incident(inc2)

    assert store.count() == 2
    assert store.get_incident(inc1.incident_id) is not None

    # Query by severity
    res_crit = store.query_incidents(
        IncidentQuery(severity=IncidentSeverity.CRITICAL)
    )
    assert len(res_crit) == 1
    assert res_crit[0].title == "Critical Malware"

    # Query by user
    res_user = store.query_incidents(IncidentQuery(affected_user="sysadmin"))
    assert len(res_user) == 1

    # Query by search
    res_search = store.query_incidents(IncidentQuery(search="Ransomware"))
    assert len(res_search) == 1

    # Metrics
    metrics = store.get_metrics()
    assert metrics["total_incidents"] == 2
    assert metrics["by_severity"]["critical"] == 1
    assert metrics["by_severity"]["low"] == 1


def test_audit_store_logging_and_query():
    store = AuditStore()
    entry1 = AuditLogEntry(
        action=ResponseActionType.DISABLE_USER,
        actor="soar_automation",
        target="jdoe",
        reason="Incident containment",
        result=ResponseActionResult.SUCCESS,
    )
    entry2 = AuditLogEntry(
        action=ResponseActionType.ISOLATE_ENDPOINT,
        actor="soc_analyst",
        target="srv01.corp.enterprise.local",
        reason="Malware isolation",
        result=ResponseActionResult.SUCCESS,
    )
    store.log(entry1)
    store.log(entry2)

    assert store.count() == 2
    entries_user = store.list_entries(action=ResponseActionType.DISABLE_USER)
    assert len(entries_user) == 1
    assert entries_user[0].target == "jdoe"

    entries_analyst = store.list_entries(actor="soc_analyst")
    assert len(entries_analyst) == 1
