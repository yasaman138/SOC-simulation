"""Unit Tests for Automated Investigation and Telemetry Correlation Engine."""

from datetime import datetime, timezone
import pytest
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.detection.storage import AlertStore
from src.response.investigation import InvestigationEngine
from src.response.models import (
    IncidentSeverity,
    IncidentStatus,
    IndicatorType,
)
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    ProcessInfo,
    UserInfo,
)
from src.siem.storage import EventStore


@pytest.fixture
def investigation_context():
    event_store = EventStore()
    alert_store = AlertStore()
    engine = InvestigationEngine(
        event_store=event_store, alert_store=alert_store
    )
    return event_store, alert_store, engine


def test_create_incident_from_alert(investigation_context):
    event_store, alert_store, engine = investigation_context

    alert = Alert(
        rule_id="DET-AUTH-001",
        rule_name="Brute Force Password Guessing",
        severity=EventSeverity.HIGH,
        title="Multiple Failed Logon Attempts for User 'jdoe'",
        description="5 failed logon attempts recorded in 30 seconds",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1110",
            technique_name="Brute Force",
        ),
    )
    alert.affected_entities.host = "dc01.corp.enterprise.local"
    alert.affected_entities.user = "jdoe"
    alert.affected_entities.ip = "172.28.10.100"
    alert_store.add_alert(alert)

    incident = engine.create_incident_from_alert(alert)

    assert incident.incident_id.startswith("INC-")
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.status == IncidentStatus.INVESTIGATING
    assert "dc01.corp.enterprise.local" in incident.affected_assets
    assert "jdoe" in incident.affected_users
    assert any(m.technique_id == "T1110" for m in incident.mitre_attack)


def test_multi_source_telemetry_correlation(investigation_context):
    event_store, alert_store, engine = investigation_context

    # 1. Ingest Auth Failure Event
    ev_auth = ECSEvent(
        timestamp=datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc),
        event=EventMetadata(
            category=EventCategory.AUTHENTICATION,
            action="ad.logon.failed",
            outcome=EventOutcome.FAILURE,
        ),
        host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
        user=UserInfo(name="jdoe"),
        source=EndpointInfo(ip="172.28.10.100"),
        message="Logon failed for jdoe",
    )
    event_store.add_event(ev_auth)

    # 2. Ingest Process Execution Event
    ev_proc = ECSEvent(
        timestamp=datetime(2026, 8, 20, 10, 2, 0, tzinfo=timezone.utc),
        event=EventMetadata(
            category=EventCategory.PROCESS,
            action="windows.process.created",
        ),
        host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
        user=UserInfo(name="jdoe"),
        process=ProcessInfo(
            name="procdump.exe", command_line="procdump.exe -ma lsass.exe"
        ),
        message="Process created: procdump",
    )
    event_store.add_event(ev_proc)

    # 3. Create Alert
    alert = Alert(
        rule_id="DET-CRED-003",
        rule_name="LSASS Memory Dump",
        severity=EventSeverity.CRITICAL,
        title="LSASS Dumping via ProcDump",
        description="Detected procdump targeting LSASS",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1003",
            technique_name="OS Credential Dumping",
        ),
    )
    alert.affected_entities.host = "dc01.corp.enterprise.local"
    alert.affected_entities.user = "jdoe"
    alert_store.add_alert(alert)

    incident = engine.create_incident_from_alert(alert)

    # Verify Timeline entries contain both events
    assert len(incident.timeline) >= 2
    timeline_titles = [t.title for t in incident.timeline]
    assert any("Auth Failure" in t for t in timeline_titles)
    assert any("Process Executed" in t for t in timeline_titles)

    # Verify Evidence Items
    assert len(incident.evidence_references) >= 2


def test_ioc_extraction_and_threat_intel_enrichment(investigation_context):
    event_store, alert_store, engine = investigation_context

    # Ingest C2 Network Connection Event with known Threat Intel IP
    ev_c2 = ECSEvent(
        timestamp=datetime(2026, 8, 20, 11, 0, 0, tzinfo=timezone.utc),
        event=EventMetadata(
            category=EventCategory.NETWORK,
            action="network.connection.outbound",
        ),
        host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
        user=UserInfo(name="sysadmin"),
        source=EndpointInfo(ip="172.28.20.15"),
        destination=EndpointInfo(ip="198.51.100.42", port=443),
        message="Outbound connection to known C2",
    )
    event_store.add_event(ev_c2)

    alert = Alert(
        rule_id="DET-C2-001",
        rule_name="C2 Beaconing Detected",
        severity=EventSeverity.HIGH,
        title="Outbound C2 Communication",
        description="Repeated beaconing traffic",
    )
    alert.affected_entities.host = "srv01.corp.enterprise.local"
    alert.affected_entities.ip = "198.51.100.42"
    alert_store.add_alert(alert)

    incident = engine.create_incident_from_alert(alert)

    # Verify extracted IOCs
    iocs = {i.value: i for i in incident.indicators}
    assert "198.51.100.42" in iocs
    c2_ioc = iocs["198.51.100.42"]
    assert c2_ioc.type == IndicatorType.IP
    assert c2_ioc.reputation == "malicious"
    assert "C2" in c2_ioc.context


def test_root_cause_analysis_and_lessons_learned_synthesis(
    investigation_context,
):
    event_store, alert_store, engine = investigation_context

    alert = Alert(
        rule_id="DET-LAT-002",
        rule_name="Cross-Subnet SSH Lateral Movement",
        severity=EventSeverity.HIGH,
        title="SSH Lateral Movement from DMZ",
        description="Inbound SSH connection from DMZ tier to Core Server",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.LATERAL_MOVEMENT,
            technique_id="T1021",
            technique_name="Remote Services",
        ),
    )
    alert.affected_entities.host = "srv01.corp.enterprise.local"
    alert.affected_entities.user = "sysadmin"
    alert_store.add_alert(alert)

    incident = engine.create_incident_from_alert(alert)

    assert incident.root_cause_analysis is not None
    assert (
        "Lateral Movement" in incident.root_cause_analysis.initial_vector
        or "SSH" in incident.root_cause_analysis.summary
    )
    assert len(incident.root_cause_analysis.vulnerabilities_exploited) > 0

    assert incident.lessons_learned is not None
    assert len(incident.lessons_learned.preventive_recommendations) > 0
    assert len(incident.lessons_learned.procedural_improvements) > 0


def test_forensic_metadata_collection(investigation_context):
    _, _, engine = investigation_context
    forensics = engine.collect_forensic_metadata("srv01.corp.enterprise.local")

    assert forensics["hostname"] == "srv01.corp.enterprise.local"
    assert len(forensics["active_processes"]) > 0
    assert len(forensics["open_sockets"]) > 0
    assert forensics["integrity_checks"]["filesystem"] == "VERIFIED_CLEAN"
