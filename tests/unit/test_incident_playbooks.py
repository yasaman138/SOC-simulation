"""Unit Tests for Incident Response Playbooks and Report Generation."""

import pytest
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.response.automation import ResponseAutomationEngine
from src.response.investigation import InvestigationEngine
from src.response.models import (
    ContainmentStatus,
    Incident,
    IncidentDisposition,
    IncidentSeverity,
    IncidentStatus,
    RecoveryStatus,
    RemediationStatus,
)
from src.response.playbooks import (
    CredentialCompromisePlaybook,
    LateralMovementPlaybook,
    MalwareRansomwarePlaybook,
    generate_incident_report_markdown,
)
from src.response.storage import AuditStore
from src.siem.collector import SIEMCollector
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
def playbook_context():
    event_store = EventStore()
    alert_store = AlertStore()
    collector = SIEMCollector(store=event_store)
    ad = ActiveDirectoryServer(siem_collector=collector)
    linux = LinuxServerService(siem_collector=collector)
    audit_store = AuditStore()

    investigation_engine = InvestigationEngine(
        event_store=event_store, alert_store=alert_store
    )
    automation_engine = ResponseAutomationEngine(
        audit_store=audit_store,
        siem_collector=collector,
        ad_server=ad,
        linux_service=linux,
    )

    return (
        event_store,
        alert_store,
        investigation_engine,
        automation_engine,
        ad,
        linux,
    )


def test_credential_compromise_playbook_lifecycle(playbook_context):
    (
        event_store,
        alert_store,
        inv_engine,
        auto_engine,
        ad,
        _,
    ) = playbook_context

    # 1. Ingest telemetry for Kerberoasting / Brute Force
    ev = ECSEvent(
        event=EventMetadata(
            category=EventCategory.DIRECTORY_SERVICE,
            action="ad.kerberos.tgs_request",
        ),
        host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
        user=UserInfo(name="jdoe"),
        source=EndpointInfo(ip="172.28.10.100"),
        message="TGS ticket requested for MSSQLSvc with RC4",
    )
    event_store.add_event(ev)

    alert = Alert(
        rule_id="DET-CRED-001",
        rule_name="Kerberoasting Activity Detected",
        severity=EventSeverity.HIGH,
        title="Kerberos TGS Request with Weak RC4 Encryption",
        description="RC4 TGS request observed for service account",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1558",
            subtechnique_id="T1558.003",
        ),
    )
    alert.affected_entities.host = "dc01.corp.enterprise.local"
    alert.affected_entities.user = "jdoe"
    alert.affected_entities.ip = "172.28.10.100"
    alert_store.add_alert(alert)

    # 2. Create Incident
    incident = inv_engine.create_incident_from_alert(alert)
    assert incident.status == IncidentStatus.INVESTIGATING

    # 3. Execute Playbook
    playbook = CredentialCompromisePlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=inv_engine,
        automation_engine=auto_engine,
    )

    # 4. Verify Final Incident State
    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.containment_status == ContainmentStatus.CONTAINED
    assert resolved_incident.remediation_status == RemediationStatus.REMEDIATED
    assert resolved_incident.recovery_status == RecoveryStatus.VERIFIED
    assert (
        resolved_incident.final_disposition
        == IncidentDisposition.TRUE_POSITIVE_MALICIOUS
    )
    assert len(resolved_incident.analyst_actions) >= 4

    # 5. Verify Markdown Report
    report = generate_incident_report_markdown(resolved_incident)
    assert "# Incident Response Report:" in report
    assert "MITRE ATT&CK Mapping" in report
    assert "Chronological Investigation Timeline" in report
    assert "Lessons Learned" in report


def test_lateral_movement_playbook_lifecycle(playbook_context):
    (
        event_store,
        alert_store,
        inv_engine,
        auto_engine,
        _,
        linux,
    ) = playbook_context

    # Ingest SSH Lateral movement telemetry
    ev = ECSEvent(
        event=EventMetadata(
            category=EventCategory.AUTHENTICATION,
            action="ssh.login.success",
        ),
        host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
        user=UserInfo(name="sysadmin"),
        source=EndpointInfo(ip="172.28.30.10"),
        destination=EndpointInfo(ip="172.28.20.15"),
        message="Accepted SSH login from DMZ",
    )
    event_store.add_event(ev)

    alert = Alert(
        rule_id="DET-LAT-002",
        rule_name="Cross-Subnet SSH Lateral Movement from DMZ",
        severity=EventSeverity.HIGH,
        title="SSH Lateral Movement Pivot",
        description="SSH from DMZ to Core Server",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.LATERAL_MOVEMENT,
            technique_id="T1021",
            subtechnique_id="T1021.004",
        ),
    )
    alert.affected_entities.host = "srv01.corp.enterprise.local"
    alert.affected_entities.ip = "172.28.30.10"
    alert.affected_entities.user = "sysadmin"
    alert_store.add_alert(alert)

    incident = inv_engine.create_incident_from_alert(alert)
    playbook = LateralMovementPlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=inv_engine,
        automation_engine=auto_engine,
    )

    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.containment_status == ContainmentStatus.CONTAINED
    assert resolved_incident.recovery_status == RecoveryStatus.VERIFIED
    assert any("dmz" in a.lower() or "172.28.30." in a for a in resolved_incident.affected_assets)


def test_malware_ransomware_playbook_lifecycle(playbook_context):
    (
        event_store,
        alert_store,
        inv_engine,
        auto_engine,
        _,
        _,
    ) = playbook_context

    # Ingest Destructive shred command telemetry
    ev = ECSEvent(
        event=EventMetadata(
            category=EventCategory.PROCESS,
            action="linux.process.created",
            severity=EventSeverity.HIGH,
        ),
        host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
        user=UserInfo(name="root"),
        process=ProcessInfo(
            name="shred",
            command_line="shred -u -z /var/log/audit/audit.log",
            pid=27350,
        ),
        message="Destructive log shredding executed",
    )
    event_store.add_event(ev)

    alert = Alert(
        rule_id="DET-IMP-002",
        rule_name="Destructive Log File Shredding Detected",
        severity=EventSeverity.CRITICAL,
        title="Anti-Forensics / Data Destruction Activity",
        description="shred utility executed against audit logs",
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.IMPACT,
            technique_id="T1485",
            technique_name="Data Destruction",
        ),
    )
    alert.affected_entities.host = "srv01.corp.enterprise.local"
    alert_store.add_alert(alert)

    incident = inv_engine.create_incident_from_alert(alert)
    playbook = MalwareRansomwarePlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=inv_engine,
        automation_engine=auto_engine,
    )

    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.severity == IncidentSeverity.CRITICAL
    assert resolved_incident.containment_status == ContainmentStatus.CONTAINED
    assert resolved_incident.remediation_status == RemediationStatus.REMEDIATED

    report = generate_incident_report_markdown(resolved_incident)
    assert "Data Destruction" in report
    assert "Executive Summary" in report
