"""Integration Tests for End-to-End Attack Detection, Automated Investigation, and Incident Response."""

import pytest
from src.detection.engine import DetectionEngine
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.response.automation import ResponseAutomationEngine
from src.response.investigation import InvestigationEngine
from src.response.models import (
    ContainmentStatus,
    IncidentDisposition,
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
from src.response.storage import AuditStore, IncidentStore
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.simulation.models import SimulationContext
from src.simulation.registry import ScenarioRegistry
from src.simulation.runner import SimulationRunner


from fastapi.testclient import TestClient
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


@pytest.fixture
def integrated_soc_environment():
    """Build integrated SOC environment connecting Simulation -> SIEM -> Detection -> Investigation -> Response."""
    event_store = EventStore(max_capacity=5000)
    alert_store = AlertStore(max_capacity=5000)
    incident_store = IncidentStore(max_capacity=1000)
    audit_store = AuditStore(max_capacity=5000)

    detection_engine = DetectionEngine(alert_store=alert_store)
    siem_collector = SIEMCollector(
        store=event_store, detection_engine=detection_engine
    )

    ad_server = ActiveDirectoryServer(siem_collector=siem_collector)
    linux_service = LinuxServerService(siem_collector=siem_collector)
    telemetry = AppTelemetryClient(local_collector=siem_collector)
    vuln_app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=telemetry,
        enable_vulnerabilities=True,
    )
    vuln_client = TestClient(vuln_app)

    investigation_engine = InvestigationEngine(
        event_store=event_store, alert_store=alert_store
    )
    automation_engine = ResponseAutomationEngine(
        audit_store=audit_store,
        siem_collector=siem_collector,
        ad_server=ad_server,
        linux_service=linux_service,
    )

    sim_context = SimulationContext(
        siem_collector=siem_collector,
        event_store=event_store,
        alert_store=alert_store,
        detection_engine=detection_engine,
        ad_server=ad_server,
        linux_service=linux_service,
        vuln_client=vuln_client,
        dry_run=False,
    )

    registry = ScenarioRegistry()
    runner = SimulationRunner(registry=registry)

    return {
        "sim_context": sim_context,
        "runner": runner,
        "registry": registry,
        "event_store": event_store,
        "alert_store": alert_store,
        "incident_store": incident_store,
        "audit_store": audit_store,
        "investigation_engine": investigation_engine,
        "automation_engine": automation_engine,
        "ad_server": ad_server,
        "linux_service": linux_service,
    }


def test_e2e_credential_attack_to_incident_response(
    integrated_soc_environment,
):
    env = integrated_soc_environment

    # 1. Execute Brute Force attack simulation
    scenario = env["registry"].get_scenario("SCN-CRED-004")
    assert scenario is not None
    sim_result = scenario.execute(env["sim_context"])
    assert sim_result.status.value == "success"

    # 2. Check Detection Alerts
    alerts = env["alert_store"].query_alerts()
    assert len(alerts) >= 1
    auth_alert = [a for a in alerts if "DET-AUTH" in a.rule_id or "Brute Force" in a.title][0]

    # 3. Transform Alert into Incident
    incident = env["investigation_engine"].create_incident_from_alert(auth_alert)
    env["incident_store"].add_incident(incident)

    assert incident.status == IncidentStatus.INVESTIGATING
    assert len(incident.timeline) >= 5
    assert "jdoe" in incident.affected_users

    # 4. Execute Response Playbook
    playbook = CredentialCompromisePlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=env["investigation_engine"],
        automation_engine=env["automation_engine"],
    )

    # 5. Validate Incident Resolution
    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.containment_status == ContainmentStatus.CONTAINED
    assert resolved_incident.remediation_status == RemediationStatus.REMEDIATED
    assert resolved_incident.recovery_status == RecoveryStatus.VERIFIED
    assert (
        resolved_incident.final_disposition
        == IncidentDisposition.TRUE_POSITIVE_MALICIOUS
    )

    # 6. Verify Audit Logs
    audit_entries = env["audit_store"].list_entries()
    assert len(audit_entries) >= 2
    actions = [e.action.value for e in audit_entries]
    assert "disable_user" in actions
    assert "enable_user" in actions

    # 7. Generate and verify report
    report = generate_incident_report_markdown(resolved_incident)
    assert "# Incident Response Report:" in report
    assert "jdoe" in report


def test_e2e_lateral_movement_to_incident_response(
    integrated_soc_environment,
):
    env = integrated_soc_environment

    # 1. Execute Lateral Movement Scenario
    scenario = env["registry"].get_scenario("SCN-LAT-001")
    assert scenario is not None
    sim_result = scenario.execute(env["sim_context"])
    assert sim_result.status.value == "success"

    # 2. Check Detection Alerts
    alerts = env["alert_store"].query_alerts()
    assert len(alerts) >= 1
    lat_alert = [a for a in alerts if "DET-LAT" in a.rule_id][0]

    # 3. Create Incident & Execute Lateral Movement Playbook
    incident = env["investigation_engine"].create_incident_from_alert(lat_alert)
    env["incident_store"].add_incident(incident)

    playbook = LateralMovementPlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=env["investigation_engine"],
        automation_engine=env["automation_engine"],
    )

    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.containment_status == ContainmentStatus.CONTAINED
    assert len(resolved_incident.analyst_actions) >= 3

    report = generate_incident_report_markdown(resolved_incident)
    assert "Lateral Movement" in report


def test_e2e_ransomware_data_destruction_to_incident_response(
    integrated_soc_environment,
):
    env = integrated_soc_environment

    # 1. Execute Destructive Data Shredding Scenario
    scenario = env["registry"].get_scenario("SCN-IMP-002")
    assert scenario is not None
    sim_result = scenario.execute(env["sim_context"])
    assert sim_result.status.value == "success"

    # 2. Check Detection Alert
    alerts = env["alert_store"].query_alerts()
    assert len(alerts) >= 1
    imp_alert = [a for a in alerts if "DET-IMP" in a.rule_id][0]

    # 3. Create Incident & Execute Malware/Ransomware Playbook
    incident = env["investigation_engine"].create_incident_from_alert(imp_alert)
    env["incident_store"].add_incident(incident)

    playbook = MalwareRansomwarePlaybook()
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=env["investigation_engine"],
        automation_engine=env["automation_engine"],
    )

    assert resolved_incident.status == IncidentStatus.RECOVERED
    assert resolved_incident.remediation_status == RemediationStatus.REMEDIATED

    # Verify backup restore action in audit trail
    audit_entries = env["audit_store"].list_entries()
    actions = [e.action.value for e in audit_entries]
    assert "restore_backup" in actions
    assert "terminate_process" in actions


def test_benign_negative_control_generates_no_incidents(
    integrated_soc_environment,
):
    env = integrated_soc_environment

    # Execute Benign Scenario
    scenario = env["registry"].get_scenario("SCN-BENIGN-001")
    assert scenario is not None
    sim_result = scenario.execute(env["sim_context"])
    assert sim_result.status.value == "success"

    # Verify no alerts or incidents triggered
    alerts = env["alert_store"].query_alerts()
    assert len(alerts) == 0
    assert env["incident_store"].count() == 0
