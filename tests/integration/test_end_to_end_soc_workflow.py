"""End-to-End SOC Lifecycle Integration Test.

Validates complete workflow:
Simulation -> Telemetry -> Detection -> Alert -> Investigation -> Containment -> Report -> Metrics.
"""

from fastapi.testclient import TestClient
from src.core.metrics import SOCMetricsCalculator
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
from src.response.playbooks import CredentialCompromisePlaybook
from src.response.reporting import IncidentReportGenerator
from src.response.storage import AuditStore, IncidentStore
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.simulation.models import SimulationContext
from src.simulation.registry import ScenarioRegistry
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


def test_complete_end_to_end_soc_lifecycle():
    """Execute complete end-to-end lifecycle verification."""

    # Stage 1: Setup Infrastructure & SOC Stores
    event_store = EventStore(max_capacity=5000)
    alert_store = AlertStore(max_capacity=5000)
    incident_store = IncidentStore(max_capacity=1000)
    audit_store = AuditStore(max_capacity=5000)

    detection_engine = DetectionEngine(alert_store=alert_store)
    siem_collector = SIEMCollector(store=event_store, detection_engine=detection_engine)
    ad_server = ActiveDirectoryServer(siem_collector=siem_collector)
    linux_service = LinuxServerService(siem_collector=siem_collector)

    telemetry = AppTelemetryClient(local_collector=siem_collector)
    vuln_app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=telemetry,
        enable_vulnerabilities=True,
    )
    vuln_client = TestClient(vuln_app)

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

    inv_engine = InvestigationEngine(event_store=event_store, alert_store=alert_store)
    auto_engine = ResponseAutomationEngine(
        audit_store=audit_store,
        siem_collector=siem_collector,
        ad_server=ad_server,
        linux_service=linux_service,
    )

    # Stage 2: Attack Simulation Execution
    registry = ScenarioRegistry()
    scenario = registry.get_scenario("SCN-CRED-004")  # LSASS Memory Dump
    assert scenario is not None

    scenario_res = scenario.execute(sim_context)
    assert scenario_res.generated_events_count > 0

    # Stage 3: Telemetry Ingestion & Storage
    assert event_store.count() >= 1

    # Stage 4: Detection & Alerting
    alerts = alert_store.query_alerts()
    assert len(alerts) >= 1
    primary_alert = alerts[0]
    assert primary_alert.rule_id.startswith("DET-")
    assert primary_alert.mitre_attack is not None

    # Stage 5: Automated Investigation & Correlation
    incident = inv_engine.create_incident_from_alert(primary_alert)
    incident_store.add_incident(incident)

    assert incident.incident_id.startswith("INC-")
    assert len(incident.timeline) >= 1
    assert incident.root_cause_analysis is not None
    assert incident.lessons_learned is not None

    # Stage 6: Incident Response Playbook Execution
    playbook = CredentialCompromisePlaybook()
    resolved_inc = playbook.execute(
        incident=incident,
        investigation_engine=inv_engine,
        automation_engine=auto_engine,
        actor="soar_automation",
    )
    incident_store.update_incident(resolved_inc)

    assert resolved_inc.containment_status == ContainmentStatus.CONTAINED
    assert resolved_inc.remediation_status == RemediationStatus.REMEDIATED
    assert resolved_inc.recovery_status == RecoveryStatus.VERIFIED
    assert resolved_inc.final_disposition == IncidentDisposition.TRUE_POSITIVE_MALICIOUS

    # Stage 7: Structured Multi-Format Report Generation
    md_report = IncidentReportGenerator.to_markdown(resolved_inc)
    assert "# Incident Response Report:" in md_report
    assert "## 1. Executive Summary" in md_report
    assert "## 12. Lessons Learned & Hardening Recommendations" in md_report

    json_report = IncidentReportGenerator.to_json(resolved_inc)
    assert "executive_summary" in json_report
    assert "remediation" in json_report

    html_report = IncidentReportGenerator.to_html(resolved_inc)
    assert "<!DOCTYPE html>" in html_report
    assert "Incident ID" in html_report

    # Stage 8: Dynamic SOC Security Metrics Computation
    metrics_calc = SOCMetricsCalculator(
        event_store=event_store,
        alert_store=alert_store,
        incident_store=incident_store,
        audit_store=audit_store,
    )
    metrics = metrics_calc.calculate_metrics()

    assert metrics.total_telemetry_events >= 1
    assert metrics.total_alerts >= 1
    assert metrics.total_incidents >= 1
    assert metrics.mttd_seconds >= 0.0
    assert metrics.mttr_seconds >= 0.0
    assert metrics.detection_rate_percent == 100.0
    assert metrics.system_health_score == 100.0
