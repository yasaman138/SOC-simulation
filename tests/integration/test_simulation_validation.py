"""End-to-End Integration Tests for Attack Simulation Suite & Detection Validation Coverage Matrix."""

from fastapi.testclient import TestClient
from src.detection.engine import DetectionEngine
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.app import create_siem_app
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.simulation.models import SimulationContext
from src.simulation.registry import ScenarioRegistry
from src.simulation.runner import SimulationRunner
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


def test_full_simulation_suite_and_coverage_report():
    """Execute the complete simulation suite across all 10 ATT&CK tactics and generate coverage report."""
    # 1. Initialize environment
    event_store = EventStore(max_capacity=5000)
    alert_store = AlertStore(max_capacity=5000)
    engine = DetectionEngine(alert_store=alert_store)
    collector = SIEMCollector(store=event_store, detection_engine=engine)

    ad = ActiveDirectoryServer(siem_collector=collector)
    linux = LinuxServerService(siem_collector=collector)
    telemetry = AppTelemetryClient(local_collector=collector)
    vuln_app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=telemetry,
        enable_vulnerabilities=True,
    )
    vuln_client = TestClient(vuln_app)

    sim_context = SimulationContext(
        siem_collector=collector,
        event_store=event_store,
        alert_store=alert_store,
        detection_engine=engine,
        ad_server=ad,
        linux_service=linux,
        vuln_client=vuln_client,
        dry_run=False,
    )

    # 2. Run simulation suite
    registry = ScenarioRegistry()
    runner = SimulationRunner(registry=registry)
    results = runner.run_all(sim_context)

    # 3. Generate Coverage Report
    report = runner.generate_coverage_report(results)

    # 4. Verify Coverage Metrics
    assert report.total_scenarios >= 25
    assert report.passed_scenarios == report.total_scenarios, (
        f"Expected 100% pass rate, but {report.failed_scenarios} scenarios failed."
    )
    assert report.failed_scenarios == 0
    assert report.summary["pass_rate_percent"] == 100.0
    assert report.benign_scenarios >= 5
    assert report.attack_scenarios >= 20

    # Verify all 10 MITRE ATT&CK tactics are represented
    expected_tactics = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Command and Control",
        "Collection",
        "Impact",
    ]
    for tactic in expected_tactics:
        assert tactic in report.tactics_covered, f"Tactic '{tactic}' not covered in report"

    # 5. Verify ASCII table formatting works
    table_str = runner.format_coverage_table(report)
    assert "Enterprise Attack Simulation & Detection Validation Coverage Report" in table_str
    assert "Pass Rate: 100.0%" in table_str

    # 6. Verify SIEM Alert Store contains generated alerts
    assert alert_store.count() >= 20

    # 7. Query alerts via SIEM API
    siem_app = create_siem_app(store=event_store, engine=engine, alerts=alert_store)
    siem_client = TestClient(siem_app)
    alerts_resp = siem_client.get("/api/v1/alerts")
    assert alerts_resp.status_code == 200
    assert len(alerts_resp.json()["alerts"]) >= 20
