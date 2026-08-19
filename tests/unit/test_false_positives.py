"""Unit tests verifying Benign Negative Controls (False Positive Validation)."""

import pytest
from fastapi.testclient import TestClient
from src.detection.engine import DetectionEngine
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.simulation.models import SimulationContext
from src.simulation.runner import SimulationRunner
from src.simulation.scenarios import get_all_scenarios
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


@pytest.fixture
def sim_context():
    """Build fully wired simulation context with local test components."""
    event_store = EventStore(max_capacity=1000)
    alert_store = AlertStore(max_capacity=1000)
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

    return SimulationContext(
        siem_collector=collector,
        event_store=event_store,
        alert_store=alert_store,
        detection_engine=engine,
        ad_server=ad,
        linux_service=linux,
        vuln_client=vuln_client,
        dry_run=False,
    )


BENIGN_SCENARIOS = [s for s in get_all_scenarios() if s.is_benign]


@pytest.mark.parametrize("scenario", BENIGN_SCENARIOS, ids=lambda s: s.id)
def test_benign_scenario_no_false_positive_alerts(scenario, sim_context):
    """Negative control test: Benign activity MUST NOT trigger any security alerts."""
    runner = SimulationRunner()
    res, val = runner.run_scenario(scenario, sim_context)

    # 1. Execution must succeed
    assert (
        res.status.value == "success"
    ), f"Benign scenario {scenario.id} failed execution: {res.error_message}"
    assert res.generated_events_count > 0, f"Benign scenario {scenario.id} generated 0 events"

    # 2. Validation must pass with ZERO alerts
    assert (
        val.passed
    ), f"False positive detected in {scenario.id}: Triggered rules {val.triggered_detection_ids}"
    assert len(val.triggered_detection_ids) == 0
    assert len(val.unexpected_detection_ids) == 0
    assert len(val.generated_alerts) == 0
