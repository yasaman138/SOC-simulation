"""Unit tests for the SOC Web Dashboard and API endpoints."""

from fastapi.testclient import TestClient
from src.detection.models import AffectedEntities, Alert, MitreAttackInfo, MitreTactic
from src.detection.storage import AlertStore
from src.response.models import (
    Incident,
    IncidentSeverity,
    IncidentStatus,
)
from src.response.storage import AuditStore, IncidentStore
from src.siem.app import create_siem_app
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventSeverity
from src.siem.storage import EventStore


def test_dashboard_html_rendering():
    """Verify GET / and /dashboard render valid HTML with required panels and stats."""
    app = create_siem_app()
    client = TestClient(app)

    r1 = client.get("/")
    assert r1.status_code == 200
    assert "text/html" in r1.headers["content-type"]
    assert "Enterprise SOC Platform" in r1.text
    assert "Investigation UX Workflow" in r1.text

    r2 = client.get("/dashboard")
    assert r2.status_code == 200
    assert "MITRE ATT&CK Matrix" in r2.text


def test_metrics_api_endpoint():
    """Verify GET /api/v1/metrics/soc returns dynamic SOC metrics summary."""
    event_store = EventStore()
    alert_store = AlertStore()
    app = create_siem_app(store=event_store, alerts=alert_store)
    client = TestClient(app)

    resp = client.get("/api/v1/metrics/soc")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_telemetry_events" in data
    assert "detection_rate_percent" in data
    assert "false_positive_rate_percent" in data
    assert "mttd_seconds" in data
    assert "mttr_seconds" in data
    assert "system_health_score" in data


def test_deep_health_api_endpoint():
    """Verify GET /api/v1/health/deep returns deep diagnostics report."""
    app = create_siem_app()
    client = TestClient(app)

    resp = client.get("/api/v1/health/deep")
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_status"] == "healthy"
    assert data["total_components"] == 7
    assert len(data["components"]) == 7


def test_incident_investigation_and_reporting_workflow():
    """Verify Alert -> Investigate -> Incident -> Report API workflow."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    audit_store = AuditStore()

    app = create_siem_app(
        store=event_store,
        alerts=alert_store,
        incidents=inc_store,
        audits=audit_store,
    )
    client = TestClient(app)

    # 1. Add alert
    alt = Alert(
        id="ALT-TEST-99",
        rule_id="RULE-AUTH-001",
        rule_name="Brute Force",
        title="Multiple Auth Failures",
        description="Threshold exceeded",
        severity=EventSeverity.HIGH,
        affected_entities=AffectedEntities(
            host="dc01.corp.enterprise.local",
            user="svc_sql",
            ip="172.28.20.10",
        ),
        mitre_attack=MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1110",
            technique_name="Brute Force",
        ),
    )
    alert_store.add_alert(alt)

    # 2. Trigger automated investigation
    inv_resp = client.post("/api/v1/incidents/investigate/ALT-TEST-99")
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    assert inv_data["status"] == "success"
    inc_id = inv_data["incident_id"]

    # 3. Query incidents list
    inc_list_resp = client.get("/api/v1/incidents")
    assert inc_list_resp.status_code == 200
    assert inc_list_resp.json()["total_matching"] >= 1

    # 4. Get specific incident
    inc_resp = client.get(f"/api/v1/incidents/{inc_id}")
    assert inc_resp.status_code == 200
    assert inc_resp.json()["incident_id"] == inc_id

    # 5. Execute playbook response
    resp_action = client.post(
        f"/api/v1/incidents/{inc_id}/respond",
        json={"playbook_type": "credential", "actor": "test_analyst"},
    )
    assert resp_action.status_code == 200
    assert resp_action.json()["containment_status"] == "contained"

    # 6. Fetch reports in all formats
    rep_html = client.get(f"/api/v1/reports/incident/{inc_id}?format=html")
    assert rep_html.status_code == 200
    assert "text/html" in rep_html.headers["content-type"]
    assert inc_id in rep_html.text

    rep_md = client.get(f"/api/v1/reports/incident/{inc_id}?format=md")
    assert rep_md.status_code == 200
    assert "text/markdown" in rep_md.headers["content-type"]
    assert "# Incident Response Report" in rep_md.text

    rep_json = client.get(f"/api/v1/reports/incident/{inc_id}?format=json")
    assert rep_json.status_code == 200
    assert rep_json.json()["executive_summary"]["incident_id"] == inc_id

    # 7. Check audit log endpoint
    audit_resp = client.get("/api/v1/audit")
    assert audit_resp.status_code == 200
    assert audit_resp.json()["total_matching"] >= 1


def test_simulation_run_api_endpoint():
    """Verify POST /api/v1/simulation/run executes attack scenarios and populates stores."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    app = create_siem_app(store=event_store, alerts=alert_store, incidents=inc_store)
    client = TestClient(app)

    # Initial baseline
    assert event_store.count() == 0
    assert alert_store.count() == 0

    # Run specific attack scenario
    resp = client.post(
        "/api/v1/simulation/run",
        json={"scenario": "SCN-CRED-004", "attack": True, "create_incident": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["scenarios_executed"] == 1
    assert data["total_telemetry_events"] > 0
    assert data["total_alerts"] > 0
    assert data["total_incidents"] > 0
    assert event_store.count() > 0
    assert alert_store.count() > 0


def test_simulation_scenarios_list_api_endpoint():
    """Verify GET /api/v1/simulation/scenarios lists registered scenarios."""
    app = create_siem_app()
    client = TestClient(app)

    resp = client.get("/api/v1/simulation/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_scenarios"] >= 10
    assert len(data["scenarios"]) >= 10


def test_deep_health_does_not_pollute_event_store():
    """Verify calling /api/v1/health/deep repeatedly does not inflate event store counts."""
    event_store = EventStore()
    alert_store = AlertStore()
    app = create_siem_app(store=event_store, alerts=alert_store)
    client = TestClient(app)

    baseline_events = event_store.count()
    assert baseline_events == 0

    # Call health check multiple times
    for _ in range(5):
        resp = client.get("/api/v1/health/deep")
        assert resp.status_code == 200
        assert resp.json()["overall_status"] == "healthy"

    # Event count must remain zero (no pollution)
    assert event_store.count() == 0


def test_reset_lab_api_endpoint():
    """Verify POST /api/v1/reset clears all telemetry, alerts, incidents, and audits."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    app = create_siem_app(store=event_store, alerts=alert_store, incidents=inc_store)
    client = TestClient(app)

    # Run simulation to populate stores
    resp = client.post(
        "/api/v1/simulation/run",
        json={"scenario": "SCN-CRED-004", "attack": True, "create_incident": True},
    )
    assert resp.status_code == 200
    assert event_store.count() > 0
    assert alert_store.count() > 0

    # Call Reset endpoint
    reset_resp = client.post("/api/v1/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "success"

    # Verify stores are empty
    assert event_store.count() == 0
    assert alert_store.count() == 0
    assert inc_store.count() == 0


def test_dashboard_renders_live_metrics_without_flicker():
    """Verify GET / dashboard renders current session numbers directly in HTML."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    app = create_siem_app(store=event_store, alerts=alert_store, incidents=inc_store)
    client = TestClient(app)

    # Populate stores via simulation
    client.post(
        "/api/v1/simulation/run",
        json={"scenario": "SCN-CRED-004", "attack": True, "create_incident": True},
    )
    ev_count = event_store.count()
    assert ev_count > 0

    # Request dashboard HTML
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.text

    # Verify live count is directly rendered in initial HTML
    assert f'id="metric-events">{ev_count}</div>' in html
    assert 'id="metric-events">__INITIAL_EVENTS__' not in html


def test_dashboard_html_remediated_metric_card_and_active_nav_tabs():
    """Verify Remediated Incidents box and active nav tabs CSS/data-attributes are present in dashboard HTML."""
    app = create_siem_app()
    client = TestClient(app)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.text

    # Verify Remediated / Contained stat box is rendered
    assert 'id="metric-remediated"' in html
    assert 'Remediated / Contained' in html

    # Verify data-tab attributes and tab active styles
    assert 'data-tab="overview"' in html
    assert 'data-tab="alerts"' in html
    assert 'data-tab="incidents"' in html
    assert 'data-tab="investigate"' in html
    assert 'tab-overview-active' in html
    assert 'tab-alerts-active' in html
    assert 'tab-incidents-active' in html
    assert 'tab-investigate-active' in html


def test_incident_resolution_flow_updates_metrics():
    """Verify investigation creation, resolve endpoint, and dynamic metric adjustments."""
    event_store = EventStore()
    alert_store = AlertStore()
    inc_store = IncidentStore()
    app = create_siem_app(store=event_store, alerts=alert_store, incidents=inc_store)
    client = TestClient(app)

    # 1. Add alert
    alt = Alert(
        id="ALT-RESOLVE-01",
        rule_id="RULE-AUTH-001",
        rule_name="Brute Force",
        title="Multiple Auth Failures",
        description="Threshold exceeded",
        severity=EventSeverity.HIGH,
    )
    alert_store.add_alert(alt)

    # 2. Investigate alert
    inv_resp = client.post("/api/v1/incidents/investigate/ALT-RESOLVE-01")
    assert inv_resp.status_code == 200
    inc_id = inv_resp.json()["incident_id"]

    # Metric check: Open incident = 1, Remediated = 0, Active alerts = 1
    m1 = client.get("/api/v1/metrics/soc").json()
    assert m1["open_incidents"] == 1
    assert m1["remediated_incidents"] == 0
    assert m1["total_alerts"] == 1

    # 3. Resolve incident upon 7-step investigation completion
    res_resp = client.post(f"/api/v1/incidents/{inc_id}/resolve")
    assert res_resp.status_code == 200
    res_data = res_resp.json()
    assert res_data["status"] == "success"
    assert res_data["containment_status"] == "contained"
    assert res_data["remediation_status"] == "remediated"

    # Metric check: Open incident drops to 0, Remediated increments to 1, Active alerts drops to 0
    m2 = client.get("/api/v1/metrics/soc").json()
    assert m2["open_incidents"] == 0
    assert m2["remediated_incidents"] == 1
    assert m2["total_alerts"] == 0


def test_investigate_endpoint_reuses_existing_incident():
    """Verify investigate endpoint returns existing incident without creating duplicates."""
    alert_store = AlertStore()
    inc_store = IncidentStore()
    app = create_siem_app(alerts=alert_store, incidents=inc_store)
    client = TestClient(app)

    alt = Alert(
        id="ALT-DEDUP-01",
        rule_id="RULE-AUTH-001",
        rule_name="Brute Force",
        title="Multiple Auth Failures",
        description="Threshold exceeded",
        severity=EventSeverity.HIGH,
    )
    alert_store.add_alert(alt)

    resp1 = client.post("/api/v1/incidents/investigate/ALT-DEDUP-01")
    assert resp1.status_code == 200
    inc_id_1 = resp1.json()["incident_id"]

    resp2 = client.post("/api/v1/incidents/investigate/ALT-DEDUP-01")
    assert resp2.status_code == 200
    inc_id_2 = resp2.json()["incident_id"]

    assert inc_id_1 == inc_id_2
    assert inc_store.count() == 1


def test_dashboard_html_structure_updates():
    """Verify reset baseline button is removed and investigation multi-incident queue is rendered."""
    app = create_siem_app()
    client = TestClient(app)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.text

    # Verify reset button is removed
    assert 'id="btn-reset"' not in html
    assert 'Reset Baseline' not in html

    # Verify multi-incident queue and workflow elements are present
    assert 'id="investigation-incidents-selector"' in html
    assert 'id="investigate-incidents-badge"' in html
    assert 'id="investigation-workflow-container"' in html

