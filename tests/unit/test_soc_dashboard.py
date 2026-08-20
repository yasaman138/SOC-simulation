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
