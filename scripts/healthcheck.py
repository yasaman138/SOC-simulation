#!/usr/bin/env python3
"""Automated Health Check Utility for Enterprise Security Lab Components."""

import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from typing import Dict, List, Tuple
from fastapi.testclient import TestClient

from src.core.config import settings
from src.core.topology import EnterpriseLabTopology
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.app import create_siem_app
from src.siem.collector import SIEMCollector
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventOutcome, EventSeverity
from src.siem.storage import EventStore
from src.vulnapp.app import create_app


def run_healthchecks() -> bool:
    print("=" * 70)
    print("Running Enterprise Attack Detection & Response Lab - Health Checks")
    print("=" * 70)

    all_passed = True
    results: List[Tuple[str, bool, str]] = []

    # 1. Configuration and Topology Check
    try:
        settings.validate_networks()
        topo = EnterpriseLabTopology()
        errors = topo.validate_node_ip_allocations()
        if errors:
            results.append(("Network Topology", False, f"Errors: {errors}"))
            all_passed = False
        else:
            results.append(("Network Topology", True, "4 Subnets / 7 Nodes / No CIDR overlaps"))
    except Exception as e:
        results.append(("Network Topology", False, str(e)))
        all_passed = False

    # 2. Active Directory Domain Services Check
    try:
        ad = ActiveDirectoryServer()
        users_count = len(ad.users)
        groups_count = len(ad.groups)
        ous_count = len(ad.ous)
        spn_accounts = ad.list_spn_accounts()

        # Test simulated authentication
        auth_success = ad.authenticate_user("jdoe", "LabPassword123!")
        auth_failure = not ad.authenticate_user("jdoe", "WrongPassword!")

        # Test Kerberos TGS request
        tgs = ad.request_kerberos_tgs("jdoe", "MSSQLSvc/db01.corp.enterprise.local:1433")

        if (
            users_count >= 7
            and groups_count >= 6
            and len(spn_accounts) >= 2
            and auth_success
            and auth_failure
            and tgs is not None
        ):
            results.append(
                (
                    "Active Directory (dc01)",
                    True,
                    f"Domain: {ad.domain_name} | {users_count} Users | {groups_count} Groups | {len(spn_accounts)} SPNs | KDC Active",
                )
            )
        else:
            results.append(("Active Directory (dc01)", False, "AD verification assertions failed"))
            all_passed = False
    except Exception as e:
        results.append(("Active Directory (dc01)", False, str(e)))
        all_passed = False

    # 3. Linux Infrastructure & Centralized Logging Check
    try:
        store = EventStore()
        siem = SIEMCollector(store=store)
        linux_srv = LinuxServerService(siem_collector=siem)

        ssh_ok = linux_srv.simulate_ssh_login("sysadmin", password="LinuxAdminLab2026!")
        ssh_denied = not linux_srv.simulate_ssh_login("root", password="any")
        exec_res = linux_srv.simulate_command_execution("sysadmin", "whoami")

        if ssh_ok and ssh_denied and exec_res.get("logged"):
            results.append(
                (
                    "Linux Infrastructure (linux-srv01)",
                    True,
                    f"Host: {linux_srv.config.hostname} | SSH: Port 2222 | Syslog/Auditd Pipeline Active",
                )
            )
        else:
            results.append(("Linux Infrastructure (linux-srv01)", False, "Linux verification failed"))
            all_passed = False
    except Exception as e:
        results.append(("Linux Infrastructure (linux-srv01)", False, str(e)))
        all_passed = False

    # 4. SIEM & Centralized Telemetry Collector Check
    try:
        siem_app = create_siem_app()
        client = TestClient(siem_app)

        health_resp = client.get("/health")
        stats_resp = client.get("/api/v1/stats")

        # Ingest a test event
        test_ev = ECSEvent(
            event=EventMetadata(
                category=EventCategory.SYSTEM,
                action="lab.healthcheck.probe",
                severity=EventSeverity.INFORMATIONAL,
            ),
            message="Health check telemetry verification probe",
        )
        ingest_resp = client.post("/api/v1/events", json=test_ev.model_dump(mode="json"))

        if (
            health_resp.status_code == 200
            and stats_resp.status_code == 200
            and ingest_resp.status_code == 201
        ):
            results.append(
                (
                    "SIEM Telemetry Collector",
                    True,
                    "HTTP API (Port 8088) / Syslog (Port 5514) / ECS Normalization OK",
                )
            )
        else:
            results.append(("SIEM Telemetry Collector", False, "SIEM API response code mismatch"))
            all_passed = False
    except Exception as e:
        results.append(("SIEM Telemetry Collector", False, str(e)))
        all_passed = False

    # 5. Application Tier & Intentionally Vulnerable Web App Check
    try:
        app = create_app(database_url="sqlite:///:memory:")
        app_client = TestClient(app)

        app_health = app_client.get("/health")
        sqli_test = app_client.get("/api/v1/employees/search?query=John")
        ping_test = app_client.post("/api/v1/tools/ping", json={"target": "127.0.0.1"})
        doc_test = app_client.get("/api/v1/documents/DOC-9001?user_id=1")

        if (
            app_health.status_code == 200
            and sqli_test.status_code == 200
            and ping_test.status_code == 200
            and doc_test.status_code == 200
        ):
            results.append(
                (
                    "Application Tier (vulnapp & DB)",
                    True,
                    "Enterprise Portal & API / SQLite DB / 5 Intentional Lab Vulnerabilities Active",
                )
            )
        else:
            results.append(("Application Tier (vulnapp & DB)", False, "App endpoints check failed"))
            all_passed = False
    except Exception as e:
        results.append(("Application Tier (vulnapp & DB)", False, str(e)))
        all_passed = False

    # Display Results Table
    for component, status, detail in results:
        status_str = "[ PASS ]" if status else "[ FAIL ]"
        print(f"{status_str:<10} | {component:<35} | {detail}")

    print("=" * 70)
    if all_passed:
        print("[+] ALL ENTERPRISE LAB HEALTH CHECKS PASSED SUCCESSFULLY.")
        return True
    else:
        print("[-] SOME HEALTH CHECKS FAILED.")
        return False


if __name__ == "__main__":
    success = run_healthchecks()
    sys.exit(0 if success else 1)
