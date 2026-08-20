#!/usr/bin/env python3
"""Unified CLI for Enterprise Attack Detection & Response Lab."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from src.core.config import settings
from src.core.topology import EnterpriseLabTopology
from src.infra.ad_directory.server import ActiveDirectoryServer


def cmd_status(args):
    print("=" * 70)
    print("Enterprise Attack Detection & Response Lab - Status")
    print("=" * 70)
    print(f"Lab Environment:    {settings.lab_environment}")
    print(f"Active Directory:   {settings.ad_domain_name} (DC: {settings.ad_dc_hostname})")
    print(f"Linux Server:       {settings.linux_srv_hostname} (SSH: {settings.linux_ssh_port})")
    print(f"Web Application:    http://{settings.app_host}:{settings.app_port}")
    print(f"SIEM Collector:     http://{settings.siem_host}:{settings.siem_http_port}")
    print("-" * 70)

    topo = EnterpriseLabTopology()
    print("Network Subnets:")
    for zone, sub in topo.subnets.items():
        print(f"  • {sub.name:<30} {sub.cidr:<18} (Trust: {sub.trust_level.name})")

    print("\nInfrastructure Nodes:")
    for node in topo.nodes:
        print(f"  • {node.hostname:<35} {node.ip_address:<16} [{', '.join(node.services)}]")
    print("=" * 70)


def cmd_health(args):
    from scripts.healthcheck import run_healthchecks

    success = run_healthchecks()
    sys.exit(0 if success else 1)


def cmd_validate(args):
    from scripts.validate_isolation import validate_network_isolation

    success = validate_network_isolation()
    sys.exit(0 if success else 1)


def cmd_bootstrap(args):
    res = subprocess.run(["bash", str(ROOT_DIR / "scripts" / "bootstrap.sh")])
    sys.exit(res.returncode)


def cmd_teardown(args):
    res = subprocess.run(["bash", str(ROOT_DIR / "scripts" / "teardown.sh")])
    sys.exit(res.returncode)


def cmd_detections(args):
    from src.detection.rules import get_default_rules

    rules = get_default_rules()
    print("=" * 80)
    print("Enterprise Attack Detection Engine - Detection Rules Catalog")
    print("=" * 80)
    print(f"{'ID':<15} {'Severity':<10} {'MITRE ATT&CK':<18} {'Rule Name'}")
    print("-" * 80)
    for r in rules:
        t_id = r.mitre_attack.technique_id
        if r.mitre_attack.subtechnique_id:
            t_id = r.mitre_attack.subtechnique_id
        print(f"{r.id:<15} {r.severity.value.upper():<10} {t_id:<18} {r.name}")
    print("=" * 80)
    print(f"Total Rules Registered: {len(rules)}")


def cmd_alerts(args):
    from src.detection.models import AlertQuery
    from src.siem.app import alert_store

    alerts = alert_store.query_alerts(AlertQuery(limit=50))
    print("=" * 80)
    print("Enterprise Attack Detection Engine - Security Alerts")
    print("=" * 80)
    if not alerts:
        print("No active alerts in local alert store.")
    else:
        print(f"{'ID':<16} {'Severity':<10} {'Rule ID':<15} {'Title'}")
        print("-" * 80)
        for a in alerts:
            print(f"{a.id:<16} {a.severity.value.upper():<10} {a.rule_id:<15} {a.title}")
    print("=" * 80)
    print(f"Total Active Alerts: {alert_store.count()}")


def cmd_simulate(args):
    """Execute attack simulation scenarios or benign negative controls."""
    from fastapi.testclient import TestClient
    from src.detection.engine import DetectionEngine
    from src.detection.storage import AlertStore
    from src.infra.ad_directory.server import ActiveDirectoryServer
    from src.infra.linux_server.service import LinuxServerService
    from src.siem.collector import SIEMCollector
    from src.siem.storage import EventStore
    from src.simulation.models import SimulationContext
    from src.simulation.registry import ScenarioRegistry
    from src.simulation.runner import SimulationRunner
    from src.vulnapp.app import create_app
    from src.vulnapp.telemetry import AppTelemetryClient

    # Set up runtime context
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
        dry_run=args.dry_run,
    )

    registry = ScenarioRegistry()
    runner = SimulationRunner(registry=registry)

    target_scenarios = []
    if args.scenario:
        scn = registry.get_scenario(args.scenario)
        if not scn:
            print(f"Error: Scenario '{args.scenario}' not found.")
            sys.exit(1)
        target_scenarios = [scn]
    elif args.benign:
        target_scenarios = registry.list_scenarios(is_benign=True)
    elif args.attack:
        target_scenarios = registry.list_scenarios(is_benign=False)
    else:
        target_scenarios = registry.list_scenarios()

    print(f"Executing {len(target_scenarios)} simulation scenarios...")
    results = runner.run_all(sim_context, scenarios=target_scenarios)
    report = runner.generate_coverage_report(results)
    print(runner.format_coverage_table(report))


def cmd_coverage(args):
    """Run full attack simulation suite and output comprehensive MITRE ATT&CK coverage report."""
    from fastapi.testclient import TestClient
    import json
    from src.detection.engine import DetectionEngine
    from src.detection.storage import AlertStore
    from src.infra.ad_directory.server import ActiveDirectoryServer
    from src.infra.linux_server.service import LinuxServerService
    from src.siem.collector import SIEMCollector
    from src.siem.storage import EventStore
    from src.simulation.models import SimulationContext
    from src.simulation.registry import ScenarioRegistry
    from src.simulation.runner import SimulationRunner
    from src.vulnapp.app import create_app
    from src.vulnapp.telemetry import AppTelemetryClient

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

    registry = ScenarioRegistry()
    runner = SimulationRunner(registry=registry)
    results = runner.run_all(sim_context)
    report = runner.generate_coverage_report(results)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(runner.format_coverage_table(report))


def cmd_incidents(args):
    """View and filter security incidents in the SOC store."""
    from src.response.models import IncidentQuery
    from src.response.playbooks import generate_incident_report_markdown
    from src.response.storage import IncidentStore

    # Standalone incident demonstration if none in runtime store
    inc_store = IncidentStore()
    if args.id:
        inc = inc_store.get_incident(args.id)
        if not inc:
            print(f"Incident '{args.id}' not found in active store.")
            sys.exit(1)
        print(generate_incident_report_markdown(inc))
    else:
        incidents = inc_store.list_incidents()
        print("=" * 80)
        print("Enterprise SOC Incident Response - Active Incidents")
        print("=" * 80)
        if not incidents:
            print("No active incidents. Use 'simulate' or 'investigate' to generate incidents.")
        else:
            print(f"{'ID':<15} {'Severity':<10} {'Status':<15} {'Title'}")
            print("-" * 80)
            for inc in incidents:
                print(f"{inc.incident_id:<15} {inc.severity.value.upper():<10} {inc.status.value.upper():<15} {inc.title}")
        print("=" * 80)


def cmd_investigate(args):
    """Execute automated multi-source investigation and correlation on simulated attack or alert."""
    from fastapi.testclient import TestClient
    from src.detection.engine import DetectionEngine
    from src.detection.storage import AlertStore
    from src.infra.ad_directory.server import ActiveDirectoryServer
    from src.infra.linux_server.service import LinuxServerService
    from src.response.investigation import InvestigationEngine
    from src.response.playbooks import generate_incident_report_markdown
    from src.response.storage import IncidentStore
    from src.siem.collector import SIEMCollector
    from src.siem.storage import EventStore
    from src.simulation.models import SimulationContext
    from src.simulation.registry import ScenarioRegistry
    from src.vulnapp.app import create_app
    from src.vulnapp.telemetry import AppTelemetryClient

    event_store = EventStore(max_capacity=5000)
    alert_store = AlertStore(max_capacity=5000)
    detection_engine = DetectionEngine(alert_store=alert_store)
    siem_collector = SIEMCollector(store=event_store, detection_engine=detection_engine)
    ad = ActiveDirectoryServer(siem_collector=siem_collector)
    linux = LinuxServerService(siem_collector=siem_collector)
    telemetry = AppTelemetryClient(local_collector=siem_collector)
    vuln_app = create_app(database_url="sqlite:///:memory:", telemetry_client=telemetry, enable_vulnerabilities=True)
    vuln_client = TestClient(vuln_app)

    sim_context = SimulationContext(
        siem_collector=siem_collector,
        event_store=event_store,
        alert_store=alert_store,
        detection_engine=detection_engine,
        ad_server=ad,
        linux_service=linux,
        vuln_client=vuln_client,
        dry_run=False,
    )

    registry = ScenarioRegistry()
    scn_id = args.scenario or "SCN-CRED-004"
    scenario = registry.get_scenario(scn_id)
    if not scenario:
        print(f"Error: Scenario '{scn_id}' not found.")
        sys.exit(1)

    print(f"1. Simulating attack scenario: [{scenario.id}] {scenario.name}...")
    scenario.execute(sim_context)

    alerts = alert_store.query_alerts()
    if not alerts:
        print("No alerts generated to investigate.")
        sys.exit(0)

    print(f"2. Detection triggered {len(alerts)} security alerts. Launching Automated Investigation Engine...")
    inv_engine = InvestigationEngine(event_store=event_store, alert_store=alert_store)
    incident = inv_engine.create_incident_from_alert(alerts[0])

    print(f"\n3. Automated Investigation Complete for Incident [{incident.incident_id}]:")
    print(f"   • Affected Assets:   {', '.join(incident.affected_assets)}")
    print(f"   • Affected Users:    {', '.join(incident.affected_users)}")
    print(f"   • Timeline Events:   {len(incident.timeline)}")
    print(f"   • Indicators (IOCs): {len(incident.indicators)}")
    print(f"   • Initial Vector:    {incident.root_cause_analysis.initial_vector if incident.root_cause_analysis else 'N/A'}")
    print("\n" + generate_incident_report_markdown(incident))


def cmd_respond(args):
    """Execute end-to-end incident investigation and response playbook workflow."""
    from fastapi.testclient import TestClient
    from src.detection.engine import DetectionEngine
    from src.detection.storage import AlertStore
    from src.infra.ad_directory.server import ActiveDirectoryServer
    from src.infra.linux_server.service import LinuxServerService
    from src.response.automation import ResponseAutomationEngine
    from src.response.investigation import InvestigationEngine
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
    from src.vulnapp.app import create_app
    from src.vulnapp.telemetry import AppTelemetryClient

    event_store = EventStore(max_capacity=5000)
    alert_store = AlertStore(max_capacity=5000)
    audit_store = AuditStore(max_capacity=5000)
    detection_engine = DetectionEngine(alert_store=alert_store)
    siem_collector = SIEMCollector(store=event_store, detection_engine=detection_engine)
    ad = ActiveDirectoryServer(siem_collector=siem_collector)
    linux = LinuxServerService(siem_collector=siem_collector)
    telemetry = AppTelemetryClient(local_collector=siem_collector)
    vuln_app = create_app(database_url="sqlite:///:memory:", telemetry_client=telemetry, enable_vulnerabilities=True)
    vuln_client = TestClient(vuln_app)

    sim_context = SimulationContext(
        siem_collector=siem_collector,
        event_store=event_store,
        alert_store=alert_store,
        detection_engine=detection_engine,
        ad_server=ad,
        linux_service=linux,
        vuln_client=vuln_client,
        dry_run=False,
    )

    inv_engine = InvestigationEngine(event_store=event_store, alert_store=alert_store)
    auto_engine = ResponseAutomationEngine(
        audit_store=audit_store,
        siem_collector=siem_collector,
        ad_server=ad,
        linux_service=linux,
    )

    playbook_map = {
        "credential": (CredentialCompromisePlaybook(), "SCN-CRED-004"),
        "lateral": (LateralMovementPlaybook(), "SCN-LAT-001"),
        "malware": (MalwareRansomwarePlaybook(), "SCN-IMP-002"),
    }

    p_type = args.playbook or "credential"
    if p_type not in playbook_map:
        print(f"Unknown playbook '{p_type}'. Options: credential, lateral, malware")
        sys.exit(1)

    playbook, default_scn = playbook_map[p_type]
    registry = ScenarioRegistry()
    scenario = registry.get_scenario(default_scn)

    print("=" * 80)
    print(f"Executing Incident Response Playbook: {playbook.name}")
    print("=" * 80)
    print(f"Stage 1: Simulating Attack Scenario [{scenario.id}] {scenario.name}...")
    scenario.execute(sim_context)

    alerts = alert_store.query_alerts()
    print(f"Stage 2: Detections triggered {len(alerts)} alerts. Initializing Incident...")
    incident = inv_engine.create_incident_from_alert(alerts[0])

    print("Stage 3: Executing Automated Containment, Remediation, and Recovery...")
    resolved_incident = playbook.execute(
        incident=incident,
        investigation_engine=inv_engine,
        automation_engine=auto_engine,
    )

    print("\nStage 4: Incident Response Final Report:")
    print(generate_incident_report_markdown(resolved_incident))


def cmd_audit(args):
    """View response action audit trail."""
    from src.response.storage import AuditStore

    # Demonstrative audit entries
    audit_store = AuditStore()
    entries = audit_store.list_entries(limit=args.limit)
    print("=" * 80)
    print("Enterprise SOC - Response Actions Audit Trail")
    print("=" * 80)
    if not entries:
        print("No actions in audit log. Execute a response playbook with 'respond' command.")
    else:
        print(f"{'ID':<16} {'Action':<18} {'Actor':<15} {'Target':<20} {'Result'}")
        print("-" * 80)
        for e in entries:
            print(f"{e.id:<16} {e.action.value:<18} {e.actor:<15} {e.target:<20} {e.result.value.upper()}")
    print("=" * 80)


def cmd_test(args):
    print("Running project test suite with pytest...")
    res = subprocess.run(["python3", "-m", "pytest", "-v"])
    sys.exit(res.returncode)


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Attack Detection & Response Lab CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Lab commands")

    subparsers.add_parser("status", help="Show lab topology and component status")
    subparsers.add_parser("health", help="Execute automated health checks")
    subparsers.add_parser("validate", help="Validate network isolation and trust boundaries")
    subparsers.add_parser("bootstrap", help="Bootstrap and verify lab baseline")
    subparsers.add_parser("teardown", help="Teardown and clean lab runtime")
    subparsers.add_parser("detections", help="List registered detection rules and MITRE ATT&CK coverage")
    subparsers.add_parser("alerts", help="View security alerts generated by detection engine")
    subparsers.add_parser("test", help="Run automated test suite")

    sim_parser = subparsers.add_parser("simulate", help="Run attack simulation scenarios")
    sim_parser.add_argument("--scenario", "-s", help="Specific scenario ID to run (e.g., SCN-INIT-001)")
    sim_parser.add_argument("--benign", action="store_true", help="Run only benign negative control scenarios")
    sim_parser.add_argument("--attack", action="store_true", help="Run only attack scenarios")
    sim_parser.add_argument("--dry-run", action="store_true", help="Perform dry-run simulation without execution")

    cov_parser = subparsers.add_parser("coverage", help="Generate MITRE ATT&CK detection coverage report")
    cov_parser.add_argument("--json", action="store_true", help="Output coverage matrix in JSON format")

    inc_parser = subparsers.add_parser("incidents", help="View security incidents")
    inc_parser.add_argument("--id", help="View details and report for a specific incident ID")

    inv_parser = subparsers.add_parser("investigate", help="Execute automated investigation on attack scenario or alert")
    inv_parser.add_argument("--scenario", "-s", help="Scenario ID to simulate and investigate (default: SCN-CRED-004)")

    resp_parser = subparsers.add_parser("respond", help="Execute automated incident response playbook")
    resp_parser.add_argument("--playbook", "-p", choices=["credential", "lateral", "malware"], default="credential", help="Playbook type to execute")

    aud_parser = subparsers.add_parser("audit", help="View response automation audit log")
    aud_parser.add_argument("--limit", type=int, default=50, help="Maximum entries to display")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmd_map = {
        "status": cmd_status,
        "health": cmd_health,
        "validate": cmd_validate,
        "bootstrap": cmd_bootstrap,
        "teardown": cmd_teardown,
        "detections": cmd_detections,
        "alerts": cmd_alerts,
        "simulate": cmd_simulate,
        "coverage": cmd_coverage,
        "incidents": cmd_incidents,
        "investigate": cmd_investigate,
        "respond": cmd_respond,
        "audit": cmd_audit,
        "test": cmd_test,
    }

    handler = cmd_map.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
