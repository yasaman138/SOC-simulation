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
        "test": cmd_test,
    }

    handler = cmd_map.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
