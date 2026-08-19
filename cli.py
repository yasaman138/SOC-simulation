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
    subparsers.add_parser("test", help="Run automated test suite")

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
        "test": cmd_test,
    }

    handler = cmd_map.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
