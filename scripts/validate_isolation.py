#!/usr/bin/env python3
"""Network Segmentation and Trust Boundary Validation Script."""

import os
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from typing import List, Tuple
from src.core.topology import EnterpriseLabTopology, NetworkZone


def validate_network_isolation() -> bool:
    print("=" * 70)
    print("Validating Enterprise Lab Network Isolation & Security Boundaries")
    print("=" * 70)

    topo = EnterpriseLabTopology()
    all_passed = True

    # Test cases: (source_zone, dest_zone, port, proto, expected_allowed, test_description)
    scenarios: List[Tuple[NetworkZone, NetworkZone, int, str, bool, str]] = [
        # Allowed legitimate traffic paths
        (
            NetworkZone.SIMULATION_EXTERNAL,
            NetworkZone.APP_TIER,
            8000,
            "TCP",
            True,
            "External -> App Tier Portal (HTTP 8000)",
        ),
        (
            NetworkZone.APP_TIER,
            NetworkZone.APP_TIER,
            5432,
            "TCP",
            True,
            "App Tier -> Backend Database (Postgres 5432)",
        ),
        (
            NetworkZone.APP_TIER,
            NetworkZone.CORP_INTERNAL,
            389,
            "TCP",
            True,
            "App Tier -> AD Domain Controller (LDAP 389)",
        ),
        (
            NetworkZone.APP_TIER,
            NetworkZone.SECMON,
            8088,
            "TCP",
            True,
            "App Tier -> SIEM Collector (HTTP Ingest 8088)",
        ),
        (
            NetworkZone.CORP_INTERNAL,
            NetworkZone.SECMON,
            5514,
            "UDP",
            True,
            "Corporate Internal -> SIEM Syslog (UDP 5514)",
        ),
        # Blocked unauthorized traversal paths
        (
            NetworkZone.SIMULATION_EXTERNAL,
            NetworkZone.CORP_INTERNAL,
            2222,
            "TCP",
            False,
            "External -> Corporate Linux SSH (Port 2222) - SHOULD BE BLOCKED",
        ),
        (
            NetworkZone.SIMULATION_EXTERNAL,
            NetworkZone.CORP_INTERNAL,
            389,
            "TCP",
            False,
            "External -> AD Domain Controller (LDAP 389) - SHOULD BE BLOCKED",
        ),
        (
            NetworkZone.SIMULATION_EXTERNAL,
            NetworkZone.CORP_INTERNAL,
            445,
            "TCP",
            False,
            "External -> Corporate SMB File Sharing (Port 445) - SHOULD BE BLOCKED",
        ),
        (
            NetworkZone.SIMULATION_EXTERNAL,
            NetworkZone.SECMON,
            8088,
            "TCP",
            False,
            "External -> SIEM Management API (Port 8088) - SHOULD BE BLOCKED",
        ),
        (
            NetworkZone.APP_TIER,
            NetworkZone.CORP_INTERNAL,
            2222,
            "TCP",
            False,
            "App Tier -> Corporate Linux SSH (Port 2222) - SHOULD BE BLOCKED",
        ),
    ]

    for src, dst, port, proto, expected, desc in scenarios:
        actual = topo.is_traffic_allowed(src, dst, port, proto)
        passed = actual == expected
        status_str = "[ PASS ]" if passed else "[ FAIL ]"
        verdict = "ALLOWED" if actual else "BLOCKED"
        expected_str = "ALLOWED" if expected else "BLOCKED"
        print(
            f"{status_str:<10} | {desc:<55} | Result: {verdict:<7} (Expected: {expected_str})"
        )
        if not passed:
            all_passed = False

    print("=" * 70)
    if all_passed:
        print("[+] ALL NETWORK ISOLATION AND TRUST BOUNDARY POLICIES VERIFIED.")
        return True
    else:
        print("[-] NETWORK ISOLATION POLICY VIOLATIONS DETECTED.")
        return False


if __name__ == "__main__":
    success = validate_network_isolation()
    sys.exit(0 if success else 1)
