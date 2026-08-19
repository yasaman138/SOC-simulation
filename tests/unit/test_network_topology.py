"""Unit tests for Network Topology and Subnet Allocations."""

from src.core.topology import (
    EnterpriseLabTopology,
    NetworkZone,
    TrustLevel,
)


def test_topology_subnets_initialization(lab_topology):
    assert len(lab_topology.subnets) == 4
    assert lab_topology.subnets[NetworkZone.SIMULATION_EXTERNAL].trust_level == TrustLevel.UNTRUSTED
    assert lab_topology.subnets[NetworkZone.CORP_INTERNAL].trust_level == TrustLevel.INTERNAL_TRUSTED
    assert lab_topology.subnets[NetworkZone.APP_TIER].trust_level == TrustLevel.SEMI_TRUSTED_APP
    assert lab_topology.subnets[NetworkZone.SECMON].trust_level == TrustLevel.SECURITY_MANAGEMENT


def test_node_ip_allocations(lab_topology):
    errors = lab_topology.validate_node_ip_allocations()
    assert len(errors) == 0, f"Found IP allocation errors: {errors}"


def test_firewall_policy_rules(lab_topology):
    # Allowed: External to App Tier (Port 8000)
    assert lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.APP_TIER, 8000, "TCP"
    )

    # Allowed: App Tier to DB (Port 5432)
    assert lab_topology.is_traffic_allowed(
        NetworkZone.APP_TIER, NetworkZone.APP_TIER, 5432, "TCP"
    )

    # Denied: External to Corporate Internal
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.CORP_INTERNAL, 2222, "TCP"
    )

    # Denied: External to Security Monitoring
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.SECMON, 8088, "TCP"
    )
