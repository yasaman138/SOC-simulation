"""Integration tests for trust boundaries and network security policy enforcement."""

from src.core.topology import EnterpriseLabTopology, NetworkZone


def test_cross_network_isolation_enforcement(lab_topology):
    # Rule 1: Simulation cannot talk directly to Corporate Internal
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.CORP_INTERNAL, 22, "TCP"
    )
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.CORP_INTERNAL, 445, "TCP"
    )
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.CORP_INTERNAL, 389, "TCP"
    )

    # Rule 2: Simulation cannot talk directly to SIEM Management
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.SIMULATION_EXTERNAL, NetworkZone.SECMON, 8088, "TCP"
    )

    # Rule 3: Application Tier cannot SSH into Corporate Linux
    assert not lab_topology.is_traffic_allowed(
        NetworkZone.APP_TIER, NetworkZone.CORP_INTERNAL, 2222, "TCP"
    )

    # Rule 4: Application Tier CAN authenticate against AD LDAP
    assert lab_topology.is_traffic_allowed(
        NetworkZone.APP_TIER, NetworkZone.CORP_INTERNAL, 389, "TCP"
    )

    # Rule 5: Application Tier CAN push logs to SIEM
    assert lab_topology.is_traffic_allowed(
        NetworkZone.APP_TIER, NetworkZone.SECMON, 8088, "TCP"
    )
