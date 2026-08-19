"""Network Topology and Trust Boundaries for the Enterprise Lab."""

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, List, Optional


class NetworkZone(str, Enum):
    """Defined network security zones within the enterprise lab."""

    SIMULATION_EXTERNAL = "simulation_external"
    CORP_INTERNAL = "corp_internal"
    APP_TIER = "app_tier"
    SECMON = "secmon"


class TrustLevel(int, Enum):
    """Trust levels associated with zones (higher = more trusted)."""

    UNTRUSTED = 0
    SEMI_TRUSTED_APP = 10
    INTERNAL_TRUSTED = 50
    SECURITY_MANAGEMENT = 100


@dataclass
class NetworkSubnet:
    """Definition of a lab network subnet."""

    name: str
    zone: NetworkZone
    cidr: str
    gateway: str
    trust_level: TrustLevel
    description: str

    @property
    def network(self) -> IPv4Network:
        return IPv4Network(self.cidr)

    def contains_ip(self, ip_str: str) -> bool:
        return IPv4Address(ip_str) in self.network


@dataclass
class NetworkNode:
    """Definition of an infrastructure host / node."""

    name: str
    hostname: str
    ip_address: str
    zone: NetworkZone
    services: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class FirewallRule:
    """Traffic policy rule between network zones or hosts."""

    source_zone: NetworkZone
    destination_zone: NetworkZone
    destination_port: int
    protocol: str  # TCP, UDP, ANY
    action: str  # ALLOW, DENY
    purpose: str


class EnterpriseLabTopology:
    """Enterprise Lab Topology Manager and Isolation Validator."""

    def __init__(self):
        self.subnets: Dict[NetworkZone, NetworkSubnet] = {
            NetworkZone.SIMULATION_EXTERNAL: NetworkSubnet(
                name="Simulation / External DMZ",
                zone=NetworkZone.SIMULATION_EXTERNAL,
                cidr="172.28.10.0/24",
                gateway="172.28.10.1",
                trust_level=TrustLevel.UNTRUSTED,
                description="Simulated internet and external attacker vantage point.",
            ),
            NetworkZone.APP_TIER: NetworkSubnet(
                name="Application & Data Tier",
                zone=NetworkZone.APP_TIER,
                cidr="172.28.30.0/24",
                gateway="172.28.30.1",
                trust_level=TrustLevel.SEMI_TRUSTED_APP,
                description="Intentionally vulnerable enterprise portal, API, and isolated DB.",
            ),
            NetworkZone.CORP_INTERNAL: NetworkSubnet(
                name="Corporate Internal Network",
                zone=NetworkZone.CORP_INTERNAL,
                cidr="172.28.20.0/24",
                gateway="172.28.20.1",
                trust_level=TrustLevel.INTERNAL_TRUSTED,
                description="Active Directory Domain Controller, Windows workstations, and Linux servers.",
            ),
            NetworkZone.SECMON: NetworkSubnet(
                name="Security & Monitoring Network",
                zone=NetworkZone.SECMON,
                cidr="172.28.90.0/24",
                gateway="172.28.90.1",
                trust_level=TrustLevel.SECURITY_MANAGEMENT,
                description="Centralized SIEM, log collection, and telemetry aggregation.",
            ),
        }

        self.nodes: List[NetworkNode] = [
            NetworkNode(
                name="Edge Reverse Proxy",
                hostname="edge-proxy.lab.local",
                ip_address="172.28.10.5",
                zone=NetworkZone.SIMULATION_EXTERNAL,
                services=["HTTP:80", "HTTPS:443"],
                description="Public-facing reverse proxy routing simulation traffic.",
            ),
            NetworkNode(
                name="Enterprise Web Portal & API",
                hostname="portal.app.local",
                ip_address="172.28.30.10",
                zone=NetworkZone.APP_TIER,
                services=["HTTP:8000"],
                description="Intentionally vulnerable corporate web application.",
            ),
            NetworkNode(
                name="Application Database",
                hostname="db01.app.local",
                ip_address="172.28.30.20",
                zone=NetworkZone.APP_TIER,
                services=["SQL:5432"],
                description="Backend relational database for enterprise portal.",
            ),
            NetworkNode(
                name="Active Directory Domain Controller",
                hostname="dc01.corp.enterprise.local",
                ip_address="172.28.20.10",
                zone=NetworkZone.CORP_INTERNAL,
                services=["LDAP:389", "LDAPS:636", "Kerberos:88", "SMB:445", "DNS:53"],
                description="Primary Domain Controller for CORP.ENTERPRISE.LOCAL.",
            ),
            NetworkNode(
                name="Linux Server (SSH / Bastion)",
                hostname="linux-srv01.corp.enterprise.local",
                ip_address="172.28.20.15",
                zone=NetworkZone.CORP_INTERNAL,
                services=["SSH:2222"],
                description="Internal Linux host with SSH and audit logging.",
            ),
            NetworkNode(
                name="Windows Workstation",
                hostname="wkstn-win10.corp.enterprise.local",
                ip_address="172.28.20.25",
                zone=NetworkZone.CORP_INTERNAL,
                services=["SMB:445", "WinRM:5985"],
                description="Simulated corporate Windows workstation.",
            ),
            NetworkNode(
                name="SIEM / Central Telemetry Collector",
                hostname="siem.secmon.local",
                ip_address="172.28.90.10",
                zone=NetworkZone.SECMON,
                services=["Syslog:5514", "HTTP-Ingest:8088"],
                description="Centralized telemetry ingestion and normalization server.",
            ),
        ]

        self.firewall_rules: List[FirewallRule] = [
            # External -> App Tier (via Proxy)
            FirewallRule(
                source_zone=NetworkZone.SIMULATION_EXTERNAL,
                destination_zone=NetworkZone.APP_TIER,
                destination_port=8000,
                protocol="TCP",
                action="ALLOW",
                purpose="Permit external simulation traffic to access the web portal.",
            ),
            # App Tier -> Database
            FirewallRule(
                source_zone=NetworkZone.APP_TIER,
                destination_zone=NetworkZone.APP_TIER,
                destination_port=5432,
                protocol="TCP",
                action="ALLOW",
                purpose="Permit app server to communicate with backend DB.",
            ),
            # App Tier -> Corporate AD (LDAP Auth query)
            FirewallRule(
                source_zone=NetworkZone.APP_TIER,
                destination_zone=NetworkZone.CORP_INTERNAL,
                destination_port=389,
                protocol="TCP",
                action="ALLOW",
                purpose="Permit portal user authentication against AD LDAP.",
            ),
            # All Zones -> SIEM (Telemetry / Logs)
            FirewallRule(
                source_zone=NetworkZone.APP_TIER,
                destination_zone=NetworkZone.SECMON,
                destination_port=8088,
                protocol="TCP",
                action="ALLOW",
                purpose="Forward application audit telemetry to SIEM.",
            ),
            FirewallRule(
                source_zone=NetworkZone.CORP_INTERNAL,
                destination_zone=NetworkZone.SECMON,
                destination_port=5514,
                protocol="UDP",
                action="ALLOW",
                purpose="Forward Linux/AD syslog events to SIEM.",
            ),
            # Default Deny Rules
            FirewallRule(
                source_zone=NetworkZone.SIMULATION_EXTERNAL,
                destination_zone=NetworkZone.CORP_INTERNAL,
                destination_port=0,
                protocol="ANY",
                action="DENY",
                purpose="Prevent direct external access to internal corporate domain.",
            ),
            FirewallRule(
                source_zone=NetworkZone.SIMULATION_EXTERNAL,
                destination_zone=NetworkZone.SECMON,
                destination_port=0,
                protocol="ANY",
                action="DENY",
                purpose="Prevent external tampering with security monitoring stack.",
            ),
            FirewallRule(
                source_zone=NetworkZone.APP_TIER,
                destination_zone=NetworkZone.CORP_INTERNAL,
                destination_port=2222,
                protocol="TCP",
                action="DENY",
                purpose="Isolate Linux SSH from application tier.",
            ),
        ]

    def is_traffic_allowed(
        self,
        source_zone: NetworkZone,
        destination_zone: NetworkZone,
        port: int,
        protocol: str = "TCP",
    ) -> bool:
        """Evaluate traffic against defined security policy."""
        if source_zone == destination_zone:
            return True

        # Check explicit rules
        for rule in self.firewall_rules:
            if (
                rule.source_zone == source_zone
                and rule.destination_zone == destination_zone
            ):
                if rule.protocol in (protocol, "ANY") and (
                    rule.destination_port in (port, 0)
                ):
                    return rule.action == "ALLOW"

        # Default policy: DENY cross-zone traffic unless explicit allow
        return False

    def validate_node_ip_allocations(self) -> List[str]:
        """Verify that every defined node belongs to its respective subnet."""
        errors = []
        for node in self.nodes:
            subnet = self.subnets.get(node.zone)
            if not subnet:
                errors.append(f"Node {node.name} assigned to unknown zone {node.zone}")
            elif not subnet.contains_ip(node.ip_address):
                errors.append(
                    f"Node {node.name} IP {node.ip_address} not in subnet {subnet.cidr} for zone {node.zone}"
                )
        return errors
