"""Safety & Containment Guardrails for Attack Simulation Framework.

Enforces strict isolation boundaries ensuring that offensive security simulations
execute exclusively against approved local laboratory infrastructure and synthetic endpoints.
"""

import ipaddress
import re
from typing import List
from src.core.logging import get_logger

logger = get_logger("simulation.safety")


class SafetyBoundaryViolation(Exception):
    """Raised when an operation attempts to target an unauthorized host or external IP."""
    pass


class LabSafetyGuardrail:
    """Validator enforcing laboratory network containment."""

    APPROVED_NETWORKS: List[ipaddress.IPv4Network] = [
        ipaddress.IPv4Network("172.28.10.0/24"),  # Simulation / External DMZ
        ipaddress.IPv4Network("172.28.20.0/24"),  # Corporate Internal
        ipaddress.IPv4Network("172.28.30.0/24"),  # Web Application Tier
        ipaddress.IPv4Network("172.28.90.0/24"),  # Security Monitoring / SIEM
        ipaddress.IPv4Network("127.0.0.0/8"),     # Localhost Loopback
        ipaddress.IPv4Network("198.51.100.0/24"), # RFC 5737 TEST-NET-2 (Simulated C2/External)
        ipaddress.IPv4Network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3 (Simulated External)
    ]

    APPROVED_HOSTNAMES: List[str] = [
        "localhost",
        "127.0.0.1",
        "portal.app.local",
        "app-portal",
        "srv01.corp.enterprise.local",
        "linux-server",
        "dc01.corp.enterprise.local",
        "ad-dc",
        "siem-collector",
        "secmon.lab.local",
        "edge-proxy.lab.local",
        "wkstn01.corp.enterprise.local",
        "wkstn-win10",
    ]

    APPROVED_DOMAIN_SUFFIXES: List[str] = [
        ".lab.local",
        ".corp.enterprise.local",
        ".app.local",
        ".local",
    ]

    @classmethod
    def is_safe_ip(cls, ip_str: str) -> bool:
        """Check if an IPv4 address resides within the approved lab subnets."""
        try:
            addr = ipaddress.IPv4Address(ip_str)
            for net in cls.APPROVED_NETWORKS:
                if addr in net:
                    return True
            return False
        except ValueError:
            return False

    @classmethod
    def is_safe_target(cls, target: str) -> bool:
        """Validate if target hostname, IP, or URL is strictly within lab boundaries."""
        if not target:
            return False

        clean_target = target.strip().lower()

        # Remove http/https protocol prefix if present
        clean_target = re.sub(r"^https?://", "", clean_target)
        # Strip port number if present
        clean_target = clean_target.split(":")[0].split("/")[0]

        # Check direct IP
        if cls.is_safe_ip(clean_target):
            return True

        # Check explicit hostname
        if clean_target in cls.APPROVED_HOSTNAMES:
            return True

        # Check domain suffix
        for suffix in cls.APPROVED_DOMAIN_SUFFIXES:
            if clean_target.endswith(suffix):
                return True

        return False

    @classmethod
    def assert_safe_target(cls, target: str) -> None:
        """Raise SafetyBoundaryViolation if target is not safe lab infrastructure."""
        if not cls.is_safe_target(target):
            error_msg = (
                f"SAFETY BOUNDARY VIOLATION: Target '{target}' is not within approved lab subnets "
                f"(172.28.0.0/16, 127.0.0.1, *.corp.enterprise.local). Execution blocked."
            )
            logger.critical(error_msg)
            raise SafetyBoundaryViolation(error_msg)
