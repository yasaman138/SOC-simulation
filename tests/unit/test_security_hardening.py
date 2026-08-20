"""Unit tests for repository-wide security hardening and boundary validation."""

import os
import re
from pathlib import Path
from src.core.config import settings
from src.core.topology import EnterpriseLabTopology
from src.simulation.safety import LabSafetyGuardrail

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def test_repository_secret_hygiene():
    """Verify that no real API keys, cloud secrets, or private keys exist in source control."""
    suspicious_patterns = [
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),  # GitHub Personal Access Token
        re.compile(r"AIza[0-9A-Za-z-_]{35}"),  # Google API Key
        re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
    ]

    violations = []
    for root, dirs, files in os.walk(ROOT_DIR):
        # Exclude git and cache
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "venv", "node_modules")]
        for file in files:
            if file.endswith((".py", ".md", ".yml", ".yaml", ".json", ".tf", ".sh", ".conf")):
                file_path = Path(root) / file
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                    for pattern in suspicious_patterns:
                        if pattern.search(content):
                            violations.append(f"{file_path}: matched {pattern.pattern}")
                except Exception:
                    pass

    assert len(violations) == 0, f"Found sensitive secret pattern violations: {violations}"


def test_safety_guardrails_prevent_external_targeting():
    """Verify safety guardrails strictly block any target outside the isolated lab boundary."""
    # Allowed internal lab targets
    assert LabSafetyGuardrail.is_safe_target("172.28.10.100") is True
    assert LabSafetyGuardrail.is_safe_target("172.28.20.10") is True
    assert LabSafetyGuardrail.is_safe_target("dc01.corp.enterprise.local") is True
    assert LabSafetyGuardrail.is_safe_target("linux-srv01.corp.enterprise.local") is True

    # External targets MUST be blocked
    assert LabSafetyGuardrail.is_safe_target("8.8.8.8") is False
    assert LabSafetyGuardrail.is_safe_target("1.1.1.1") is False
    assert LabSafetyGuardrail.is_safe_target("google.com") is False
    assert LabSafetyGuardrail.is_safe_target("192.168.1.1") is False
    assert LabSafetyGuardrail.is_safe_target("10.0.0.1") is False


def test_network_isolation_and_trust_boundaries():
    """Verify network segmentation and non-overlapping subnets."""
    topo = EnterpriseLabTopology()
    assert topo.validate_node_ip_allocations() == []
    assert settings.validate_networks() is True

    # Verify 4 distinct subnets
    assert len(topo.subnets) == 4
    zone_names = [z.value for z in topo.subnets.keys()]
    assert "simulation_external" in zone_names
    assert "corp_internal" in zone_names
    assert "app_tier" in zone_names
    assert "secmon" in zone_names
