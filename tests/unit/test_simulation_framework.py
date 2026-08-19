"""Unit tests for Attack Simulation Framework Core Components."""

import pytest
from src.core.topology import NetworkZone
from src.detection.engine import DetectionEngine
from src.detection.models import MitreTactic
from src.detection.storage import AlertStore
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.simulation.models import (
    BaseScenario,
    CoverageReport,
    ScenarioExecutionStatus,
    ScenarioResult,
    SimulationContext,
    ValidationResult,
)
from src.simulation.registry import ScenarioRegistry
from src.simulation.runner import SimulationRunner
from src.simulation.safety import LabSafetyGuardrail, SafetyBoundaryViolation
from src.simulation.scenarios import get_all_scenarios


def test_safety_guardrail_allows_approved_targets():
    """Verify that lab networks, subnets, and lab hostnames pass safety checks."""
    assert LabSafetyGuardrail.is_safe_ip("172.28.10.100")
    assert LabSafetyGuardrail.is_safe_ip("172.28.20.10")
    assert LabSafetyGuardrail.is_safe_ip("172.28.30.10")
    assert LabSafetyGuardrail.is_safe_ip("172.28.90.10")
    assert LabSafetyGuardrail.is_safe_ip("127.0.0.1")
    assert LabSafetyGuardrail.is_safe_ip("198.51.100.20")  # Test C2 subnet

    assert LabSafetyGuardrail.is_safe_target("portal.app.local")
    assert LabSafetyGuardrail.is_safe_target("http://portal.app.local:8000")
    assert LabSafetyGuardrail.is_safe_target("srv01.corp.enterprise.local")
    assert LabSafetyGuardrail.is_safe_target("dc01.corp.enterprise.local")
    assert LabSafetyGuardrail.is_safe_target("http://172.28.20.10:389")


def test_safety_guardrail_blocks_external_arbitrary_targets():
    """Verify that external public Internet IPs and unauthorized domains are rejected."""
    unauthorized_targets = [
        "8.8.8.8",
        "1.1.1.1",
        "example.com",
        "evil-attacker-site.org",
        "http://93.184.216.34:80",
        "192.168.1.1",  # Not in lab topology
        "10.0.0.1",     # Not in lab topology
    ]
    for target in unauthorized_targets:
        assert not LabSafetyGuardrail.is_safe_target(target), f"Target should be unsafe: {target}"
        with pytest.raises(SafetyBoundaryViolation):
            LabSafetyGuardrail.assert_safe_target(target)


def test_scenario_registry_and_catalog():
    """Verify scenario discovery, registration, and indexing by tactic."""
    registry = ScenarioRegistry()
    assert registry.count() >= 25, f"Expected >= 25 scenarios, got {registry.count()}"

    # Verify all 10 MITRE tactics are present
    tactic_counts = registry.count_by_tactic()
    required_tactics = [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Command and Control",
        "Collection",
        "Impact",
    ]
    for tactic in required_tactics:
        assert tactic in tactic_counts, f"Missing scenarios for tactic: {tactic}"
        assert tactic_counts[tactic] >= 1

    # Verify benign negative controls
    benign_scenarios = registry.list_scenarios(is_benign=True)
    assert len(benign_scenarios) >= 5


def test_scenario_metadata_serialization():
    """Verify that every scenario exports valid and complete specification metadata."""
    scenarios = get_all_scenarios()
    for s in scenarios:
        meta = s.to_metadata_dict()
        assert meta["id"].startswith("SCN-")
        assert len(meta["name"]) > 0
        assert len(meta["description"]) > 0
        assert "technique_id" in meta["mitre_attack"]
        assert meta["mitre_attack"]["technique_id"].startswith("T")
        assert len(meta["preconditions"]) > 0 or s.is_benign
        assert len(meta["lab_target"]) > 0
        assert len(meta["simulated_behavior"]) > 0
        assert isinstance(meta["is_benign"], bool)


def test_simulation_runner_dry_run():
    """Verify that dry-run mode skips real execution safely."""
    registry = ScenarioRegistry()
    runner = SimulationRunner(registry=registry)

    ctx = SimulationContext(dry_run=True)
    outcomes = runner.run_all(ctx)

    assert len(outcomes) == registry.count()
    for scenario, res, val in outcomes:
        assert res.status == ScenarioExecutionStatus.SKIPPED
        assert "[DRY RUN]" in res.execution_logs[0]
