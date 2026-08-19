"""Comprehensive Unit Tests for All Detection Rules using Positive and Negative Fixtures."""

import pytest
from src.detection.fixtures import get_all_fixtures
from src.detection.rules import get_default_rules


@pytest.fixture
def rules_by_id():
    rules = get_default_rules()
    return {r.id: r for r in rules}


@pytest.fixture
def fixtures_by_id():
    return get_all_fixtures()


def test_rule_catalog_completeness(rules_by_id, fixtures_by_id):
    """Ensure every registered rule has a corresponding fixture and valid metadata."""
    assert len(rules_by_id) >= 20, f"Expected >= 20 rules, got {len(rules_by_id)}"
    for rule_id, rule in rules_by_id.items():
        assert rule_id in fixtures_by_id, f"Missing fixture for rule: {rule_id}"
        assert rule.id.startswith("DET-")
        assert len(rule.name) > 0
        assert len(rule.description) > 0
        assert rule.severity is not None
        assert rule.mitre_attack is not None
        assert rule.mitre_attack.technique_id.startswith("T")
        assert len(rule.why) > 0
        assert len(rule.data_sources) > 0


@pytest.mark.parametrize("rule_id", list(get_all_fixtures().keys()))
def test_detection_rule_positive_case(rule_id, rules_by_id, fixtures_by_id):
    """Positive test case: Malicious telemetry fixture MUST generate an alert."""
    rule = rules_by_id[rule_id]
    fixture = fixtures_by_id[rule_id]

    alerts = []
    state = {}
    for event in fixture.positive_events:
        alt = rule.evaluate(event, state=state)
        if alt:
            alerts.append(alt)

    assert len(alerts) >= 1, f"Expected alert for positive fixture on {rule_id}, got 0"
    alert = alerts[0]
    assert alert.rule_id == rule.id
    assert alert.severity == fixture.expected_severity
    assert alert.mitre_attack.technique_id.startswith(
        fixture.expected_mitre_technique
    )
    assert len(alert.title) > 0
    assert len(alert.description) > 0


@pytest.mark.parametrize("rule_id", list(get_all_fixtures().keys()))
def test_detection_rule_negative_case(rule_id, rules_by_id, fixtures_by_id):
    """Negative test case: Benign/normal telemetry fixture MUST NOT generate an alert."""
    rule = rules_by_id[rule_id]
    fixture = fixtures_by_id[rule_id]

    alerts = []
    state = {}
    for event in fixture.negative_events:
        alt = rule.evaluate(event, state=state)
        if alt:
            alerts.append(alt)

    assert len(alerts) == 0, f"Expected 0 alerts for negative fixture on {rule_id}, got {len(alerts)}"
