"""Unit tests for SIEM Collector, Syslog Parser, and Storage Engine."""

from src.siem.collector import SyslogParser
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventOutcome, EventQuery, EventSeverity


def test_syslog_rfc3164_parser():
    raw_syslog = "<86>Aug 19 12:00:00 linux-srv01 sshd[1234]: Accepted password for sysadmin from 172.28.20.25 port 49152 ssh2"
    event = SyslogParser.parse(raw_syslog, source_ip="172.28.20.15")

    assert event.host.name == "linux-srv01"
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.process.name == "sshd"
    assert event.process.pid == 1234
    assert "Accepted password" in event.message


def test_siem_event_store_query(event_store):
    ev1 = ECSEvent(
        event=EventMetadata(
            category=EventCategory.AUTHENTICATION,
            action="login.success",
            severity=EventSeverity.INFORMATIONAL,
        ),
        message="User logged in",
    )
    ev2 = ECSEvent(
        event=EventMetadata(
            category=EventCategory.PROCESS,
            action="process.spawn",
            severity=EventSeverity.HIGH,
        ),
        message="Suspicious binary executed",
    )

    event_store.add_event(ev1)
    event_store.add_event(ev2)

    # Query by category
    auth_events = event_store.query_events(EventQuery(category=EventCategory.AUTHENTICATION))
    assert len(auth_events) == 1
    assert auth_events[0].event.action == "login.success"

    # Query by severity
    high_events = event_store.query_events(EventQuery(severity=EventSeverity.HIGH))
    assert len(high_events) == 1
    assert high_events[0].event.category == EventCategory.PROCESS

    # Stats
    stats = event_store.get_stats()
    assert stats["total_events"] == 2
    assert stats["by_category"]["authentication"] == 1
    assert stats["by_severity"]["high"] == 1
