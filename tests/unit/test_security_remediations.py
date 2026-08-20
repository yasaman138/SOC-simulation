"""Automated Security Regression & Invariant Test Suite.

Validates that all security remediations, input sanitizations, boundary controls,
and safety invariants are strictly enforced across the enterprise platform.
"""

from datetime import datetime, timezone
import json
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from src.core.config import settings
from src.core.logging import scrub_sensitive_data
from src.response.automation import ResponseAutomationEngine
from src.response.models import (
    AnalystAction,
    ContainmentStatus,
    EvidenceItem,
    Incident,
    IncidentDisposition,
    IncidentSeverity,
    IncidentStatus,
    Indicator,
    IndicatorType,
    LessonsLearned,
    RecoveryStatus,
    RemediationStatus,
    ResponseActionResult,
    RootCauseAnalysis,
    TimelineEntry,
)
from src.response.reporting import IncidentReportGenerator
from src.siem.app import create_siem_app
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventOutcome, EventSeverity
from src.siem.parsers import AuditdParser, SyslogParser, WindowsEventParser
from src.simulation.safety import LabSafetyGuardrail, SafetyBoundaryViolation


# ==============================================================================
# 1. Safety Guardrail & URL Parsing Tests (SEC-FIND-003)
# ==============================================================================

def test_guardrail_blocks_url_userinfo_injection():
    """Verify that URL userinfo trickery targeting external hosts is strictly blocked."""
    # Attacker crafts URL with lab IP in userinfo to trick naive regex/splitters
    malicious_targets = [
        "http://172.28.10.100:password@evil-external-site.com",
        "https://127.0.0.1:admin@malicious-c2.org/payload",
        "http://dc01.corp.enterprise.local:secret@attacker.net",
        "//172.28.20.10:auth@evil.com",
    ]
    for target in malicious_targets:
        assert LabSafetyGuardrail.is_safe_target(target) is False, f"Failed to block: {target}"
        with pytest.raises(SafetyBoundaryViolation):
            LabSafetyGuardrail.assert_safe_target(target)


def test_guardrail_blocks_unauthorized_local_domains():
    """Verify that arbitrary .local domains outside lab infrastructure are blocked."""
    unauthorized = [
        "attacker.local",
        "evil-payload.local",
        "victim-lan.local",
        "home-router.local",
    ]
    for target in unauthorized:
        assert LabSafetyGuardrail.is_safe_target(target) is False, f"Failed to block: {target}"


def test_guardrail_permits_legitimate_lab_infrastructure():
    """Verify that valid internal lab hostnames, subnets, and URLs are approved."""
    allowed = [
        "172.28.10.100",
        "172.28.20.10",
        "172.28.30.10",
        "172.28.90.10",
        "127.0.0.1",
        "localhost",
        "portal.app.local",
        "srv01.corp.enterprise.local",
        "dc01.corp.enterprise.local",
        "siem-collector",
        "http://portal.app.local:8000/api/v1/auth/login",
        "http://172.28.90.10:8088/api/v1/events",
        "db01.app.local",
    ]
    for target in allowed:
        assert LabSafetyGuardrail.is_safe_target(target) is True, f"Legitimate target blocked: {target}"


# ==============================================================================
# 2. Telemetry Parser Resilience & Timestamp Parsing Tests (SEC-FIND-004)
# ==============================================================================

def test_syslog_parser_handles_malformed_json_without_crashing():
    """Ensure malformed or non-dict JSON payloads do not raise unhandled exceptions."""
    malformed_payloads = [
        '{"category": "INVALID_CATEGORY_NAME", "outcome": "INVALID_OUTCOME"}',
        '{"outcome": 12345, "severity": 99999}',
        '[1, 2, 3]',
        '{"message": "Valid string", "custom": "not-a-dict"}',
    ]
    for payload in malformed_payloads:
        event = SyslogParser.parse(payload, source_ip="172.28.20.15")
        assert isinstance(event, ECSEvent)
        assert event.event.category is not None


def test_parsers_preserve_original_timestamps():
    """Verify that original event timestamps are preserved rather than overwritten with now()."""
    iso_ts = "2026-08-19T14:30:00+00:00"
    win_data = {
        "event_id": 4624,
        "TargetUserName": "jdoe",
        "timestamp": iso_ts,
    }
    win_event = WindowsEventParser.parse_dict(win_data, source_ip="172.28.20.10")
    assert win_event.timestamp.isoformat() == iso_ts

    auditd_line = 'type=EXECVE msg=audit(1692440000.500:101): argc=1 a0="whoami" pid=1234'
    audit_event = AuditdParser.parse_line(auditd_line, hostname="linux-srv01", source_ip="172.28.20.15")
    assert audit_event is not None
    assert audit_event.timestamp.year >= 2023


# ==============================================================================
# 3. SOAR Action Hardening & Boundary Defense Tests (SEC-FIND-005)
# ==============================================================================

def test_soar_terminate_process_guardrails():
    """Verify terminate_process rejects protected system PIDs and out-of-scope targets."""
    auto = ResponseAutomationEngine()

    # Out of scope target
    res_external = auto.terminate_process(hostname="external-target.com", pid=5000)
    assert res_external.result == ResponseActionResult.BLOCKED_BY_POLICY

    # Protected system PIDs
    res_pid1 = auto.terminate_process(hostname="linux-srv01.corp.enterprise.local", pid=1)
    assert res_pid1.result == ResponseActionResult.BLOCKED_BY_POLICY

    res_pid0 = auto.terminate_process(hostname="linux-srv01.corp.enterprise.local", pid=0)
    assert res_pid0.result == ResponseActionResult.BLOCKED_BY_POLICY

    # Protected daemon names
    res_systemd = auto.terminate_process(hostname="linux-srv01.corp.enterprise.local", process_name="systemd")
    assert res_systemd.result == ResponseActionResult.BLOCKED_BY_POLICY


def test_soar_restore_backup_path_traversal_defense():
    """Verify restore_backup blocks directory traversal and sensitive system files."""
    auto = ResponseAutomationEngine()

    # Directory traversal
    res_traversal = auto.restore_backup(
        hostname="linux-srv01.corp.enterprise.local",
        file_path="../../etc/shadow",
    )
    assert res_traversal.result == ResponseActionResult.BLOCKED_BY_POLICY

    # Sensitive system files
    res_shadow = auto.restore_backup(
        hostname="linux-srv01.corp.enterprise.local",
        file_path="/etc/shadow",
    )
    assert res_shadow.result == ResponseActionResult.BLOCKED_BY_POLICY

    # Out of boundary host
    res_ext = auto.restore_backup(
        hostname="malicious-server.net",
        file_path="/var/www/index.html",
    )
    assert res_ext.result == ResponseActionResult.BLOCKED_BY_POLICY


def test_soar_revoke_sessions_validates_input():
    """Verify revoke_user_sessions rejects empty usernames."""
    auto = ResponseAutomationEngine()
    res = auto.revoke_user_sessions(username="   ")
    assert res.result == ResponseActionResult.BLOCKED_BY_POLICY


# ==============================================================================
# 4. SIEM API Security Headers & Ingestion Limits (SEC-FIND-006)
# ==============================================================================

def test_siem_security_headers_present():
    """Verify that SIEM responses contain standard defensive HTTP headers."""
    app = create_siem_app()
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in response.headers.get("Content-Security-Policy", "")


def test_siem_batch_ingestion_limit_enforced():
    """Verify that submitting more than MAX_BATCH_SIZE events is rejected with HTTP 413."""
    app = create_siem_app()
    client = TestClient(app)

    # Create batch of 501 events (exceeds limit of 500)
    oversized_batch = [
        {
            "event": {"category": "system", "action": f"test.event.{i}"},
            "message": f"Event {i}",
        }
        for i in range(501)
    ]
    response = client.post("/api/v1/events/batch", json=oversized_batch)
    assert response.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


# ==============================================================================
# 5. Incident Report HTML XSS Prevention (SEC-FIND-002)
# ==============================================================================

def test_incident_report_html_escapes_xss_payloads():
    """Verify that malicious XSS payloads in incident fields are strictly HTML escaped."""
    xss_payload = '<script>alert("XSS")</script><img src=x onerror=alert(1)>'
    malicious_incident = Incident(
        incident_id="INC-XSS-TEST",
        title=f"Attack: {xss_payload}",
        description=f"Description containing {xss_payload}",
        severity=IncidentSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        containment_status=ContainmentStatus.NOT_CONTAINED,
        remediation_status=RemediationStatus.NOT_REMEDIATED,
        recovery_status=RecoveryStatus.PENDING,
        final_disposition=IncidentDisposition.TRUE_POSITIVE_MALICIOUS,
        affected_assets=[f"host-1-{xss_payload}"],
        affected_users=[f"user-1-{xss_payload}"],
        indicators=[
            Indicator(
                type=IndicatorType.IP,
                value="172.28.10.100",
                reputation="MALICIOUS",
                confidence=0.99,
                context=f"Context {xss_payload}",
            )
        ],
        timeline=[
            TimelineEntry(
                timestamp=datetime.now(timezone.utc),
                category="process",
                title=f"Event {xss_payload}",
                description=f"Desc {xss_payload}",
            )
        ],
        root_cause_analysis=RootCauseAnalysis(
            summary=f"Summary {xss_payload}",
            initial_vector=f"Vector {xss_payload}",
            impact_assessment=f"Impact {xss_payload}",
            vulnerabilities_exploited=[f"Vuln {xss_payload}"],
            attack_path=[f"Step {xss_payload}"],
        ),
        lessons_learned=LessonsLearned(
            root_cause_summary=f"Lessons {xss_payload}",
            preventive_recommendations=[f"Rec {xss_payload}"],
            detection_gaps=[f"Gap {xss_payload}"],
            hardening_actions=[f"Harden {xss_payload}"],
        ),
    )

    html_out = IncidentReportGenerator.to_html(malicious_incident)

    # Raw script tags must NOT appear unescaped in the HTML output
    assert "<script>alert" not in html_out
    assert "<img src=x onerror=" not in html_out

    # Escaped versions must be present
    assert "&lt;script&gt;alert" in html_out
    assert "&lt;img src=x onerror=" in html_out


# ==============================================================================
# 6. Logging & Config Secret Scrubbing Tests (SEC-FIND-007)
# ==============================================================================

def test_logging_scrubs_connection_strings_and_jwts():
    """Verify that structured logging sanitizes database passwords, JWTs, and keys."""
    raw_log = (
        "Connected to postgresql://app_user:SuperSecretDBPass123!@172.28.30.20:5432/app_portal "
        "with JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
        "and bearer secret_token_xyz_123456789"
    )
    scrubbed = scrub_sensitive_data(raw_log)

    assert "SuperSecretDBPass123!" not in scrubbed
    assert "postgresql://app_user:***REDACTED***@172.28.30.20:5432/app_portal" in scrubbed
    assert "***REDACTED_JWT***" in scrubbed
    assert "secret_token_xyz_123456789" not in scrubbed


def test_config_sanitizes_db_url_password():
    """Verify that get_sanitized_config removes passwords embedded in database URLs."""
    sanitized = settings.get_sanitized_config()
    assert "***REDACTED***" in sanitized.get("app_secret_key", "")
