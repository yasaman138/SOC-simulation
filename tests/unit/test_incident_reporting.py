"""Unit tests for the Structured Multi-Format Incident Reporting Engine."""

from datetime import datetime, timezone
import json
from src.detection.models import MitreAttackInfo, MitreTactic
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
    RootCauseAnalysis,
    TimelineEntry,
)
from src.response.reporting import IncidentReportGenerator


def _create_sample_incident() -> Incident:
    """Build a comprehensive sample incident with all 12 sections populated."""
    inc = Incident(
        incident_id="INC-TEST-001",
        title="Kerberoasting and Domain Escalation",
        description="Adversary executed Kerberoasting to extract TGS service tickets for SPN accounts.",
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.RECOVERED,
        containment_status=ContainmentStatus.CONTAINED,
        remediation_status=RemediationStatus.REMEDIATED,
        recovery_status=RecoveryStatus.VERIFIED,
        final_disposition=IncidentDisposition.TRUE_POSITIVE_MALICIOUS,
        affected_assets=["dc01.corp.enterprise.local", "172.28.20.10"],
        affected_users=["svc_sql", "jdoe"],
        detection_source=["ALT-001", "DET-CRED-002"],
        metadata={"rule_name": "Kerberoasting Service Ticket Request", "primary_alert_id": "ALT-001"},
    )

    # MITRE ATT&CK
    inc.mitre_attack.append(
        MitreAttackInfo(
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            technique_id="T1558",
            technique_name="Steal or Forge Kerberos Tickets",
            subtechnique_id="T1558.003",
            subtechnique_name="Kerberoasting",
        )
    )

    # Timeline
    now = datetime.now(timezone.utc)
    inc.add_timeline_entry(
        TimelineEntry(
            timestamp=now,
            category="directory_service",
            title="TGS Request for MSSQLSvc",
            description="RC4-HMAC ticket requested by jdoe",
            is_key_event=True,
        )
    )

    # Indicator
    inc.add_indicator(
        Indicator(
            type=IndicatorType.IP,
            value="172.28.10.100",
            reputation="malicious",
            confidence=0.9,
            context="Attack simulation origin",
        )
    )

    # Evidence
    inc.add_evidence(
        EvidenceItem(
            evidence_type="log_event",
            description="Active Directory Event 4769",
            source="windows.security_auditing",
        )
    )

    # Actions
    inc.log_action(
        AnalystAction(
            actor="soar_automation",
            action_type="containment",
            description="Disabled user account 'svc_sql'",
            status="completed",
        )
    )
    inc.log_action(
        AnalystAction(
            actor="soc_analyst",
            action_type="remediation",
            description="Rotated SPN password to AES-256 Kerberos keys",
            status="completed",
        )
    )

    # Root Cause Analysis
    inc.root_cause_analysis = RootCauseAnalysis(
        summary="Service account had weak RC4 encryption enabled.",
        initial_vector="Compromised Domain User workstation",
        vulnerabilities_exploited=["Weak Kerberos Service Encryption (RC4-HMAC)"],
        attack_path=["jdoe requests TGS for MSSQLSvc -> Offline hash cracking"],
        impact_assessment="Scope isolated to lab service account.",
        confidence=0.95,
    )

    # Lessons Learned
    inc.lessons_learned = LessonsLearned(
        root_cause_summary="Legacy encryption types permitted offline cracking.",
        preventive_recommendations=["Enforce AES-256 Kerberos across all SPNs."],
        detection_gaps=["Add alerting for RC4 ticket downgrade attempts."],
        hardening_actions=["Audit all domain service accounts."],
    )

    return inc


def test_incident_report_dict_generation():
    """Verify dictionary report compiles all 12 required sections."""
    inc = _create_sample_incident()
    data = IncidentReportGenerator.generate_report_dict(inc)

    assert "report_metadata" in data
    assert "executive_summary" in data
    assert "technical_summary" in data
    assert "timeline" in data
    assert "indicators" in data
    assert "affected_systems" in data
    assert "attack_techniques" in data
    assert "detection_details" in data
    assert "analyst_actions" in data
    assert "containment" in data
    assert "root_cause" in data
    assert "remediation" in data
    assert "lessons_learned" in data

    assert data["executive_summary"]["incident_id"] == "INC-TEST-001"
    assert data["executive_summary"]["severity"] == "high"
    assert len(data["timeline"]) == 1
    assert len(data["indicators"]) == 1
    assert len(data["attack_techniques"]) == 1


def test_incident_report_json():
    """Verify JSON report serializes cleanly and is valid JSON."""
    inc = _create_sample_incident()
    json_str = IncidentReportGenerator.to_json(inc)
    parsed = json.loads(json_str)

    assert parsed["executive_summary"]["incident_id"] == "INC-TEST-001"
    assert parsed["technical_summary"]["containment_status"] == "contained"
    assert "T1558" in json_str


def test_incident_report_markdown():
    """Verify Markdown report format contains headers and formatted tables."""
    inc = _create_sample_incident()
    md = IncidentReportGenerator.to_markdown(inc)

    assert "# Incident Response Report: Kerberoasting and Domain Escalation" in md
    assert "## 1. Executive Summary" in md
    assert "## 2. Technical Summary" in md
    assert "## 3. Chronological Investigation Timeline" in md
    assert "## 4. Indicators of Compromise (IOCs)" in md
    assert "## 5. Affected Systems & Assets" in md
    assert "## 6. MITRE ATT&CK Mapping" in md
    assert "## 7. Detection Details & Telemetry" in md
    assert "## 8. Analyst Actions & SOAR Audit Log" in md
    assert "## 9. Containment Verification" in md
    assert "## 10. Root Cause Analysis" in md
    assert "## 11. Remediation & Recovery Steps" in md
    assert "## 12. Lessons Learned & Hardening Recommendations" in md
    assert "172.28.10.100" in md
    assert "T1558.003" in md


def test_incident_report_html():
    """Verify HTML report is valid, self-contained HTML with styling and data."""
    inc = _create_sample_incident()
    html_out = IncidentReportGenerator.to_html(inc)

    assert "<!DOCTYPE html>" in html_out
    assert "<title>Incident Report: Kerberoasting and Domain Escalation</title>" in html_out
    assert "INC-TEST-001" in html_out
    assert "1. Executive Summary" in html_out
    assert "172.28.10.100" in html_out
    assert "T1558" in html_out
