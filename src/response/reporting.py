"""Structured Multi-Format Incident Reporting Engine.

Generates comprehensive Executive and Technical Incident Response reports
in Markdown, JSON, and self-contained styled HTML format across all 12 standard
incident reporting sections.
"""

from datetime import datetime, timezone
import html
import json
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.response.models import (
    AnalystAction,
    ContainmentStatus,
    EvidenceItem,
    Incident,
    IncidentDisposition,
    IncidentSeverity,
    IncidentStatus,
    Indicator,
    LessonsLearned,
    RecoveryStatus,
    RemediationStatus,
    RootCauseAnalysis,
    TimelineEntry,
)

logger = get_logger("response.reporting")


class IncidentReportGenerator:
    """Enterprise Incident Response Report Generator."""

    @staticmethod
    def generate_report_dict(incident: Incident) -> Dict[str, Any]:
        """Compile a structured dictionary containing all 12 report sections."""
        ts_str = incident.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Executive Summary
        exec_summary = {
            "title": incident.title,
            "incident_id": incident.incident_id,
            "timestamp": ts_str,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "final_disposition": incident.final_disposition.value,
            "overview": incident.description,
            "impact": incident.root_cause_analysis.impact_assessment if incident.root_cause_analysis else "Threat contained to isolated lab environment.",
            "root_cause_summary": incident.root_cause_analysis.summary if incident.root_cause_analysis else "Security incident triggered by anomalous activity.",
        }

        # 2. Technical Summary
        tech_summary = {
            "containment_status": incident.containment_status.value,
            "remediation_status": incident.remediation_status.value,
            "recovery_status": incident.recovery_status.value,
            "timeline_event_count": len(incident.timeline),
            "indicators_count": len(incident.indicators),
            "evidence_items_count": len(incident.evidence_references),
            "analyst_actions_count": len(incident.analyst_actions),
        }

        # 3. Timeline
        timeline_entries = [t.to_dict() for t in incident.timeline]

        # 4. Indicators (IOCs)
        indicators = [i.to_dict() for i in incident.indicators]

        # 5. Affected Systems & Users
        affected_entities = {
            "affected_assets": incident.affected_assets,
            "affected_users": incident.affected_users,
        }

        # 6. Attack Techniques (MITRE ATT&CK)
        attack_techniques = [m.to_dict() for m in incident.mitre_attack]

        # 7. Detection Details
        detection_details = {
            "detection_sources": incident.detection_source,
            "primary_alert_id": incident.metadata.get("primary_alert_id", "N/A"),
            "rule_name": incident.metadata.get("rule_name", "N/A"),
            "evidence_references": [e.to_dict() for e in incident.evidence_references],
        }

        # 8. Analyst Actions & Automation Log
        analyst_actions = [a.to_dict() for a in incident.analyst_actions]

        # 9. Containment Actions
        containment_section = {
            "status": incident.containment_status.value,
            "actions": [
                a.to_dict()
                for a in incident.analyst_actions
                if a.action_type in ("containment", "isolation", "block")
            ],
        }

        # 10. Root Cause Analysis
        root_cause = incident.root_cause_analysis.to_dict() if incident.root_cause_analysis else {}

        # 11. Remediation & Recovery
        remediation_section = {
            "remediation_status": incident.remediation_status.value,
            "recovery_status": incident.recovery_status.value,
            "remediation_actions": [
                a.to_dict()
                for a in incident.analyst_actions
                if a.action_type in ("remediation", "recovery", "rollback")
            ],
        }

        # 12. Lessons Learned & Hardening
        lessons_learned = incident.lessons_learned.to_dict() if incident.lessons_learned else {}

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "generator": "Enterprise SOC Automated Reporting Engine",
                "version": "1.0.0",
            },
            "executive_summary": exec_summary,
            "technical_summary": tech_summary,
            "timeline": timeline_entries,
            "indicators": indicators,
            "affected_systems": affected_entities,
            "attack_techniques": attack_techniques,
            "detection_details": detection_details,
            "analyst_actions": analyst_actions,
            "containment": containment_section,
            "root_cause": root_cause,
            "remediation": remediation_section,
            "lessons_learned": lessons_learned,
        }

    @classmethod
    def to_json(cls, incident: Incident, indent: int = 2) -> str:
        """Generate structured JSON incident report."""
        data = cls.generate_report_dict(incident)
        return json.dumps(data, indent=indent)

    @classmethod
    def to_markdown(cls, incident: Incident) -> str:
        """Generate structured Markdown incident report."""
        md = []
        md.append(f"# Incident Response Report: {incident.title}")
        md.append(f"**Incident ID:** `{incident.incident_id}`  ")
        md.append(f"**Generated:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ")
        md.append(f"**Severity:** `{incident.severity.value.upper()}` | **Status:** `{incident.status.value.upper()}` | **Disposition:** `{incident.final_disposition.value.upper()}`\n")
        md.append("---")

        # 1. Executive Summary
        md.append("## 1. Executive Summary")
        md.append(incident.description)
        if incident.root_cause_analysis:
            md.append(f"\n- **Root Cause Summary:** {incident.root_cause_analysis.summary}")
            md.append(f"- **Impact Assessment:** {incident.root_cause_analysis.impact_assessment}")
            md.append(f"- **Initial Attack Vector:** {incident.root_cause_analysis.initial_vector}")
        md.append("")

        # 2. Technical Summary
        md.append("## 2. Technical Summary")
        md.append(f"- **Containment Status:** `{incident.containment_status.value.upper()}`")
        md.append(f"- **Remediation Status:** `{incident.remediation_status.value.upper()}`")
        md.append(f"- **Recovery Status:** `{incident.recovery_status.value.upper()}`")
        md.append(f"- **Correlated Events:** {len(incident.timeline)}")
        md.append(f"- **Identified Indicators (IOCs):** {len(incident.indicators)}")
        md.append(f"- **Forensic Evidence Items:** {len(incident.evidence_references)}\n")

        # 3. Chronological Incident Timeline
        md.append("## 3. Chronological Investigation Timeline")
        if incident.timeline:
            md.append("| Timestamp (UTC) | Category | Key Event | Title | Description |")
            md.append("|---|---|---|---|---|")
            for t in incident.timeline:
                t_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                key_tag = "⚡ **YES**" if t.is_key_event else "No"
                md.append(f"| {t_str} | `{t.category}` | {key_tag} | **{t.title}** | {t.description} |")
        else:
            md.append("No timeline events recorded.")
        md.append("")

        # 4. Indicators of Compromise (IOCs)
        md.append("## 4. Indicators of Compromise (IOCs)")
        if incident.indicators:
            md.append("| Type | Value | Reputation | Confidence | Context |")
            md.append("|---|---|---|---|---|")
            for ioc in incident.indicators:
                md.append(f"| `{ioc.type.value}` | `{ioc.value}` | **{ioc.reputation.upper()}** | {ioc.confidence:.2f} | {ioc.context} |")
        else:
            md.append("No specific indicators identified.")
        md.append("")

        # 5. Affected Systems & Users
        md.append("## 5. Affected Systems & Assets")
        md.append(f"- **Affected Hosts/IPs:** {', '.join(f'`{a}`' for a in incident.affected_assets) or 'None'}")
        md.append(f"- **Affected User Accounts:** {', '.join(f'`{u}`' for u in incident.affected_users) or 'None'}\n")

        # 6. Attack Techniques (MITRE ATT&CK)
        md.append("## 6. MITRE ATT&CK Mapping")
        if incident.mitre_attack:
            md.append("| Tactic | Technique ID | Technique Name | Subtechnique |")
            md.append("|---|---|---|---|")
            for m in incident.mitre_attack:
                sub = f"`{m.subtechnique_id}` ({m.subtechnique_name})" if m.subtechnique_id else "N/A"
                md.append(f"| `{m.tactic.value}` | `{m.technique_id}` | {m.technique_name} | {sub} |")
        else:
            md.append("No MITRE ATT&CK mappings identified.")
        md.append("")

        # 7. Detection Details
        md.append("## 7. Detection Details & Telemetry")
        md.append(f"- **Detection Sources:** {', '.join(incident.detection_source) or 'N/A'}")
        if incident.metadata.get("rule_name"):
            md.append(f"- **Triggering Detection Rule:** {incident.metadata['rule_name']}")
        if incident.evidence_references:
            md.append(f"- **Forensic Evidence Items Collected:** {len(incident.evidence_references)}")
            for ev in incident.evidence_references:
                md.append(f"  - `[{ev.evidence_type}]` {ev.description} (Source: `{ev.source}`)")
        md.append("")

        # 8. Analyst Actions & Automation Log
        md.append("## 8. Analyst Actions & SOAR Audit Log")
        if incident.analyst_actions:
            for act in incident.analyst_actions:
                act_ts = act.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                md.append(f"- `[{act_ts}]` **{act.action_type.upper()}** by `{act.actor}`: {act.description} *(Status: {act.status})*")
        else:
            md.append("No response actions recorded.")
        md.append("")

        # 9. Containment Actions
        md.append("## 9. Containment Verification")
        md.append(f"- **Containment Status:** `{incident.containment_status.value.upper()}`")
        containment_actions = [a for a in incident.analyst_actions if a.action_type in ("containment", "isolation", "block")]
        if containment_actions:
            for c in containment_actions:
                md.append(f"  - {c.description} (Status: `{c.status}`)")
        else:
            md.append("  - No active containment actions required.")
        md.append("")

        # 10. Root Cause Analysis
        md.append("## 10. Root Cause Analysis")
        if incident.root_cause_analysis:
            md.append(f"**Analysis Summary:** {incident.root_cause_analysis.summary}\n")
            md.append(f"**Initial Attack Vector:** {incident.root_cause_analysis.initial_vector}\n")
            if incident.root_cause_analysis.vulnerabilities_exploited:
                md.append("**Exploited Vulnerabilities / Misconfigurations:**")
                for v in incident.root_cause_analysis.vulnerabilities_exploited:
                    md.append(f"- {v}")
            if incident.root_cause_analysis.attack_path:
                md.append("\n**Reconstructed Attack Path:**")
                for p in incident.root_cause_analysis.attack_path:
                    md.append(f"1. {p}")
        else:
            md.append("Root cause analysis pending.")
        md.append("")

        # 11. Remediation & Recovery
        md.append("## 11. Remediation & Recovery Steps")
        md.append(f"- **Remediation Status:** `{incident.remediation_status.value.upper()}`")
        md.append(f"- **Recovery Status:** `{incident.recovery_status.value.upper()}`")
        rem_actions = [a for a in incident.analyst_actions if a.action_type in ("remediation", "recovery", "rollback")]
        for r in rem_actions:
            md.append(f"- {r.description}")
        md.append("")

        # 12. Lessons Learned & Hardening Recommendations
        md.append("## 12. Lessons Learned & Hardening Recommendations")
        if incident.lessons_learned:
            md.append(f"**Post-Incident Summary:** {incident.lessons_learned.root_cause_summary}\n")
            if incident.lessons_learned.preventive_recommendations:
                md.append("### Preventive Security Controls")
                for rec in incident.lessons_learned.preventive_recommendations:
                    md.append(f"- {rec}")
            if incident.lessons_learned.detection_gaps:
                md.append("\n### Detection Engineering Improvements")
                for gap in incident.lessons_learned.detection_gaps:
                    md.append(f"- {gap}")
            if incident.lessons_learned.hardening_actions:
                md.append("\n### Infrastructure Hardening Actions")
                for act in incident.lessons_learned.hardening_actions:
                    md.append(f"- {act}")
        else:
            md.append("No post-incident recommendations recorded.")

        md.append("\n---")
        md.append("*Enterprise Security Operations Center - Automated Incident Response Platform*")
        return "\n".join(md)

    @classmethod
    def to_html(cls, incident: Incident) -> str:
        """Generate self-contained, printable, polished HTML incident report."""
        ts_str = incident.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        sev_colors = {
            "critical": "#EF4444",
            "high": "#F97316",
            "medium": "#F59E0B",
            "low": "#3B82F6",
            "informational": "#6B7280",
        }
        sev_color = sev_colors.get(incident.severity.value, "#F59E0B")

        # Build timeline rows
        timeline_rows = []
        if incident.timeline:
            for t in incident.timeline:
                t_str = t.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                mark = "⚡ " if t.is_key_event else ""
                row = f"<tr><td>{t_str}</td><td><code>{html.escape(t.category)}</code></td><td>{mark}<strong>{html.escape(t.title)}</strong></td><td>{html.escape(t.description)}</td></tr>"
                timeline_rows.append(row)
        else:
            timeline_rows.append("<tr><td colspan='4'>No timeline events.</td></tr>")

        # Build IOC rows
        ioc_rows = []
        if incident.indicators:
            for i in incident.indicators:
                row = f"<tr><td><code>{html.escape(i.type.value)}</code></td><td><code>{html.escape(i.value)}</code></td><td><strong>{html.escape(i.reputation.upper())}</strong></td><td>{i.confidence:.2f}</td><td>{html.escape(i.context)}</td></tr>"
                ioc_rows.append(row)
        else:
            ioc_rows.append("<tr><td colspan='5'>No IOCs recorded.</td></tr>")

        # Build MITRE rows
        mitre_rows = []
        if incident.mitre_attack:
            for m in incident.mitre_attack:
                sub_text = f"<code>{html.escape(m.subtechnique_id)}</code> ({html.escape(m.subtechnique_name or '')})" if m.subtechnique_id else "N/A"
                row = f"<tr><td><code>{html.escape(m.tactic.value)}</code></td><td><code>{html.escape(m.technique_id)}</code></td><td>{html.escape(m.technique_name)}</td><td>{sub_text}</td></tr>"
                mitre_rows.append(row)
        else:
            mitre_rows.append("<tr><td colspan='4'>No MITRE mappings.</td></tr>")

        # Build Evidence rows
        evidence_items = []
        if incident.evidence_references:
            for e in incident.evidence_references:
                evidence_items.append(f"<li><code>[{html.escape(e.evidence_type)}]</code> {html.escape(e.description)} (Source: <code>{html.escape(e.source)}</code>)</li>")
        else:
            evidence_items.append("<li>No evidence records attached.</li>")

        # Build Actions rows
        action_items = []
        if incident.analyst_actions:
            for a in incident.analyst_actions:
                a_ts = a.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                action_items.append(f"<li><code>[{a_ts}]</code> <strong>{html.escape(a.action_type.upper())}</strong> by <code>{html.escape(a.actor)}</code>: {html.escape(a.description)} (Status: {html.escape(a.status)})</li>")
        else:
            action_items.append("<li>No actions recorded.</li>")

        # Build Lessons Learned items
        lessons_body = []
        if incident.lessons_learned:
            lessons_body.append(f"<p>{html.escape(incident.lessons_learned.root_cause_summary)}</p>")
            if incident.lessons_learned.preventive_recommendations:
                recs = "".join(f"<li>{html.escape(r)}</li>" for r in incident.lessons_learned.preventive_recommendations)
                lessons_body.append(f"<h3>Preventive Recommendations</h3><ul>{recs}</ul>")
        else:
            lessons_body.append("<p>No lessons learned recorded.</p>")

        root_cause_body = []
        if incident.root_cause_analysis:
            root_cause_body.append(f"<p><strong>Root Cause:</strong> {html.escape(incident.root_cause_analysis.summary)}</p>")
            root_cause_body.append(f"<p><strong>Impact Assessment:</strong> {html.escape(incident.root_cause_analysis.impact_assessment)}</p>")

        hosts_str = ", ".join(f"<code>{html.escape(a)}</code>" for a in incident.affected_assets) or "None"
        users_str = ", ".join(f"<code>{html.escape(u)}</code>" for u in incident.affected_users) or "None"

        # HTML document assembly
        html_code = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Incident Report: {html.escape(incident.title)}</title>
<style>
  :root {{
    --bg: #0B0F19;
    --card-bg: #111827;
    --border: #1F2937;
    --text: #E5E7EB;
    --text-muted: #9CA3AF;
    --accent: #6366F1;
    --cyan: #06B6D4;
    --green: #10B981;
    --red: #EF4444;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text);
    line-height: 1.6;
    margin: 0;
    padding: 40px 20px;
  }}
  .container {{
    max-width: 1000px;
    margin: 0 auto;
  }}
  .header-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5);
  }}
  .badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .section {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  h1, h2, h3 {{
    color: #F9FAFB;
    margin-top: 0;
  }}
  h2 {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    font-size: 1.25rem;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 14px;
  }}
  th, td {{
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  th {{
    background-color: #1F2937;
    color: #9CA3AF;
    font-weight: 600;
  }}
  code {{
    background: #1F2937;
    color: #38BDF8;
    padding: 2px 6px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
  }}
  ul {{
    padding-left: 20px;
  }}
  li {{
    margin-bottom: 6px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-top: 16px;
  }}
  .meta-item {{
    background: #1F2937;
    padding: 12px;
    border-radius: 8px;
  }}
  .meta-label {{
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
  }}
  .meta-value {{
    font-size: 15px;
    font-weight: 600;
    color: #F9FAFB;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header-card">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <h1>{html.escape(incident.title)}</h1>
      <span class="badge" style="background:{sev_color}; color:#fff;">{incident.severity.value.upper()}</span>
    </div>
    <div class="meta-grid">
      <div class="meta-item">
        <div class="meta-label">Incident ID</div>
        <div class="meta-value"><code>{incident.incident_id}</code></div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Timestamp</div>
        <div class="meta-value">{ts_str}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Status</div>
        <div class="meta-value"><span class="badge" style="background:#374151;">{incident.status.value.upper()}</span></div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Disposition</div>
        <div class="meta-value">{incident.final_disposition.value.upper()}</div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>1. Executive Summary</h2>
    <p>{html.escape(incident.description)}</p>
    {"".join(root_cause_body)}
  </div>

  <div class="section">
    <h2>2. Technical Summary</h2>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Containment</div><div class="meta-value">{incident.containment_status.value.upper()}</div></div>
      <div class="meta-item"><div class="meta-label">Remediation</div><div class="meta-value">{incident.remediation_status.value.upper()}</div></div>
      <div class="meta-item"><div class="meta-label">Recovery</div><div class="meta-value">{incident.recovery_status.value.upper()}</div></div>
      <div class="meta-item"><div class="meta-label">Timeline Events</div><div class="meta-value">{len(incident.timeline)}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>3. Chronological Timeline</h2>
    <table>
      <thead><tr><th>Timestamp (UTC)</th><th>Category</th><th>Event</th><th>Description</th></tr></thead>
      <tbody>
        {"".join(timeline_rows)}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>4. Indicators of Compromise (IOCs)</h2>
    <table>
      <thead><tr><th>Type</th><th>Value</th><th>Reputation</th><th>Confidence</th><th>Context</th></tr></thead>
      <tbody>
        {"".join(ioc_rows)}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>5. Affected Systems & Assets</h2>
    <ul>
      <li><strong>Hosts / IP Addresses:</strong> {hosts_str}</li>
      <li><strong>User Accounts:</strong> {users_str}</li>
    </ul>
  </div>

  <div class="section">
    <h2>6. MITRE ATT&CK Mapping</h2>
    <table>
      <thead><tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Subtechnique</th></tr></thead>
      <tbody>
        {"".join(mitre_rows)}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>7. Detection Details & Evidence</h2>
    <p><strong>Detection Sources:</strong> {html.escape(', '.join(incident.detection_source) or 'N/A')}</p>
    <ul>
      {"".join(evidence_items)}
    </ul>
  </div>

  <div class="section">
    <h2>8. Containment & Remediation Audit Log</h2>
    <ul>
      {"".join(action_items)}
    </ul>
  </div>

  <div class="section">
    <h2>9. Lessons Learned & Recommendations</h2>
    {"".join(lessons_body)}
  </div>

  <div style="text-align:center; color:var(--text-muted); font-size:12px; margin-top:30px;">
    Enterprise Security Operations Center &bull; Generated {gen_time}
  </div>
</div>
</body>
</html>"""
        return html_code
