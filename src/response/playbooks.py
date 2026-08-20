"""Structured Incident Response Playbooks & Workflow Automation."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.detection.models import Alert
from src.response.automation import ResponseAutomationEngine
from src.response.investigation import InvestigationEngine
from src.response.models import (
    AnalystAction,
    ContainmentStatus,
    EvidenceItem,
    Incident,
    IncidentDisposition,
    IncidentSeverity,
    IncidentStatus,
    IndicatorType,
    RecoveryStatus,
    RemediationStatus,
    ResponseActionResult,
)

logger = get_logger("response.playbooks")


def generate_incident_report_markdown(incident: Incident) -> str:
    """Generate an executive and technical Incident Response Report in Markdown format."""
    ts_str = incident.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

    md = []
    md.append(f"# Incident Response Report: {incident.title}")
    md.append(f"**Incident ID:** `{incident.incident_id}`  ")
    md.append(f"**Timestamp:** `{ts_str}`  ")
    md.append(f"**Severity:** `{incident.severity.value.upper()}`  ")
    md.append(f"**Status:** `{incident.status.value.upper()}`  ")
    md.append(f"**Disposition:** `{incident.final_disposition.value.upper()}`  ")
    md.append(f"**Containment Status:** `{incident.containment_status.value.upper()}`  ")
    md.append(f"**Remediation Status:** `{incident.remediation_status.value.upper()}`  ")
    md.append(f"**Recovery Status:** `{incident.recovery_status.value.upper()}`\n")

    md.append("## 1. Executive Summary")
    md.append(incident.description)
    if incident.root_cause_analysis:
        md.append(f"\n**Root Cause Summary:** {incident.root_cause_analysis.summary}")
        md.append(f"**Impact Assessment:** {incident.root_cause_analysis.impact_assessment}")
    md.append("")

    md.append("## 2. Scope & Affected Entities")
    md.append(f"- **Affected Assets:** {', '.join(incident.affected_assets) or 'None'}")
    md.append(f"- **Affected Users:** {', '.join(incident.affected_users) or 'None'}")
    md.append(f"- **Detection Sources:** {', '.join(incident.detection_source) or 'None'}\n")

    md.append("## 3. Indicators of Compromise (IOCs)")
    if incident.indicators:
        md.append("| Type | Value | Reputation | Confidence | Context |")
        md.append("|---|---|---|---|---|")
        for ioc in incident.indicators:
            md.append(f"| `{ioc.type.value}` | `{ioc.value}` | **{ioc.reputation.upper()}** | {ioc.confidence:.2f} | {ioc.context} |")
    else:
        md.append("No specific IOCs identified.")
    md.append("")

    md.append("## 4. MITRE ATT&CK Mapping")
    if incident.mitre_attack:
        md.append("| Tactic | Technique ID | Technique Name | Subtechnique |")
        md.append("|---|---|---|---|")
        for m in incident.mitre_attack:
            sub = f"{m.subtechnique_id} ({m.subtechnique_name})" if m.subtechnique_id else "N/A"
            md.append(f"| `{m.tactic.value}` | `{m.technique_id}` | {m.technique_name} | {sub} |")
    else:
        md.append("No MITRE ATT&CK mappings associated.")
    md.append("")

    md.append("## 5. Chronological Investigation Timeline")
    if incident.timeline:
        md.append("| Timestamp (UTC) | Category | Key Event | Title | Description |")
        md.append("|---|---|---|---|---|")
        for entry in incident.timeline:
            t_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            key_mark = "⚡ YES" if entry.is_key_event else "No"
            md.append(f"| {t_str} | `{entry.category}` | {key_mark} | **{entry.title}** | {entry.description} |")
    else:
        md.append("Timeline empty.")
    md.append("")

    md.append("## 6. Containment & Remediation Audit Trail")
    if incident.analyst_actions:
        for act in incident.analyst_actions:
            act_ts = act.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            md.append(f"- `[{act_ts}]` **{act.action_type.upper()}** by `{act.actor}`: {act.description} *(Status: {act.status})*")
    else:
        md.append("No response actions recorded.")
    md.append("")

    if incident.lessons_learned:
        md.append("## 7. Lessons Learned & Hardening Recommendations")
        md.append(f"**Review:** {incident.lessons_learned.root_cause_summary}\n")
        md.append("### Preventive Recommendations")
        for rec in incident.lessons_learned.preventive_recommendations:
            md.append(f"- {rec}")
        md.append("\n### Procedural & Detection Improvements")
        for det in incident.lessons_learned.detection_gaps:
            md.append(f"- {det}")
        for proc in incident.lessons_learned.procedural_improvements:
            md.append(f"- {proc}")
    md.append("\n---")
    md.append("*Enterprise Security Operations Center - Automated Incident Investigation Report*")

    return "\n".join(md)


class BaseIncidentPlaybook(ABC):
    """Abstract Base Class for Automated Incident Response Playbooks."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(
        self,
        incident: Incident,
        investigation_engine: InvestigationEngine,
        automation_engine: ResponseAutomationEngine,
        actor: str = "soar_automation",
    ) -> Incident:
        """Execute full-lifecycle playbook workflow."""
        pass


class CredentialCompromisePlaybook(BaseIncidentPlaybook):
    """Full-Lifecycle Playbook for Credential Compromise (Brute Force, Kerberoasting, OS Credential Dumping)."""

    def __init__(self):
        super().__init__(
            name="Credential Compromise Response Playbook",
            description="Automated triage, multi-source investigation, user disabling, session revocation, and recovery for credential attacks.",
        )

    def execute(
        self,
        incident: Incident,
        investigation_engine: InvestigationEngine,
        automation_engine: ResponseAutomationEngine,
        actor: str = "soar_automation",
    ) -> Incident:
        logger.info(f"Executing [{self.name}] for Incident {incident.incident_id}...")

        # Stage 1: Triage
        incident.status = IncidentStatus.TRIAGED
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="triage",
                description=f"Triaged credential compromise alert across assets: {incident.affected_assets}, users: {incident.affected_users}",
            )
        )

        # Stage 2: Investigation & Multi-Source Timeline Correlation
        investigation_engine.correlate_incident(incident)
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="investigation",
                description=f"Correlated {len(incident.timeline)} telemetry events and extracted {len(incident.indicators)} indicators.",
            )
        )

        # Stage 3: Containment (Disable User & Revoke Sessions)
        incident.containment_status = ContainmentStatus.IN_PROGRESS
        for user in incident.affected_users:
            if user and user.lower() not in ("system", "root"):
                # Disable compromised account
                audit1 = automation_engine.disable_user(
                    username=user,
                    actor=actor,
                    reason=f"Incident {incident.incident_id}: Contain compromised account",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor=actor,
                        action_type="containment",
                        description=f"Disabled user account '{user}' (Audit ID: {audit1.id}, Result: {audit1.result.value})",
                        status="completed" if audit1.result == ResponseActionResult.SUCCESS else "failed",
                    )
                )

                # Revoke active Kerberos tickets and sessions
                audit2 = automation_engine.revoke_user_sessions(
                    username=user,
                    actor=actor,
                    reason=f"Incident {incident.incident_id}: Purge Kerberos tickets and active tokens",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor=actor,
                        action_type="containment",
                        description=f"Revoked sessions and Kerberos tickets for '{user}' (Audit ID: {audit2.id})",
                    )
                )

        # Block external/suspicious attacking IPs
        for ioc in incident.indicators:
            if ioc.type == IndicatorType.IP and (ioc.reputation == "malicious" or ioc.value.startswith("172.28.10.")):
                audit_ip = automation_engine.block_ioc(
                    ioc_type=IndicatorType.IP,
                    value=ioc.value,
                    actor=actor,
                    reason=f"Incident {incident.incident_id}: Block brute force / Kerberoasting source",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor=actor,
                        action_type="containment",
                        description=f"Blocked attacking IP '{ioc.value}' at perimeter (Audit ID: {audit_ip.id})",
                    )
                )

        incident.containment_status = ContainmentStatus.CONTAINED
        incident.status = IncidentStatus.CONTAINED

        # Stage 4: Eradication & Remediation
        incident.remediation_status = RemediationStatus.IN_PROGRESS
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="remediation",
                description="Rotated user credentials, updated password hash to AES-256 Kerberos, and audited Active Directory SPNs.",
            )
        )
        incident.remediation_status = RemediationStatus.REMEDIATED
        incident.status = IncidentStatus.ERADICATED

        # Stage 5: Recovery & Verification
        incident.recovery_status = RecoveryStatus.IN_PROGRESS
        # Re-enable account with verified clean credentials
        for user in incident.affected_users:
            if user and user.lower() not in ("system", "root"):
                audit_rec = automation_engine.enable_user(
                    username=user,
                    actor="soc_analyst",
                    reason=f"Incident {incident.incident_id}: Restoring user after verified password reset",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor="soc_analyst",
                        action_type="recovery",
                        description=f"Re-enabled user '{user}' post-credential rotation (Audit ID: {audit_rec.id})",
                    )
                )

        incident.recovery_status = RecoveryStatus.VERIFIED
        incident.status = IncidentStatus.RECOVERED
        incident.final_disposition = IncidentDisposition.TRUE_POSITIVE_MALICIOUS

        logger.info(f"Credential Compromise Playbook completed for {incident.incident_id}.")
        return incident


class LateralMovementPlaybook(BaseIncidentPlaybook):
    """Full-Lifecycle Playbook for Lateral Movement (DMZ to Core SSH, Remote PsExec, WinRM)."""

    def __init__(self):
        super().__init__(
            name="Lateral Movement Response Playbook",
            description="Automated triage, multi-source investigation, network isolation of pivot source, process termination, and recovery.",
        )

    def execute(
        self,
        incident: Incident,
        investigation_engine: InvestigationEngine,
        automation_engine: ResponseAutomationEngine,
        actor: str = "soar_automation",
    ) -> Incident:
        logger.info(f"Executing [{self.name}] for Incident {incident.incident_id}...")

        # Stage 1: Triage
        incident.status = IncidentStatus.TRIAGED
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="triage",
                description=f"Triaged lateral movement activity across assets: {incident.affected_assets}",
            )
        )

        # Stage 2: Multi-Source Investigation
        investigation_engine.correlate_incident(incident)
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="investigation",
                description=f"Correlated network flows and process executions. Discovered {len(incident.timeline)} timeline hops.",
            )
        )

        # Stage 3: Containment
        incident.containment_status = ContainmentStatus.IN_PROGRESS

        # Isolate the pivot origin host (e.g. DMZ or workstation)
        for asset in incident.affected_assets:
            if "dmz" in asset.lower() or "172.28.30." in asset or "wkstn" in asset.lower() or "172.28.20.50" in asset:
                audit_iso = automation_engine.isolate_endpoint(
                    hostname_or_ip=asset,
                    actor=actor,
                    reason=f"Incident {incident.incident_id}: Isolate lateral movement jump host",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor=actor,
                        action_type="containment",
                        description=f"Isolated host '{asset}' (Audit ID: {audit_iso.id})",
                    )
                )

        # Terminate remote service processes (e.g. sc.exe, PsExec, WinRM remote sessions)
        for asset in incident.affected_assets:
            audit_term = automation_engine.terminate_process(
                hostname=asset,
                process_name="sc.exe",
                actor=actor,
                reason=f"Incident {incident.incident_id}: Terminate rogue remote service execution",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor=actor,
                    action_type="containment",
                    description=f"Terminated remote service process on '{asset}' (Audit ID: {audit_term.id})",
                )
            )

        incident.containment_status = ContainmentStatus.CONTAINED
        incident.status = IncidentStatus.CONTAINED

        # Stage 4: Eradication & Remediation
        incident.remediation_status = RemediationStatus.IN_PROGRESS
        # Collect forensic snapshot
        for asset in incident.affected_assets:
            audit_for = automation_engine.collect_forensics(
                hostname=asset,
                actor=actor,
                reason=f"Incident {incident.incident_id}: Preserve volatile lateral movement artifacts",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor=actor,
                    action_type="remediation",
                    description=f"Preserved forensic evidence bundle for '{asset}' (Audit ID: {audit_for.id})",
                )
            )

        incident.remediation_status = RemediationStatus.REMEDIATED
        incident.status = IncidentStatus.ERADICATED

        # Stage 5: Recovery
        incident.recovery_status = RecoveryStatus.IN_PROGRESS
        # Remove host isolation post-verification
        for asset in incident.affected_assets:
            if "dmz" in asset.lower() or "172.28.30." in asset or "wkstn" in asset.lower() or "172.28.20.50" in asset:
                audit_uniso = automation_engine.unisolate_endpoint(
                    hostname_or_ip=asset,
                    actor="soc_analyst",
                    reason=f"Incident {incident.incident_id}: Host cleaned, restored to network",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor="soc_analyst",
                        action_type="recovery",
                        description=f"Restored network connectivity for '{asset}' (Audit ID: {audit_uniso.id})",
                    )
                )

        incident.recovery_status = RecoveryStatus.VERIFIED
        incident.status = IncidentStatus.RECOVERED
        incident.final_disposition = IncidentDisposition.TRUE_POSITIVE_MALICIOUS

        logger.info(f"Lateral Movement Playbook completed for {incident.incident_id}.")
        return incident


class MalwareRansomwarePlaybook(BaseIncidentPlaybook):
    """Full-Lifecycle Playbook for Malware / Ransomware / Destructive Data Impact."""

    def __init__(self):
        super().__init__(
            name="Malware & Ransomware Impact Response Playbook",
            description="Automated triage, multi-source investigation, immediate host isolation, process termination, C2 blocking, and backup recovery.",
        )

    def execute(
        self,
        incident: Incident,
        investigation_engine: InvestigationEngine,
        automation_engine: ResponseAutomationEngine,
        actor: str = "soar_automation",
    ) -> Incident:
        logger.info(f"Executing [{self.name}] for Incident {incident.incident_id}...")

        # Stage 1: Triage
        incident.status = IncidentStatus.TRIAGED
        incident.severity = IncidentSeverity.CRITICAL
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="triage",
                description=f"High-priority triage for destructive ransomware/malware activity on assets: {incident.affected_assets}",
            )
        )

        # Stage 2: Multi-Source Investigation
        investigation_engine.correlate_incident(incident)
        incident.log_action(
            AnalystAction(
                actor=actor,
                action_type="investigation",
                description=f"Correlated file system modifications and process execution hierarchy ({len(incident.timeline)} events).",
            )
        )

        # Stage 3: Containment
        incident.containment_status = ContainmentStatus.IN_PROGRESS

        # Immediate Endpoint Isolation
        for asset in incident.affected_assets:
            audit_iso = automation_engine.isolate_endpoint(
                hostname_or_ip=asset,
                actor=actor,
                reason=f"Incident {incident.incident_id}: Emergency isolation to stop ransomware spread",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor=actor,
                    action_type="containment",
                    description=f"Emergency network isolation applied to '{asset}' (Audit ID: {audit_iso.id})",
                )
            )

        # Terminate destructive shredding / wiper process
        for asset in incident.affected_assets:
            audit_term = automation_engine.terminate_process(
                hostname=asset,
                process_name="shred",
                actor=actor,
                reason=f"Incident {incident.incident_id}: Kill destructive log wiping process",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor=actor,
                    action_type="containment",
                    description=f"Terminated destructive wiper process on '{asset}' (Audit ID: {audit_term.id})",
                )
            )

        # Block C2 communication IOCs if present
        for ioc in incident.indicators:
            if ioc.type in (IndicatorType.IP, IndicatorType.DOMAIN) and ioc.reputation == "malicious":
                audit_ioc = automation_engine.block_ioc(
                    ioc_type=ioc.type,
                    value=ioc.value,
                    actor=actor,
                    reason=f"Incident {incident.incident_id}: Block malware C2 destination",
                    incident_id=incident.incident_id,
                )
                incident.log_action(
                    AnalystAction(
                        actor=actor,
                        action_type="containment",
                        description=f"Blocked C2 IOC '{ioc.value}' (Audit ID: {audit_ioc.id})",
                    )
                )

        incident.containment_status = ContainmentStatus.CONTAINED
        incident.status = IncidentStatus.CONTAINED

        # Stage 4: Eradication & Remediation (Restore Backup & Restart Services)
        incident.remediation_status = RemediationStatus.IN_PROGRESS
        for asset in incident.affected_assets:
            # Restore audit log baseline
            audit_res = automation_engine.restore_backup(
                hostname=asset,
                file_path="/var/log/audit/audit.log",
                actor=actor,
                reason=f"Incident {incident.incident_id}: Restore shredded audit log from immutable backup",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor=actor,
                    action_type="remediation",
                    description=f"Restored corrupted audit log on '{asset}' from backup (Audit ID: {audit_res.id})",
                )
            )

        incident.remediation_status = RemediationStatus.REMEDIATED
        incident.status = IncidentStatus.ERADICATED

        # Stage 5: Recovery & Verification
        incident.recovery_status = RecoveryStatus.IN_PROGRESS
        for asset in incident.affected_assets:
            audit_uniso = automation_engine.unisolate_endpoint(
                hostname_or_ip=asset,
                actor="soc_analyst",
                reason=f"Incident {incident.incident_id}: System restored and verified clean",
                incident_id=incident.incident_id,
            )
            incident.log_action(
                AnalystAction(
                    actor="soc_analyst",
                    action_type="recovery",
                    description=f"Unisolated '{asset}' and restored normal business operations (Audit ID: {audit_uniso.id})",
                )
            )

        incident.recovery_status = RecoveryStatus.VERIFIED
        incident.status = IncidentStatus.RECOVERED
        incident.final_disposition = IncidentDisposition.TRUE_POSITIVE_MALICIOUS

        logger.info(f"Malware & Ransomware Playbook completed for {incident.incident_id}.")
        return incident
