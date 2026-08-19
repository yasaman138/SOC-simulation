"""Impact Detection Rules for MITRE ATT&CK Tactics."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class ServiceTerminationRule(DetectionRule):
    """Detects stopping or disabling of critical logging, security, or production services."""

    id: str = "DET-IMP-001"
    name: str = "Critical Service Termination / Disruption"
    description: str = (
        "Detects commands stopping or disabling core security, auditing, or system services "
        "(e.g. systemctl stop auditd, net stop, sc stop, kill -9 rsyslog, taskkill)."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.IMPACT,
        technique_id="T1489",
        technique_name="Service Stop",
        url="https://attack.mitre.org/techniques/T1489/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.system",
        "windows.sysmon",
    ]
    why: str = (
        "Adversaries terminate security services (EDR, Syslog, Auditd) to blind defenders "
        "or disrupt business services to cause denial of service."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1489/",
        "https://attack.mitre.org/techniques/T1562/001/",
    ]

    STOP_PATTERNS: ClassVar[List[str]] = [
        "systemctl stop auditd",
        "systemctl stop rsyslog",
        "systemctl stop syslog",
        "systemctl stop iptables",
        "systemctl stop ufw",
        "service auditd stop",
        "service rsyslog stop",
        "net stop ",
        "sc stop ",
        "sc.exe stop ",
        "taskkill /f /im",
        "taskkill /im",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        if not cmd:
            return None

        cmd_lower = cmd.lower()
        if any(pat in cmd_lower for pat in self.STOP_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Critical Service Stop Command Executed",
                description=f"Service termination command observed: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "service",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Check if stopped service affects telemetry collection or system availability.",
                    "Verify user session and authorizations for service administration.",
                ],
            )
        return None


class DataDestructionRansomwareRule(DetectionRule):
    """Detects destructive disk wiping, shadow copy deletion, log tampering, or ransomware encryption patterns."""

    id: str = "DET-IMP-002"
    name: str = "Data Destruction & Ransomware Activity"
    description: str = (
        "Detects file shredding (shred, wipe, rm -rf /), backup/shadow copy deletion "
        "(vssadmin delete shadows, wbadmin delete catalog), Windows EventLog clearing (wevtutil cl), "
        "or ransomware encryption behaviors."
    )
    severity: EventSeverity = EventSeverity.CRITICAL
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.IMPACT,
        technique_id="T1485",
        technique_name="Data Destruction",
        url="https://attack.mitre.org/techniques/T1485/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.security_auditing",
        "windows.sysmon",
    ]
    why: str = (
        "Adversaries destroy data or backups to maximize business disruption, cover tracks, "
        "or enforce ransomware extortion demands."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1485/",
        "https://attack.mitre.org/techniques/T1486/",
        "https://attack.mitre.org/techniques/T1490/",
    ]

    DESTRUCTIVE_PATTERNS: ClassVar[List[str]] = [
        "vssadmin delete shadows",
        "vssadmin.exe delete shadows",
        "wbadmin delete catalog",
        "wevtutil cl ",
        "wevtutil.exe cl ",
        "shred -u",
        "shred -z",
        "rm -rf /var/log",
        "rm -rf /data",
        "dd if=/dev/zero",
        "dd if=/dev/urandom",
        "cipher /w:",
        ".ransomware_encrypted",
        "ransom_note.txt",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        if not cmd:
            return None

        cmd_lower = cmd.lower()
        if any(pat in cmd_lower for pat in self.DESTRUCTIVE_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Destructive Impact or Ransomware Activity Detected",
                description=f"Destructive action or backup invalidation detected: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Isolate endpoint immediately to prevent further data destruction.",
                    "Verify backup storage integrity and initiate incident response playbook.",
                ],
            )
        return None
