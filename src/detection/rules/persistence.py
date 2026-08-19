"""Persistence Detection Rules."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class LinuxCronPersistenceRule(DetectionRule):
    """Detects creation or modification of scheduled tasks via cron or systemd units."""

    id: str = "DET-PERSIST-001"
    name: str = "Linux Cron Job or Systemd Service Persistence"
    description: str = (
        "Detects modifications to /etc/cron*, crontab manipulations, or systemd service additions "
        "used by adversaries to maintain persistent scheduled execution."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        subtechnique_id="T1053.003",
        subtechnique_name="Cron",
        url="https://attack.mitre.org/techniques/T1053/003/",
    )
    data_sources: List[str] = ["linux.auditd", "linux.syslog"]
    why: str = (
        "Adversaries use cron jobs and systemd timer/services to automatically restart reverse shells "
        "or backdoors upon reboot."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1053/003/"]

    CRON_PATTERNS: ClassVar[List[str]] = [
        "/etc/cron",
        "/var/spool/cron",
        "crontab -e",
        "crontab -u",
        "/etc/systemd/system",
        "systemctl enable",
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
        if any(pat in cmd_lower for pat in self.CRON_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Linux Scheduled Persistence Mechanism Configured",
                description=f"Cron or systemd persistence command executed: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "crontab",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Inspect crontab entries across all system accounts.",
                    "Verify file contents of newly registered systemd service units.",
                ],
            )
        return None


class RegistryRunKeyPersistenceRule(DetectionRule):
    """Detects modification of Windows Registry Run / RunOnce autostart keys."""

    id: str = "DET-PERSIST-002"
    name: str = "Windows Registry Run Key Persistence"
    description: str = (
        "Detects additions or alterations to Windows CurrentVersion\\Run and RunOnce registry keys "
        "designed to execute payloads automatically on user logon or system boot."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1547",
        technique_name="Boot or Logon Autostart Execution",
        subtechnique_id="T1547.001",
        subtechnique_name="Registry Run Keys / Startup Folder",
        url="https://attack.mitre.org/techniques/T1547/001/",
    )
    data_sources: List[str] = ["windows.sysmon", "registry"]
    why: str = (
        "The Registry Run and RunOnce keys are standard Windows autostart extensibility points (ASEPs) "
        "frequently leveraged by malware for persistence."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1547/001/"]

    REG_PATTERNS: ClassVar[List[str]] = [
        "currentversion\\run",
        "currentversion\\runonce",
        "currentversion\\runonceex",
        "currentversion\\winlogon\\shell",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        reg_key = (
            event.registry.key.lower()
            if (event.registry and event.registry.key)
            else ""
        )

        search_text = f"{cmd} {reg_key}".lower()

        if any(pat in search_text for pat in self.REG_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Windows Autostart Registry Run Key Persistence Configured",
                description=f"Registry Run key modification detected: {cmd or reg_key}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "reg.exe",
                ),
                context={
                    "registry_key": reg_key,
                    "command_line": cmd,
                },
                investigation_hints=[
                    "Check executable binary path configured in the registry value.",
                    "Verify digital signature and hash of the autostart target binary.",
                ],
            )
        return None


class BackdoorAccountCreationRule(DetectionRule):
    """Detects creation of new local user accounts outside approved provisioning."""

    id: str = "DET-PERSIST-003"
    name: str = "Unauthorized Local User Account Creation"
    description: str = (
        "Detects local user account creation commands (useradd, adduser, net user /add) "
        "or Windows Event 4720 used by adversaries to establish secondary backdoor access."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1136",
        technique_name="Create Account",
        subtechnique_id="T1136.001",
        subtechnique_name="Local Account",
        url="https://attack.mitre.org/techniques/T1136/001/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.security_auditing",
        "windows.sysmon",
    ]
    why: str = (
        "Adversaries create local accounts with administrative privileges to ensure redundant access "
        "in case primary exploitation vectors are closed."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1136/001/"]

    ACCOUNT_PATTERNS: ClassVar[List[str]] = [
        "useradd ",
        "adduser ",
        "net user /add",
        "net localgroup administrators /add",
        "usermod -a -g sudo",
        "usermod -a -g wheel",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        custom = event.custom or {}
        win_ev_id = custom.get("windows", {}).get("event_id")

        cmd_lower = cmd.lower()
        is_account_cmd = any(pat in cmd_lower for pat in self.ACCOUNT_PATTERNS)
        is_event_4720 = win_ev_id == 4720

        if is_account_cmd or is_event_4720:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Local User Account Creation Detected",
                description=f"Account provisioning command observed: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "useradd",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Verify if user creation was authorized by IT change ticket.",
                    "Check group memberships granted to the newly created account.",
                ],
            )
        return None
