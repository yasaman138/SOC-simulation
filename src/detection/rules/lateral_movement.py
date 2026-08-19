"""Lateral Movement Detection Rules."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class RemoteServiceExecutionRule(DetectionRule):
    """Detects remote Windows service creation or execution (PsExec / PaExec / sc.exe)."""

    id: str = "DET-LAT-001"
    name: str = "Remote Service Creation / PsExec Lateral Movement"
    description: str = (
        "Detects remote Windows service creation (sc.exe create, Event 7045) or PsExec execution "
        "used to execute code on remote enterprise endpoints."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.002",
        subtechnique_name="SMB/Windows Admin Shares",
        url="https://attack.mitre.org/techniques/T1021/002/",
    )
    data_sources: List[str] = [
        "windows.system",
        "windows.security_auditing",
        "windows.sysmon",
    ]
    why: str = (
        "Adversaries leverage SMB administrative shares (ADMIN$, C$) to install temporary services "
        "(e.g., PSEXESVC) and execute commands remotely with SYSTEM privileges."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1021/002/",
        "https://attack.mitre.org/techniques/T1569/002/",
    ]

    PATTERNS: ClassVar[List[str]] = [
        "psexec",
        "paexec",
        "psexesvc",
        "sc create ",
        "sc.exe create ",
        "sc \\\\",
        "sc.exe \\\\",
        "wmic /node:",
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
        is_psexec_pattern = any(pat in cmd_lower for pat in self.PATTERNS)
        is_event_7045 = win_ev_id == 7045

        if is_psexec_pattern or is_event_7045:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Remote Service / PsExec Execution Detected",
                description=f"Remote service creation or PsExec execution observed: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "sc.exe",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Check source IP of SMB connection and administrative share access.",
                    "Verify if binary installed as a service exists in system32 or temp directories.",
                ],
            )
        return None


class CrossSubnetSSHLateralRule(DetectionRule):
    """Detects SSH lateral hops originating from DMZ or untrusted user subnets to core servers."""

    id: str = "DET-LAT-002"
    name: str = "Cross-Subnet SSH Lateral Movement"
    description: str = (
        "Detects SSH connections originating from DMZ web servers (172.28.30.0/24) into internal corporate "
        "infrastructure (172.28.20.0/24)."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.004",
        subtechnique_name="SSH",
        url="https://attack.mitre.org/techniques/T1021/004/",
    )
    data_sources: List[str] = ["linux.sshd", "network"]
    why: str = (
        "Direct SSH connections from public-facing DMZ servers to internal database/server networks "
        "indicate that an attacker who compromised the web tier is attempting to pivot deeper into the enterprise."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1021/004/"]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        if event.event.category != EventCategory.AUTHENTICATION:
            return None

        action = event.event.action.lower()
        msg = event.message.lower()
        if "ssh" not in action and "sshd" not in msg:
            return None

        source_ip = event.source.ip if event.source else ""
        dest_ip = event.destination.ip if event.destination else (
            event.host.ip if event.host else ""
        )

        # DMZ source (172.28.30.x or 172.28.10.x) targeting Internal Server (172.28.20.x)
        is_dmz_source = source_ip.startswith("172.28.30.") or source_ip.startswith("172.28.10.")
        is_internal_target = dest_ip.startswith("172.28.20.")

        if is_dmz_source and is_internal_target:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Cross-Subnet SSH Lateral Movement from DMZ ({source_ip}) to ({dest_ip})",
                description=(
                    f"Inbound SSH authentication attempt from DMZ tier '{source_ip}' to internal server '{dest_ip}' "
                    f"for user '{event.user.name if event.user else 'unknown'}'."
                ),
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    ip=source_ip,
                ),
                context={
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Check whether web server at source IP has active reverse shell or webshell.",
                    "Verify whether SSH keys were stolen from the web application server.",
                ],
            )
        return None


class RemoteWinRMExecutionRule(DetectionRule):
    """Detects remote PowerShell and WinRM invocations from unapproved endpoints."""

    id: str = "DET-LAT-003"
    name: str = "Remote PowerShell / WinRM Lateral Execution"
    description: str = (
        "Detects WinRM (ports 5985/5986) or Enter-PSSession / Invoke-Command executions used for remote administration "
        "originating from non-standard endpoints."
    )
    severity: EventSeverity = EventSeverity.MEDIUM
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.006",
        subtechnique_name="Windows Remote Management",
        url="https://attack.mitre.org/techniques/T1021/006/",
    )
    data_sources: List[str] = ["windows.sysmon", "windows.powershell"]
    why: str = (
        "Windows Remote Management (WinRM) enables remote PowerShell sessions. Adversaries utilize WinRM "
        "for interactive lateral movement without dropping files."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1021/006/"]

    WINRM_PATTERNS: ClassVar[List[str]] = [
        "enter-pssession",
        "invoke-command -computername",
        "winrs -r:",
        "wsman",
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
        if any(pat in cmd_lower for pat in self.WINRM_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Remote WinRM / PowerShell Session Initiated",
                description=f"Remote WinRM command invocation detected: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "powershell.exe",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Verify target computer name and user credentials utilized for WinRM session.",
                ],
            )
        return None
