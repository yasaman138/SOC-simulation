"""PowerShell Abuse and Scripting Execution Detection Rules."""

import re
from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class EncodedPowerShellRule(DetectionRule):
    """Detects obfuscated and Base64-encoded PowerShell command executions."""

    id: str = "DET-PS-001"
    name: str = "Suspicious Encoded PowerShell Execution"
    description: str = (
        "Detects PowerShell invocations utilizing encoded command flags (-EncodedCommand, -enc, -e, -encoded) "
        "typically used by adversaries to obfuscate malicious payloads and evade inspection."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.001",
        subtechnique_name="PowerShell",
        url="https://attack.mitre.org/techniques/T1059/001/",
    )
    data_sources: List[str] = [
        "windows.sysmon",
        "windows.security_auditing",
        "windows.powershell",
    ]
    why: str = (
        "Base64 encoding is frequently abused by offensive frameworks (e.g. Empire, Metasploit, Cobalt Strike) "
        "to conceal command arguments and payloads from command-line auditing."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1059/001/",
        "https://redcanary.com/threat-detection/powershell-encoded-command/",
    ]

    PATTERN: ClassVar[re.Pattern] = re.compile(
        r"(?:powershell|pwsh)(?:\.exe)?\s+.*?(?:-e|-enc|-encoded|-encodedcommand)\s+[A-Za-z0-9+/=]{8,}",
        re.IGNORECASE,
    )

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

        # Check process name or command string
        is_ps = (
            (event.process and event.process.name and "powershell" in event.process.name.lower())
            or "powershell" in cmd.lower()
            or "pwsh" in cmd.lower()
        )

        if not is_ps:
            return None

        if self.PATTERN.search(cmd) or any(
            flag in cmd.lower()
            for flag in [" -enc ", " -encodedcommand ", " -e ", " /enc "]
        ):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Base64 Encoded PowerShell Command Execution",
                description=f"PowerShell was executed with an encoded command payload: {cmd[:160]}...",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "powershell.exe",
                ),
                context={
                    "command_line": cmd,
                    "process_pid": event.process.pid if event.process else None,
                    "parent_process": event.process.parent_name if event.process else None,
                },
                investigation_hints=[
                    "Decode the Base64 command payload to identify the executed script.",
                    "Check network connections initiated by the PowerShell PID.",
                    "Inspect parent process lineage to identify origin of execution.",
                ],
            )
        return None


class PowerShellDownloadCradleRule(DetectionRule):
    """Detects in-memory PowerShell download cradles pulling remote code."""

    id: str = "DET-PS-002"
    name: str = "PowerShell Remote Download Cradle"
    description: str = (
        "Detects PowerShell executing web client download cradles (DownloadString, IEX, Invoke-WebRequest) "
        "fetching and executing scripts directly in memory."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.001",
        subtechnique_name="PowerShell",
        url="https://attack.mitre.org/techniques/T1059/001/",
    )
    data_sources: List[str] = ["windows.sysmon", "windows.powershell"]
    why: str = (
        "Download cradles enable fileless malware execution and initial payload delivery without "
        "writing files to disk, bypassing basic antivirus signature scans."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1105/",
        "https://attack.mitre.org/techniques/T1059/001/",
    ]

    INDICATORS: ClassVar[List[str]] = [
        "downloadstring",
        "downloadfile",
        "net.webclient",
        "invoke-webrequest",
        "iwr http",
        "irm http",
        "iex (new-object",
        "iex(new-object",
        "| iex",
        "|iex",
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
        matched_indicators = [ind for ind in self.INDICATORS if ind in cmd_lower]

        # Require at least one download method and/or execution cradle
        if (
            ("downloadstring" in matched_indicators)
            or ("net.webclient" in matched_indicators and ("iex" in cmd_lower or "invoke-expression" in cmd_lower))
            or (("iwr" in cmd_lower or "invoke-webrequest" in cmd_lower or "irm" in cmd_lower) and ("| iex" in cmd_lower or "|iex" in cmd_lower))
        ):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="PowerShell Remote Download Cradle Detected",
                description=f"In-memory script download cradle detected: {cmd[:160]}...",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "powershell.exe",
                ),
                context={
                    "command_line": cmd,
                    "matched_indicators": matched_indicators,
                },
                investigation_hints=[
                    "Identify remote IP/URL contacted by the PowerShell cradle.",
                    "Check proxy and DNS logs for associated domain resolutions.",
                ],
            )
        return None


class PowerShellPolicyBypassRule(DetectionRule):
    """Detects PowerShell execution with ExecutionPolicy Bypass or hidden window styles."""

    id: str = "DET-PS-003"
    name: str = "PowerShell Execution Policy Bypass"
    description: str = (
        "Detects command lines explicitly overriding PowerShell ExecutionPolicy (-ep bypass, -ExecutionPolicy Unrestricted) "
        "combined with non-interactive or hidden flags."
    )
    severity: EventSeverity = EventSeverity.MEDIUM
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DEFENSE_EVASION,
        technique_id="T1562",
        technique_name="Impair Defenses",
        subtechnique_id="T1562.001",
        subtechnique_name="Disable or Modify Tools",
        url="https://attack.mitre.org/techniques/T1562/001/",
    )
    data_sources: List[str] = ["windows.sysmon", "windows.security_auditing"]
    why: str = (
        "PowerShell ExecutionPolicy is a basic protection against inadvertent script execution. "
        "Bypassing it in conjunction with -nop or -w hidden is standard tradecraft for adversary automation."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1562/001/"]

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
        has_ps = "powershell" in cmd_lower or "pwsh" in cmd_lower or (
            event.process and event.process.name and "powershell" in event.process.name.lower()
        )

        if not has_ps:
            return None

        has_bypass = any(
            bp in cmd_lower
            for bp in [
                "executionpolicy bypass",
                "executionpolicy unrestricted",
                "-ep bypass",
                "-ep unrestricted",
                "/ep bypass",
            ]
        )

        has_stealth = any(
            st in cmd_lower
            for st in [
                "-w hidden",
                "-windowstyle hidden",
                "-noni",
                "-noninteractive",
                "-nop",
                "-noprofile",
            ]
        )

        if has_bypass and has_stealth:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="PowerShell ExecutionPolicy Bypass with Hidden Window",
                description=f"PowerShell spawned with policy bypass and stealth arguments: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "powershell.exe",
                ),
                context={
                    "command_line": cmd,
                },
                investigation_hints=[
                    "Check if the command was initiated by an administrative script or unusual user parent process.",
                ],
            )
        return None
