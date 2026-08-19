"""Suspicious Process Execution and Reverse Shell Detection Rules."""

import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class ReverseShellDetectionRule(DetectionRule):
    """Detects interactive reverse shell executions on Linux and Windows endpoints."""

    id: str = "DET-PROC-001"
    name: str = "Interactive Reverse Shell Execution"
    description: str = (
        "Detects interactive reverse shells redirecting stdin/stdout over TCP sockets "
        "(e.g., bash -i, /dev/tcp, nc -e, python pty/socket wrappers)."
    )
    severity: EventSeverity = EventSeverity.CRITICAL
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.004",
        subtechnique_name="Unix Shell",
        url="https://attack.mitre.org/techniques/T1059/004/",
    )
    data_sources: List[str] = ["linux.auditd", "linux.syslog", "windows.sysmon"]
    why: str = (
        "Reverse shells provide adversaries with interactive command execution across network boundaries "
        "and are a hallmark of remote code exploitation."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1059/004/",
        "https://gtfobins.github.io/",
    ]

    PATTERNS: ClassVar[List[str]] = [
        r"bash\s+-i\s+>&?\s*/dev/tcp/",
        r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
        r"nc(?:\.traditional)?\s+.*?-e\s+/bin/(?:bash|sh)",
        r"ncat\s+.*?-e\s+/bin/(?:bash|sh)",
        r"python(?:3)?\s+-c\s+.*?(?:pty\.spawn|socket\.socket)",
        r"socat\s+exec:.*?(?:bash|sh)",
        r"mkfifo\s+.*?;\s*nc\s+",
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
        matched = False
        for pat in self.PATTERNS:
            if re.search(pat, cmd_lower):
                matched = True
                break

        # Also check fallback simple indicators
        if not matched:
            if (
                ("/dev/tcp/" in cmd_lower and "bash" in cmd_lower)
                or ("nc -e" in cmd_lower or "nc.traditional -e" in cmd_lower)
                or ("pty.spawn" in cmd_lower and "socket" in cmd_lower)
            ):
                matched = True

        if matched:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Interactive Network Reverse Shell Executed",
                description=f"Reverse shell payload detected in command line: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Isolate the host from the network immediately.",
                    "Identify remote IP connecting to the reverse shell.",
                    "Check parent process to determine infection vector.",
                ],
            )
        return None


class LOLBinAbuseDetectionRule(DetectionRule):
    """Detects Living Off The Land Binaries (LOLBins) used for download and execution."""

    id: str = "DET-PROC-002"
    name: str = "Living Off the Land Binary (LOLBin) Abuse"
    description: str = (
        "Detects built-in system utilities (certutil, mshta, bitsadmin, curl/wget pipe to shell) "
        "executed with parameters designed to download and execute untrusted remote content."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DEFENSE_EVASION,
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
        url="https://attack.mitre.org/techniques/T1218/",
    )
    data_sources: List[str] = [
        "windows.sysmon",
        "linux.auditd",
        "enterprise.security",
    ]
    why: str = (
        "LOLBins allow attackers to download payloads and execute code while evading application whitelisting "
        "by utilizing trusted OS binaries."
    )
    references: List[str] = [
        "https://lolbas-project.github.io/",
        "https://attack.mitre.org/techniques/T1218/",
    ]

    LOLBIN_RULES: ClassVar[List[Tuple[str, List[str]]]] = [
        ("certutil", ["-urlcache", "-split", "-f"]),
        ("mshta", ["http://", "https://", "javascript:", "vbscript:"]),
        ("bitsadmin", ["/transfer", "/download"]),
        ("curl", ["| bash", "| sh", "|bash", "|sh"]),
        ("wget", ["| bash", "| sh", "|bash", "|sh", "-O - |"]),
        ("rundll32", ["javascript:", "mshtml", "http://", "https://"]),
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

        for binary, patterns in self.LOLBIN_RULES:
            if binary in cmd_lower:
                if any(pat in cmd_lower for pat in patterns):
                    return Alert(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        mitre_attack=self.mitre_attack,
                        title=f"LOLBin Abuse Detected: {binary}",
                        description=f"Built-in utility '{binary}' executed with suspicious download/execution parameters: {cmd[:160]}",
                        source_event_ids=[event.event.id],
                        source_events=[event.to_dict()],
                        affected_entities=AffectedEntities(
                            host=event.host.name if event.host else None,
                            user=event.user.name if event.user else None,
                            process=event.process.name if event.process else binary,
                        ),
                        context={
                            "binary": binary,
                            "command_line": cmd,
                        },
                        investigation_hints=[
                            "Inspect downloaded file destination and execution flags.",
                            "Check proxy logs for external URLs accessed by the utility.",
                        ],
                    )
        return None


class WebProcessSpawnRule(DetectionRule):
    """Detects web application processes spawning system shells or diagnostic utilities (Command Injection)."""

    id: str = "DET-PROC-003"
    name: str = "Web Server Spawning Command Shell / Process Injection"
    description: str = (
        "Detects web server processes (e.g. uvicorn, gunicorn, nginx, w3wp) spawning system shells "
        "or commands (sh, bash, cmd.exe, whoami, ping) indicating command injection."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        url="https://attack.mitre.org/techniques/T1059/",
    )
    data_sources: List[str] = [
        "enterprise.web_portal",
        "linux.auditd",
    ]
    why: str = (
        "Web application workers should rarely execute arbitrary OS shell commands. "
        "Child shells spawned from web processes indicate successful command injection vulnerabilities."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1190/",
        "https://attack.mitre.org/techniques/T1059/",
    ]

    WEB_PARENTS: ClassVar[List[str]] = ["uvicorn", "python", "gunicorn", "nginx", "apache2", "httpd", "w3wp.exe"]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        parent = (
            event.process.parent_name.lower()
            if (event.process and event.process.parent_name)
            else ""
        )
        proc_name = (
            event.process.name.lower()
            if (event.process and event.process.name)
            else ""
        )
        cmd = (
            event.process.command_line
            if (event.process and event.process.command_line)
            else event.message
        )
        dataset = event.event.dataset if event.event else ""

        # Case 1: Parent is web server
        is_web_parent = any(w in parent for w in self.WEB_PARENTS)
        is_shell = any(s in proc_name for s in ["sh", "bash", "cmd", "powershell", "ping", "whoami", "id"])

        # Case 2: Web portal action explicitly reports command injection
        is_web_dataset = "web_portal" in dataset or event.event.category == EventCategory.WEB
        is_injection_action = "command_injection" in event.event.action.lower() or (
            event.custom.get("injection_type") == "command"
        )

        if (is_web_parent and is_shell) or is_injection_action or (
            is_web_dataset and (";" in cmd or "|" in cmd) and ("whoami" in cmd or "id" in cmd or "cat /etc" in cmd)
        ):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Web Application Command Injection Process Spawn",
                description=f"Web server spawned suspicious child process: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=proc_name or "shell",
                ),
                context={
                    "parent_process": parent,
                    "command_line": cmd,
                    "dataset": dataset,
                },
                investigation_hints=[
                    "Inspect HTTP access logs for malicious payload in request parameters.",
                    "Verify if user inputs are properly sanitized before OS command execution.",
                ],
            )
        return None
