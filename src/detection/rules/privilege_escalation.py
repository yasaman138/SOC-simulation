"""Privilege Escalation Detection Rules."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class SudoersModificationRule(DetectionRule):
    """Detects modification or editing of sudoers files and unauthorized sudo elevation."""

    id: str = "DET-PRIVESC-001"
    name: str = "Sudoers File Modification or Sudo Abuse"
    description: str = (
        "Detects modifications to /etc/sudoers, /etc/sudoers.d, or execution of sensitive administrative commands "
        "granting passwordless root access."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        subtechnique_id="T1548.003",
        subtechnique_name="Sudo and Sudo Caching",
        url="https://attack.mitre.org/techniques/T1548/003/",
    )
    data_sources: List[str] = ["linux.auditd", "linux.syslog"]
    why: str = (
        "Adversaries alter sudoers configuration (e.g. NOPASSWD: ALL) to establish persistent, unrestricted "
        "root execution privileges."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1548/003/"]

    SUDOERS_PATTERNS: ClassVar[List[str]] = [
        "/etc/sudoers",
        "/etc/sudoers.d",
        "visudo",
        "nopasswd: all",
        "nopasswd:all",
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
        if any(pat in cmd_lower for pat in self.SUDOERS_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Sudoers Security Configuration Modification Detected",
                description=f"User '{event.user.name if event.user else 'unknown'}' executed command targeting sudoers: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "sudo",
                ),
                context={
                    "command_line": cmd,
                    "user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Audit /etc/sudoers and /etc/sudoers.d/ contents for newly added rules.",
                    "Verify change management ticket for authorized privilege modifications.",
                ],
            )
        return None


class SUIDBinaryAbuseRule(DetectionRule):
    """Detects modification of file permissions setting SUID/SGID bits for privilege escalation."""

    id: str = "DET-PRIVESC-002"
    name: str = "SUID / SGID Bit Modification"
    description: str = (
        "Detects chmod commands configuring the SUID (+s, 4755) or SGID (+s, 2755) bits on binaries, "
        "enabling unprivileged users to execute files with elevated privileges."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        subtechnique_id="T1548.001",
        subtechnique_name="Setuid and Setgid",
        url="https://attack.mitre.org/techniques/T1548/001/",
    )
    data_sources: List[str] = ["linux.auditd", "linux.syslog"]
    why: str = (
        "Setting SUID permissions on shells or utilities (e.g. bash, find, vim) allows adversaries to "
        "bypass kernel access checks and spawn permanent root shells."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1548/001/",
        "https://gtfobins.github.io/",
    ]

    SUID_PATTERNS: ClassVar[List[str]] = [
        "chmod +s",
        "chmod u+s",
        "chmod 4755",
        "chmod 4777",
        "chmod 4555",
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
        if any(pat in cmd_lower for pat in self.SUID_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="SUID Permission Elevation Configured on Binary",
                description=f"Command modified file permissions to include SUID bit: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else "chmod",
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Check targeted binary path and verify ownership.",
                    "Audit system with find / -perm -4000 for unauthorized SUID files.",
                ],
            )
        return None


class SQLInjectionPrivilegeEscalationRule(DetectionRule):
    """Detects SQL Injection attacks attempting to bypass authentication or extract sensitive tables."""

    id: str = "DET-PRIVESC-003"
    name: str = "Web Application SQL Injection Privilege Escalation"
    description: str = (
        "Detects SQL injection syntax patterns (UNION SELECT, OR 1=1, comment truncations) in web queries "
        "attempting authentication bypass or database schema extraction."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        url="https://attack.mitre.org/techniques/T1190/",
    )
    data_sources: List[str] = ["enterprise.web_portal", "web", "database"]
    why: str = (
        "SQL injection against web application backends allows attackers to bypass login forms, "
        "retrieve administrative credentials, or execute arbitrary database commands."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1190/",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ]

    SQLI_PATTERNS: ClassVar[List[str]] = [
        "union select",
        "union all select",
        "' or 1=1",
        "' or '1'='1",
        "admin'--",
        "admin' #",
        "information_schema.tables",
        "sqlite_master",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        url = event.http.url if event.http else ""
        msg = event.message
        custom_sql = str(event.custom.get("sql_query", ""))
        action = event.event.action.lower()

        search_text = f"{url} {msg} {custom_sql} {action}".lower()

        is_sqli = any(pat in search_text for pat in self.SQLI_PATTERNS) or (
            event.custom.get("injection_type") == "sqli"
        )

        if is_sqli:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="SQL Injection Exploit Pattern Detected",
                description=f"Web request contained SQL injection payload targeting database backend: {url or msg[:140]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    ip=event.source.ip if event.source else None,
                ),
                context={
                    "request_url": url,
                    "source_ip": event.source.ip if event.source else None,
                },
                investigation_hints=[
                    "Check whether the SQL query was blocked or returned data to the client.",
                    "Verify application database access logs for data exfiltration.",
                ],
            )
        return None
