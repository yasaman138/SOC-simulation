"""Collection Detection Rules for MITRE ATT&CK Tactics."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class DataStagingAndArchiveRule(DetectionRule):
    """Detects staging and archiving of files into compressed containers for exfiltration."""

    id: str = "DET-COLL-001"
    name: str = "Sensitive Data Staging & Archive Compression"
    description: str = (
        "Detects command-line utilities (tar, zip, 7z, gzip) compressing sensitive directories "
        "or writing compressed archives into temporary staging paths (/tmp, /dev/shm, C:\\Users\\Public)."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1560",
        technique_name="Archive Collected Data",
        subtechnique_id="T1560.001",
        subtechnique_name="Archive via Utility",
        url="https://attack.mitre.org/techniques/T1560/001/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.sysmon",
    ]
    why: str = (
        "Adversaries compress and package targeted corporate data before exfiltrating it across the network "
        "to minimize transfer time and blend with normal encrypted traffic."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1560/001/",
        "https://attack.mitre.org/techniques/T1074/",
    ]

    ARCHIVE_PATTERNS: ClassVar[List[str]] = [
        "tar -czf /tmp/",
        "tar -czvf /tmp/",
        "tar -cf /tmp/",
        "zip -r /tmp/",
        "zip /tmp/",
        "7z a /tmp/",
        "7z.exe a ",
        "rar a /tmp/",
        "gzip -c /etc/",
        "tar -czf /dev/shm/",
        "zip -r /dev/shm/",
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
        if any(pat in cmd_lower for pat in self.ARCHIVE_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Sensitive Data Staged in Compressed Archive",
                description=f"Data staging command detected: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Inspect contents of the archive file in /tmp or staging directory.",
                    "Review network firewall and egress proxy logs for upcoming exfiltration spikes.",
                ],
            )
        return None


class SensitiveDataHarvestingRule(DetectionRule):
    """Detects automated collection, database dumping, and unauthorized document harvesting (BOLA)."""

    id: str = "DET-COLL-002"
    name: str = "Sensitive Data & Database Harvesting"
    description: str = (
        "Detects database dumping utilities (mysqldump, pg_dump, sqlite dump), "
        "recursive search for credentials/documents, or BOLA authorization bypasses harvesting files."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1005",
        technique_name="Data from Local System",
        url="https://attack.mitre.org/techniques/T1005/",
    )
    data_sources: List[str] = [
        "enterprise.web_portal",
        "linux.auditd",
        "database",
    ]
    why: str = (
        "Adversaries harvest sensitive business data, customer records, and confidential documents "
        "for extortion, intelligence, or financial gain."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1005/",
        "https://attack.mitre.org/techniques/T1119/",
    ]

    HARVEST_PATTERNS: ClassVar[List[str]] = [
        "mysqldump ",
        "pg_dump ",
        "sqlite3 ",
        ".dump",
        "grep -r password",
        "find / -name *.conf",
        "find / -name *.key",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        action = event.event.action.lower() if event.event else ""
        is_bola = event.custom.get("unauthorized_bola") is True
        search_text = f"{cmd} {action}".lower()

        is_dump_tool = any(pat in search_text for pat in self.HARVEST_PATTERNS) and (
            "dump" in search_text or "password" in search_text
        )

        if is_dump_tool or is_bola:
            reason = "Unauthorized BOLA document harvesting" if is_bola else "Database or credential dump command"
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Sensitive Data Harvesting Detected ({reason})",
                description=f"Data collection activity observed: {cmd or action or search_text[:140]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                    ip=event.source.ip if event.source else None,
                ),
                context={
                    "command_line": cmd,
                    "reason": reason,
                    "doc_id": event.custom.get("doc_id"),
                },
                investigation_hints=[
                    "Check total volume of documents or records accessed by requesting entity.",
                    "Audit affected user identity permissions and session tokens.",
                ],
            )
        return None
