"""Credential Access and Extraction Detection Rules."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class KerberoastingDetectionRule(DetectionRule):
    """Detects Kerberoasting TGS ticket requests requesting weak RC4 encryption for user SPNs."""

    id: str = "DET-CRED-001"
    name: str = "Kerberoasting TGS Request with Weak Encryption"
    description: str = (
        "Detects Kerberos TGS-REQ ticket requests (Event 4769) for Service Principal Names configured on user accounts "
        "requesting RC4-HMAC (0x17) encryption, typical of offline ticket cracking attacks (Kerberoasting)."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1558",
        technique_name="Steal or Forge Kerberos Tickets",
        subtechnique_id="T1558.003",
        subtechnique_name="Kerberoasting",
        url="https://attack.mitre.org/techniques/T1558/003/",
    )
    data_sources: List[str] = [
        "windows.security_auditing",
        "directory_service",
    ]
    why: str = (
        "Adversaries request Kerberos service tickets for accounts with SPNs to crack password hashes offline. "
        "Requesting legacy RC4 encryption is done because RC4 hashes are significantly easier to crack than AES-256."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1558/003/",
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        action = event.event.action.lower()
        msg = event.message.lower()
        custom = event.custom or {}

        is_kerberos_event = (
            "tgs" in action
            or "4769" in str(custom.get("windows", {}).get("event_id", ""))
            or "kerberos tgs ticket requested" in msg
            or event.event.category == EventCategory.DIRECTORY_SERVICE
        )

        if not is_kerberos_event:
            return None

        encryption = str(custom.get("encryption_type", "")).lower()
        has_rc4 = (
            "rc4" in encryption
            or "0x17" in encryption
            or "rc4-hmac" in msg
        )

        spn = custom.get("spn", "") or ""
        service_account = custom.get("service_account", "")

        if has_rc4 or ("tgs" in action and "spn" in msg):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Kerberoasting Activity Detected (SPN: {spn or 'Service Account'})",
                description=(
                    f"User '{event.user.name if event.user else 'unknown'}' requested a Kerberos service ticket "
                    f"using weak RC4 encryption for SPN '{spn}'."
                ),
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    ip=event.source.ip if event.source else None,
                ),
                context={
                    "spn": spn,
                    "service_account": service_account,
                    "encryption_type": encryption or "rc4-hmac",
                    "requesting_user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Check if requesting account has performed SPN discovery (LDAP queries with servicePrincipalName=*).",
                    "Rotate password and upgrade SPN account encryption to AES-256.",
                ],
            )
        return None


class LinuxShadowFileAccessRule(DetectionRule):
    """Detects access or extraction of Linux /etc/shadow credential database."""

    id: str = "DET-CRED-002"
    name: str = "Linux Sensitive Credential File Access (/etc/shadow)"
    description: str = (
        "Detects command execution or file access targeting /etc/shadow or /etc/gshadow "
        "to dump password hashes for offline cracking."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        subtechnique_id="T1003.008",
        subtechnique_name="/etc/passwd and /etc/shadow",
        url="https://attack.mitre.org/techniques/T1003/008/",
    )
    data_sources: List[str] = ["linux.auditd", "linux.syslog"]
    why: str = (
        "/etc/shadow stores hashed user passwords. Only privileged system utilities require access; "
        "manual reading by users or scripts indicates credential harvesting."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1003/008/"]

    SHADOW_PATTERNS: ClassVar[List[str]] = [
        "/etc/shadow",
        "/etc/gshadow",
        "unshadow ",
        "cat /etc/shadow",
        "getent shadow",
        "awk -f /etc/shadow",
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
        if any(pat in cmd_lower for pat in self.SHADOW_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Sensitive Shadow Password Database Access Detected",
                description=f"User '{event.user.name if event.user else 'unknown'}' attempted to read /etc/shadow: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={
                    "command_line": cmd,
                    "user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Check if command executed with sudo / root privileges.",
                    "Inspect recent network connections or file downloads to determine if hashes were exfiltrated.",
                ],
            )
        return None


class LSASSDumpDetectionRule(DetectionRule):
    """Detects LSASS process memory dumping and SAM registry hive exporting."""

    id: str = "DET-CRED-003"
    name: str = "LSASS Memory Dump & SAM Hive Export"
    description: str = (
        "Detects commands and tools (procdump, comsvcs.dll, reg save HKLM\\SAM, mimikatz) "
        "attempting to dump LSASS memory or export local account password hashes."
    )
    severity: EventSeverity = EventSeverity.CRITICAL
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        subtechnique_id="T1003.001",
        subtechnique_name="LSASS Memory",
        url="https://attack.mitre.org/techniques/T1003/001/",
    )
    data_sources: List[str] = [
        "windows.sysmon",
        "windows.security_auditing",
    ]
    why: str = (
        "Dumping LSASS memory or the SAM registry hive extracts plaintext credentials, NTLM hashes, "
        "and Kerberos tickets for all logged-on enterprise users."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1003/001/",
        "https://attack.mitre.org/techniques/T1003/002/",
    ]

    DUMP_PATTERNS: ClassVar[List[str]] = [
        "minidump",
        "comsvcs.dll",
        "procdump",
        "sekurlsa",
        "mimikatz",
        "reg save hklm\\sam",
        "reg save hklm\\system",
        "reg save hklm\\security",
        "lsass.dmp",
        "dumpert",
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
        is_dump = False

        # Context 1: Direct LSASS targeting with dumping utilities
        if "lsass" in cmd_lower:
            if any(
                tool in cmd_lower
                for tool in [
                    "procdump",
                    "minidump",
                    "comsvcs",
                    "rundll32",
                    ".dmp",
                    "dump",
                ]
            ):
                is_dump = True

        # Context 2: Dedicated offensive dumping tools
        if any(tool in cmd_lower for tool in ["mimikatz", "sekurlsa", "dumpert", "nanodump"]):
            is_dump = True

        # Context 3: Comsvcs minidump export
        if "comsvcs" in cmd_lower and "minidump" in cmd_lower:
            is_dump = True

        # Context 4: SAM / SYSTEM registry hive backup commands
        if "reg save" in cmd_lower or "reg.exe save" in cmd_lower:
            if any(hive in cmd_lower for hive in ["hklm\\sam", "hklm\\system", "hklm\\security", "sam ", "system "]):
                is_dump = True

        if is_dump:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="LSASS Memory Dump or SAM Registry Export Detected",
                description=f"Credential extraction command detected: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={
                    "command_line": cmd,
                    "user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Isolate the affected endpoint immediately.",
                    "Invalidate all active Kerberos sessions and reset passwords for logged-on accounts.",
                ],
            )
        return None
