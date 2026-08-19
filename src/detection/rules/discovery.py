"""Discovery Detection Rules for MITRE ATT&CK Tactics."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class ActiveDirectoryDiscoveryRule(DetectionRule):
    """Detects Active Directory enumeration and domain account reconnaissance."""

    id: str = "DET-DISC-001"
    name: str = "Active Directory Domain & Account Discovery"
    description: str = (
        "Detects commands or LDAP queries enumerating domain users, groups, computers, "
        "or domain trusts (e.g. net user /domain, nltest, adfind, Get-ADUser)."
    )
    severity: EventSeverity = EventSeverity.MEDIUM
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1087",
        technique_name="Account Discovery",
        subtechnique_id="T1087.002",
        subtechnique_name="Domain Account",
        url="https://attack.mitre.org/techniques/T1087/002/",
    )
    data_sources: List[str] = [
        "windows.security_auditing",
        "windows.powershell",
        "enterprise.web_portal",
        "directory_service",
    ]
    why: str = (
        "Adversaries perform Active Directory enumeration to locate high-value accounts (such as Domain Admins) "
        "and map domain infrastructure before attempting privilege escalation or lateral movement."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1087/002/",
        "https://attack.mitre.org/techniques/T1069/002/",
    ]

    AD_DISC_PATTERNS: ClassVar[List[str]] = [
        "net user /domain",
        "net group /domain",
        "net group \"domain admins\" /domain",
        "net group 'domain admins' /domain",
        "net group \"enterprise admins\" /domain",
        "nltest /dclist",
        "nltest /domain_trusts",
        "adfind",
        "get-aduser",
        "get-adgroup",
        "get-adcomputer",
        "ldap_injection",
        "samaccountname=*",
        "serviceprincipalname=*",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        custom_filter = str(event.custom.get("ldap_filter", ""))
        action = event.event.action.lower() if event.event else ""
        search_text = f"{cmd} {custom_filter} {action}".lower()

        # Check for LDAP wildcard probing in web portal or directory service
        is_ldap_wildcard = (
            event.custom.get("ldap_injection") is True
            or (event.event.category == EventCategory.DIRECTORY_SERVICE and "*" in search_text and "lookup" in action)
        )

        is_ad_cmd = any(pat in search_text for pat in self.AD_DISC_PATTERNS)

        if is_ad_cmd or is_ldap_wildcard:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Active Directory Domain & Account Enumeration Detected",
                description=f"Domain discovery activity detected: {cmd or custom_filter or search_text[:140]}",
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
                    "ldap_filter": custom_filter,
                    "action": action,
                },
                investigation_hints=[
                    "Check source IP and user conducting directory enumeration.",
                    "Verify if source account was recently authenticated or compromised.",
                ],
            )
        return None


class NetworkPortScanDiscoveryRule(DetectionRule):
    """Detects internal network service scanning and port reconnaissance."""

    id: str = "DET-DISC-002"
    name: str = "Internal Network & Port Scanning Discovery"
    description: str = (
        "Detects port scanning, internal subnet sweep tools (nmap, masscan, fping), "
        "or SSRF probes targeting internal enterprise subnets."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.sysmon",
        "enterprise.web_portal",
        "network",
    ]
    why: str = (
        "Adversaries scan internal network segments to identify listening ports, exposed services, "
        "and vulnerable hosts for lateral movement."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1046/",
    ]

    SCAN_PATTERNS: ClassVar[List[str]] = [
        "nmap ",
        "masscan ",
        "zmap ",
        "fping ",
        "nc -zv",
        "nc -z",
        "test-netconnection",
        "portqry",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        cmd = ""
        if event.process and event.process.command_line:
            cmd = event.process.command_line
        elif event.message:
            cmd = event.message

        custom_target = str(event.custom.get("target_url", ""))
        is_ssrf = event.custom.get("ssrf_detected") is True
        search_text = f"{cmd} {custom_target}".lower()

        is_scan_tool = any(pat in search_text for pat in self.SCAN_PATTERNS)

        if is_scan_tool or is_ssrf:
            reason = "Port scanning utility execution" if is_scan_tool else "SSRF internal network probing"
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Network Service Discovery Detected ({reason})",
                description=f"Internal network discovery observed: {cmd or custom_target or search_text[:140]}",
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
                    "target_url": custom_target,
                    "reason": reason,
                },
                investigation_hints=[
                    "Identify scanned destination IP ranges and port list.",
                    "Verify if source host has authorization for network vulnerability scanning.",
                ],
            )
        return None


class SystemInfoDiscoveryRule(DetectionRule):
    """Detects system information and network configuration discovery commands."""

    id: str = "DET-DISC-003"
    name: str = "System & Security Configuration Discovery"
    description: str = (
        "Detects command execution collecting host system info, OS version, firewall status, "
        "or network interfaces (e.g. systeminfo, whoami /all, uname -a, ipconfig /all)."
    )
    severity: EventSeverity = EventSeverity.LOW
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1082",
        technique_name="System Information Discovery",
        url="https://attack.mitre.org/techniques/T1082/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.sysmon",
        "windows.security_auditing",
    ]
    why: str = (
        "Post-exploitation discovery commands give adversaries situational awareness of system patches, "
        "active network connections, and security controls."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1082/",
        "https://attack.mitre.org/techniques/T1016/",
    ]

    SYS_DISC_PATTERNS: ClassVar[List[str]] = [
        "systeminfo",
        "whoami /all",
        "whoami /priv",
        "ipconfig /all",
        "netstat -ano",
        "ss -tulpn",
        "uname -a",
        "cat /etc/os-release",
        "get-computerinfo",
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
        if any(pat in cmd_lower for pat in self.SYS_DISC_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="System Information Discovery Command Executed",
                description=f"Host configuration discovery observed: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Determine parent process and execution context.",
                    "Check for subsequent privilege escalation or credential access attempts.",
                ],
            )
        return None
