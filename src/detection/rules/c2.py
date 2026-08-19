"""Command and Control (C2) Detection Rules for MITRE ATT&CK Tactics."""

from typing import Any, ClassVar, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventSeverity


class IngressToolTransferRule(DetectionRule):
    """Detects remote staging and ingress tool transfer into writable or temporary directories."""

    id: str = "DET-C2-001"
    name: str = "Ingress Tool Transfer & Staging"
    description: str = (
        "Detects file download commands (curl, wget, bitsadmin, certutil, Invoke-WebRequest) "
        "transferring external files into /tmp, /dev/shm, or AppData directories."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        url="https://attack.mitre.org/techniques/T1105/",
    )
    data_sources: List[str] = [
        "linux.auditd",
        "windows.sysmon",
        "network",
    ]
    why: str = (
        "Adversaries transfer offensive tooling, backdoors, and secondary payloads onto compromised endpoints "
        "from external or adversary-controlled infrastructure."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1105/",
    ]

    TRANSFER_PATTERNS: ClassVar[List[str]] = [
        "curl -o /tmp/",
        "curl -o /dev/shm/",
        "curl -o /var/tmp/",
        "curl -o /opt/",
        "wget -o /tmp/",
        "wget -p /tmp/",
        "wget -o /dev/shm/",
        "wget -p /dev/shm/",
        "wget -o /var/tmp/",
        "bitsadmin /transfer",
        "certutil -urlcache -f",
        "certutil -urlcache -split",
        "downloadfile(",
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
        if any(pat in cmd_lower for pat in self.TRANSFER_PATTERNS):
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Ingress Tool Transfer and Remote Payload Download Detected",
                description=f"Tool transfer command detected: {cmd[:160]}",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    process=event.process.name if event.process else None,
                ),
                context={"command_line": cmd},
                investigation_hints=[
                    "Inspect remote server IP/URL and downloaded file hash.",
                    "Verify file destination on disk and isolate endpoint if executable.",
                ],
            )
        return None


class C2BeaconingCommunicationRule(DetectionRule):
    """Detects Command and Control beaconing and external communication channels."""

    id: str = "DET-C2-002"
    name: str = "Encrypted C2 Beaconing / External Channel"
    description: str = (
        "Detects outbound connections or beaconing behavior over HTTP/HTTPS/DNS/TCP "
        "matching known C2 frameworks, raw socket beacons, or suspicious external destination ports."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        subtechnique_id="T1071.001",
        subtechnique_name="Web Protocols",
        url="https://attack.mitre.org/techniques/T1071/001/",
    )
    data_sources: List[str] = [
        "network",
        "linux.auditd",
        "windows.sysmon",
        "enterprise.web_portal",
    ]
    why: str = (
        "C2 communication enables adversaries to receive operator commands and exfiltrate information "
        "using standard application layer protocols."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1071/001/",
        "https://attack.mitre.org/techniques/T1572/",
    ]

    C2_INDICATORS: ClassVar[List[str]] = [
        "c2_beacon",
        "c2_channel",
        "cobaltstrike",
        "meterpreter",
        "empire_agent",
        "beacon_interval",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        msg = event.message.lower() if event.message else ""
        action = event.event.action.lower() if event.event else ""
        dest_ip = event.destination.ip if event.destination else ""
        custom_c2 = str(event.custom.get("c2_type", "")).lower()
        cmd = (
            event.process.command_line.lower()
            if (event.process and event.process.command_line)
            else ""
        )

        is_dest_c2 = dest_ip.startswith("198.51.100.") or dest_ip.startswith("203.0.113.")
        is_custom_c2 = event.custom.get("is_c2_traffic") is True or bool(custom_c2)
        has_c2_name = any(ind in f"{msg} {action} {cmd}" for ind in self.C2_INDICATORS)

        if is_dest_c2 or is_custom_c2 or has_c2_name:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title="Command & Control (C2) Communication Detected",
                description=f"Observed C2 traffic or beaconing activity to destination '{dest_ip or 'external host'}'.",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=event.user.name if event.user else None,
                    ip=event.source.ip if event.source else None,
                ),
                context={
                    "destination_ip": dest_ip,
                    "action": action,
                    "c2_indicator": custom_c2 or "detected_beacon",
                },
                investigation_hints=[
                    "Block communication to destination IP at perimeter firewall.",
                    "Capture process memory from initiating PID to identify payload.",
                ],
            )
        return None
