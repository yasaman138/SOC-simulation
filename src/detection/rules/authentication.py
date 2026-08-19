"""Authentication Abuse Detection Rules."""

from typing import Any, Dict, List, Optional
from src.detection.models import (
    AffectedEntities,
    Alert,
    DetectionRule,
    MitreAttackInfo,
    MitreTactic,
)
from src.siem.models import ECSEvent, EventCategory, EventOutcome, EventSeverity


class BruteForceAuthenticationRule(DetectionRule):
    """Detects multiple failed logon attempts indicating brute force or password spraying."""

    id: str = "DET-AUTH-001"
    name: str = "Multiple Failed Logon Attempts (Brute Force / Password Spray)"
    description: str = (
        "Detects repeated failed authentication attempts against single or multiple user accounts "
        "within a correlation window, characteristic of password spraying or credential brute force."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1110",
        technique_name="Brute Force",
        subtechnique_id="T1110.001",
        subtechnique_name="Password Guessing",
        url="https://attack.mitre.org/techniques/T1110/001/",
    )
    data_sources: List[str] = [
        "windows.security_auditing",
        "linux.sshd",
        "enterprise.web_portal",
    ]
    why: str = (
        "Adversaries systematically attempt passwords to gain initial access or escalate privileges. "
        "Detecting failed logon clusters enables early containment before account compromise."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1110/",
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625",
    ]
    failure_threshold: int = 3

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        # Check if event is an authentication failure
        is_auth_failure = False

        if event.event.category == EventCategory.AUTHENTICATION:
            if event.event.outcome == EventOutcome.FAILURE:
                is_auth_failure = True
            elif "fail" in event.event.action.lower():
                is_auth_failure = True

        # Check Windows Event ID 4625
        win_ev_id = (
            event.custom.get("windows", {}).get("event_id")
            if event.custom
            else None
        )
        if win_ev_id == 4625:
            is_auth_failure = True

        # Check Linux sshd failure
        if "failed password" in event.message.lower():
            is_auth_failure = True

        if not is_auth_failure:
            return None

        # Check state tracker for failure counts
        source_key = (
            event.source.ip
            if (event.source and event.source.ip)
            else (event.host.ip if event.host else "unknown")
        )
        user_key = event.user.name if (event.user and event.user.name) else "unknown"

        current_count = 1
        source_events = [event.to_dict()]

        if state is not None:
            tracker_key = f"auth_fail:{source_key}"
            history = state.get(tracker_key, [])
            history.append(event.to_dict())
            state[tracker_key] = history
            current_count = len(history)
            source_events = history

        # Trigger alert if threshold met or single batch context exceeds threshold
        batch_count = (
            event.custom.get("failed_attempts_count", current_count)
            if event.custom
            else current_count
        )

        if batch_count >= self.failure_threshold:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Brute Force Authentication Detected from {source_key}",
                description=(
                    f"Observed {batch_count} failed authentication attempts from source IP {source_key} "
                    f"targeting user '{user_key}'."
                ),
                source_event_ids=[event.event.id],
                source_events=source_events[-5:],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=user_key if user_key != "unknown" else None,
                    ip=source_key if source_key != "unknown" else None,
                ),
                context={
                    "source_ip": source_key,
                    "target_user": user_key,
                    "attempt_count": batch_count,
                    "threshold": self.failure_threshold,
                },
                investigation_hints=[
                    "Check if source IP belongs to trusted subnet or VPN pool.",
                    "Verify if targeted account was subsequently locked out or successfully logged in.",
                    "Inspect other network activity from source IP.",
                ],
            )

        return None


class UnauthorizedAccountLogonRule(DetectionRule):
    """Detects logon attempts against disabled, restricted, or administrative accounts (e.g. root SSH)."""

    id: str = "DET-AUTH-002"
    name: str = "Unauthorized or Disabled Account Logon Attempt"
    description: str = (
        "Detects interactive login attempts against restricted accounts such as direct root login "
        "or disabled service accounts."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1078",
        technique_name="Valid Accounts",
        subtechnique_id="T1078.003",
        subtechnique_name="Local Accounts",
        url="https://attack.mitre.org/techniques/T1078/003/",
    )
    data_sources: List[str] = ["linux.sshd", "windows.security_auditing"]
    why: str = (
        "Direct root access bypasses non-repudiation and privilege segregation policies. "
        "Attempts to log in directly as root or guest indicate adversary exploration or unauthorized access."
    )
    references: List[str] = [
        "https://attack.mitre.org/techniques/T1078/003/",
    ]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        msg = event.message.lower()
        user = (
            event.user.name.lower()
            if (event.user and event.user.name)
            else ""
        )

        is_root_attempt = (
            "permitrootlogin=no" in msg
            or "failed password for root" in msg
            or "failed password for invalid user root" in msg
            or (user == "root" and event.event.category == EventCategory.AUTHENTICATION)
        )

        is_disabled_account = (
            "disabled account" in msg
            or "account is currently disabled" in msg
            or (event.custom.get("account_disabled") is True)
        )

        if is_root_attempt or is_disabled_account:
            reason = (
                "Direct root SSH logon attempt denied by policy"
                if is_root_attempt
                else "Logon attempt against disabled account"
            )
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Unauthorized Account Access Attempt: {user or 'root'}",
                description=f"{reason} on host '{event.host.name if event.host else 'unknown'}'.",
                source_event_ids=[event.event.id],
                source_events=[event.to_dict()],
                affected_entities=AffectedEntities(
                    host=event.host.name if event.host else None,
                    user=user or "root",
                    ip=event.source.ip if event.source else None,
                ),
                context={
                    "target_account": user or "root",
                    "reason": reason,
                    "raw_message": event.message,
                },
                investigation_hints=[
                    "Verify SSH configuration on target host (/etc/ssh/sshd_config).",
                    "Identify source host and investigate whether it is an internal host or external attacker.",
                ],
            )
        return None


class SuspiciousRemoteLogonRule(DetectionRule):
    """Detects logon activity originating from untrusted/DMZ network segments to Tier-0/1 assets."""

    id: str = "DET-AUTH-003"
    name: str = "Suspicious Cross-Zone Remote Logon"
    description: str = (
        "Detects logon events to domain controllers or critical management interfaces originating from untrusted or DMZ tiers."
    )
    severity: EventSeverity = EventSeverity.HIGH
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1078",
        technique_name="Valid Accounts",
        url="https://attack.mitre.org/techniques/T1078/",
    )
    data_sources: List[str] = ["windows.security_auditing", "linux.sshd"]
    why: str = (
        "Core infrastructure should only be administered from dedicated management workstations. "
        "Logons from web application containers or DMZ subnets signify lateral movement or boundary breach."
    )
    references: List[str] = ["https://attack.mitre.org/techniques/T1078/"]

    def evaluate(
        self, event: ECSEvent, state: Optional[Dict[str, Any]] = None
    ) -> Optional[Alert]:
        if event.event.category != EventCategory.AUTHENTICATION:
            return None

        # Check if destination is DC / sensitive and source is DMZ (172.28.10.x / 172.28.30.x)
        source_ip = event.source.ip if event.source else ""
        host_name = event.host.name.lower() if (event.host and event.host.name) else ""

        is_dmz_source = source_ip.startswith("172.28.30.") or source_ip.startswith("172.28.10.")
        is_dc_target = "dc" in host_name or "172.28.20.10" in (
            event.destination.ip if event.destination else ""
        )

        if is_dmz_source and is_dc_target:
            return Alert(
                rule_id=self.id,
                rule_name=self.name,
                severity=self.severity,
                mitre_attack=self.mitre_attack,
                title=f"Suspicious Cross-Zone Logon to {host_name} from DMZ ({source_ip})",
                description=(
                    f"Authentication attempt to Domain Controller '{host_name}' originating from "
                    f"untrusted DMZ source IP '{source_ip}'."
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
                    "target_host": host_name,
                    "user": event.user.name if event.user else "unknown",
                },
                investigation_hints=[
                    "Check firewall segmentation rules between DMZ and Corporate Active Directory.",
                    "Inspect DMZ web application for compromise or command injection.",
                ],
            )
        return None
