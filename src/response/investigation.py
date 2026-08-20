"""Automated Investigation & Multi-Source Telemetry Correlation Engine."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from src.core.logging import get_logger
from src.core.topology import EnterpriseLabTopology
from src.detection.models import Alert, MitreAttackInfo, MitreTactic
from src.detection.storage import AlertStore
from src.response.models import (
    EvidenceItem,
    Incident,
    IncidentDisposition,
    IncidentSeverity,
    IncidentStatus,
    Indicator,
    IndicatorType,
    LessonsLearned,
    RootCauseAnalysis,
    TimelineEntry,
)
from src.siem.models import ECSEvent, EventCategory, EventOutcome, EventQuery
from src.siem.storage import EventStore

logger = get_logger("response.investigation")

# Known Threat Intelligence feeds & IOC indicators for the enterprise lab
KNOWN_THREAT_INTEL: Dict[str, Dict[str, Any]] = {
    "198.51.100.42": {
        "type": IndicatorType.IP,
        "reputation": "malicious",
        "context": "Known APT C2 Beaconing Server (Cobalt Strike / Empire)",
        "confidence": 0.95,
    },
    "198.51.100.99": {
        "type": IndicatorType.IP,
        "reputation": "malicious",
        "context": "External Attack Infrastructure & Scanner",
        "confidence": 0.90,
    },
    "c2.evil-attacker.org": {
        "type": IndicatorType.DOMAIN,
        "reputation": "malicious",
        "context": "Adversary Dynamic DNS C2 Domain",
        "confidence": 0.95,
    },
    "pastebin.com/raw/attacker_payload": {
        "type": IndicatorType.URL,
        "reputation": "suspicious",
        "context": "Stage 2 Stager Payload Hosting",
        "confidence": 0.85,
    },
    "procdump.exe": {
        "type": IndicatorType.PROCESS_NAME,
        "reputation": "suspicious",
        "context": "Sysinternals ProcDump used for LSASS credential dumping",
        "confidence": 0.85,
    },
    "mimikatz.exe": {
        "type": IndicatorType.PROCESS_NAME,
        "reputation": "malicious",
        "context": "Known Credential Extraction Utility",
        "confidence": 1.0,
    },
    "nc": {
        "type": IndicatorType.PROCESS_NAME,
        "reputation": "suspicious",
        "context": "Netcat reverse shell utility",
        "confidence": 0.80,
    },
    "shred": {
        "type": IndicatorType.PROCESS_NAME,
        "reputation": "suspicious",
        "context": "Linux Anti-Forensics / Data Destruction utility",
        "confidence": 0.80,
    },
}


class InvestigationEngine:
    """Enterprise SOC Automated Investigation & Event Correlation Engine."""

    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        alert_store: Optional[AlertStore] = None,
        topology: Optional[EnterpriseLabTopology] = None,
    ):
        self.event_store = event_store or EventStore()
        self.alert_store = alert_store or AlertStore()
        self.topology = topology or EnterpriseLabTopology()

    def create_incident_from_alert(
        self,
        alert: Alert,
        time_window_minutes: int = 60,
    ) -> Incident:
        """Transform a Detection Alert into a structured Incident and execute initial investigation."""
        severity_map = {
            "informational": IncidentSeverity.INFORMATIONAL,
            "low": IncidentSeverity.LOW,
            "medium": IncidentSeverity.MEDIUM,
            "high": IncidentSeverity.HIGH,
            "critical": IncidentSeverity.CRITICAL,
        }
        inc_severity = severity_map.get(
            alert.severity.value, IncidentSeverity.MEDIUM
        )

        affected_assets: List[str] = []
        if alert.affected_entities.host:
            affected_assets.append(alert.affected_entities.host)
        if alert.affected_entities.ip:
            affected_assets.append(alert.affected_entities.ip)

        affected_users: List[str] = []
        if alert.affected_entities.user:
            affected_users.append(alert.affected_entities.user)

        mitre_list: List[MitreAttackInfo] = []
        if alert.mitre_attack:
            mitre_list.append(alert.mitre_attack)

        incident = Incident(
            severity=inc_severity,
            status=IncidentStatus.NEW,
            title=f"Incident: {alert.title}",
            description=f"Generated from Detection Alert [{alert.id}] ({alert.rule_id}): {alert.description}",
            affected_assets=affected_assets,
            affected_users=affected_users,
            detection_source=[alert.id, alert.rule_id],
            mitre_attack=mitre_list,
            metadata={"primary_alert_id": alert.id, "rule_name": alert.rule_name},
        )

        # Correlate all telemetry and build timeline
        self.correlate_incident(incident, time_window_minutes=time_window_minutes)
        return incident

    def correlate_incident(
        self,
        incident: Incident,
        time_window_minutes: int = 60,
    ) -> Incident:
        """Perform automated multi-source correlation across authentication, process, network, and file activity."""
        incident.status = IncidentStatus.INVESTIGATING

        target_hosts = set(incident.affected_assets)
        target_users = set(incident.affected_users)
        target_ips: Set[str] = set()

        for asset in list(target_hosts):
            if any(char.isdigit() for char in asset) and "." in asset:
                target_ips.add(asset)

        # Pull all stored events
        all_events = self.event_store.query_events(
            EventQuery(limit=self.event_store.count())
        )

        # Filter events matching entities if events are present
        correlated_events: List[ECSEvent] = []
        if all_events:
            for ev in all_events:
                matched = False

                # Check host
                if ev.host and ev.host.name:
                    if any(h.lower() in ev.host.name.lower() for h in target_hosts):
                        matched = True
                if ev.host and ev.host.ip and ev.host.ip in target_ips:
                    matched = True

                # Check user
                if ev.user and ev.user.name:
                    if any(u.lower() == ev.user.name.lower() for u in target_users):
                        matched = True

                # Check network source / destination
                if ev.source and ev.source.ip and (ev.source.ip in target_ips or ev.source.ip in target_hosts):
                    matched = True
                if ev.destination and ev.destination.ip and (ev.destination.ip in target_ips or ev.destination.ip in target_hosts):
                    matched = True

                if matched:
                    correlated_events.append(ev)

                    # Expand discovered entities
                    if ev.host and ev.host.name and ev.host.name not in incident.affected_assets:
                        incident.affected_assets.append(ev.host.name)
                        target_hosts.add(ev.host.name)
                    if ev.user and ev.user.name and ev.user.name not in incident.affected_users and ev.user.name != "unknown":
                        incident.affected_users.append(ev.user.name)
                        target_users.add(ev.user.name)
                    if ev.source and ev.source.ip and ev.source.ip not in target_ips:
                        target_ips.add(ev.source.ip)
                    if ev.destination and ev.destination.ip and ev.destination.ip not in target_ips:
                        target_ips.add(ev.destination.ip)

        # Build chronological timeline
        timeline_entries: List[TimelineEntry] = []

        # 1. Add Correlated SIEM Events
        for ev in correlated_events:
            entry = self._convert_event_to_timeline_entry(ev)
            timeline_entries.append(entry)

            # Store evidence reference
            evidence = EvidenceItem(
                evidence_type="log_event",
                description=f"SIEM Event [{ev.event.action}] on host {ev.host.name if ev.host else 'unknown'}",
                raw_data=ev.to_dict(),
                source=ev.event.dataset,
            )
            incident.add_evidence(evidence)

        # 2. Add Related Alerts
        all_alerts = self.alert_store.query_alerts()
        for alt in all_alerts:
            alt_matched = False
            if alt.affected_entities.host and alt.affected_entities.host in target_hosts:
                alt_matched = True
            if alt.affected_entities.user and alt.affected_entities.user in target_users:
                alt_matched = True
            if alt.affected_entities.ip and alt.affected_entities.ip in target_ips:
                alt_matched = True

            if alt_matched:
                if alt.mitre_attack and not any(m.technique_id == alt.mitre_attack.technique_id for m in incident.mitre_attack):
                    incident.mitre_attack.append(alt.mitre_attack)

                t_entry = TimelineEntry(
                    timestamp=alt.timestamp,
                    category="alert",
                    title=f"Detection Alert: {alt.title}",
                    description=alt.description,
                    source_id=alt.id,
                    source_type="alert",
                    entities={
                        "host": alt.affected_entities.host,
                        "user": alt.affected_entities.user,
                        "ip": alt.affected_entities.ip,
                        "rule_id": alt.rule_id,
                    },
                    confidence=1.0,
                    is_key_event=True,
                    mitre_technique=alt.mitre_attack.technique_id if alt.mitre_attack else None,
                )
                timeline_entries.append(t_entry)

        # Sort timeline chronologically
        timeline_entries.sort(key=lambda x: x.timestamp)
        incident.timeline = timeline_entries

        # Extract and enrich Indicators of Compromise (IOCs)
        self._extract_and_enrich_indicators(incident, correlated_events, target_ips)

        # Synthesize Root Cause Analysis & Lessons Learned
        incident.root_cause_analysis = self._synthesize_root_cause(incident)
        incident.lessons_learned = self._synthesize_lessons_learned(incident)
        incident.final_disposition = IncidentDisposition.TRUE_POSITIVE_MALICIOUS

        logger.info(
            f"Investigation completed for {incident.incident_id}: {len(timeline_entries)} timeline entries, {len(incident.indicators)} indicators identified."
        )
        return incident

    def _convert_event_to_timeline_entry(self, ev: ECSEvent) -> TimelineEntry:
        """Convert a normalized ECS event into a descriptive Timeline entry."""
        cat = ev.event.category.value
        title = f"{cat.capitalize()}: {ev.event.action}"
        desc = ev.message or f"Action {ev.event.action} recorded on dataset {ev.event.dataset}"

        is_key = False
        mitre_tech = None

        if ev.event.category == EventCategory.AUTHENTICATION:
            if ev.event.outcome == EventOutcome.FAILURE:
                title = f"Auth Failure: {ev.user.name if ev.user else 'unknown'}"
            else:
                title = f"Successful Logon: {ev.user.name if ev.user else 'unknown'}"
        elif ev.event.category == EventCategory.PROCESS:
            cmd = ev.process.command_line if ev.process else ""
            title = f"Process Executed: {ev.process.name if ev.process else 'unknown'}"
            desc = f"Command: {cmd}"
            if any(k in cmd.lower() for k in ["lsass", "/etc/shadow", "shred", "psexec", "sc.exe", "powershell", "systemctl stop"]):
                is_key = True
        elif ev.event.category == EventCategory.DIRECTORY_SERVICE:
            title = f"Directory Request: {ev.event.action}"
            is_key = True
        elif ev.event.category == EventCategory.NETWORK or ev.event.category == EventCategory.WEB:
            src = ev.source.ip if ev.source else "?"
            dst = ev.destination.ip if ev.destination else "?"
            title = f"Network Connection: {src} -> {dst}"

        entities = {
            "host": ev.host.name if ev.host else None,
            "user": ev.user.name if ev.user else None,
            "src_ip": ev.source.ip if ev.source else None,
            "dst_ip": ev.destination.ip if ev.destination else None,
            "process": ev.process.name if ev.process else None,
        }

        return TimelineEntry(
            timestamp=ev.timestamp,
            category=cat,
            title=title,
            description=desc,
            source_id=ev.event.id,
            source_type="event",
            entities=entities,
            confidence=0.95,
            is_key_event=is_key,
            mitre_technique=mitre_tech,
        )

    def _extract_and_enrich_indicators(
        self,
        incident: Incident,
        events: List[ECSEvent],
        target_ips: Set[str],
    ) -> None:
        """Extract network, user, file, and process IOCs and query Threat Intel."""
        # 1. IP Indicators
        for ip in target_ips:
            if not ip or ip in ("127.0.0.1", "::1"):
                continue
            rep = "suspicious"
            context = "Observed in correlated telemetry"
            conf = 0.7

            if ip in KNOWN_THREAT_INTEL:
                intel = KNOWN_THREAT_INTEL[ip]
                rep = intel["reputation"]
                context = intel["context"]
                conf = intel["confidence"]
            elif ip.startswith("172.28.30."):
                context = "DMZ Network Tier Host"
            elif ip.startswith("172.28.20."):
                context = "Internal Corporate Secure Zone Host"
            elif ip.startswith("172.28.10."):
                context = "Simulation / Testing Segment Host"

            incident.add_indicator(
                Indicator(
                    type=IndicatorType.IP,
                    value=ip,
                    context=context,
                    reputation=rep,
                    confidence=conf,
                )
            )

        # 2. User Indicators
        for user in incident.affected_users:
            if user and user not in ("SYSTEM", "root", "unknown"):
                incident.add_indicator(
                    Indicator(
                        type=IndicatorType.USER,
                        value=user,
                        context=f"Compromised / Targeted Account in incident {incident.incident_id}",
                        reputation="suspicious",
                        confidence=0.85,
                    )
                )

        # 3. Process & File IOCs
        for ev in events:
            if ev.process and ev.process.name:
                pname = ev.process.name.lower()
                for known_proc, intel in KNOWN_THREAT_INTEL.items():
                    if intel["type"] == IndicatorType.PROCESS_NAME and known_proc.lower() in pname:
                        incident.add_indicator(
                            Indicator(
                                type=IndicatorType.PROCESS_NAME,
                                value=ev.process.name,
                                context=f"{intel['context']} (Command: {ev.process.command_line or ''})",
                                reputation=intel["reputation"],
                                confidence=intel["confidence"],
                            )
                        )
            if ev.file and ev.file.path:
                incident.add_indicator(
                    Indicator(
                        type=IndicatorType.FILE_PATH,
                        value=ev.file.path,
                        context=f"Accessed or modified file in dataset {ev.event.dataset}",
                        reputation="suspicious",
                        confidence=0.75,
                    )
                )

    def _synthesize_root_cause(self, incident: Incident) -> RootCauseAnalysis:
        """Generate structured root-cause assessment based on MITRE tactics and correlated telemetry."""
        tactics = [m.tactic.value for m in incident.mitre_attack]
        techniques = [f"{m.technique_id} ({m.technique_name})" for m in incident.mitre_attack]

        initial_vector = "Unknown Initial Vector"
        if any("Initial Access" in t for t in tactics):
            initial_vector = "Exploitation of Web Facing Application / Phishing"
        elif any("Credential Access" in t for t in tactics):
            initial_vector = "Credential Dumping / Kerberoasting / Password Guessing"
        elif any("Lateral Movement" in t for t in tactics):
            initial_vector = "Lateral Movement via Remote Administrative Protocol (SSH/SMB/WinRM)"
        elif any("Execution" in t for t in tactics):
            initial_vector = "Command Execution / Scripting Interpreter Abuse"

        attack_path = []
        for entry in incident.timeline:
            if entry.is_key_event:
                attack_path.append(f"[{entry.timestamp.strftime('%H:%M:%S')}] {entry.title}: {entry.description}")

        if not attack_path and incident.timeline:
            attack_path = [f"{t.title} ({t.category})" for t in incident.timeline[:5]]

        summary = (
            f"Adversary initiated attack involving {', '.join(tactics) if tactics else 'suspicious actions'}. "
            f"Affected assets: {', '.join(incident.affected_assets) or 'Unknown'}. "
            f"Primary techniques: {', '.join(techniques) or 'Uncategorized'}."
        )

        return RootCauseAnalysis(
            summary=summary,
            initial_vector=initial_vector,
            attack_path=attack_path,
            vulnerabilities_exploited=[
                "Weak credential policy or service ticket encryption (RC4-HMAC)",
                "Lack of restrictive network microsegmentation between DMZ and Internal servers",
                "Unrestricted process execution privileges",
            ],
            impact_assessment=f"Threat severity is {incident.severity.value.upper()}. Scope contained to lab assets.",
            confidence=0.90,
        )

    def _synthesize_lessons_learned(self, incident: Incident) -> LessonsLearned:
        """Formulate post-incident security hardening recommendations."""
        return LessonsLearned(
            root_cause_summary=f"Incident {incident.incident_id} revealed security weaknesses in authentication, process monitoring, and lateral movement defenses.",
            detection_gaps=[
                "Improve correlation rules for rapid cross-subnet DMZ pivots",
                "Increase logging fidelity on sensitive endpoint system calls",
            ],
            preventive_recommendations=[
                "Enforce AES-256 Kerberos encryption and rotate service account passwords regularly",
                "Implement strict network isolation firewall rules between DMZ and corporate core",
                "Deploy Endpoint Detection and Response (EDR) agent policies to block unauthorized process injection and memory dumps",
            ],
            procedural_improvements=[
                "Automate immediate user session revocation and endpoint network isolation upon high-confidence alert triggers",
                "Standardize forensic artifact preservation protocols",
            ],
            hardening_actions=[
                "Audit local administrator group memberships",
                "Enforce Multi-Factor Authentication (MFA) across all administrative entry points",
            ],
        )

    def collect_forensic_metadata(
        self, hostname: str
    ) -> Dict[str, Any]:
        """Collect simulated forensic metadata snapshot for an investigated endpoint."""
        return {
            "hostname": hostname,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "os_version": "Enterprise Linux 9 / Windows Server 2022",
            "active_processes": [
                {"pid": 1, "name": "systemd", "user": "root"},
                {"pid": 800, "name": "auditd", "user": "root"},
                {"pid": 1050, "name": "sshd", "user": "root"},
                {"pid": 14200, "name": "bash", "user": "sysadmin"},
            ],
            "open_sockets": [
                {"protocol": "tcp", "local_port": 22, "state": "LISTEN"},
                {"protocol": "tcp", "local_port": 443, "state": "LISTEN"},
                {"protocol": "tcp", "local_port": 88, "state": "LISTEN"},
            ],
            "logged_in_users": ["sysadmin", "jdoe"],
            "integrity_checks": {
                "filesystem": "VERIFIED_CLEAN",
                "kernel_modules": "SIGNED_ONLY",
            },
        }
