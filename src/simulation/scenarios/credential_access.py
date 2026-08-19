"""Credential Access Attack Simulation Scenarios."""

import time
from datetime import datetime, timezone
from typing import List
from src.detection.models import MitreAttackInfo, MitreTactic
from src.siem.models import (
    ECSEvent,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    ProcessInfo,
    UserInfo,
)
from src.simulation.models import (
    BaseScenario,
    ScenarioExecutionStatus,
    ScenarioResult,
    SimulationContext,
)
from src.simulation.safety import LabSafetyGuardrail


class KerberoastingScenario(BaseScenario):
    """Simulates requesting a Kerberos TGS service ticket with RC4 encryption for offline cracking."""

    id: str = "SCN-CRED-001"
    name: str = "Kerberoasting TGS Service Ticket Request"
    description: str = (
        "Simulates an authenticated adversary querying Active Directory for accounts with registered SPNs "
        "and requesting TGS service tickets with weak RC4-HMAC encryption to perform offline password hash cracking."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1558",
        technique_name="Steal or Forge Kerberos Tickets",
        subtechnique_id="T1558.003",
        subtechnique_name="Kerberoasting",
        url="https://attack.mitre.org/techniques/T1558/003/",
    )
    preconditions: List[str] = [
        "Active Directory Server emulator operational",
        "Target service account exists with registered SPN",
    ]
    lab_target: str = "dc01.corp.enterprise.local (172.28.20.10)"
    simulated_behavior: str = (
        "Request Kerberos TGS ticket for SPN 'MSSQLSvc/db01.corp.enterprise.local:1433' with RC4-HMAC encryption."
    )
    expected_telemetry: List[str] = [
        "ad.kerberos.tgs_request",
        "Event ID 4769",
        "encryption_type: rc4-hmac",
    ]
    expected_detections: List[str] = ["DET-CRED-001"]
    expected_alerts: List[str] = [
        "Kerberoasting Activity Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless Kerberos ticket issuance"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("dc01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute Kerberoasting TGS request against DC")
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.SKIPPED,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                duration_ms=(time.time() - start) * 1000,
                execution_logs=logs,
            )

        if not context.ad_server:
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message="SimulationContext missing ad_server handle",
            )

        spn = "MSSQLSvc/db01.corp.enterprise.local:1433"
        logs.append(f"Requesting Kerberos TGS ticket for {spn}...")
        ticket = context.ad_server.request_kerberos_tgs(
            client_user="jdoe",
            spn=spn,
            source_ip="172.28.20.25",
        )
        logs.append(f"Ticket generated: {ticket.ticket_id if ticket else 'None'}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "tgs" in e.event.action or e.event.category == EventCategory.DIRECTORY_SERVICE
            ]

        return ScenarioResult(
            scenario_id=self.id,
            scenario_name=self.name,
            status=ScenarioExecutionStatus.SUCCESS,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            duration_ms=(time.time() - start) * 1000,
            generated_events_count=len(events_generated),
            generated_events=events_generated,
            execution_logs=logs,
        )


class ShadowFileAccessScenario(BaseScenario):
    """Simulates reading the Linux /etc/shadow password database."""

    id: str = "SCN-CRED-002"
    name: str = "Linux /etc/shadow Credential File Access"
    description: str = (
        "Simulates an adversary reading /etc/shadow on a compromised Linux host to dump local user "
        "password hashes for offline hash cracking."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        subtechnique_id="T1003.008",
        subtechnique_name="/etc/passwd and /etc/shadow",
        url="https://attack.mitre.org/techniques/T1003/008/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: cat /etc/shadow"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains /etc/shadow",
    ]
    expected_detections: List[str] = ["DET-CRED-002"]
    expected_alerts: List[str] = [
        "Sensitive Shadow Password Database Access Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless read command"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute cat /etc/shadow on srv01")
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.SKIPPED,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                duration_ms=(time.time() - start) * 1000,
                execution_logs=logs,
            )

        if not context.linux_service:
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message="SimulationContext missing linux_service handle",
            )

        cmd = "cat /etc/shadow"
        logs.append(f"Simulating shadow file access: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=23100,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "/etc/shadow" in (e.process.command_line or "")
            ]

        return ScenarioResult(
            scenario_id=self.id,
            scenario_name=self.name,
            status=ScenarioExecutionStatus.SUCCESS,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            duration_ms=(time.time() - start) * 1000,
            generated_events_count=len(events_generated),
            generated_events=events_generated,
            execution_logs=logs,
        )


class LSASSDumpScenario(BaseScenario):
    """Simulates dumping LSASS process memory on a Windows endpoint."""

    id: str = "SCN-CRED-003"
    name: str = "LSASS Memory Dump via Procdump"
    description: str = (
        "Simulates an adversary executing procdump.exe against the Local Security Authority Subsystem Service (LSASS) "
        "to extract active Kerberos tickets and NTLM hashes."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        subtechnique_id="T1003.001",
        subtechnique_name="LSASS Memory",
        url="https://attack.mitre.org/techniques/T1003/001/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "wkstn01.corp.enterprise.local (172.28.20.50)"
    simulated_behavior: str = (
        "Emit Sysmon Event for procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"
    )
    expected_telemetry: List[str] = [
        "dataset: windows.sysmon",
        "command_line contains procdump lsass",
    ]
    expected_detections: List[str] = ["DET-CRED-003"]
    expected_alerts: List[str] = [
        "LSASS Memory Dump or SAM Registry Export Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless event emission"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("wkstn01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would emit LSASS dump event")
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.SKIPPED,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                duration_ms=(time.time() - start) * 1000,
                execution_logs=logs,
            )

        if not context.siem_collector:
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message="SimulationContext missing siem_collector handle",
            )

        cmd = "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.PROCESS,
                action="windows.process.created",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.HIGH,
                dataset="windows.sysmon",
            ),
            host=HostInfo(name="wkstn01.corp.enterprise.local", ip="172.28.20.50"),
            user=UserInfo(name="attacker", domain="CORP"),
            process=ProcessInfo(
                name="procdump.exe",
                pid=9124,
                command_line=cmd,
            ),
            message=f"Process created: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted Windows Sysmon LSASS memory dumping event to SIEM.")

        return ScenarioResult(
            scenario_id=self.id,
            scenario_name=self.name,
            status=ScenarioExecutionStatus.SUCCESS,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            duration_ms=(time.time() - start) * 1000,
            generated_events_count=len(events_generated),
            generated_events=events_generated,
            execution_logs=logs,
        )


class BruteForceAuthScenario(BaseScenario):
    """Simulates an authentication brute force / password guessing attack cluster."""

    id: str = "SCN-CRED-004"
    name: str = "Active Directory Password Guessing / Brute Force"
    description: str = (
        "Simulates an adversary sending multiple failed authentication attempts against a target account "
        "to guess credentials."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1110",
        technique_name="Brute Force",
        subtechnique_id="T1110.001",
        subtechnique_name="Password Guessing",
        url="https://attack.mitre.org/techniques/T1110/001/",
    )
    preconditions: List[str] = ["Active Directory Server emulator operational"]
    lab_target: str = "dc01.corp.enterprise.local (172.28.20.10)"
    simulated_behavior: str = (
        "Send 5 consecutive failed logon attempts for user 'jdoe' from simulation host (172.28.10.100)."
    )
    expected_telemetry: List[str] = [
        "ad.logon.failed",
        "Event ID 4625",
        "failed_attempts_count >= 3",
    ]
    expected_detections: List[str] = ["DET-AUTH-001"]
    expected_alerts: List[str] = [
        "Brute Force Authentication Detected",
    ]
    cleanup_requirements: List[str] = [
        "Reset user bad password counter (badPasswordCount = 0)",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("dc01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute password guessing on DC")
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.SKIPPED,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                duration_ms=(time.time() - start) * 1000,
                execution_logs=logs,
            )

        if not context.ad_server:
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message="SimulationContext missing ad_server handle",
            )

        logs.append("Executing 5 failed logon attempts for user 'jdoe'...")
        for i in range(5):
            context.ad_server.authenticate_user(
                username="jdoe",
                password=f"WrongPasswordGuess_{i}!",
                source_ip="172.28.10.100",
                workstation_name="ATTACKER-NODE",
            )

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.user and e.user.name == "jdoe" and "failed" in e.event.action
            ]

        return ScenarioResult(
            scenario_id=self.id,
            scenario_name=self.name,
            status=ScenarioExecutionStatus.SUCCESS,
            start_time=start_time,
            end_time=datetime.now(timezone.utc),
            duration_ms=(time.time() - start) * 1000,
            generated_events_count=len(events_generated),
            generated_events=events_generated,
            execution_logs=logs,
        )

    def cleanup(self, context: SimulationContext) -> bool:
        if context.ad_server:
            user = context.ad_server.users.get("jdoe")
            if user:
                user.badPasswordCount = 0
        return True
