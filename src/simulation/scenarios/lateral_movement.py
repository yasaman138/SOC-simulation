"""Lateral Movement Attack Simulation Scenarios."""

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


class CrossSubnetSSHLateralScenario(BaseScenario):
    """Simulates SSH lateral movement originating from the DMZ web tier to internal servers."""

    id: str = "SCN-LAT-001"
    name: str = "Cross-Subnet SSH Lateral Movement"
    description: str = (
        "Simulates an adversary who has compromised the DMZ web tier (172.28.30.10) pivoting deeper "
        "into the corporate network by connecting via SSH into internal server srv01 (172.28.20.15)."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.004",
        subtechnique_name="SSH",
        url="https://attack.mitre.org/techniques/T1021/004/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15:22)"
    simulated_behavior: str = (
        "Simulate inbound SSH connection to srv01 from DMZ web host IP 172.28.30.10."
    )
    expected_telemetry: List[str] = [
        "ssh.login.success",
        "source.ip: 172.28.30.10",
        "destination.ip: 172.28.20.15",
    ]
    expected_detections: List[str] = ["DET-LAT-002"]
    expected_alerts: List[str] = [
        "Cross-Subnet SSH Lateral Movement from DMZ",
    ]
    cleanup_requirements: List[str] = ["Stateless authentication event"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute cross-subnet SSH on srv01")
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

        logs.append("Executing SSH login from DMZ source 172.28.30.10...")
        context.linux_service.simulate_ssh_login(
            username="sysadmin",
            password="LinuxAdminLab2026!",
            source_ip="172.28.30.10",
            source_port=49822,
        )
        logs.append("SSH login from DMZ succeeded.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.source and e.source.ip == "172.28.30.10"
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


class RemoteServicePsExecScenario(BaseScenario):
    """Simulates remote Windows service creation (PsExec) across the SMB administrative share."""

    id: str = "SCN-LAT-002"
    name: str = "Remote Service Creation / PsExec Lateral Movement"
    description: str = (
        "Simulates an adversary executing sc.exe or PsExec against a remote Domain Controller "
        "to install and launch a service remotely."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.002",
        subtechnique_name="SMB/Windows Admin Shares",
        url="https://attack.mitre.org/techniques/T1021/002/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "dc01.corp.enterprise.local (172.28.20.10)"
    simulated_behavior: str = (
        "Emit Windows Process Event for: sc.exe \\\\dc01 create PSEXESVC binPath= C:\\Temp\\psexec.exe"
    )
    expected_telemetry: List[str] = [
        "dataset: windows.sysmon / system",
        "command_line contains sc.exe create or psexec",
    ]
    expected_detections: List[str] = ["DET-LAT-001"]
    expected_alerts: List[str] = [
        "Remote Service / PsExec Execution Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless event emission"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("dc01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would emit PsExec remote service event")
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

        cmd = "sc.exe \\\\dc01 create PSEXESVC binPath= C:\\Temp\\psexec.exe"
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.PROCESS,
                action="windows.process.created",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.HIGH,
                dataset="windows.sysmon",
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            user=UserInfo(name="da_johnson", domain="CORP"),
            process=ProcessInfo(
                name="sc.exe",
                pid=9312,
                command_line=cmd,
            ),
            message=f"Process created: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted remote PsExec service execution event to SIEM.")

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


class RemoteWinRMScenario(BaseScenario):
    """Simulates remote PowerShell WinRM lateral execution."""

    id: str = "SCN-LAT-003"
    name: str = "Remote WinRM / PowerShell Lateral Execution"
    description: str = (
        "Simulates an adversary establishing an interactive remote WinRM session (Enter-PSSession) "
        "to execute commands on the Domain Controller."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        subtechnique_id="T1021.006",
        subtechnique_name="Windows Remote Management",
        url="https://attack.mitre.org/techniques/T1021/006/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "dc01.corp.enterprise.local (172.28.20.10:5985)"
    simulated_behavior: str = (
        "Emit PowerShell Event for: Enter-PSSession -ComputerName dc01.corp.enterprise.local -Credential CORP\\Administrator"
    )
    expected_telemetry: List[str] = [
        "dataset: windows.powershell",
        "command_line contains Enter-PSSession",
    ]
    expected_detections: List[str] = ["DET-LAT-003"]
    expected_alerts: List[str] = [
        "Remote WinRM / PowerShell Session Initiated",
    ]
    cleanup_requirements: List[str] = ["Stateless event emission"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("dc01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would emit WinRM lateral session event")
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

        cmd = "Enter-PSSession -ComputerName dc01.corp.enterprise.local -Credential CORP\\Administrator"
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.PROCESS,
                action="windows.process.created",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.MEDIUM,
                dataset="windows.powershell",
            ),
            host=HostInfo(name="wkstn01.corp.enterprise.local", ip="172.28.20.50"),
            user=UserInfo(name="attacker", domain="CORP"),
            process=ProcessInfo(
                name="powershell.exe",
                pid=9450,
                command_line=cmd,
            ),
            message=f"PowerShell remote invocation: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted WinRM remote PowerShell session event to SIEM.")

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


class CrossZoneDCRemoteLogonScenario(BaseScenario):
    """Simulates an authentication attempt to the Domain Controller directly originating from DMZ."""

    id: str = "SCN-LAT-004"
    name: str = "Suspicious DMZ to Domain Controller Remote Logon"
    description: str = (
        "Simulates an adversary attempting to authenticate directly to the Domain Controller "
        "from the DMZ subnet (172.28.30.10)."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1078",
        technique_name="Valid Accounts",
        url="https://attack.mitre.org/techniques/T1078/",
    )
    preconditions: List[str] = ["Active Directory Server emulator operational"]
    lab_target: str = "dc01.corp.enterprise.local (172.28.20.10)"
    simulated_behavior: str = (
        "Authenticate as 'administrator' to DC from DMZ IP 172.28.30.10."
    )
    expected_telemetry: List[str] = [
        "ad.logon.success",
        "source.ip: 172.28.30.10",
        "destination: dc01",
    ]
    expected_detections: List[str] = ["DET-AUTH-003"]
    expected_alerts: List[str] = [
        "Suspicious Cross-Zone Logon",
    ]
    cleanup_requirements: List[str] = ["Stateless authentication event"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("dc01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute DMZ to DC logon")
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

        logs.append("Executing DC logon from DMZ source 172.28.30.10...")
        context.ad_server.authenticate_user(
            username="administrator",
            password="LabPassword123!",
            source_ip="172.28.30.10",
            workstation_name="DMZ-WEB-PORTAL",
        )
        logs.append("Authenticated administrator from DMZ.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.source and e.source.ip == "172.28.30.10"
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
