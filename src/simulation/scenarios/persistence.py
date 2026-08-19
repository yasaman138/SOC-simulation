"""Persistence Attack Simulation Scenarios."""

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
    RegistryInfo,
    UserInfo,
)
from src.simulation.models import (
    BaseScenario,
    ScenarioExecutionStatus,
    ScenarioResult,
    SimulationContext,
)
from src.simulation.safety import LabSafetyGuardrail


class LinuxCronPersistenceScenario(BaseScenario):
    """Simulates establishing persistence on a Linux host via a cron job."""

    id: str = "SCN-PERSIST-001"
    name: str = "Linux Cron Job Persistence Installation"
    description: str = (
        "Simulates an adversary creating a scheduled cron job in /etc/cron.d/ "
        "to guarantee periodic re-execution of a malicious backdoor script."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1053",
        technique_name="Scheduled Task/Job",
        subtechnique_id="T1053.003",
        subtechnique_name="Cron",
        url="https://attack.mitre.org/techniques/T1053/003/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command modifying /etc/cron.d/updater to execute /tmp/backdoor.sh every 5 minutes."
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains /etc/cron",
    ]
    expected_detections: List[str] = ["DET-PERSIST-001"]
    expected_alerts: List[str] = [
        "Linux Scheduled Persistence Mechanism Configured",
    ]
    cleanup_requirements: List[str] = [
        "Remove temporary cron entries from /etc/cron.d/updater",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute cron persistence on srv01")
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

        cmd = "echo '*/5 * * * * root /tmp/backdoor.sh' >> /etc/cron.d/updater"
        logs.append(f"Simulating cron job addition: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=20410,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "/etc/cron" in (e.process.command_line or "")
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


class RegistryRunKeyPersistenceScenario(BaseScenario):
    """Simulates establishing persistence via Windows Registry CurrentVersion\\Run autostart key."""

    id: str = "SCN-PERSIST-002"
    name: str = "Windows Registry Run Key Auto-start Persistence"
    description: str = (
        "Simulates an adversary adding an autostart payload under the Windows Run registry key "
        "(HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) for persistence across reboots."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1547",
        technique_name="Boot or Logon Autostart Execution",
        subtechnique_id="T1547.001",
        subtechnique_name="Registry Run Keys / Startup Folder",
        url="https://attack.mitre.org/techniques/T1547/001/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "wkstn01.corp.enterprise.local (172.28.20.50)"
    simulated_behavior: str = (
        "Emit Registry Event adding 'SecurityUpdate' under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    expected_telemetry: List[str] = [
        "dataset: windows.sysmon / registry",
        "key contains CurrentVersion\\Run",
    ]
    expected_detections: List[str] = ["DET-PERSIST-002"]
    expected_alerts: List[str] = [
        "Windows Autostart Registry Run Key Persistence Configured",
    ]
    cleanup_requirements: List[str] = [
        "Delete test registry value 'SecurityUpdate'",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("wkstn01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would emit registry persistence event")
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

        cmd = "reg.exe add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /t REG_SZ /d C:\\Temp\\payload.exe /f"
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.REGISTRY,
                action="windows.registry.set_value",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.HIGH,
                dataset="windows.sysmon",
            ),
            host=HostInfo(name="wkstn01.corp.enterprise.local", ip="172.28.20.50"),
            user=UserInfo(name="attacker", domain="CORP"),
            registry=RegistryInfo(
                key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                value_name="SecurityUpdate",
                value_data="C:\\Temp\\payload.exe",
                action="set_value",
            ),
            process=ProcessInfo(
                name="reg.exe",
                pid=7812,
                command_line=cmd,
            ),
            message=f"Registry Run key modified: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted Windows Registry Run key persistence event to SIEM.")

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


class BackdoorAccountCreationScenario(BaseScenario):
    """Simulates creating an unauthorized local backdoor administrative user account."""

    id: str = "SCN-PERSIST-003"
    name: str = "Local Backdoor User Account Creation"
    description: str = (
        "Simulates an adversary creating a local user account and adding it to administrative groups (sudo/wheel) "
        "to establish secondary redundant access."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PERSISTENCE,
        technique_id="T1136",
        technique_name="Create Account",
        subtechnique_id="T1136.001",
        subtechnique_name="Local Account",
        url="https://attack.mitre.org/techniques/T1136/001/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: useradd -m -s /bin/bash -G sudo backdoor_admin"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains useradd",
    ]
    expected_detections: List[str] = ["DET-PERSIST-003"]
    expected_alerts: List[str] = [
        "Local User Account Creation Detected",
    ]
    cleanup_requirements: List[str] = [
        "Delete local backdoor user 'backdoor_admin' (userdel -r backdoor_admin)",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute useradd on srv01")
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

        cmd = "useradd -m -s /bin/bash -G sudo backdoor_admin"
        logs.append(f"Simulating backdoor user account creation: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="root",
            command_line=cmd,
            pid=21500,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "useradd" in (e.process.command_line or "")
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
