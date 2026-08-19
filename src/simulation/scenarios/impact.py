"""Impact Attack Simulation Scenarios."""

import time
from datetime import datetime, timezone
from typing import List
from src.detection.models import MitreAttackInfo, MitreTactic
from src.simulation.models import (
    BaseScenario,
    ScenarioExecutionStatus,
    ScenarioResult,
    SimulationContext,
)
from src.simulation.safety import LabSafetyGuardrail


class ServiceTerminationScenario(BaseScenario):
    """Simulates stopping critical security auditing or logging services to impair defenses."""

    id: str = "SCN-IMP-001"
    name: str = "Critical Security Service Termination"
    description: str = (
        "Simulates an adversary stopping the Linux audit daemon (auditd) "
        "to terminate telemetry collection and blind security monitoring."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.IMPACT,
        technique_id="T1489",
        technique_name="Service Stop",
        url="https://attack.mitre.org/techniques/T1489/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: systemctl stop auditd"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains systemctl stop auditd",
    ]
    expected_detections: List[str] = ["DET-IMP-001"]
    expected_alerts: List[str] = [
        "Critical Service Stop Command Executed",
    ]
    cleanup_requirements: List[str] = [
        "Restart simulated service (systemctl start auditd)",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute service termination on srv01")
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

        cmd = "systemctl stop auditd"
        logs.append(f"Simulating service stop: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="root",
            command_line=cmd,
            pid=27100,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "systemctl stop auditd" in (e.process.command_line or "")
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


class DataDestructionRansomwareScenario(BaseScenario):
    """Simulates destructive log wiping and data destruction."""

    id: str = "SCN-IMP-002"
    name: str = "Destructive Log File Shredding & Anti-Forensics"
    description: str = (
        "Simulates an adversary executing a destructive file shredder command (shred -u -z) "
        "targeting security audit logs to destroy forensic evidence."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.IMPACT,
        technique_id="T1485",
        technique_name="Data Destruction",
        url="https://attack.mitre.org/techniques/T1485/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: shred -u -z /var/log/audit/audit.log"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains shred -u",
    ]
    expected_detections: List[str] = ["DET-IMP-002"]
    expected_alerts: List[str] = [
        "Destructive Impact or Ransomware Activity Detected",
    ]
    cleanup_requirements: List[str] = [
        "Restore audit log baseline file",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute log shredding on srv01")
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

        cmd = "shred -u -z /var/log/audit/audit.log"
        logs.append(f"Simulating data destruction: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="root",
            command_line=cmd,
            pid=27350,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "shred -u" in (e.process.command_line or "")
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
