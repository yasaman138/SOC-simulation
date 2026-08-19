"""Privilege Escalation Attack Simulation Scenarios."""

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


class SudoersModificationScenario(BaseScenario):
    """Simulates modifying /etc/sudoers to grant unrestricted passwordless root execution."""

    id: str = "SCN-PRIVESC-001"
    name: str = "Sudoers Configuration Tampering"
    description: str = (
        "Simulates an adversary modifying the /etc/sudoers file to grant a compromised account "
        "NOPASSWD: ALL privileges for unrestricted root command execution."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        subtechnique_id="T1548.003",
        subtechnique_name="Sudo and Sudo Caching",
        url="https://attack.mitre.org/techniques/T1548/003/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: echo 'sysadmin ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains /etc/sudoers or nopasswd: all",
    ]
    expected_detections: List[str] = ["DET-PRIVESC-001"]
    expected_alerts: List[str] = [
        "Sudoers Security Configuration Modification Detected",
    ]
    cleanup_requirements: List[str] = [
        "Revert /etc/sudoers file to original baseline permissions",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute sudoers modification on srv01")
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

        cmd = "echo 'sysadmin ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"
        logs.append(f"Simulating sudoers modification: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=22100,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "/etc/sudoers" in (e.process.command_line or "")
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


class SUIDBinaryAbuseScenario(BaseScenario):
    """Simulates setting SUID permission bit on a binary for local privilege escalation."""

    id: str = "SCN-PRIVESC-002"
    name: str = "SUID / SGID Bit Modification"
    description: str = (
        "Simulates an adversary setting the SUID bit (+s / 4755) on a binary to allow unprivileged users "
        "to execute the binary with root privileges."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.PRIVILEGE_ESCALATION,
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        subtechnique_id="T1548.001",
        subtechnique_name="Setuid and Setgid",
        url="https://attack.mitre.org/techniques/T1548/001/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: chmod 4755 /tmp/elevated_shell"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains chmod 4755 or chmod +s",
    ]
    expected_detections: List[str] = ["DET-PRIVESC-002"]
    expected_alerts: List[str] = [
        "SUID Permission Elevation Configured on Binary",
    ]
    cleanup_requirements: List[str] = [
        "Remove SUID permissions from /tmp/elevated_shell or delete temporary file",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute chmod SUID on srv01")
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

        cmd = "chmod 4755 /tmp/elevated_shell"
        logs.append(f"Simulating SUID bit modification: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="root",
            command_line=cmd,
            pid=22340,
            is_sudo=True,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "chmod 4755" in (e.process.command_line or "")
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
