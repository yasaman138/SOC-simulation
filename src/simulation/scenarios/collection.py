"""Collection Attack Simulation Scenarios."""

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


class DataStagingAndArchiveScenario(BaseScenario):
    """Simulates compressing sensitive directories into a staging archive."""

    id: str = "SCN-COLL-001"
    name: str = "Sensitive Data Staging & Archive Compression"
    description: str = (
        "Simulates an adversary packaging and compressing confidential business directories "
        "into /tmp/confidential_data.tar.gz prior to exfiltration."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1560",
        technique_name="Archive Collected Data",
        subtechnique_id="T1560.001",
        subtechnique_name="Archive via Utility",
        url="https://attack.mitre.org/techniques/T1560/001/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: tar -czf /tmp/confidential_data.tar.gz /var/data/finance"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains tar -czf /tmp/",
    ]
    expected_detections: List[str] = ["DET-COLL-001"]
    expected_alerts: List[str] = [
        "Sensitive Data Staged in Compressed Archive",
    ]
    cleanup_requirements: List[str] = [
        "Delete staged archive /tmp/confidential_data.tar.gz",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute tar archive staging on srv01")
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

        cmd = "tar -czf /tmp/confidential_data.tar.gz /var/data/finance"
        logs.append(f"Simulating archive staging: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=26100,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "tar -czf /tmp/" in (e.process.command_line or "")
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


class BOLADocumentHarvestingScenario(BaseScenario):
    """Simulates harvesting confidential documents via BOLA authorization bypass."""

    id: str = "SCN-COLL-002"
    name: str = "Unauthorized BOLA Confidential Document Harvesting"
    description: str = (
        "Simulates an adversary bypassing Broken Object-Level Authorization (BOLA) "
        "to harvest sensitive corporate strategic documents owned by executive users."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1005",
        technique_name="Data from Local System",
        url="https://attack.mitre.org/techniques/T1005/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP GET /api/v1/documents/DOC-9001?user_id=999 to harvest unowned document"
    )
    expected_telemetry: List[str] = [
        "portal.doc.access",
        "custom.unauthorized_bola = True",
    ]
    expected_detections: List[str] = ["DET-COLL-002"]
    expected_alerts: List[str] = [
        "Sensitive Data Harvesting Detected (Unauthorized BOLA document harvesting)",
    ]
    cleanup_requirements: List[str] = ["Stateless document request"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute BOLA document harvesting on portal")
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

        logs.append("Executing BOLA document retrieval request for DOC-9001 with user_id=999...")
        response = context.vuln_client.get(
            "/api/v1/documents/DOC-9001?user_id=999"
        )
        logs.append(f"Retrieved document: {response.json().get('title', 'Not found')}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "portal.doc.access" in e.event.action
                and e.custom.get("unauthorized_bola") is True
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
