"""Discovery Attack Simulation Scenarios."""

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


class ActiveDirectoryDiscoveryScenario(BaseScenario):
    """Simulates Active Directory domain and account enumeration via LDAP wildcard injection."""

    id: str = "SCN-DISC-001"
    name: str = "Active Directory Domain & Account Enumeration"
    description: str = (
        "Simulates an adversary performing LDAP directory queries using wildcards (sAMAccountName=*) "
        "to discover all domain users and identify Domain Admins."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1087",
        technique_name="Account Discovery",
        subtechnique_id="T1087.002",
        subtechnique_name="Domain Account",
        url="https://attack.mitre.org/techniques/T1087/002/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP GET /api/v1/auth/directory-lookup?user=* to enumerate AD domain accounts."
    )
    expected_telemetry: List[str] = [
        "portal.ad.ldap.lookup",
        "category: directory_service",
        "custom.ldap_injection = True",
    ]
    expected_detections: List[str] = ["DET-DISC-001"]
    expected_alerts: List[str] = [
        "Active Directory Domain & Account Enumeration Detected",
    ]
    cleanup_requirements: List[str] = ["Stateless directory query"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute AD directory lookup on portal")
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

        logs.append("Executing LDAP directory enumeration query with user=*...")
        response = context.vuln_client.get("/api/v1/auth/directory-lookup?user=*")
        logs.append(f"Received {response.json().get('results_count', 0)} AD user records.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "directory-lookup" in (e.http.url if e.http else "")
                or "ldap" in e.event.action
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


class NetworkPortScanDiscoveryScenario(BaseScenario):
    """Simulates internal network port and service discovery via SSRF probing."""

    id: str = "SCN-DISC-002"
    name: str = "Internal Network & Port Scanning Discovery"
    description: str = (
        "Simulates an adversary probing internal corporate infrastructure (172.28.20.10:389) "
        "via a vulnerable web integration webhook dispatcher (SSRF)."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        url="https://attack.mitre.org/techniques/T1046/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP POST /api/v1/integrations/webhook-test with target 'http://172.28.20.10:389'"
    )
    expected_telemetry: List[str] = [
        "portal.integration.webhook.dispatch",
        "custom.ssrf_detected = True",
    ]
    expected_detections: List[str] = ["DET-DISC-002"]
    expected_alerts: List[str] = [
        "Network Service Discovery Detected (SSRF internal network probing)",
    ]
    cleanup_requirements: List[str] = ["Stateless webhook probe"]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("172.28.20.10")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute SSRF network scan on portal")
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

        payload = {"url": "http://172.28.20.10:389"}
        logs.append(f"Executing SSRF probe to internal target: {payload['url']}...")
        response = context.vuln_client.post(
            "/api/v1/integrations/webhook-test", json=payload
        )
        logs.append(f"Response: {response.json()}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "webhook" in e.event.action or e.custom.get("ssrf_detected") is True
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


class SystemInfoDiscoveryScenario(BaseScenario):
    """Simulates system and network configuration discovery commands."""

    id: str = "SCN-DISC-003"
    name: str = "System & Security Configuration Discovery"
    description: str = (
        "Simulates an adversary running situational awareness commands (uname -a, ss -tulpn, ipconfig /all) "
        "to discover operating system versions and network listening services."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1082",
        technique_name="System Information Discovery",
        url="https://attack.mitre.org/techniques/T1082/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: uname -a && cat /etc/os-release && ss -tulpn"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains uname -a or ss -tulpn",
    ]
    expected_detections: List[str] = ["DET-DISC-003"]
    expected_alerts: List[str] = [
        "System Information Discovery Command Executed",
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
            logs.append("[DRY RUN] Would execute systeminfo discovery on srv01")
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

        cmd = "uname -a"
        logs.append(f"Executing system information discovery: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=24100,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "uname -a" in (e.process.command_line or "")
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
