"""Initial Access Attack Simulation Scenarios."""

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


class SQLInjectionInitialAccessScenario(BaseScenario):
    """Simulates exploiting a public-facing web application via SQL injection."""

    id: str = "SCN-INIT-001"
    name: str = "Web Application SQL Injection Exploitation"
    description: str = (
        "Simulates an external adversary discovering and exploiting a SQL injection vulnerability "
        "on the public enterprise web portal search endpoint to bypass authorization and extract database records."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        url="https://attack.mitre.org/techniques/T1190/",
    )
    preconditions: List[str] = [
        "Web application portal running and accessible",
        "SIEM telemetry collector operational",
    ]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP GET request to /api/v1/employees/search containing SQL union payload: "
        "' UNION SELECT 1,2,3,4,5,6,7,8 --"
    )
    expected_telemetry: List[str] = [
        "portal.db.query.search",
        "HTTP GET /api/v1/employees/search",
        "custom.sqli_detected = True",
    ]
    expected_detections: List[str] = ["DET-PRIVESC-003"]
    expected_alerts: List[str] = [
        "SQL Injection Exploit Pattern Detected",
    ]
    cleanup_requirements: List[str] = [
        "Stateless web request; no database state cleanup required",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute SQL injection against portal.app.local")
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

        payload = "' UNION SELECT 1,2,3,4,5,6,7,8 --"
        logs.append(f"Dispatching SQL injection payload to {self.lab_target}...")
        response = context.vuln_client.get(
            f"/api/v1/employees/search?query={payload}"
        )
        logs.append(f"Response status: {response.status_code}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "search" in e.event.action or "portal" in e.event.action
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


class UnauthorizedRootLogonScenario(BaseScenario):
    """Simulates unauthorized direct root SSH authentication attempt against enterprise server."""

    id: str = "SCN-INIT-002"
    name: str = "Unauthorized Direct Root SSH Logon Attempt"
    description: str = (
        "Simulates an adversary attempting to gain initial administrative access by connecting "
        "directly as root via SSH against policy-restricted Linux servers."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1078",
        technique_name="Valid Accounts",
        subtechnique_id="T1078.003",
        subtechnique_name="Local Accounts",
        url="https://attack.mitre.org/techniques/T1078/003/",
    )
    preconditions: List[str] = [
        "Linux Server Service operational",
        "SSH service configured with PermitRootLogin=no",
    ]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15:22)"
    simulated_behavior: str = (
        "Simulate SSH authentication as user 'root' from simulation DMZ source IP (172.28.10.100)."
    )
    expected_telemetry: List[str] = [
        "ssh.login.failed",
        "dataset: linux.sshd",
        "Failed password for root (PermitRootLogin=no)",
    ]
    expected_detections: List[str] = ["DET-AUTH-002"]
    expected_alerts: List[str] = [
        "Unauthorized Account Access Attempt: root",
    ]
    cleanup_requirements: List[str] = [
        "Reset failed login counters on target host",
    ]
    is_benign: bool = False

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would simulate root SSH logon against srv01")
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

        logs.append("Executing SSH login attempt for user 'root'...")
        context.linux_service.simulate_ssh_login(
            username="root",
            password="AttackerPassword123!",
            source_ip="172.28.10.100",
            source_port=54321,
        )
        logs.append("Emitted SSHD telemetry event.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.user and e.user.name == "root"
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
