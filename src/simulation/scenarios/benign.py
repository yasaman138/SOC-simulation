"""Benign Simulation Scenarios (Negative Controls for False Positive Validation).

These scenarios simulate legitimate enterprise operations and normal administrative workflows.
Validation asserts that the detection engine does NOT generate false positive alerts.
"""

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


class BenignPortalLoginScenario(BaseScenario):
    """Simulates legitimate user authentication to the enterprise portal."""

    id: str = "SCN-BENIGN-001"
    name: str = "Legitimate Portal User Authentication"
    description: str = (
        "Simulates a legitimate corporate user logging into the enterprise web portal "
        "with valid credentials. Validates that normal authentication does not trigger brute force alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1078",
        technique_name="Valid Accounts",
        url="https://attack.mitre.org/techniques/T1078/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP POST /api/v1/auth/login with valid user 'jdoe' and correct password."
    )
    expected_telemetry: List[str] = [
        "portal.auth.login.success",
        "outcome: SUCCESS",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless login"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute benign login on portal")
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

        payload = {"username": "jdoe", "password": "LabPassword123!"}
        logs.append("Executing legitimate login for jdoe...")
        response = context.vuln_client.post("/api/v1/auth/login", json=payload)
        logs.append(f"Login response status: {response.status_code}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.user and e.user.name == "jdoe" and "login" in e.event.action
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


class BenignLinuxAdminSSHScenario(BaseScenario):
    """Simulates authorized administrator SSH session from management network."""

    id: str = "SCN-BENIGN-002"
    name: str = "Authorized Linux Administrator SSH Session"
    description: str = (
        "Simulates a authorized systems administrator connecting via SSH to srv01 from the "
        "designated management tier (172.28.20.25). Validates that legitimate SSH logins do not trigger alerts."
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
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Authenticate user 'sysadmin' from trusted source IP 172.28.20.25."
    )
    expected_telemetry: List[str] = [
        "ssh.login.success",
        "source.ip: 172.28.20.25",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless authentication"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute authorized SSH login on srv01")
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

        logs.append("Executing authorized SSH login for sysadmin from 172.28.20.25...")
        context.linux_service.simulate_ssh_login(
            username="sysadmin",
            password="LinuxAdminLab2026!",
            source_ip="172.28.20.25",
        )
        logs.append("SSH login succeeded.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.source and e.source.ip == "172.28.20.25" and "ssh" in e.event.action
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


class BenignNetworkPingToolScenario(BaseScenario):
    """Simulates standard network ping diagnostic tool usage with a clean hostname."""

    id: str = "SCN-BENIGN-003"
    name: str = "Clean Diagnostic Network Ping Usage"
    description: str = (
        "Simulates a legitimate engineer using the web portal ping tool with an approved hostname "
        "(gateway.lab.local). Validates that clean diagnostic commands do not trigger command injection alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        url="https://attack.mitre.org/techniques/T1059/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP POST /api/v1/tools/ping with payload {'target': 'gateway.lab.local'}"
    )
    expected_telemetry: List[str] = [
        "portal.tool.ping.exec",
        "custom.injection_detected = False",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless diagnostic call"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute benign ping on portal")
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

        payload = {"target": "gateway.lab.local"}
        logs.append(f"Executing clean ping tool request for {payload['target']}...")
        response = context.vuln_client.post("/api/v1/tools/ping", json=payload)
        logs.append(f"Response status: {response.status_code}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "ping" in e.event.action and e.custom.get("injection_detected") is False
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


class BenignEmployeeDirectorySearchScenario(BaseScenario):
    """Simulates standard employee directory lookup without SQL syntax."""

    id: str = "SCN-BENIGN-004"
    name: str = "Normal Employee Directory Search"
    description: str = (
        "Simulates a user searching for department 'Engineering' in the employee directory. "
        "Validates that normal queries do not trigger SQL injection alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        url="https://attack.mitre.org/techniques/T1190/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP GET /api/v1/employees/search?query=Engineering"
    )
    expected_telemetry: List[str] = [
        "portal.db.query.search",
        "custom.sqli_detected = False",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless query"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute normal employee search")
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

        logs.append("Searching for department 'Engineering'...")
        response = context.vuln_client.get("/api/v1/employees/search?query=Engineering")
        logs.append(f"Found {response.json().get('count', 0)} employees.")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "search" in e.event.action and e.custom.get("sqli_detected") is False
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


class BenignSystemAdminCommandsScenario(BaseScenario):
    """Simulates routine Linux administration commands (uptime, df -h, ls)."""

    id: str = "SCN-BENIGN-005"
    name: str = "Routine Linux Administration Commands"
    description: str = (
        "Simulates executing standard maintenance commands (uptime, df -h, ls -la /var/log). "
        "Validates that baseline administrative commands do not trigger alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        subtechnique_id="T1059.004",
        subtechnique_name="Unix Shell",
        url="https://attack.mitre.org/techniques/T1059/004/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: uptime && df -h"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line: uptime",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless read command"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute routine admin commands on srv01")
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

        cmd = "uptime"
        logs.append(f"Executing routine maintenance command: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="sysadmin",
            command_line=cmd,
            pid=28100,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "uptime" in (e.process.command_line or "")
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


class BenignADDirectoryLookupScenario(BaseScenario):
    """Simulates standard single-user Active Directory LDAP lookup."""

    id: str = "SCN-BENIGN-006"
    name: str = "Standard Single-User Active Directory Query"
    description: str = (
        "Simulates a legitimate user looking up a specific colleague ('jdoe') in Active Directory. "
        "Validates that specific account queries without wildcards do not trigger discovery alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1087",
        technique_name="Account Discovery",
        url="https://attack.mitre.org/techniques/T1087/",
    )
    preconditions: List[str] = ["Web application portal running"]
    lab_target: str = "portal.app.local:8000"
    simulated_behavior: str = (
        "Send HTTP GET /api/v1/auth/directory-lookup?user=jdoe"
    )
    expected_telemetry: List[str] = [
        "portal.ad.ldap.lookup",
        "custom.ldap_injection = False",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless directory lookup"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("portal.app.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute single user lookup on portal")
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

        logs.append("Executing clean LDAP lookup for 'jdoe'...")
        response = context.vuln_client.get("/api/v1/auth/directory-lookup?user=jdoe")
        logs.append(f"Lookup status: {response.status_code}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if "directory-lookup" in (e.http.url if e.http else "")
                and e.custom.get("ldap_injection") is False
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


class BenignApplicationLogArchiveScenario(BaseScenario):
    """Simulates standard unarchiving / extracting of application packages."""

    id: str = "SCN-BENIGN-007"
    name: str = "Standard Application Package Extraction"
    description: str = (
        "Simulates a deployer unarchiving an application release into /opt/app (tar -xzf). "
        "Validates that extraction into application directories does not trigger data staging alerts."
    )
    mitre_attack: MitreAttackInfo = MitreAttackInfo(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1560",
        technique_name="Archive Collected Data",
        url="https://attack.mitre.org/techniques/T1560/",
    )
    preconditions: List[str] = ["Linux Server Service operational"]
    lab_target: str = "srv01.corp.enterprise.local (172.28.20.15)"
    simulated_behavior: str = (
        "Execute command: tar -xzf /opt/deployments/app.tar.gz -C /opt/app"
    )
    expected_telemetry: List[str] = [
        "linux.auditd EXECVE",
        "command_line contains tar -xzf",
    ]
    expected_detections: List[str] = []
    expected_alerts: List[str] = []
    cleanup_requirements: List[str] = ["Stateless extraction"]
    is_benign: bool = True

    def execute(self, context: SimulationContext) -> ScenarioResult:
        LabSafetyGuardrail.assert_safe_target("srv01.corp.enterprise.local")
        start = time.time()
        start_time = datetime.now(timezone.utc)
        logs = []
        events_generated = []

        if context.dry_run:
            logs.append("[DRY RUN] Would execute benign tar extraction on srv01")
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

        cmd = "tar -xzf /opt/deployments/app.tar.gz -C /opt/app"
        logs.append(f"Executing standard application deployment extraction: {cmd}")
        res = context.linux_service.simulate_command_execution(
            user="deployer",
            command_line=cmd,
            pid=28500,
        )
        logs.append(f"Audit log generated: {res}")

        if context.event_store:
            recent = context.event_store.query_events()
            events_generated = [
                e.to_dict()
                for e in recent
                if e.process and "tar -xzf" in (e.process.command_line or "")
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
