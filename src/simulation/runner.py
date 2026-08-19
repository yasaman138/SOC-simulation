"""Attack Simulation Runner & Detection Validation Engine."""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from src.core.logging import get_logger
from src.detection.models import Alert
from src.siem.models import ECSEvent, EventQuery
from src.simulation.models import (
    BaseScenario,
    CoverageItem,
    CoverageReport,
    ScenarioExecutionStatus,
    ScenarioResult,
    SimulationContext,
    ValidationResult,
)
from src.simulation.registry import ScenarioRegistry

logger = get_logger("simulation.runner")


class SimulationRunner:
    """Orchestrator for controlled attack simulation execution, detection validation, and coverage reporting."""

    def __init__(self, registry: Optional[ScenarioRegistry] = None):
        self.registry = registry or ScenarioRegistry()

    def run_scenario(
        self,
        scenario: BaseScenario,
        context: SimulationContext,
    ) -> Tuple[ScenarioResult, ValidationResult]:
        """Execute a single scenario, evaluate generated telemetry & alerts, and run cleanup."""
        logger.info(f"Running scenario [{scenario.id}] {scenario.name}...")

        # Record baseline counts prior to execution
        baseline_event_count = (
            context.event_store.count() if context.event_store else 0
        )
        baseline_alert_count = (
            context.alert_store.count() if context.alert_store else 0
        )

        # 1. Execute scenario
        try:
            result = scenario.execute(context)
        except Exception as e:
            logger.error(f"Error executing scenario {scenario.id}: {e}")
            result = ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                status=ScenarioExecutionStatus.FAILED,
                error_message=str(e),
            )

        # 2. Extract generated events and alerts from delta
        new_events: List[ECSEvent] = []
        if context.event_store and context.event_store.count() > baseline_event_count:
            all_events = context.event_store.query_events(
                EventQuery(limit=context.event_store.count())
            )
            # Take newest events added during this scenario (newest first at index 0)
            delta_count = context.event_store.count() - baseline_event_count
            new_events = all_events[:delta_count]

        new_alerts: List[Alert] = []
        if context.alert_store and context.alert_store.count() > baseline_alert_count:
            all_alerts = context.alert_store.query_alerts()
            delta_alert_count = context.alert_store.count() - baseline_alert_count
            new_alerts = all_alerts[:delta_alert_count]

        # 3. Validate detection outcome
        validation = scenario.validate(events=new_events, alerts=new_alerts)

        # 4. Cleanup
        try:
            cleanup_ok = scenario.cleanup(context)
            result.cleanup_success = cleanup_ok
        except Exception as e:
            logger.warning(f"Cleanup failed for scenario {scenario.id}: {e}")
            result.cleanup_success = False

        if validation.passed:
            logger.info(
                f"Scenario [{scenario.id}] VALIDATION PASSED (Events: {len(new_events)}, Alerts: {len(new_alerts)})"
            )
        else:
            logger.warning(
                f"Scenario [{scenario.id}] VALIDATION FAILED: {validation.detection_gap}"
            )

        return result, validation

    def run_all(
        self,
        context: SimulationContext,
        scenarios: Optional[List[BaseScenario]] = None,
    ) -> List[Tuple[BaseScenario, ScenarioResult, ValidationResult]]:
        """Execute all or specified scenarios in sequence."""
        target_scenarios = (
            scenarios if scenarios is not None else self.registry.list_scenarios()
        )
        outcomes: List[Tuple[BaseScenario, ScenarioResult, ValidationResult]] = []

        for scenario in target_scenarios:
            res, val = self.run_scenario(scenario, context)
            outcomes.append((scenario, res, val))

        return outcomes

    def generate_coverage_report(
        self,
        results: List[Tuple[BaseScenario, ScenarioResult, ValidationResult]],
    ) -> CoverageReport:
        """Produce a comprehensive MITRE ATT&CK detection coverage report."""
        items: List[CoverageItem] = []
        passed_count = 0
        failed_count = 0
        attack_count = 0
        benign_count = 0
        tactics_set = set()

        for scenario, res, val in results:
            if scenario.is_benign:
                benign_count += 1
                det_res = "PASS" if val.passed else "FALSE_POSITIVE"
            else:
                attack_count += 1
                det_res = "PASS" if val.passed else "GAP"
                tactics_set.add(scenario.mitre_attack.tactic.value)

            if val.passed:
                passed_count += 1
            else:
                failed_count += 1

            telemetry_summary = (
                f"{len(res.generated_events)} events generated ({scenario.expected_telemetry[0] if scenario.expected_telemetry else 'telemetry'})"
            )

            item = CoverageItem(
                technique_id=scenario.mitre_attack.technique_id,
                technique_name=scenario.mitre_attack.technique_name,
                tactic=scenario.mitre_attack.tactic.value,
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                is_benign=scenario.is_benign,
                telemetry_generated=telemetry_summary,
                detection_rules=scenario.expected_detections if not scenario.is_benign else val.unexpected_detection_ids,
                detection_result=det_res,
                passed=val.passed,
                detection_gaps=val.detection_gap,
            )
            items.append(item)

        total = len(results)
        summary = {
            "total_executed": total,
            "passed": passed_count,
            "failed": failed_count,
            "pass_rate_percent": round((passed_count / total * 100) if total > 0 else 0.0, 1),
            "attack_scenarios_count": attack_count,
            "benign_scenarios_count": benign_count,
            "tactics_count": len(tactics_set),
        }

        return CoverageReport(
            timestamp=datetime.now(timezone.utc),
            total_scenarios=total,
            passed_scenarios=passed_count,
            failed_scenarios=failed_count,
            attack_scenarios=attack_count,
            benign_scenarios=benign_count,
            tactics_covered=sorted(list(tactics_set)),
            items=items,
            summary=summary,
        )

    @staticmethod
    def format_coverage_table(report: CoverageReport) -> str:
        """Format the coverage matrix as a clean ASCII text table."""
        lines = []
        lines.append("=" * 115)
        lines.append("Enterprise Attack Simulation & Detection Validation Coverage Report")
        lines.append("=" * 115)
        lines.append(
            f"{'Tactic':<22} {'Technique':<12} {'Scenario ID':<16} {'Result':<10} {'Rules':<18} {'Scenario Name'}"
        )
        lines.append("-" * 115)

        for item in report.items:
            tactic_display = item.tactic if not item.is_benign else "[Benign Control]"
            res_display = "PASS" if item.passed else ("FAIL" if not item.is_benign else "FALSE POS")
            rules_str = ",".join(item.detection_rules) if item.detection_rules else "-"
            lines.append(
                f"{tactic_display:<22} {item.technique_id:<12} {item.scenario_id:<16} {res_display:<10} {rules_str:<18} {item.scenario_name[:32]}"
            )

        lines.append("=" * 115)
        lines.append(
            f"Summary: Total: {report.total_scenarios} | Passed: {report.passed_scenarios} | "
            f"Failed: {report.failed_scenarios} | Pass Rate: {report.summary.get('pass_rate_percent', 0)}% | "
            f"Tactics Covered: {len(report.tactics_covered)}/10"
        )
        lines.append("=" * 115)
        return "\n".join(lines)
