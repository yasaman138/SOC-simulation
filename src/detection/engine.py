"""Detection Engine Core: Registry, Stateful Correlation, and Rule Execution."""

import threading
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.detection.models import Alert, DetectionRule
from src.detection.rules import get_default_rules
from src.detection.storage import AlertStore
from src.siem.models import ECSEvent, EventQuery
from src.siem.storage import EventStore

logger = get_logger("detection.engine")


class DetectionEngine:
    """Enterprise Detection Engine executing detection rules against real-time and stored telemetry."""

    def __init__(
        self,
        rules: Optional[List[DetectionRule]] = None,
        alert_store: Optional[AlertStore] = None,
    ):
        self.alert_store = alert_store or AlertStore()
        self._rules: Dict[str, DetectionRule] = {}
        self._state: Dict[str, Any] = {}
        self._lock = threading.Lock()

        # Load initial rules
        initial_rules = rules if rules is not None else get_default_rules()
        for rule in initial_rules:
            self.register_rule(rule)

    def register_rule(self, rule: DetectionRule) -> None:
        """Register or update a detection rule."""
        with self._lock:
            self._rules[rule.id] = rule
            logger.debug(f"Registered detection rule: [{rule.id}] {rule.name}")

    def unregister_rule(self, rule_id: str) -> bool:
        """Remove a detection rule by ID."""
        with self._lock:
            if rule_id in self._rules:
                del self._rules[rule_id]
                return True
        return False

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Retrieve detection rule by unique ID."""
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self) -> List[DetectionRule]:
        """List all currently registered detection rules."""
        with self._lock:
            return list(self._rules.values())

    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a specific detection rule."""
        with self._lock:
            if rule_id in self._rules:
                self._rules[rule_id].enabled = enabled
                return True
        return False

    def evaluate_event(self, event: ECSEvent) -> List[Alert]:
        """Evaluate a single normalized telemetry event against all enabled detection rules."""
        generated_alerts: List[Alert] = []

        with self._lock:
            active_rules = [r for r in self._rules.values() if r.enabled]
            state_snapshot = self._state

        for rule in active_rules:
            try:
                alert = rule.evaluate(event, state=state_snapshot)
                if alert:
                    generated_alerts.append(alert)
                    self.alert_store.add_alert(alert)
                    logger.warning(
                        f"ALERT TRIGGERED: [{alert.rule_id}] {alert.title} (Severity: {alert.severity.value})"
                    )
            except Exception as e:
                logger.error(
                    f"Error evaluating detection rule {rule.id} against event {event.event.id}: {e}"
                )

        return generated_alerts

    def evaluate_batch(self, events: List[ECSEvent]) -> List[Alert]:
        """Evaluate a sequence of events against detection rules."""
        alerts: List[Alert] = []
        for ev in events:
            alerts.extend(self.evaluate_event(ev))
        return alerts

    def evaluate_store(self, store: EventStore) -> List[Alert]:
        """Run all detection rules across all events currently in an EventStore."""
        events = store.query_events(EventQuery(limit=store.count()))
        # Sort oldest to newest for temporal correlation
        events.sort(key=lambda x: x.timestamp)
        return self.evaluate_batch(events)

    def clear_state(self) -> None:
        """Reset internal correlation sliding window state."""
        with self._lock:
            self._state.clear()

    def get_metrics(self) -> Dict[str, Any]:
        """Retrieve metrics summarizing loaded detection rules."""
        with self._lock:
            total_rules = len(self._rules)
            enabled_rules = sum(1 for r in self._rules.values() if r.enabled)
            by_severity: Dict[str, int] = {}
            by_tactic: Dict[str, int] = {}
            by_datasource: Dict[str, int] = {}

            for r in self._rules.values():
                sev = r.severity.value
                by_severity[sev] = by_severity.get(sev, 0) + 1

                tactic = r.mitre_attack.tactic.value
                by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

                for ds in r.data_sources:
                    by_datasource[ds] = by_datasource.get(ds, 0) + 1

        return {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "by_severity": by_severity,
            "by_tactic": by_tactic,
            "by_datasource": by_datasource,
            "total_alerts": self.alert_store.count(),
        }
