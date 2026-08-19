"""Storage and Query Engine for Security Alerts."""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.detection.models import Alert, AlertQuery, AlertStatus
from src.siem.models import EventSeverity


class AlertStore:
    """Thread-safe in-memory and searchable Alert repository."""

    def __init__(self, max_capacity: int = 5000):
        self.max_capacity = max_capacity
        self._alerts: List[Alert] = []
        self._lock = threading.Lock()

    def add_alert(self, alert: Alert) -> str:
        """Add a generated alert to the store."""
        with self._lock:
            if len(self._alerts) >= self.max_capacity:
                self._alerts.pop(0)
            self._alerts.append(alert)
            return alert.id

    def add_batch(self, alerts: List[Alert]) -> List[str]:
        """Add multiple alerts in batch."""
        ids = []
        with self._lock:
            for alt in alerts:
                if len(self._alerts) >= self.max_capacity:
                    self._alerts.pop(0)
                self._alerts.append(alt)
                ids.append(alt.id)
        return ids

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve a specific alert by unique ID."""
        with self._lock:
            for alt in self._alerts:
                if alt.id == alert_id:
                    return alt.model_copy()
        return None

    def update_status(
        self, alert_id: str, status: AlertStatus, note: Optional[str] = None
    ) -> bool:
        """Update triage/investigation status of an alert."""
        with self._lock:
            for alt in self._alerts:
                if alt.id == alert_id:
                    alt.status = status
                    if note:
                        alt.context["status_note"] = note
                        alt.context["status_updated_at"] = (
                            datetime.now(timezone.utc).isoformat()
                        )
                    return True
        return False

    def query_alerts(self, query: Optional[AlertQuery] = None) -> List[Alert]:
        """Filter alerts matching search and filter criteria."""
        q = query or AlertQuery(limit=max(self.count(), 100))
        with self._lock:
            results = self._alerts[:]

        if q.severity:
            results = [a for a in results if a.severity == q.severity]
        if q.rule_id:
            results = [
                a
                for a in results
                if q.rule_id.lower() in a.rule_id.lower()
            ]
        if q.status:
            results = [a for a in results if a.status == q.status]
        if q.host_name:
            results = [
                a
                for a in results
                if a.affected_entities.host
                and q.host_name.lower()
                in a.affected_entities.host.lower()
            ]
        if q.user_name:
            results = [
                a
                for a in results
                if a.affected_entities.user
                and q.user_name.lower()
                in a.affected_entities.user.lower()
            ]
        if q.source_ip:
            results = [
                a
                for a in results
                if a.affected_entities.ip
                and q.source_ip == a.affected_entities.ip
            ]
        if q.search:
            s = q.search.lower()
            results = [
                a
                for a in results
                if (s in a.title.lower())
                or (s in a.description.lower())
                or (s in a.rule_name.lower())
                or (
                    a.affected_entities.user
                    and s in a.affected_entities.user.lower()
                )
                or (
                    a.affected_entities.host
                    and s in a.affected_entities.host.lower()
                )
            ]

        # Reverse sort by timestamp (newest alerts first)
        results.sort(key=lambda x: x.timestamp, reverse=True)

        start = q.offset
        end = start + q.limit
        return results[start:end]

    def count(self) -> int:
        with self._lock:
            return len(self._alerts)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate alert metrics by severity, MITRE tactic, and status."""
        with self._lock:
            total = len(self._alerts)
            by_severity: Dict[str, int] = {}
            by_tactic: Dict[str, int] = {}
            by_rule: Dict[str, int] = {}
            by_status: Dict[str, int] = {}

            for alt in self._alerts:
                sev = alt.severity.value
                stat = alt.status.value
                rule = alt.rule_id

                by_severity[sev] = by_severity.get(sev, 0) + 1
                by_status[stat] = by_status.get(stat, 0) + 1
                by_rule[rule] = by_rule.get(rule, 0) + 1

                if alt.mitre_attack:
                    tactic = alt.mitre_attack.tactic.value
                    by_tactic[tactic] = by_tactic.get(tactic, 0) + 1

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_tactic": by_tactic,
            "by_rule": by_rule,
            "by_status": by_status,
        }

    def clear(self) -> None:
        """Clear all stored alerts."""
        with self._lock:
            self._alerts.clear()
