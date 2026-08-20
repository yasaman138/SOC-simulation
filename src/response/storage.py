"""Incident Storage & Audit Log Repository."""

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.response.models import (
    AuditLogEntry,
    Incident,
    IncidentQuery,
    IncidentSeverity,
    IncidentStatus,
    ResponseActionType,
)

logger = get_logger("response.storage")


class IncidentStore:
    """Thread-safe in-memory store for Incident Lifecycle Management."""

    def __init__(self, max_capacity: int = 10000):
        self._max_capacity = max_capacity
        self._incidents: Dict[str, Incident] = {}
        self._lock = threading.Lock()

    def add_incident(self, incident: Incident) -> None:
        """Store or update a security incident."""
        with self._lock:
            if (
                len(self._incidents) >= self._max_capacity
                and incident.incident_id not in self._incidents
            ):
                # Evict oldest incident
                oldest_id = min(
                    self._incidents.keys(),
                    key=lambda k: self._incidents[k].timestamp,
                )
                del self._incidents[oldest_id]

            self._incidents[incident.incident_id] = incident
            logger.info(
                f"Incident stored: [{incident.incident_id}] '{incident.title}' (Status: {incident.status.value}, Severity: {incident.severity.value})"
            )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by unique ID."""
        with self._lock:
            return self._incidents.get(incident_id)

    def update_incident(self, incident: Incident) -> bool:
        """Update an existing incident in place."""
        with self._lock:
            if incident.incident_id in self._incidents:
                self._incidents[incident.incident_id] = incident
                return True
            return False

    def delete_incident(self, incident_id: str) -> bool:
        """Delete an incident by ID."""
        with self._lock:
            if incident_id in self._incidents:
                del self._incidents[incident_id]
                return True
            return False

    def list_incidents(self) -> List[Incident]:
        """List all stored incidents sorted newest first."""
        with self._lock:
            return sorted(
                list(self._incidents.values()),
                key=lambda x: x.timestamp,
                reverse=True,
            )

    def query_incidents(
        self, query: Optional[IncidentQuery] = None
    ) -> List[Incident]:
        """Query incidents matching filter criteria."""
        q = query or IncidentQuery()
        with self._lock:
            results = list(self._incidents.values())

        if q.status:
            results = [i for i in results if i.status == q.status]

        if q.severity:
            results = [i for i in results if i.severity == q.severity]

        if q.disposition:
            results = [i for i in results if i.final_disposition == q.disposition]

        if q.affected_asset:
            target = q.affected_asset.lower()
            results = [
                i
                for i in results
                if any(target in a.lower() for a in i.affected_assets)
            ]

        if q.affected_user:
            target = q.affected_user.lower()
            results = [
                i
                for i in results
                if any(target in u.lower() for u in i.affected_users)
            ]

        if q.search:
            search_str = q.search.lower()
            results = [
                i
                for i in results
                if search_str in i.title.lower()
                or search_str in i.description.lower()
                or search_str in i.incident_id.lower()
            ]

        results.sort(key=lambda x: x.timestamp, reverse=True)
        return results[q.offset : q.offset + q.limit]

    def count(self) -> int:
        """Total incidents count."""
        with self._lock:
            return len(self._incidents)

    def clear(self) -> None:
        """Clear all stored incidents."""
        with self._lock:
            self._incidents.clear()

    def get_metrics(self) -> Dict[str, Any]:
        """Summary metrics across stored incidents."""
        with self._lock:
            incidents = list(self._incidents.values())

        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_disposition: Dict[str, int] = {}

        for inc in incidents:
            s = inc.status.value
            by_status[s] = by_status.get(s, 0) + 1

            sev = inc.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            disp = inc.final_disposition.value
            by_disposition[disp] = by_disposition.get(disp, 0) + 1

        return {
            "total_incidents": len(incidents),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_disposition": by_disposition,
        }


class AuditStore:
    """Immutable, thread-safe audit log for all automated and analyst security actions."""

    def __init__(self, max_capacity: int = 50000):
        self._max_capacity = max_capacity
        self._entries: List[AuditLogEntry] = []
        self._lock = threading.Lock()

    def log(self, entry: AuditLogEntry) -> None:
        """Append an audit log entry."""
        with self._lock:
            if len(self._entries) >= self._max_capacity:
                self._entries.pop(0)
            self._entries.append(entry)
            logger.info(
                f"AUDIT LOG: [{entry.id}] Action={entry.action.value} Actor={entry.actor} Target={entry.target} Result={entry.result.value}"
            )

    def list_entries(
        self,
        action: Optional[ResponseActionType] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditLogEntry]:
        """Query audit log entries."""
        with self._lock:
            results = list(self._entries)

        if action:
            results = [e for e in results if e.action == action]
        if actor:
            results = [e for e in results if e.actor.lower() == actor.lower()]
        if target:
            target_str = target.lower()
            results = [e for e in results if target_str in e.target.lower()]

        # Newest first
        results.sort(key=lambda x: x.timestamp, reverse=True)
        return results[:limit]

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
