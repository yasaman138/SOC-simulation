"""Storage Engine for Normalized Telemetry Events."""

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.siem.models import ECSEvent, EventCategory, EventQuery, EventSeverity


class EventStore:
    """Thread-safe in-memory and searchable telemetry store."""

    def __init__(self, max_capacity: int = 10000):
        self.max_capacity = max_capacity
        self._events: List[ECSEvent] = []
        self._lock = threading.Lock()

    def add_event(self, event: ECSEvent) -> str:
        """Add a normalized event to the store."""
        with self._lock:
            if len(self._events) >= self.max_capacity:
                # Discard oldest event
                self._events.pop(0)
            self._events.append(event)
            return event.event.id

    def add_batch(self, events: List[ECSEvent]) -> List[str]:
        """Add multiple events in batch."""
        ids = []
        with self._lock:
            for ev in events:
                if len(self._events) >= self.max_capacity:
                    self._events.pop(0)
                self._events.append(ev)
                ids.append(ev.event.id)
        return ids

    def query_events(self, query: Optional[EventQuery] = None) -> List[ECSEvent]:
        """Filter events matching the query criteria."""
        q = query or EventQuery(limit=max(self.count(), 100))
        with self._lock:
            results = self._events[:]

        # Apply filters
        if q.category:
            results = [e for e in results if e.event.category == q.category]
        if q.action:
            results = [
                e
                for e in results
                if q.action.lower() in e.event.action.lower()
            ]
        if q.severity:
            results = [e for e in results if e.event.severity == q.severity]
        if q.host_name:
            results = [
                e
                for e in results
                if e.host
                and e.host.name
                and q.host_name.lower() in e.host.name.lower()
            ]
        if q.source_ip:
            results = [
                e
                for e in results
                if e.source and e.source.ip and q.source_ip == e.source.ip
            ]
        if q.user_name:
            results = [
                e
                for e in results
                if e.user
                and e.user.name
                and q.user_name.lower() in e.user.name.lower()
            ]
        if q.search:
            s = q.search.lower()
            results = [
                e
                for e in results
                if (s in e.message.lower())
                or (s in e.event.action.lower())
                or (e.user and e.user.name and s in e.user.name.lower())
                or (e.host and e.host.name and s in e.host.name.lower())
            ]

        # Reverse sort by timestamp (newest first)
        results.sort(key=lambda x: x.timestamp, reverse=True)

        start = q.offset
        end = start + q.limit
        return results[start:end]

    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def get_stats(self) -> Dict[str, Any]:
        """Calculate high-level telemetry statistics."""
        with self._lock:
            total = len(self._events)
            by_category: Dict[str, int] = {}
            by_severity: Dict[str, int] = {}

            for e in self._events:
                cat = e.event.category.value
                sev = e.event.severity.value
                by_category[cat] = by_category.get(cat, 0) + 1
                by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total_events": total,
            "by_category": by_category,
            "by_severity": by_severity,
        }

    def clear(self) -> None:
        """Clear all stored events."""
        with self._lock:
            self._events.clear()
