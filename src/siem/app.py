"""FastAPI Application exposing SIEM HTTP Ingestion, Query, Detection, and Alert APIs."""

from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel
from src.core.config import settings
from src.detection.engine import DetectionEngine
from src.detection.models import Alert, AlertQuery, AlertStatus
from src.detection.storage import AlertStore
from src.siem.collector import SIEMCollector
from src.siem.models import ECSEvent, EventCategory, EventQuery, EventSeverity
from src.siem.storage import EventStore

# Global singletons
event_store = EventStore()
alert_store = AlertStore()
detection_engine = DetectionEngine(alert_store=alert_store)
siem_collector = SIEMCollector(
    store=event_store, detection_engine=detection_engine
)


class StatusUpdateRequest(BaseModel):
    status: AlertStatus
    note: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start UDP syslog listener if configured
    await siem_collector.start_udp_listener(
        host=settings.siem_host,
        port=settings.siem_syslog_udp_port,
    )
    yield
    # Shutdown: Stop collector
    siem_collector.stop()


def create_siem_app(
    store: Optional[EventStore] = None,
    engine: Optional[DetectionEngine] = None,
    alerts: Optional[AlertStore] = None,
) -> FastAPI:
    """Create and configure the SIEM FastAPI application."""
    active_store = store or event_store
    active_alerts = alerts or alert_store
    active_engine = engine or (
        detection_engine if alerts is None else DetectionEngine(alert_store=active_alerts)
    )
    active_collector = (
        siem_collector
        if (store is None and engine is None)
        else SIEMCollector(store=active_store, detection_engine=active_engine)
    )

    app = FastAPI(
        title="Enterprise Lab SIEM & Detection Pipeline",
        description="Receives, normalizes, stores, analyzes telemetry, and produces MITRE ATT&CK mapped security alerts.",
        version="0.2.0",
        lifespan=lifespan,
    )

    @app.get("/health", tags=["Health"])
    def health_check() -> Dict[str, Any]:
        return {
            "status": "healthy",
            "service": "siem-collector",
            "version": "0.2.0",
            "stored_events": active_store.count(),
            "active_alerts": active_alerts.count(),
            "active_detection_rules": len(active_engine.list_rules()),
            "udp_active": active_collector.is_running,
        }

    # ---------------- Telemetry Ingestion Endpoints ----------------

    @app.post(
        "/api/v1/events",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_event(event: ECSEvent) -> Dict[str, Any]:
        """Ingest a single normalized ECS security event and evaluate detection rules."""
        event_id = active_collector.ingest_event(event)
        return {"status": "success", "event_id": event_id}

    @app.post(
        "/api/v1/events/batch",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_batch(events: List[ECSEvent]) -> Dict[str, Any]:
        """Ingest multiple ECS events in a single batch with real-time detection analysis."""
        ids = []
        for ev in events:
            ev_id = active_collector.ingest_event(ev)
            ids.append(ev_id)
        return {
            "status": "success",
            "count": len(ids),
            "event_ids": ids,
        }

    @app.get("/api/v1/events", tags=["Query"])
    def query_events(
        category: Optional[EventCategory] = None,
        action: Optional[str] = None,
        severity: Optional[EventSeverity] = None,
        host_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> Dict[str, Any]:
        """Query and filter stored telemetry events."""
        q = EventQuery(
            category=category,
            action=action,
            severity=severity,
            host_name=host_name,
            source_ip=source_ip,
            user_name=user_name,
            search=search,
            limit=limit,
            offset=offset,
        )
        results = active_store.query_events(q)
        return {
            "total_matching": len(results),
            "limit": limit,
            "offset": offset,
            "events": [e.to_dict() for e in results],
        }

    @app.get("/api/v1/stats", tags=["Metrics"])
    def get_stats() -> Dict[str, Any]:
        """Get summary statistics of stored telemetry."""
        return active_store.get_stats()

    @app.delete("/api/v1/events", tags=["Management"])
    def clear_events() -> Dict[str, str]:
        """Clear all stored events (for lab reset/testing)."""
        active_store.clear()
        return {"status": "success", "message": "Event store cleared"}

    # ---------------- Detection Engine Endpoints ----------------

    @app.get("/api/v1/detections", tags=["Detections"])
    def list_detections() -> Dict[str, Any]:
        """List all active detection rules with MITRE ATT&CK mappings."""
        rules = active_engine.list_rules()
        return {
            "total_rules": len(rules),
            "rules": [r.to_metadata_dict() for r in rules],
        }

    @app.get("/api/v1/detections/{rule_id}", tags=["Detections"])
    def get_detection(rule_id: str) -> Dict[str, Any]:
        """Retrieve details of a specific detection rule by ID."""
        rule = active_engine.get_rule(rule_id)
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection rule '{rule_id}' not found",
            )
        return rule.to_metadata_dict()

    @app.post("/api/v1/detections/evaluate", tags=["Detections"])
    def trigger_evaluation() -> Dict[str, Any]:
        """Manually trigger detection rule evaluation across all stored events."""
        alerts = active_engine.evaluate_store(active_store)
        return {
            "status": "success",
            "alerts_generated": len(alerts),
            "alert_ids": [a.id for a in alerts],
        }

    # ---------------- Security Alerts Endpoints ----------------

    @app.get("/api/v1/alerts", tags=["Alerts"])
    def query_alerts(
        severity: Optional[EventSeverity] = None,
        rule_id: Optional[str] = None,
        status: Optional[AlertStatus] = None,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> Dict[str, Any]:
        """Query and filter security alerts produced by detection engine."""
        q = AlertQuery(
            severity=severity,
            rule_id=rule_id,
            status=status,
            host_name=host_name,
            user_name=user_name,
            source_ip=source_ip,
            search=search,
            limit=limit,
            offset=offset,
        )
        results = active_alerts.query_alerts(q)
        return {
            "total_matching": len(results),
            "limit": limit,
            "offset": offset,
            "alerts": [a.to_dict() for a in results],
        }

    @app.get("/api/v1/alerts/stats", tags=["Alerts"])
    def get_alert_stats() -> Dict[str, Any]:
        """Get summary metrics of security alerts by severity, MITRE tactic, and status."""
        return active_alerts.get_stats()

    @app.get("/api/v1/alerts/{alert_id}", tags=["Alerts"])
    def get_alert(alert_id: str) -> Dict[str, Any]:
        """Retrieve full details and source events for a specific alert."""
        alert = active_alerts.get_alert(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found",
            )
        return alert.to_dict()

    @app.patch("/api/v1/alerts/{alert_id}", tags=["Alerts"])
    def update_alert_status(
        alert_id: str, update: StatusUpdateRequest
    ) -> Dict[str, Any]:
        """Update triage/investigation status of an alert."""
        success = active_alerts.update_status(
            alert_id=alert_id, status=update.status, note=update.note
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found",
            )
        return {"status": "success", "alert_id": alert_id, "new_status": update.status.value}

    @app.delete("/api/v1/alerts", tags=["Alerts"])
    def clear_alerts() -> Dict[str, str]:
        """Clear all stored alerts (for lab reset/testing)."""
        active_alerts.clear()
        return {"status": "success", "message": "Alert store cleared"}

    return app


app = create_siem_app()
