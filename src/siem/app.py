"""FastAPI Application exposing SIEM HTTP Ingestion, Query, and Health APIs."""

from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel
from src.core.config import settings
from src.siem.collector import SIEMCollector
from src.siem.models import ECSEvent, EventCategory, EventQuery, EventSeverity
from src.siem.storage import EventStore

# Global singletons
event_store = EventStore()
siem_collector = SIEMCollector(store=event_store)


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


def create_siem_app() -> FastAPI:
    """Create and configure the SIEM FastAPI application."""
    app = FastAPI(
        title="Enterprise Lab SIEM & Centralized Telemetry Aggregator",
        description="Receives, normalizes, stores, and queries security telemetry across all lab tiers.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health", tags=["Health"])
    def health_check() -> Dict[str, Any]:
        return {
            "status": "healthy",
            "service": "siem-collector",
            "version": "0.1.0",
            "stored_events": event_store.count(),
            "udp_active": siem_collector.is_running,
        }

    @app.post(
        "/api/v1/events",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_event(event: ECSEvent) -> Dict[str, Any]:
        """Ingest a single normalized ECS security event."""
        event_id = siem_collector.ingest_event(event)
        return {"status": "success", "event_id": event_id}

    @app.post(
        "/api/v1/events/batch",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_batch(events: List[ECSEvent]) -> Dict[str, Any]:
        """Ingest multiple ECS events in a single batch."""
        ids = event_store.add_batch(events)
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
        results = event_store.query_events(q)
        return {
            "total_matching": len(results),
            "limit": limit,
            "offset": offset,
            "events": [e.to_dict() for e in results],
        }

    @app.get("/api/v1/stats", tags=["Metrics"])
    def get_stats() -> Dict[str, Any]:
        """Get summary statistics of stored telemetry."""
        return event_store.get_stats()

    @app.delete("/api/v1/events", tags=["Management"])
    def clear_events() -> Dict[str, str]:
        """Clear all stored events (for lab reset/testing)."""
        event_store.clear()
        return {"status": "success", "message": "Event store cleared"}

    return app


app = create_siem_app()
