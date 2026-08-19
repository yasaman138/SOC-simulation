"""Application Telemetry Forwarder to Centralized SIEM."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import httpx
from src.core.logging import get_logger
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    HTTPInfo,
    UserInfo,
)

logger = get_logger("vulnapp.telemetry")


class AppTelemetryClient:
    """Sends normalized application events to the SIEM HTTP ingestion endpoint."""

    def __init__(
        self,
        siem_endpoint: str = "http://172.28.90.10:8088/api/v1/events",
        local_collector=None,
    ):
        self.siem_endpoint = siem_endpoint
        self.local_collector = local_collector

    def send_event(
        self,
        action: str,
        category: EventCategory,
        severity: EventSeverity,
        outcome: EventOutcome,
        message: str,
        source_ip: str = "172.28.10.100",
        source_port: int = 0,
        user_name: Optional[str] = None,
        http_method: Optional[str] = None,
        http_url: Optional[str] = None,
        http_status: Optional[int] = None,
        custom: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Dispatch security event to SIEM."""
        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=category,
                action=action,
                outcome=outcome,
                severity=severity,
                dataset="enterprise.web_portal",
            ),
            host=HostInfo(
                name="portal.app.local",
                ip="172.28.30.10",
                os="Linux Container",
            ),
            source=EndpointInfo(ip=source_ip, port=source_port),
            destination=EndpointInfo(ip="172.28.30.10", port=8000),
            user=UserInfo(name=user_name) if user_name else None,
            http=HTTPInfo(
                method=http_method, url=http_url, status_code=http_status
            )
            if http_method or http_url
            else None,
            message=message,
            custom=custom or {},
        )

        # In-process ingestion if local_collector available
        if self.local_collector:
            return self.local_collector.ingest_event(event)

        # Async HTTP dispatch if live network
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.post(
                    self.siem_endpoint, json=event.model_dump(mode="json")
                )
                if res.status_code == 201:
                    return res.json().get("event_id")
        except Exception:
            logger.debug(
                f"SIEM collector offline or unreachable at {self.siem_endpoint}"
            )

        return None
