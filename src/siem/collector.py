"""Central Telemetry Ingestion Engine supporting HTTP and Syslog protocols."""

import asyncio
import json
import re
import socket
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional
from src.core.logging import get_logger
from src.siem.models import (
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    HostInfo,
    ProcessInfo,
    UserInfo,
)
from src.siem.parsers import SyslogParser
from src.siem.storage import EventStore

if TYPE_CHECKING:
    from src.detection.engine import DetectionEngine

logger = get_logger("siem.collector")


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """AsyncIO Datagram Protocol for receiving Syslog over UDP."""

    def __init__(self, collector: "SIEMCollector"):
        self.collector = collector

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            message_str = data.decode("utf-8", errors="replace")
            source_ip = addr[0]
            event = SyslogParser.parse(message_str, source_ip=source_ip)
            self.collector.ingest_event(event)
            logger.debug(
                f"Received Syslog UDP from {source_ip}: {event.event.action}"
            )
        except Exception as e:
            logger.error(f"Error handling UDP syslog message: {e}")


class SIEMCollector:
    """Orchestrator for SIEM Log Collection services and real-time detection pipeline."""

    def __init__(
        self,
        store: Optional[EventStore] = None,
        detection_engine: Optional[DetectionEngine] = None,
    ):
        self.store = store or EventStore()
        self.detection_engine = detection_engine
        self.udp_transport = None
        self.is_running = False

    def ingest_event(self, event: ECSEvent) -> str:
        """Ingest single normalized ECS event and evaluate detection rules in real-time."""
        event_id = self.store.add_event(event)

        # Real-time detection evaluation
        if self.detection_engine:
            self.detection_engine.evaluate_event(event)

        return event_id

    def ingest_raw_syslog(
        self, raw_message: str, source_ip: str = "127.0.0.1"
    ) -> str:
        """Parse and ingest raw syslog string."""
        event = SyslogParser.parse(raw_message, source_ip=source_ip)
        return self.ingest_event(event)

    async def start_udp_listener(
        self, host: str = "0.0.0.0", port: int = 5514
    ):
        """Start background Syslog UDP listener."""
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self),
                local_addr=(host, port),
            )
            self.udp_transport = transport
            self.is_running = True
            logger.info(f"Syslog UDP listener running on {host}:{port}")
        except Exception as e:
            logger.warning(
                f"Could not bind Syslog UDP on {host}:{port} ({e}). Running in API-only mode."
            )

    def stop(self):
        """Stop background listeners."""
        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None
        self.is_running = False
