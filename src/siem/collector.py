"""Central Telemetry Ingestion Engine supporting HTTP and Syslog protocols."""

import asyncio
import json
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, Optional
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
from src.siem.storage import EventStore

logger = get_logger("siem.collector")


class SyslogParser:
    """Parser for RFC 3164 and RFC 5424 formatted Syslog messages."""

    # RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MESSAGE
    RFC3164_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )

    @classmethod
    def parse(
        cls, raw_data: str, source_ip: str = "127.0.0.1"
    ) -> ECSEvent:
        """Parse raw syslog message into normalized ECSEvent."""
        raw_data = raw_data.strip()

        # Try parsing as JSON first if message payload is JSON
        if raw_data.startswith("{") and raw_data.endswith("}"):
            try:
                data = json.loads(raw_data)
                return cls._from_json_payload(data, source_ip)
            except Exception:
                pass

        match = cls.RFC3164_PATTERN.match(raw_data)
        if match:
            pri = int(match.group("pri"))
            severity_num = pri % 8
            hostname = match.group("host")
            tag = match.group("tag")
            pid_str = match.group("pid")
            message = match.group("message")

            severity_map = {
                0: EventSeverity.CRITICAL,  # Emergency
                1: EventSeverity.CRITICAL,  # Alert
                2: EventSeverity.CRITICAL,  # Critical
                3: EventSeverity.HIGH,  # Error
                4: EventSeverity.MEDIUM,  # Warning
                5: EventSeverity.LOW,  # Notice
                6: EventSeverity.INFORMATIONAL,  # Info
                7: EventSeverity.INFORMATIONAL,  # Debug
            }

            category = EventCategory.SYSTEM
            if "sshd" in tag.lower() or "auth" in tag.lower():
                category = EventCategory.AUTHENTICATION
            elif "audit" in tag.lower():
                category = EventCategory.PROCESS

            return ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(
                    category=category,
                    action=f"syslog.{tag}",
                    severity=severity_map.get(
                        severity_num, EventSeverity.INFORMATIONAL
                    ),
                    dataset="syslog",
                ),
                host=HostInfo(name=hostname, ip=source_ip),
                source=EndpointInfo(ip=source_ip),
                process=ProcessInfo(
                    name=tag, pid=int(pid_str) if pid_str else None
                ),
                message=message,
                custom={"raw_pri": pri, "facility": pri // 8},
            )

        # Fallback raw line event
        return ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.SYSTEM,
                action="syslog.raw",
                severity=EventSeverity.INFORMATIONAL,
            ),
            host=HostInfo(ip=source_ip),
            source=EndpointInfo(ip=source_ip),
            message=raw_data,
        )

    @classmethod
    def _from_json_payload(
        cls, data: Dict[str, Any], source_ip: str
    ) -> ECSEvent:
        category_str = data.get("category", "system")
        try:
            category = EventCategory(category_str)
        except Exception:
            category = EventCategory.SYSTEM

        severity_str = data.get("severity", "informational")
        try:
            severity = EventSeverity(severity_str)
        except Exception:
            severity = EventSeverity.INFORMATIONAL

        return ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=category,
                action=data.get("action", "custom_event"),
                severity=severity,
                outcome=EventOutcome(
                    data.get("outcome", EventOutcome.SUCCESS.value)
                ),
            ),
            host=HostInfo(
                name=data.get("host_name"),
                ip=data.get("host_ip", source_ip),
            ),
            source=EndpointInfo(ip=data.get("source_ip", source_ip)),
            destination=EndpointInfo(
                ip=data.get("dest_ip"), port=data.get("dest_port")
            ),
            user=UserInfo(
                name=data.get("user_name"), domain=data.get("user_domain")
            ),
            process=ProcessInfo(
                name=data.get("process_name"),
                command_line=data.get("command_line"),
            ),
            message=data.get("message", ""),
            custom=data.get("custom", {}),
        )


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """AsyncIO Datagram Protocol for receiving Syslog over UDP."""

    def __init__(self, store: EventStore):
        self.store = store

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            message_str = data.decode("utf-8", errors="replace")
            source_ip = addr[0]
            event = SyslogParser.parse(message_str, source_ip=source_ip)
            self.store.add_event(event)
            logger.debug(
                f"Received Syslog UDP from {source_ip}: {event.event.action}"
            )
        except Exception as e:
            logger.error(f"Error handling UDP syslog message: {e}")


class SIEMCollector:
    """Orchestrator for SIEM Log Collection services."""

    def __init__(self, store: Optional[EventStore] = None):
        self.store = store or EventStore()
        self.udp_transport = None
        self.is_running = False

    def ingest_event(self, event: ECSEvent) -> str:
        """Ingest single normalized ECS event."""
        return self.store.add_event(event)

    def ingest_raw_syslog(
        self, raw_message: str, source_ip: str = "127.0.0.1"
    ) -> str:
        """Parse and ingest raw syslog string."""
        event = SyslogParser.parse(raw_message, source_ip=source_ip)
        return self.store.add_event(event)

    async def start_udp_listener(
        self, host: str = "0.0.0.0", port: int = 5514
    ):
        """Start background Syslog UDP listener."""
        loop = asyncio.get_running_loop()
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(self.store),
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
