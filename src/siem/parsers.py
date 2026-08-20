"""Telemetry Parsers and Normalizers for Windows, Linux, Web, and Network Sources."""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from src.siem.models import (
    DNSInfo,
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    FileInfo,
    HostInfo,
    HTTPInfo,
    NetworkInfo,
    ProcessInfo,
    RegistryInfo,
    UserInfo,
)


def _parse_timestamp(raw_ts: Any) -> datetime:
    """Parse various timestamp representations into timezone-aware UTC datetime."""
    if isinstance(raw_ts, datetime):
        if raw_ts.tzinfo is None:
            return raw_ts.replace(tzinfo=timezone.utc)
        return raw_ts
    if isinstance(raw_ts, (int, float)):
        try:
            return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    if isinstance(raw_ts, str) and raw_ts.strip():
        try:
            clean = raw_ts.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return datetime.now(timezone.utc)


class WindowsEventParser:
    """Parser for Windows Security Auditing, Sysmon, and PowerShell event logs."""

    SEVERITY_MAP = {
        1: EventSeverity.INFORMATIONAL,
        2: EventSeverity.LOW,
        3: EventSeverity.MEDIUM,
        4: EventSeverity.HIGH,
        5: EventSeverity.CRITICAL,
    }

    CATEGORY_MAP = {
        4624: EventCategory.AUTHENTICATION,
        4625: EventCategory.AUTHENTICATION,
        4688: EventCategory.PROCESS,
        4720: EventCategory.DIRECTORY_SERVICE,
        4768: EventCategory.DIRECTORY_SERVICE,
        4769: EventCategory.DIRECTORY_SERVICE,
        7045: EventCategory.SYSTEM,
        1: EventCategory.PROCESS,  # Sysmon Process Create
        3: EventCategory.NETWORK,  # Sysmon Network Connect
        11: EventCategory.FILE,  # Sysmon File Create
        13: EventCategory.REGISTRY,  # Sysmon Registry Event
        22: EventCategory.DNS,  # Sysmon DNS Query
    }

    @classmethod
    def parse_dict(
        cls, data: Dict[str, Any], source_ip: str = "127.0.0.1"
    ) -> ECSEvent:
        if not isinstance(data, dict):
            return ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(category=EventCategory.SYSTEM, action="windows.invalid"),
                message=str(data),
            )

        event_id = data.get("event_id") or data.get("EventID")
        category = cls.CATEGORY_MAP.get(event_id, EventCategory.SYSTEM)

        action = data.get("action") or f"windows.event.{event_id}"
        outcome = (
            EventOutcome.FAILURE
            if event_id == 4625
            else EventOutcome.SUCCESS
        )
        severity = (
            EventSeverity.MEDIUM
            if event_id in (4625, 4769)
            else EventSeverity.INFORMATIONAL
        )

        user_name = data.get("user") or data.get("TargetUserName") or data.get("SubjectUserName")
        domain = data.get("domain") or data.get("TargetDomainName")
        proc_name = data.get("process") or data.get("NewProcessName") or data.get("Image")
        cmd_line = data.get("command_line") or data.get("CommandLine")
        parent_name = data.get("parent_process") or data.get("ParentImage")

        reg_key = data.get("target_object") or data.get("TargetObject")
        file_path = data.get("target_filename") or data.get("TargetFilename")
        dns_query = data.get("query_name") or data.get("QueryName")

        raw_ts = data.get("timestamp") or data.get("@timestamp") or data.get("TimeCreated") or data.get("UtcTime")
        event_ts = _parse_timestamp(raw_ts)

        return ECSEvent(
            timestamp=event_ts,
            event=EventMetadata(
                category=category,
                action=action,
                outcome=outcome,
                severity=severity,
                dataset="windows.security_auditing",
            ),
            host=HostInfo(
                name=data.get("computer_name") or data.get("host_name"),
                ip=source_ip,
                os="Windows",
            ),
            source=EndpointInfo(
                ip=data.get("source_ip") or data.get("IpAddress", source_ip),
                port=data.get("source_port") or data.get("IpPort"),
            ),
            destination=EndpointInfo(
                ip=data.get("dest_ip") or data.get("DestinationIp"),
                port=data.get("dest_port") or data.get("DestinationPort"),
            ),
            user=UserInfo(name=user_name, domain=domain),
            process=ProcessInfo(
                name=proc_name.split("\\")[-1] if proc_name else None,
                command_line=cmd_line,
                executable=proc_name,
                parent_name=parent_name.split("\\")[-1] if parent_name else None,
            )
            if (proc_name or cmd_line)
            else None,
            registry=RegistryInfo(key=reg_key) if reg_key else None,
            file=FileInfo(path=file_path) if file_path else None,
            dns=DNSInfo(query_name=dns_query) if dns_query else None,
            message=data.get("message", f"Windows Event {event_id}"),
            raw_event=json.dumps(data) if isinstance(data, dict) else str(data),
            custom={"windows": {"event_id": event_id}},
        )


class AuditdParser:
    """Parser for Linux auditd and execve/syscall log records."""

    AUDIT_PATTERN = re.compile(
        r"type=(?P<type>[A-Z_]+)\s+msg=audit\((?P<epoch>[\d\.]+):(?P<id>\d+)\):\s+(?P<kv>.*)$"
    )

    @classmethod
    def parse_line(
        cls, line: str, hostname: str = "localhost", source_ip: str = "127.0.0.1"
    ) -> Optional[ECSEvent]:
        match = cls.AUDIT_PATTERN.search(line)
        if not match:
            return None

        record_type = match.group("type")
        epoch_str = match.group("epoch")
        kv_pairs = match.group("kv")

        # Parse key=value pairs
        parsed = {}
        for token in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s]+))', kv_pairs):
            key = token[0]
            val = token[1] if token[1] else token[2]
            parsed[key] = val

        category = EventCategory.PROCESS
        action = f"auditd.{record_type.lower()}"
        severity = EventSeverity.INFORMATIONAL
        cmd = parsed.get("a0") or parsed.get("cmd") or parsed.get("exe")
        comm = parsed.get("comm")
        pid_str = parsed.get("pid")
        uid_str = parsed.get("uid") or parsed.get("auid")

        try:
            event_ts = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc)
        except Exception:
            event_ts = datetime.now(timezone.utc)

        return ECSEvent(
            timestamp=event_ts,
            event=EventMetadata(
                category=category,
                action=action,
                severity=severity,
                dataset="linux.auditd",
            ),
            host=HostInfo(name=hostname, ip=source_ip, os="Linux"),
            source=EndpointInfo(ip=source_ip),
            user=UserInfo(name=parsed.get("user") or uid_str),
            process=ProcessInfo(
                name=comm or (cmd.split()[0] if cmd else "auditd"),
                pid=int(pid_str) if pid_str and pid_str.isdigit() else None,
                command_line=cmd,
                executable=parsed.get("exe"),
            ),
            message=line,
            raw_event=line,
            custom={"auditd": {"record_type": record_type, "fields": parsed}},
        )


class SyslogParser:
    """Enhanced Syslog parser supporting RFC 3164, RFC 5424, Auditd, and JSON syslog."""

    RFC3164_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
    )

    @classmethod
    def parse(cls, raw_data: str, source_ip: str = "127.0.0.1") -> ECSEvent:
        raw_data = raw_data.strip()

        # 1. JSON Payload parsing
        if raw_data.startswith("{") and raw_data.endswith("}"):
            try:
                data = json.loads(raw_data)
                if isinstance(data, dict):
                    if "EventID" in data or "event_id" in data:
                        return WindowsEventParser.parse_dict(data, source_ip=source_ip)
                    return cls._from_json_payload(data, source_ip, raw_data)
            except Exception:
                pass

        # 2. RFC 3164 Syslog parsing
        match = cls.RFC3164_PATTERN.match(raw_data)
        if match:
            try:
                pri = int(match.group("pri"))
            except Exception:
                pri = 13
            severity_num = pri % 8
            hostname = match.group("host")
            tag = match.group("tag")
            pid_str = match.group("pid")
            message = match.group("message")

            severity_map = {
                0: EventSeverity.CRITICAL,
                1: EventSeverity.CRITICAL,
                2: EventSeverity.CRITICAL,
                3: EventSeverity.HIGH,
                4: EventSeverity.MEDIUM,
                5: EventSeverity.LOW,
                6: EventSeverity.INFORMATIONAL,
                7: EventSeverity.INFORMATIONAL,
            }

            # Check if inner message is an auditd line
            if "auditd" in tag.lower() or "type=EXECVE" in message:
                audit_ev = AuditdParser.parse_line(
                    message, hostname=hostname, source_ip=source_ip
                )
                if audit_ev:
                    audit_ev.raw_event = raw_data
                    return audit_ev

            category = EventCategory.SYSTEM
            action = f"syslog.{tag}"
            user_name = None

            if "sshd" in tag.lower() or "auth" in tag.lower():
                category = EventCategory.AUTHENTICATION
                if "for invalid user" in message:
                    user_name = message.split("for invalid user")[-1].split()[0]
                elif "for" in message:
                    try:
                        user_name = message.split("for")[-1].split()[0]
                    except Exception:
                        pass
            elif "sudo" in tag.lower():
                category = EventCategory.PROCESS
                action = "linux.sudo.execution"
                try:
                    user_name = message.split(":")[0].strip()
                except Exception:
                    pass

            return ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(
                    category=category,
                    action=action,
                    severity=severity_map.get(
                        severity_num, EventSeverity.INFORMATIONAL
                    ),
                    dataset="syslog",
                ),
                host=HostInfo(name=hostname, ip=source_ip, os="Linux"),
                source=EndpointInfo(ip=source_ip),
                user=UserInfo(name=user_name) if user_name else None,
                process=ProcessInfo(
                    name=tag,
                    pid=int(pid_str) if pid_str and pid_str.isdigit() else None,
                    command_line=message if "sudo" in tag.lower() else None,
                ),
                message=message,
                raw_event=raw_data,
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
            raw_event=raw_data,
        )

    @classmethod
    def _from_json_payload(
        cls, data: Dict[str, Any], source_ip: str, raw_data: str
    ) -> ECSEvent:
        if not isinstance(data, dict):
            return ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(category=EventCategory.SYSTEM, action="json.invalid"),
                message=raw_data,
                raw_event=raw_data,
            )

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

        outcome_str = data.get("outcome", EventOutcome.SUCCESS.value)
        try:
            outcome = EventOutcome(outcome_str)
        except Exception:
            outcome = EventOutcome.SUCCESS

        raw_ts = data.get("timestamp") or data.get("@timestamp")
        event_ts = _parse_timestamp(raw_ts)

        return ECSEvent(
            timestamp=event_ts,
            event=EventMetadata(
                category=category,
                action=str(data.get("action", "custom_event")),
                severity=severity,
                outcome=outcome,
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
            message=str(data.get("message", "")),
            raw_event=raw_data,
            custom=data.get("custom", {}) if isinstance(data.get("custom"), dict) else {},
        )
