"""Unit tests for ECS Telemetry Schema Models and Deserialization."""

from datetime import datetime, timezone
from src.siem.models import (
    DNSInfo,
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventQuery,
    EventSeverity,
    FileInfo,
    HostInfo,
    HTTPInfo,
    NetworkInfo,
    ProcessInfo,
    RegistryInfo,
    UserInfo,
)


def test_ecs_event_instantiation_defaults():
    event = ECSEvent()
    assert event.event.kind == "event"
    assert event.event.category == EventCategory.SYSTEM
    assert event.event.severity == EventSeverity.INFORMATIONAL
    assert event.event.outcome == EventOutcome.SUCCESS
    assert event.tags == []
    assert event.raw_event is None
    assert event.custom == {}


def test_ecs_event_full_telemetry_fields():
    event = ECSEvent(
        timestamp=datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc),
        event=EventMetadata(
            category=EventCategory.PROCESS,
            action="process.created",
            outcome=EventOutcome.SUCCESS,
            severity=EventSeverity.HIGH,
            dataset="windows.sysmon",
        ),
        host=HostInfo(
            name="wkstn01.corp.enterprise.local",
            ip="172.28.20.25",
            os="Windows 10 Enterprise",
        ),
        source=EndpointInfo(ip="172.28.20.25", port=49152),
        destination=EndpointInfo(ip="172.28.100.5", port=4444),
        user=UserInfo(name="attacker", domain="CORP", roles=["Users"]),
        process=ProcessInfo(
            name="powershell.exe",
            pid=4096,
            ppid=2048,
            command_line="powershell.exe -enc SQBFAFgA...",
            executable="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_name="cmd.exe",
            parent_command_line="cmd.exe /c start",
            hash="SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            integrity_level="High",
        ),
        http=HTTPInfo(
            method="POST",
            url="http://internal/api",
            status_code=200,
            user_agent="Mozilla/5.0",
        ),
        network=NetworkInfo(
            transport="tcp",
            protocol="http",
            direction="outbound",
            bytes=1024,
            packets=8,
        ),
        dns=DNSInfo(
            query_name="c2.attacker.com",
            query_type="A",
            resolved_ips=["198.51.100.55"],
            response_code="NOERROR",
        ),
        file=FileInfo(
            path="C:\\Users\\victim\\Downloads\\payload.exe",
            name="payload.exe",
            extension=".exe",
            size=204800,
            hash="SHA256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            action="created",
        ),
        registry=RegistryInfo(
            key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="BackdoorStub",
            value_data="C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe",
            action="set_value",
        ),
        message="Suspicious encoded PowerShell process execution detected.",
        raw_event="<SysmonEvent>EventData...</SysmonEvent>",
        tags=["powershell", "obfuscation", "mitre_t1059_001"],
        custom={"sysmon_event_id": 1},
    )

    data = event.to_dict()
    assert data["event"]["category"] == "process"
    assert data["process"]["name"] == "powershell.exe"
    assert data["process"]["ppid"] == 2048
    assert data["network"]["direction"] == "outbound"
    assert data["dns"]["query_name"] == "c2.attacker.com"
    assert data["file"]["name"] == "payload.exe"
    assert data["registry"]["value_name"] == "BackdoorStub"
    assert data["raw_event"] == "<SysmonEvent>EventData...</SysmonEvent>"
    assert "powershell" in data["tags"]


def test_event_query_model():
    q = EventQuery(
        category=EventCategory.AUTHENTICATION,
        action="login.failed",
        severity=EventSeverity.HIGH,
        host_name="dc01",
        source_ip="172.28.20.25",
        user_name="admin",
        search="bad password",
        limit=50,
        offset=10,
    )
    assert q.category == EventCategory.AUTHENTICATION
    assert q.limit == 50
    assert q.offset == 10
