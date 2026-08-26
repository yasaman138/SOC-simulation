"""Linux Server Simulation Service with Centralized Logging Integration."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.core.logging import get_logger
from src.infra.linux_server.config import LinuxServerConfig
from src.siem.collector import SIEMCollector
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

logger = get_logger("infra.linux_server")


class LinuxServerService:
    """Enterprise Linux Server simulation service."""

    def __init__(
        self,
        config: Optional[LinuxServerConfig] = None,
        siem_collector: Optional[SIEMCollector] = None,
    ):
        self.config = config or LinuxServerConfig()
        self.siem_collector = siem_collector
        self.local_users: Dict[str, str] = {
            "root": "disabled_login",
            "sysadmin": "LinuxAdminLab2026!",
            "deployer": "DeployKeySecretOnly!",
            "analyst": "AnalystLabReadOnly!",
        }

    def simulate_ssh_login(
        self,
        username: str,
        password: Optional[str] = None,
        key_fingerprint: Optional[str] = None,
        source_ip: str = "172.28.20.25",
        source_port: int = 49152,
    ) -> bool:
        """Simulate SSH authentication attempt with SSHD syslog generation."""
        is_success = False
        now_ts = datetime.now(timezone.utc)
        syslog_ts = now_ts.strftime("%b %d %H:%M:%S")

        if username == "root" and self.config.ssh.permit_root_login == "no":
            is_success = False
            raw_msg = f"<85>{syslog_ts} {self.config.hostname} sshd[12345]: Failed password for root from {source_ip} port {source_port} ssh2 (PermitRootLogin=no)"
        elif password and self.local_users.get(username) == password:
            is_success = True
            raw_msg = f"<86>{syslog_ts} {self.config.hostname} sshd[12345]: Accepted password for {username} from {source_ip} port {source_port} ssh2"
        elif (
            key_fingerprint
            and username in self.local_users
            and username != "root"
        ):
            is_success = True
            raw_msg = f"<86>{syslog_ts} {self.config.hostname} sshd[12345]: Accepted publickey for {username} from {source_ip} port {source_port} ssh2: RSA {key_fingerprint}"
        else:
            is_success = False
            raw_msg = f"<85>{syslog_ts} {self.config.hostname} sshd[12345]: Failed password for invalid user {username} from {source_ip} port {source_port} ssh2"

        # Emit telemetry
        self._emit_syslog(raw_msg, source_ip=self.config.ip_address)
        self._emit_structured_auth_event(
            username=username,
            success=is_success,
            source_ip=source_ip,
            source_port=source_port,
        )

        return is_success

    def simulate_command_execution(
        self,
        user: str,
        command_line: str,
        pid: int = 14200,
        is_sudo: bool = False,
    ) -> Dict[str, Any]:
        """Simulate process execution and trigger Linux auditd telemetry."""
        is_suspicious = is_sudo or any(
            susp in command_line.lower()
            for susp in [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/tmp/",
                "chmod 777",
                "curl -s",
                "wget",
                "bash -i",
                "/dev/tcp/",
                "nc -e",
            ]
        )

        severity = (
            EventSeverity.HIGH if is_suspicious else EventSeverity.INFORMATIONAL
        )

        now_ts = datetime.now(timezone.utc)
        syslog_ts = now_ts.strftime("%b %d %H:%M:%S")
        epoch_ts = now_ts.timestamp()

        if is_sudo:
            sudo_msg = f"<86>{syslog_ts} {self.config.hostname} sudo[14199]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command_line}"
            self._emit_syslog(sudo_msg, source_ip=self.config.ip_address)

        audit_msg = f"<134>{syslog_ts} {self.config.hostname} auditd[800]: type=EXECVE msg=audit({epoch_ts:.3f}:101): argc=1 a0=\"{command_line}\" pid={pid} comm=\"{command_line.split()[0]}\""
        self._emit_syslog(audit_msg, source_ip=self.config.ip_address)

        if self.siem_collector:
            ecs_event = ECSEvent(
                timestamp=datetime.now(timezone.utc),
                event=EventMetadata(
                    category=EventCategory.PROCESS,
                    action="linux.process.created",
                    outcome=EventOutcome.SUCCESS,
                    severity=severity,
                    dataset="linux.auditd",
                ),
                host=HostInfo(
                    name=self.config.hostname,
                    ip=self.config.ip_address,
                    os=self.config.os_release,
                ),
                user=UserInfo(name=user),
                process=ProcessInfo(
                    name=command_line.split()[0] if command_line else "unknown",
                    pid=pid,
                    command_line=command_line,
                ),
                message=f"Process executed by '{user}': {command_line}",
                custom={"is_sudo": is_sudo, "suspicious": is_suspicious},
            )
            self.siem_collector.ingest_event(ecs_event)

        return {
            "user": user,
            "command": command_line,
            "pid": pid,
            "logged": True,
            "suspicious": is_suspicious,
        }

    def _emit_syslog(self, raw_line: str, source_ip: str):
        if self.siem_collector:
            self.siem_collector.ingest_raw_syslog(
                raw_line, source_ip=source_ip
            )

    def _emit_structured_auth_event(
        self,
        username: str,
        success: bool,
        source_ip: str,
        source_port: int,
    ):
        if not self.siem_collector:
            return

        event = ECSEvent(
            timestamp=datetime.now(timezone.utc),
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ssh.login.success" if success else "ssh.login.failed",
                outcome=EventOutcome.SUCCESS
                if success
                else EventOutcome.FAILURE,
                severity=EventSeverity.INFORMATIONAL
                if success
                else EventSeverity.MEDIUM,
                dataset="linux.sshd",
            ),
            host=HostInfo(
                name=self.config.hostname,
                ip=self.config.ip_address,
                os=self.config.os_release,
            ),
            source=EndpointInfo(ip=source_ip, port=source_port),
            destination=EndpointInfo(
                ip=self.config.ip_address, port=self.config.ssh.port
            ),
            user=UserInfo(name=username),
            process=ProcessInfo(name="sshd"),
            message=f"SSH authentication {'succeeded' if success else 'failed'} for user '{username}' from {source_ip}:{source_port}.",
        )
        self.siem_collector.ingest_event(event)
