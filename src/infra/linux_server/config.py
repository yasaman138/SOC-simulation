"""Linux Server and Centralized Logging Daemon Configuration."""

from typing import Dict, List
from pydantic import BaseModel, Field


class SSHDaemonConfig(BaseModel):
    """OpenSSH server configuration parameters."""

    port: int = 2222
    permit_root_login: str = "no"
    password_authentication: str = "yes"
    pubkey_authentication: str = "yes"
    max_auth_tries: int = 3
    log_level: str = "VERBOSE"
    subsystem_sftp: str = "/usr/lib/openssh/sftp-server"


class AuditdRule(BaseModel):
    """Auditd kernel monitoring rule."""

    key: str
    syscall: str
    path: str
    permissions: str  # r, w, x, a
    description: str


class RsyslogForwardingConfig(BaseModel):
    """Rsyslog remote forwarding configuration."""

    target_host: str = "172.28.90.10"
    target_port: int = 5514
    protocol: str = "udp"
    facility_filter: str = "*.*"


class LinuxServerConfig(BaseModel):
    """Linux Server configuration."""

    hostname: str = "linux-srv01.corp.enterprise.local"
    ip_address: str = "172.28.20.15"
    os_release: str = "Ubuntu 22.04.4 LTS"
    ssh: SSHDaemonConfig = Field(default_factory=SSHDaemonConfig)
    rsyslog: RsyslogForwardingConfig = Field(
        default_factory=RsyslogForwardingConfig
    )
    auditd_rules: List[AuditdRule] = Field(
        default_factory=lambda: [
            AuditdRule(
                key="identity_change",
                syscall="execve",
                path="/etc/passwd",
                permissions="wa",
                description="Monitor modifications to system user credentials",
            ),
            AuditdRule(
                key="sudoers_tampering",
                syscall="execve",
                path="/etc/sudoers",
                permissions="wa",
                description="Monitor modifications to sudoers privilege configuration",
            ),
            AuditdRule(
                key="suspicious_execution",
                syscall="execve",
                path="/tmp",
                permissions="x",
                description="Monitor binary executions from temporary world-writable directory",
            ),
        ]
    )
