"""Core Configuration Management for the Enterprise Lab."""

from ipaddress import IPv4Network
import os
from typing import Any, Dict, List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LabSettings(BaseSettings):
    """Global laboratory configuration settings."""

    # Lab Environment
    lab_environment: str = Field(default="development", alias="LAB_ENVIRONMENT")
    lab_name: str = Field(
        default="Enterprise Attack Detection & Response Lab", alias="LAB_NAME"
    )
    lab_log_level: str = Field(default="INFO", alias="LAB_LOG_LEVEL")

    # Network CIDRs
    net_simulation_cidr: str = Field(
        default="172.28.10.0/24", alias="NET_SIMULATION_CIDR"
    )
    net_corp_internal_cidr: str = Field(
        default="172.28.20.0/24", alias="NET_CORP_INTERNAL_CIDR"
    )
    net_app_tier_cidr: str = Field(
        default="172.28.30.0/24", alias="NET_APP_TIER_CIDR"
    )
    net_secmon_cidr: str = Field(
        default="172.28.90.0/24", alias="NET_SECMON_CIDR"
    )

    # Active Directory Settings
    ad_domain_name: str = Field(
        default="CORP.ENTERPRISE.LOCAL", alias="AD_DOMAIN_NAME"
    )
    ad_netbios_name: str = Field(default="CORP", alias="AD_NETBIOS_NAME")
    ad_dc_hostname: str = Field(
        default="dc01.corp.enterprise.local", alias="AD_DC_HOSTNAME"
    )
    ad_dc_ip: str = Field(default="172.28.20.10", alias="AD_DC_IP")
    ad_ldap_port: int = Field(default=389, alias="AD_LDAP_PORT")
    ad_ldaps_port: int = Field(default=636, alias="AD_LDAPS_PORT")
    ad_kerberos_port: int = Field(default=88, alias="AD_KERBEROS_PORT")

    # Linux Server Settings
    linux_srv_hostname: str = Field(
        default="linux-srv01.corp.enterprise.local", alias="LINUX_SRV_HOSTNAME"
    )
    linux_srv_ip: str = Field(default="172.28.20.15", alias="LINUX_SRV_IP")
    linux_ssh_port: int = Field(default=2222, alias="LINUX_SSH_PORT")

    # Application Tier Settings
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    app_db_url: str = Field(
        default="sqlite:///./data/app_portal.db", alias="APP_DB_URL"
    )
    app_secret_key: str = Field(
        default="lab-development-insecure-key-do-not-use-in-prod",
        alias="APP_SECRET_KEY",
    )

    # SIEM / Security Monitoring Settings
    siem_host: str = Field(default="0.0.0.0", alias="SIEM_HOST")
    siem_http_port: int = Field(default=8088, alias="SIEM_HTTP_PORT")
    siem_syslog_udp_port: int = Field(
        default=5514, alias="SIEM_SYSLOG_UDP_PORT"
    )
    siem_syslog_tcp_port: int = Field(
        default=5514, alias="SIEM_SYSLOG_TCP_PORT"
    )
    siem_storage_backend: str = Field(
        default="memory", alias="SIEM_STORAGE_BACKEND"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def validate_networks(self) -> bool:
        """Validate all configured network CIDRs are valid IPv4 subnets without overlapping."""
        subnets = [
            IPv4Network(self.net_simulation_cidr),
            IPv4Network(self.net_corp_internal_cidr),
            IPv4Network(self.net_app_tier_cidr),
            IPv4Network(self.net_secmon_cidr),
        ]
        for i in range(len(subnets)):
            for j in range(i + 1, len(subnets)):
                if subnets[i].overlaps(subnets[j]):
                    raise ValueError(
                        f"Network CIDR conflict: {subnets[i]} overlaps with {subnets[j]}"
                    )
        return True

    def validate_ports(self) -> bool:
        """Ensure configured ports are valid and non-colliding within shared host interfaces."""
        ports = {
            "AD LDAP": self.ad_ldap_port,
            "AD LDAPS": self.ad_ldaps_port,
            "AD Kerberos": self.ad_kerberos_port,
            "Linux SSH": self.linux_ssh_port,
            "App HTTP": self.app_port,
            "SIEM HTTP": self.siem_http_port,
            "SIEM Syslog UDP": self.siem_syslog_udp_port,
        }

        for name, port in ports.items():
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port configuration for {name}: {port}")

        return True

    def validate_all(self) -> bool:
        """Execute full configuration validation suite."""
        self.validate_networks()
        self.validate_ports()
        return True

    def get_sanitized_config(self) -> Dict[str, Any]:
        """Export configuration with sensitive keys redacted for diagnostic output."""
        cfg = self.model_dump()
        if "app_secret_key" in cfg:
            cfg["app_secret_key"] = "***REDACTED***"
        return cfg


# Global settings singleton instance
settings = LabSettings()
