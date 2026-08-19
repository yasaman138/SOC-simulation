"""Unit tests for configuration management."""

import pytest
from src.core.config import LabSettings


def test_default_settings_initialization():
    settings = LabSettings()
    assert settings.lab_environment == "development"
    assert settings.ad_domain_name == "CORP.ENTERPRISE.LOCAL"
    assert settings.ad_dc_hostname == "dc01.corp.enterprise.local"
    assert settings.linux_ssh_port == 2222
    assert settings.siem_http_port == 8088
    assert settings.siem_syslog_udp_port == 5514


def test_network_validation_success():
    settings = LabSettings(
        net_simulation_cidr="172.28.10.0/24",
        net_corp_internal_cidr="172.28.20.0/24",
        net_app_tier_cidr="172.28.30.0/24",
        net_secmon_cidr="172.28.90.0/24",
    )
    assert settings.validate_networks() is True


def test_network_validation_overlap_failure():
    settings = LabSettings(
        net_simulation_cidr="172.28.10.0/24",
        net_corp_internal_cidr="172.28.10.0/24",  # overlapping
        net_app_tier_cidr="172.28.30.0/24",
        net_secmon_cidr="172.28.90.0/24",
    )
    with pytest.raises(ValueError, match="Network CIDR conflict"):
        settings.validate_networks()
