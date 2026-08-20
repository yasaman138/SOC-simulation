"""Unit tests for the Deep Health Check and Observability subsystem."""

from src.core.health import (
    ComponentHealth,
    DeepHealthChecker,
    DeepHealthReport,
    HealthStatus,
)


def test_deep_health_checker_check_all():
    """Verify check_all returns healthy status across all lab subsystems."""
    checker = DeepHealthChecker()
    report = checker.check_all()

    assert isinstance(report, DeepHealthReport)
    assert report.overall_status == HealthStatus.HEALTHY
    assert report.total_components == 7
    assert report.healthy_components == 7
    assert report.unhealthy_components == 0
    assert report.degraded_components == 0
    assert report.uptime_seconds >= 0.0

    comp_names = [c.name for c in report.components]
    assert "Network Topology" in comp_names
    assert "Active Directory (dc01)" in comp_names
    assert "Linux Server (linux-srv01)" in comp_names
    assert "SIEM Collector" in comp_names
    assert "Detection Engine" in comp_names
    assert "Incident Response & SOAR" in comp_names
    assert "Application Tier (vulnapp)" in comp_names


def test_individual_subsystem_health_checks():
    """Verify individual component health checks and latency reporting."""
    checker = DeepHealthChecker()

    # Network topology check
    topo_health = checker.check_network_topology()
    assert topo_health.status == HealthStatus.HEALTHY
    assert topo_health.latency_ms >= 0.0
    assert topo_health.details["subnets_count"] == 4

    # Active Directory check
    ad_health = checker.check_active_directory()
    assert ad_health.status == HealthStatus.HEALTHY
    assert ad_health.details["users_count"] >= 5

    # SIEM Collector check
    siem_health = checker.check_siem_collector()
    assert siem_health.status == HealthStatus.HEALTHY
    assert "stored_events" in siem_health.details

    # Detection Engine check
    det_health = checker.check_detection_engine()
    assert det_health.status == HealthStatus.HEALTHY
    assert det_health.details["registered_rules"] >= 30

    # Web application tier check
    app_health = checker.check_web_application_tier()
    assert app_health.status == HealthStatus.HEALTHY
    assert app_health.details["http_status"] == "ONLINE"


def test_health_report_serialization():
    """Verify DeepHealthReport serialization to dictionary."""
    checker = DeepHealthChecker()
    report = checker.check_all()
    rep_dict = report.to_dict()

    assert rep_dict["overall_status"] == "healthy"
    assert rep_dict["total_components"] == 7
    assert len(rep_dict["components"]) == 7
    assert "timestamp" in rep_dict
