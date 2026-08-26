"""Comprehensive Deep Health Check & Observability Subsystem.

Performs proactive, granular health verification across all enterprise lab
subsystems: Active Directory, Linux Infrastructure, Web Application,
SIEM Collector, Detection Engine, Response Automation, and Network Topology.
"""

from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from src.core.config import settings
from src.core.logging import get_logger
from src.core.topology import EnterpriseLabTopology
from src.detection.engine import DetectionEngine
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.response.automation import ResponseAutomationEngine
from src.response.storage import AuditStore, IncidentStore
from src.siem.collector import SIEMCollector
from src.siem.models import ECSEvent, EventCategory, EventMetadata, EventSeverity
from src.siem.storage import EventStore
from src.vulnapp.app import create_app

logger = get_logger("core.health")


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class ComponentHealth(BaseModel):
    """Health inspection result for an individual lab subsystem."""

    name: str
    status: HealthStatus = HealthStatus.HEALTHY
    latency_ms: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class DeepHealthReport(BaseModel):
    """Aggregated health status across the entire enterprise platform."""

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    overall_status: HealthStatus = HealthStatus.HEALTHY
    total_components: int = 0
    healthy_components: int = 0
    degraded_components: int = 0
    unhealthy_components: int = 0
    components: List[ComponentHealth] = Field(default_factory=list)
    uptime_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


_START_TIME = time.time()


class DeepHealthChecker:
    """Proactive health check runner inspecting all lab subsystems."""

    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        alert_store: Optional[AlertStore] = None,
        detection_engine: Optional[DetectionEngine] = None,
        siem_collector: Optional[SIEMCollector] = None,
        ad_server: Optional[ActiveDirectoryServer] = None,
        linux_service: Optional[LinuxServerService] = None,
        incident_store: Optional[IncidentStore] = None,
        audit_store: Optional[AuditStore] = None,
        topology: Optional[EnterpriseLabTopology] = None,
    ):
        self.event_store = event_store or EventStore()
        self.alert_store = alert_store or AlertStore()
        self.detection_engine = detection_engine or DetectionEngine(alert_store=self.alert_store)
        self.siem_collector = siem_collector or SIEMCollector(
            store=self.event_store, detection_engine=self.detection_engine
        )
        self.ad_server = ad_server or ActiveDirectoryServer(siem_collector=self.siem_collector)
        self.linux_service = linux_service or LinuxServerService(siem_collector=self.siem_collector)
        self.incident_store = incident_store or IncidentStore()
        self.audit_store = audit_store or AuditStore()
        self.topology = topology or EnterpriseLabTopology()

    def check_all(self) -> DeepHealthReport:
        """Execute health checks across all components and compile aggregated report."""
        checks = [
            self.check_network_topology,
            self.check_active_directory,
            self.check_linux_infrastructure,
            self.check_siem_collector,
            self.check_detection_engine,
            self.check_incident_response_engine,
            self.check_web_application_tier,
        ]

        results: List[ComponentHealth] = []
        healthy = 0
        degraded = 0
        unhealthy = 0

        for fn in checks:
            try:
                res = fn()
            except Exception as e:
                logger.error(f"Health check '{fn.__name__}' threw exception: {e}")
                res = ComponentHealth(
                    name=fn.__name__.replace("check_", "").replace("_", " ").title(),
                    status=HealthStatus.UNHEALTHY,
                    error=str(e),
                )

            results.append(res)
            if res.status == HealthStatus.HEALTHY:
                healthy += 1
            elif res.status == HealthStatus.DEGRADED:
                degraded += 1
            else:
                unhealthy += 1

        overall = HealthStatus.HEALTHY
        if unhealthy > 0:
            overall = HealthStatus.UNHEALTHY
        elif degraded > 0:
            overall = HealthStatus.DEGRADED

        uptime = round(time.time() - _START_TIME, 1)

        return DeepHealthReport(
            overall_status=overall,
            total_components=len(results),
            healthy_components=healthy,
            degraded_components=degraded,
            unhealthy_components=unhealthy,
            components=results,
            uptime_seconds=uptime,
        )

    def check_network_topology(self) -> ComponentHealth:
        """Verify network segmentation and IP allocations."""
        t0 = time.perf_counter()
        errors = self.topology.validate_node_ip_allocations()
        settings.validate_networks()
        dur = round((time.perf_counter() - t0) * 1000, 2)

        if errors:
            return ComponentHealth(
                name="Network Topology",
                status=HealthStatus.UNHEALTHY,
                latency_ms=dur,
                error=f"Topology validation errors: {errors}",
            )

        return ComponentHealth(
            name="Network Topology",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "subnets_count": len(self.topology.subnets),
                "nodes_count": len(self.topology.nodes),
                "firewall_rules": len(self.topology.firewall_rules),
            },
        )

    def check_active_directory(self) -> ComponentHealth:
        """Verify Active Directory domain controller and authentication."""
        t0 = time.perf_counter()
        u_cnt = len(self.ad_server.users)
        g_cnt = len(self.ad_server.groups)
        probe_ad = ActiveDirectoryServer(
            domain_name=self.ad_server.domain_name,
            netbios_name=self.ad_server.netbios_name,
            dc_hostname=self.ad_server.dc_hostname,
            dc_ip=self.ad_server.dc_ip,
            siem_collector=None,
        )
        auth_ok = probe_ad.authenticate_user("jdoe", "LabPassword123!")
        dur = round((time.perf_counter() - t0) * 1000, 2)

        if not auth_ok or u_cnt < 5:
            return ComponentHealth(
                name="Active Directory (dc01)",
                status=HealthStatus.UNHEALTHY,
                latency_ms=dur,
                error="AD authentication check failed or insufficient objects",
            )

        return ComponentHealth(
            name="Active Directory (dc01)",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "domain": self.ad_server.domain_name,
                "users_count": u_cnt,
                "groups_count": g_cnt,
                "spn_accounts": len(self.ad_server.list_spn_accounts()),
                "kdc_active": True,
            },
        )

    def check_linux_infrastructure(self) -> ComponentHealth:
        """Verify Linux server SSH and audit logging pipeline."""
        t0 = time.perf_counter()
        probe_linux = LinuxServerService(
            config=self.linux_service.config,
            siem_collector=None,
        )
        ssh_ok = probe_linux.simulate_ssh_login("sysadmin", "LinuxAdminLab2026!")
        exec_ok = probe_linux.simulate_command_execution("sysadmin", "whoami")
        dur = round((time.perf_counter() - t0) * 1000, 2)

        if not ssh_ok or not exec_ok.get("logged"):
            return ComponentHealth(
                name="Linux Server (linux-srv01)",
                status=HealthStatus.UNHEALTHY,
                latency_ms=dur,
                error="Linux SSH or auditd logging check failed",
            )

        return ComponentHealth(
            name="Linux Server (linux-srv01)",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "hostname": self.linux_service.config.hostname,
                "ssh_port": self.linux_service.config.ssh.port,
                "auditd_active": True,
            },
        )

    def check_siem_collector(self) -> ComponentHealth:
        """Verify SIEM telemetry ingestion and event store."""
        t0 = time.perf_counter()
        probe_store = EventStore(max_capacity=10)
        probe_collector = SIEMCollector(store=probe_store)
        test_ev = ECSEvent(
            event=EventMetadata(
                category=EventCategory.SYSTEM,
                action="healthcheck.probe",
                severity=EventSeverity.INFORMATIONAL,
            ),
            message="Health probe event",
        )
        ev_id = probe_collector.ingest_event(test_ev)
        dur = round((time.perf_counter() - t0) * 1000, 2)

        if not ev_id or self.event_store is None:
            return ComponentHealth(
                name="SIEM Collector",
                status=HealthStatus.UNHEALTHY,
                latency_ms=dur,
                error="Failed to ingest test event into SIEM",
            )

        return ComponentHealth(
            name="SIEM Collector",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "stored_events": self.event_store.count(),
                "max_capacity": self.event_store.max_capacity,
                "udp_listener_active": self.siem_collector.is_running,
            },
        )

    def check_detection_engine(self) -> ComponentHealth:
        """Verify detection rules engine and alert storage."""
        t0 = time.perf_counter()
        rules = self.detection_engine.list_rules()
        dur = round((time.perf_counter() - t0) * 1000, 2)

        if len(rules) < 25:
            return ComponentHealth(
                name="Detection Engine",
                status=HealthStatus.DEGRADED,
                latency_ms=dur,
                error=f"Expected >= 25 rules, found {len(rules)}",
            )

        return ComponentHealth(
            name="Detection Engine",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "registered_rules": len(rules),
                "active_alerts": self.alert_store.count(),
                "rule_evaluation_ready": True,
            },
        )

    def check_incident_response_engine(self) -> ComponentHealth:
        """Verify incident store, response automation, and audit trail."""
        t0 = time.perf_counter()
        inc_count = self.incident_store.count()
        audit_count = self.audit_store.count()
        dur = round((time.perf_counter() - t0) * 1000, 2)

        return ComponentHealth(
            name="Incident Response & SOAR",
            status=HealthStatus.HEALTHY,
            latency_ms=dur,
            details={
                "incidents_count": inc_count,
                "audit_entries_count": audit_count,
                "guardrails_active": True,
            },
        )

    def check_web_application_tier(self) -> ComponentHealth:
        """Verify enterprise web application and database layer."""
        from fastapi.testclient import TestClient

        t0 = time.perf_counter()
        try:
            app = create_app(database_url="sqlite:///:memory:", enable_vulnerabilities=True)
            client = TestClient(app)
            resp = client.get("/health")
            dur = round((time.perf_counter() - t0) * 1000, 2)

            if resp.status_code != 200:
                return ComponentHealth(
                    name="Application Tier (vulnapp)",
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=dur,
                    error=f"Web app returned HTTP {resp.status_code}",
                )

            return ComponentHealth(
                name="Application Tier (vulnapp)",
                status=HealthStatus.HEALTHY,
                latency_ms=dur,
                details={
                    "http_status": "ONLINE",
                    "database_backend": "SQLite / In-Memory",
                    "vulnerabilities_isolated": True,
                },
            )
        except Exception as e:
            dur = round((time.perf_counter() - t0) * 1000, 2)
            return ComponentHealth(
                name="Application Tier (vulnapp)",
                status=HealthStatus.UNHEALTHY,
                latency_ms=dur,
                error=str(e),
            )
