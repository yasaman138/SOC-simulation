"""FastAPI Application exposing SIEM HTTP Ingestion, Query, Detection, Incident Response, and Dashboard APIs."""

from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from src.core.config import settings
from src.core.health import DeepHealthChecker
from src.core.metrics import SOCMetricsCalculator
from src.detection.engine import DetectionEngine
from src.detection.models import Alert, AlertQuery, AlertStatus
from src.detection.storage import AlertStore
from src.response.automation import ResponseAutomationEngine
from src.response.investigation import InvestigationEngine
from src.response.models import Incident, IncidentQuery, ResponseActionType
from src.response.playbooks import (
    CredentialCompromisePlaybook,
    LateralMovementPlaybook,
    MalwareRansomwarePlaybook,
)
from src.response.reporting import IncidentReportGenerator
from src.response.storage import AuditStore, IncidentStore
from src.siem.collector import SIEMCollector
from src.siem.dashboard import render_dashboard_html
from src.siem.models import ECSEvent, EventCategory, EventQuery, EventSeverity
from src.siem.storage import EventStore

# Global singletons
event_store = EventStore()
alert_store = AlertStore()
incident_store = IncidentStore()
audit_store = AuditStore()

detection_engine = DetectionEngine(alert_store=alert_store)
siem_collector = SIEMCollector(
    store=event_store, detection_engine=detection_engine
)
investigation_engine = InvestigationEngine(
    event_store=event_store, alert_store=alert_store
)
automation_engine = ResponseAutomationEngine(
    audit_store=audit_store, siem_collector=siem_collector
)


class StatusUpdateRequest(BaseModel):
    status: AlertStatus
    note: Optional[str] = Field(default=None, max_length=1000)


class PlaybookExecutionRequest(BaseModel):
    playbook_type: str = Field(default="credential", max_length=50)
    actor: str = Field(default="soar_automation", max_length=100)


class SimulationRunRequest(BaseModel):
    scenario: Optional[str] = Field(default=None, max_length=100)
    attack: Optional[bool] = Field(default=True)
    benign: Optional[bool] = Field(default=False)
    create_incident: Optional[bool] = Field(default=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start UDP syslog listener if configured
    await siem_collector.start_udp_listener(
        host=settings.siem_host,
        port=settings.siem_syslog_udp_port,
    )
    yield
    # Shutdown: Stop collector
    siem_collector.stop()


def create_siem_app(
    store: Optional[EventStore] = None,
    engine: Optional[DetectionEngine] = None,
    alerts: Optional[AlertStore] = None,
    incidents: Optional[IncidentStore] = None,
    audits: Optional[AuditStore] = None,
) -> FastAPI:
    """Create and configure the SIEM & SOC FastAPI application."""
    active_store = store or event_store
    active_alerts = alerts or alert_store
    active_incidents = incidents or incident_store
    active_audits = audits or audit_store

    active_engine = engine or (
        detection_engine if alerts is None else DetectionEngine(alert_store=active_alerts)
    )
    active_collector = (
        siem_collector
        if (store is None and engine is None)
        else SIEMCollector(store=active_store, detection_engine=active_engine)
    )

    active_inv = InvestigationEngine(event_store=active_store, alert_store=active_alerts)
    active_auto = ResponseAutomationEngine(audit_store=active_audits, siem_collector=active_collector)
    active_metrics = SOCMetricsCalculator(
        event_store=active_store,
        alert_store=active_alerts,
        incident_store=active_incidents,
        audit_store=active_audits,
    )
    active_health = DeepHealthChecker(
        event_store=active_store,
        alert_store=active_alerts,
        detection_engine=active_engine,
        siem_collector=active_collector,
        incident_store=active_incidents,
        audit_store=active_audits,
    )

    app = FastAPI(
        title="Enterprise Lab SIEM & SOC Operations Platform",
        description="Unified SIEM Collector, MITRE ATT&CK Detection Engine, Incident Response Workbench, and Real-Time Dashboard.",
        version="0.5.0",
        lifespan=lifespan,
    )

    # Security Headers Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        )
        return response

    # ---------------- SOC Web Dashboard Endpoints ----------------

    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    @app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
    def get_dashboard() -> str:
        """Render interactive SOC Analyst Web Dashboard and Investigation Workbench."""
        return render_dashboard_html()

    # ---------------- Health & Observability Endpoints ----------------

    @app.get("/health", tags=["Health"])
    def health_check() -> Dict[str, Any]:
        """Basic service health check."""
        return {
            "status": "healthy",
            "service": "siem-soc-platform",
            "version": "0.5.0",
            "stored_events": active_store.count(),
            "active_alerts": active_alerts.count(),
            "active_incidents": active_incidents.count(),
            "active_detection_rules": len(active_engine.list_rules()),
            "udp_active": active_collector.is_running,
        }

    @app.get("/api/v1/health/deep", tags=["Health"])
    def deep_health_check() -> Dict[str, Any]:
        """Run deep diagnostics across all 7 lab infrastructure and security subsystems."""
        return active_health.check_all().to_dict()

    @app.get("/metrics", tags=["Metrics"])
    @app.get("/api/v1/metrics/soc", tags=["Metrics"])
    def get_soc_metrics() -> Dict[str, Any]:
        """Get live calculated security metrics (MTTD, MTTR, detection rate, false positive rate, coverage)."""
        return active_metrics.calculate_metrics().to_dict()

    # ---------------- Telemetry Ingestion Endpoints ----------------

    @app.post(
        "/api/v1/events",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_event(event: ECSEvent) -> Dict[str, Any]:
        """Ingest a single normalized ECS security event and evaluate detection rules."""
        event_id = active_collector.ingest_event(event)
        return {"status": "success", "event_id": event_id}

    MAX_BATCH_SIZE = 500

    @app.post(
        "/api/v1/events/batch",
        status_code=status.HTTP_201_CREATED,
        tags=["Ingestion"],
    )
    def ingest_batch(events: List[ECSEvent]) -> Dict[str, Any]:
        """Ingest multiple ECS events in a single batch with real-time detection analysis."""
        if len(events) > MAX_BATCH_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Batch size {len(events)} exceeds maximum limit of {MAX_BATCH_SIZE} events per request.",
            )
        ids = []
        for ev in events:
            ev_id = active_collector.ingest_event(ev)
            ids.append(ev_id)
        return {
            "status": "success",
            "count": len(ids),
            "event_ids": ids,
        }

    @app.get("/api/v1/events", tags=["Query"])
    def query_events(
        category: Optional[EventCategory] = None,
        action: Optional[str] = None,
        severity: Optional[EventSeverity] = None,
        host_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_name: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> Dict[str, Any]:
        """Query and filter stored telemetry events."""
        q = EventQuery(
            category=category,
            action=action,
            severity=severity,
            host_name=host_name,
            source_ip=source_ip,
            user_name=user_name,
            search=search,
            limit=limit,
            offset=offset,
        )
        results = active_store.query_events(q)
        return {
            "total_matching": len(results),
            "limit": limit,
            "offset": offset,
            "events": [e.to_dict() for e in results],
        }

    @app.get("/api/v1/stats", tags=["Metrics"])
    def get_stats() -> Dict[str, Any]:
        """Get summary statistics of stored telemetry."""
        return active_store.get_stats()

    @app.delete("/api/v1/events", tags=["Management"])
    def clear_events() -> Dict[str, str]:
        """Clear all stored events (for lab reset/testing)."""
        active_store.clear()
        return {"status": "success", "message": "Event store cleared"}

    # ---------------- Detection Engine Endpoints ----------------

    @app.get("/api/v1/detections", tags=["Detections"])
    def list_detections() -> Dict[str, Any]:
        """List all active detection rules with MITRE ATT&CK mappings."""
        rules = active_engine.list_rules()
        return {
            "total_rules": len(rules),
            "rules": [r.to_metadata_dict() for r in rules],
        }

    @app.get("/api/v1/detections/{rule_id}", tags=["Detections"])
    def get_detection(rule_id: str) -> Dict[str, Any]:
        """Retrieve details of a specific detection rule by ID."""
        rule = active_engine.get_rule(rule_id)
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection rule '{rule_id}' not found",
            )
        return rule.to_metadata_dict()

    @app.post("/api/v1/detections/evaluate", tags=["Detections"])
    def trigger_evaluation() -> Dict[str, Any]:
        """Manually trigger detection rule evaluation across all stored events."""
        alerts = active_engine.evaluate_store(active_store)
        return {
            "status": "success",
            "alerts_generated": len(alerts),
            "alert_ids": [a.id for a in alerts],
        }

    # ---------------- Attack Simulation Endpoints ----------------

    @app.post("/api/v1/simulation/run", tags=["Simulation"])
    @app.post("/api/v1/simulation/simulate", tags=["Simulation"])
    def run_simulation(
        request: Optional[SimulationRunRequest] = None,
        scenario: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute attack simulation scenarios and ingest real telemetry into SIEM platform."""
        from fastapi.testclient import TestClient
        from src.infra.ad_directory.server import ActiveDirectoryServer
        from src.infra.linux_server.service import LinuxServerService
        from src.simulation.models import SimulationContext
        from src.simulation.registry import ScenarioRegistry
        from src.simulation.runner import SimulationRunner
        from src.vulnapp.app import create_app
        from src.vulnapp.telemetry import AppTelemetryClient

        target_scenario_id = scenario or (request.scenario if request else None)
        run_attack = request.attack if request and request.attack is not None else True
        run_benign = request.benign if request and request.benign is not None else False
        auto_incident = request.create_incident if request and request.create_incident is not None else True

        ad = ActiveDirectoryServer(siem_collector=active_collector)
        linux = LinuxServerService(siem_collector=active_collector)
        telemetry = AppTelemetryClient(local_collector=active_collector)
        vuln_app = create_app(
            database_url="sqlite:///:memory:",
            telemetry_client=telemetry,
            enable_vulnerabilities=True,
        )
        vuln_client = TestClient(vuln_app)

        sim_context = SimulationContext(
            siem_collector=active_collector,
            event_store=active_store,
            alert_store=active_alerts,
            detection_engine=active_engine,
            ad_server=ad,
            linux_service=linux,
            vuln_client=vuln_client,
            dry_run=False,
        )

        registry = ScenarioRegistry()
        runner = SimulationRunner(registry=registry)

        if target_scenario_id:
            scn = registry.get_scenario(target_scenario_id)
            if not scn:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Scenario '{target_scenario_id}' not found",
                )
            target_scenarios = [scn]
        elif run_benign and not run_attack:
            target_scenarios = registry.list_scenarios(is_benign=True)
        elif run_attack and not run_benign:
            target_scenarios = registry.list_scenarios(is_benign=False)
        else:
            target_scenarios = registry.list_scenarios()

        results = runner.run_all(sim_context, scenarios=target_scenarios)
        report = runner.generate_coverage_report(results)

        incident_id = None
        if auto_incident:
            current_alerts = active_alerts.query_alerts()
            if current_alerts and active_incidents.count() == 0:
                top_alert = current_alerts[0]
                inc = active_inv.create_incident_from_alert(top_alert)
                active_incidents.add_incident(inc)
                incident_id = inc.incident_id

        return {
            "status": "success",
            "scenarios_executed": len(results),
            "passed_scenarios": sum(1 for _, _, val in results if val.passed),
            "total_telemetry_events": active_store.count(),
            "total_alerts": active_alerts.count(),
            "total_incidents": active_incidents.count(),
            "auto_promoted_incident_id": incident_id,
            "coverage_summary": report.summary,
        }

    @app.get("/api/v1/simulation/scenarios", tags=["Simulation"])
    def list_simulation_scenarios() -> Dict[str, Any]:
        """List registered simulation attack scenarios and benign controls."""
        from src.simulation.registry import ScenarioRegistry
        reg = ScenarioRegistry()
        scenarios = reg.list_scenarios()
        return {
            "total_scenarios": len(scenarios),
            "scenarios": [s.to_metadata_dict() for s in scenarios],
        }

    # ---------------- Security Alerts Endpoints ----------------

    @app.get("/api/v1/alerts", tags=["Alerts"])
    def query_alerts(
        severity: Optional[EventSeverity] = None,
        rule_id: Optional[str] = None,
        status: Optional[AlertStatus] = None,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> Dict[str, Any]:
        """Query and filter security alerts produced by detection engine."""
        q = AlertQuery(
            severity=severity,
            rule_id=rule_id,
            status=status,
            host_name=host_name,
            user_name=user_name,
            source_ip=source_ip,
            search=search,
            limit=limit,
            offset=offset,
        )
        results = active_alerts.query_alerts(q)
        return {
            "total_matching": len(results),
            "limit": limit,
            "offset": offset,
            "alerts": [a.to_dict() for a in results],
        }

    @app.get("/api/v1/alerts/stats", tags=["Alerts"])
    def get_alert_stats() -> Dict[str, Any]:
        """Get summary metrics of security alerts by severity, MITRE tactic, and status."""
        return active_alerts.get_stats()

    @app.get("/api/v1/alerts/{alert_id}", tags=["Alerts"])
    def get_alert(alert_id: str) -> Dict[str, Any]:
        """Retrieve full details and source events for a specific alert."""
        alert = active_alerts.get_alert(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found",
            )
        return alert.to_dict()

    @app.patch("/api/v1/alerts/{alert_id}", tags=["Alerts"])
    def update_alert_status(
        alert_id: str, update: StatusUpdateRequest
    ) -> Dict[str, Any]:
        """Update triage/investigation status of an alert."""
        success = active_alerts.update_status(
            alert_id=alert_id, status=update.status, note=update.note
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found",
            )
        return {"status": "success", "alert_id": alert_id, "new_status": update.status.value}

    @app.delete("/api/v1/alerts", tags=["Alerts"])
    def clear_alerts() -> Dict[str, str]:
        """Clear all stored alerts (for lab reset/testing)."""
        active_alerts.clear()
        return {"status": "success", "message": "Alert store cleared"}

    # ---------------- Incident Management & Investigation Endpoints ----------------

    @app.get("/api/v1/incidents", tags=["Incidents"])
    def query_incidents(
        search: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> Dict[str, Any]:
        """Query and list stored security incidents."""
        q = IncidentQuery(search=search, limit=limit, offset=offset)
        incidents = active_incidents.query_incidents(q)
        return {
            "total_matching": len(incidents),
            "limit": limit,
            "offset": offset,
            "incidents": [i.to_dict() for i in incidents],
        }

    @app.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
    def get_incident(incident_id: str) -> Dict[str, Any]:
        """Retrieve full details of a specific incident."""
        inc = active_incidents.get_incident(incident_id)
        if not inc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )
        return inc.to_dict()

    @app.post("/api/v1/incidents/investigate/{alert_id}", tags=["Incidents"])
    def trigger_investigation(alert_id: str) -> Dict[str, Any]:
        """Promote an Alert into an Incident and execute automated multi-source correlation."""
        alert = active_alerts.get_alert(alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found to investigate",
            )
        incident = active_inv.create_incident_from_alert(alert)
        active_incidents.add_incident(incident)
        return {
            "status": "success",
            "incident_id": incident.incident_id,
            "title": incident.title,
            "timeline_events": len(incident.timeline),
            "indicators": len(incident.indicators),
        }

    @app.post("/api/v1/incidents/{incident_id}/respond", tags=["Incidents"])
    def execute_incident_response(
        incident_id: str, request: PlaybookExecutionRequest
    ) -> Dict[str, Any]:
        """Execute automated response playbook on an incident."""
        inc = active_incidents.get_incident(incident_id)
        if not inc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

        playbooks = {
            "credential": CredentialCompromisePlaybook(),
            "lateral": LateralMovementPlaybook(),
            "malware": MalwareRansomwarePlaybook(),
        }

        pb = playbooks.get(request.playbook_type.lower())
        if not pb:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid playbook '{request.playbook_type}'. Options: credential, lateral, malware",
            )

        resolved_inc = pb.execute(
            incident=inc,
            investigation_engine=active_inv,
            automation_engine=active_auto,
            actor=request.actor,
        )
        active_incidents.update_incident(resolved_inc)

        return {
            "status": "success",
            "incident_id": resolved_inc.incident_id,
            "playbook_executed": pb.name,
            "containment_status": resolved_inc.containment_status.value,
            "remediation_status": resolved_inc.remediation_status.value,
            "recovery_status": resolved_inc.recovery_status.value,
            "final_disposition": resolved_inc.final_disposition.value,
        }

    @app.get("/api/v1/reports/incident/{incident_id}", tags=["Reporting"])
    def get_incident_report(
        incident_id: str,
        format: str = Query(default="html", pattern="^(html|md|json)$"),
    ) -> Response:
        """Fetch structured Incident Report in HTML, Markdown, or JSON."""
        inc = active_incidents.get_incident(incident_id)
        if not inc:
            # Check for demo incident ID fallback if not present in runtime store
            if incident_id.startswith("INC-DEMO"):
                from src.response.models import IncidentSeverity, IncidentStatus, ContainmentStatus, RemediationStatus, RecoveryStatus, IncidentDisposition
                inc = Incident(
                    incident_id=incident_id,
                    title="Kerberoasting and Domain Escalation",
                    description="Demonstration security incident for report preview.",
                    severity=IncidentSeverity.HIGH,
                    status=IncidentStatus.RECOVERED,
                    containment_status=ContainmentStatus.CONTAINED,
                    remediation_status=RemediationStatus.REMEDIATED,
                    recovery_status=RecoveryStatus.VERIFIED,
                    final_disposition=IncidentDisposition.TRUE_POSITIVE_MALICIOUS,
                    affected_assets=["dc01.corp.enterprise.local", "172.28.20.10"],
                    affected_users=["svc_sql", "jdoe"],
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Incident '{incident_id}' not found",
                )

        if format == "json":
            return Response(
                content=IncidentReportGenerator.to_json(inc),
                media_type="application/json",
            )
        elif format == "md":
            return PlainTextResponse(
                content=IncidentReportGenerator.to_markdown(inc),
                media_type="text/markdown",
            )
        else:
            return HTMLResponse(
                content=IncidentReportGenerator.to_html(inc),
            )

    @app.get("/api/v1/audit", tags=["SOAR"])
    def query_audit_logs(
        action: Optional[ResponseActionType] = None,
        actor: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> Dict[str, Any]:
        """Query immutable audit log of automated and analyst response actions."""
        entries = active_audits.list_entries(
            action=action, actor=actor, target=target, limit=limit
        )
        return {
            "total_matching": len(entries),
            "entries": [e.to_dict() for e in entries],
        }

    return app


app = create_siem_app()
