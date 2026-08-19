"""Pytest Test Configuration and Shared Fixtures."""

import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from src.core.config import LabSettings
from src.core.topology import EnterpriseLabTopology
from src.detection.engine import DetectionEngine
from src.detection.storage import AlertStore
from src.infra.ad_directory.server import ActiveDirectoryServer
from src.infra.linux_server.service import LinuxServerService
from src.siem.app import create_siem_app
from src.siem.collector import SIEMCollector
from src.siem.storage import EventStore
from src.vulnapp.app import create_app
from src.vulnapp.telemetry import AppTelemetryClient


@pytest.fixture
def lab_topology():
    return EnterpriseLabTopology()


@pytest.fixture
def event_store():
    return EventStore(max_capacity=1000)


@pytest.fixture
def alert_store():
    return AlertStore(max_capacity=1000)


@pytest.fixture
def detection_engine(alert_store):
    return DetectionEngine(alert_store=alert_store)


@pytest.fixture
def siem_collector(event_store, detection_engine):
    return SIEMCollector(store=event_store, detection_engine=detection_engine)


@pytest.fixture
def siem_client(siem_collector, event_store, detection_engine, alert_store):
    app = create_siem_app(
        store=event_store, engine=detection_engine, alerts=alert_store
    )
    return TestClient(app)


@pytest.fixture
def ad_server(siem_collector):
    return ActiveDirectoryServer(siem_collector=siem_collector)


@pytest.fixture
def linux_service(siem_collector):
    return LinuxServerService(siem_collector=siem_collector)


@pytest.fixture
def vuln_app_client(siem_collector):
    telemetry = AppTelemetryClient(local_collector=siem_collector)
    app = create_app(
        database_url="sqlite:///:memory:",
        telemetry_client=telemetry,
        enable_vulnerabilities=True,
    )
    return TestClient(app)
