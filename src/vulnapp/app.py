"""FastAPI Application Factory for Enterprise Portal & API."""

from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from src.core.logging import get_logger
from src.vulnapp.api.endpoints import router
from src.vulnapp.config import app_settings
from src.vulnapp.database import init_db
from src.vulnapp.telemetry import AppTelemetryClient

logger = get_logger("vulnapp.app")


def create_app(
    database_url: Optional[str] = None,
    telemetry_client: Optional[AppTelemetryClient] = None,
    enable_vulnerabilities: bool = True,
) -> FastAPI:
    """Create and configure the FastAPI web application."""
    db_url = database_url or app_settings.database_url
    engine, SessionLocal = init_db(db_url)

    app = FastAPI(
        title=app_settings.app_name,
        description="Miniature Enterprise Web Portal and Intentionally Vulnerable Testing Target for Detection Lab.",
        version="0.1.0",
    )

    # Attach state
    app.state.db_engine = engine
    app.state.db_session = SessionLocal
    app.state.telemetry_client = (
        telemetry_client
        or AppTelemetryClient(siem_endpoint=app_settings.siem_endpoint)
    )
    app.state.enable_vulnerabilities = enable_vulnerabilities

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8080",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://127.0.0.1:8080",
            "http://edge-proxy.lab.local",
            "http://portal.app.local",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Register API routes
    app.include_router(router)

    return app


app = create_app()
