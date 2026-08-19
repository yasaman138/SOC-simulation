"""Intentionally Vulnerable and Standard Enterprise API Endpoints."""

import os
import re
import shlex
import subprocess
import urllib.parse
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session
from src.core.logging import get_logger
from src.siem.models import EventCategory, EventOutcome, EventSeverity
from src.vulnapp.database import ConfidentialDocument, Employee, PortalUser
from src.vulnapp.telemetry import AppTelemetryClient

logger = get_logger("vulnapp.api")
router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class PingRequest(BaseModel):
    target: str


class WebhookTestRequest(BaseModel):
    url: str


def get_telemetry_client(request: Request) -> AppTelemetryClient:
    return getattr(
        request.app.state,
        "telemetry_client",
        AppTelemetryClient(),
    )


def get_db(request: Request):
    SessionLocal = request.app.state.db_session
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/health", tags=["Health"])
def health_check(
    request: Request, db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Health check endpoint validating application and DB status."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {e}"

    return {
        "status": "healthy",
        "service": "enterprise-web-portal",
        "database": db_status,
        "vulnerabilities_enabled": getattr(
            request.app.state, "enable_vulnerabilities", True
        ),
    }


@router.post("/api/v1/auth/login", tags=["Authentication"])
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """User authentication endpoint emitting login audit telemetry."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = (
        db.query(PortalUser)
        .filter(PortalUser.username == req.username)
        .first()
    )

    is_valid = user and (
        req.password in user.password_hash or req.password == "LabPassword123!"
    )

    if is_valid:
        telemetry.send_event(
            action="portal.auth.login.success",
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.INFORMATIONAL,
            outcome=EventOutcome.SUCCESS,
            message=f"Portal login successful for user '{req.username}'",
            source_ip=client_ip,
            user_name=req.username,
            http_method="POST",
            http_url="/api/v1/auth/login",
            http_status=200,
        )
        return {
            "status": "authenticated",
            "username": req.username,
            "role": user.role,
            "token": f"simulated-jwt-token-for-{req.username}",
        }
    else:
        telemetry.send_event(
            action="portal.auth.login.failure",
            category=EventCategory.AUTHENTICATION,
            severity=EventSeverity.MEDIUM,
            outcome=EventOutcome.FAILURE,
            message=f"Portal login failed for user '{req.username}': Invalid credentials",
            source_ip=client_ip,
            user_name=req.username,
            http_method="POST",
            http_url="/api/v1/auth/login",
            http_status=401,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )


@router.get("/api/v1/employees/search", tags=["Vulnerable: SQL Injection"])
def search_employees(
    query: str = Query(..., description="Employee search term (Name/Dept)"),
    request: Request = None,
    db: Session = Depends(get_db),
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """Search employee directory.

    [INTENTIONAL VULNERABILITY]: SQL Injection
    - Target: Internal database tier (app-db)
    - Vulnerability: Unsanitized string concatenation in SQL query.
    - Detection Signal: SQL syntax keywords, comment characters (--), UNION constructs.
    - Purpose: Generate telemetry for SQL injection detection rules in Phase 2.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    vulnerabilities_enabled = getattr(
        request.app.state, "enable_vulnerabilities", True
    )

    is_suspicious = any(
        sqli in query.upper()
        for sqli in ["UNION", "SELECT", "--", "OR 1=1", "' OR '", ";", "DROP"]
    )
    severity = (
        EventSeverity.HIGH if is_suspicious else EventSeverity.INFORMATIONAL
    )

    telemetry.send_event(
        action="portal.db.query.search",
        category=EventCategory.DATABASE,
        severity=severity,
        outcome=EventOutcome.SUCCESS,
        message=f"Employee search query executed: '{query}'",
        source_ip=client_ip,
        http_method="GET",
        http_url=f"/api/v1/employees/search?query={urllib.parse.quote(query)}",
        http_status=200,
        custom={"query_string": query, "sqli_detected": is_suspicious},
    )

    if vulnerabilities_enabled:
        # Intentionally vulnerable raw string query execution (for lab detection telemetry)
        raw_sql = f"SELECT id, emp_id, full_name, email, department, role, salary, ssn FROM employees WHERE full_name LIKE '%{query}%' OR department LIKE '%{query}%'"
        try:
            result = db.execute(text(raw_sql))  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
            rows = []
            for row in result:
                rows.append(
                    {
                        "id": row[0],
                        "emp_id": row[1],
                        "full_name": row[2],
                        "email": row[3],
                        "department": row[4],
                        "role": row[5],
                        "salary": row[6],
                        "ssn": row[7],
                    }
                )
            return {"query": query, "count": len(rows), "results": rows}
        except Exception as e:
            return {"query": query, "error": str(e), "results": []}
    else:
        # Secure parameterized implementation
        stmt = text(
            "SELECT id, emp_id, full_name, email, department, role, salary, ssn FROM employees WHERE full_name LIKE :q OR department LIKE :q"
        )
        result = db.execute(stmt, {"q": f"%{query}%"})
        rows = [
            {
                "id": r[0],
                "emp_id": r[1],
                "full_name": r[2],
                "email": r[3],
                "department": r[4],
                "role": r[5],
                "salary": r[6],
                "ssn": r[7],
            }
            for r in result
        ]
        return {"query": query, "count": len(rows), "results": rows}


@router.post("/api/v1/tools/ping", tags=["Vulnerable: Command Injection"])
def network_ping_tool(
    req: PingRequest,
    request: Request,
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """Network diagnostic ping utility.

    [INTENTIONAL VULNERABILITY]: Command Injection
    - Target: Application host container (portal.app.local)
    - Vulnerability: Unsanitized input passed to shell command execution.
    - Detection Signal: Shell metacharacters (| ; & ` $), process spawning (whoami, id, /bin/sh).
    - Purpose: Generate telemetry for Linux RCE and command injection detections.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    target = req.target
    vulnerabilities_enabled = getattr(
        request.app.state, "enable_vulnerabilities", True
    )

    is_suspicious = any(
        meta in target for meta in [";", "|", "&", "`", "$", "\n", ">", "<"]
    )
    severity = (
        EventSeverity.CRITICAL if is_suspicious else EventSeverity.INFORMATIONAL
    )

    telemetry.send_event(
        action="portal.tool.ping.exec",
        category=EventCategory.PROCESS,
        severity=severity,
        outcome=EventOutcome.SUCCESS,
        message=f"Network diagnostic ping tool invoked for target: '{target}'",
        source_ip=client_ip,
        http_method="POST",
        http_url="/api/v1/tools/ping",
        http_status=200,
        custom={"raw_target": target, "injection_detected": is_suspicious},
    )

    if vulnerabilities_enabled and is_suspicious:
        # Simulate shell execution safely within python sandbox without destroying host
        output = f"PING {target} (simulated 56 data bytes)\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.04 ms\n"
        # If commands are chained, simulate output for safe common commands
        if "whoami" in target:
            output += "www-data\n"
        elif "id" in target:
            output += "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
        elif "cat /etc/passwd" in target or "/etc/passwd" in target:
            output += "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        elif "hostname" in target:
            output += "portal.app.local\n"
        else:
            output += "[Command injection executed in simulated environment]\n"

        return {"target": target, "status": "executed", "output": output}
    else:
        # Clean ping output
        clean_ip = re.sub(r"[^0-9a-zA-Z\.\-]", "", target)
        return {
            "target": clean_ip,
            "status": "success",
            "output": f"PING {clean_ip} 56(84) bytes of data.\n64 bytes from {clean_ip}: icmp_seq=1 ttl=64 time=0.452 ms\n1 packets transmitted, 1 received, 0% packet loss",
        }


@router.get(
    "/api/v1/documents/{doc_id}",
    tags=["Vulnerable: Broken Object-Level Authorization"],
)
def get_confidential_document(
    doc_id: str,
    request: Request,
    user_id: int = Query(
        1, description="Current authenticated user ID (simulated session)"
    ),
    db: Session = Depends(get_db),
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """Retrieve confidential corporate document.

    [INTENTIONAL VULNERABILITY]: BOLA / IDOR (Broken Object-Level Authorization)
    - Target: Application data tier
    - Vulnerability: No authorization check validating requesting user ownership.
    - Detection Signal: User accessing documents owned by another department or user_id.
    - Purpose: Generate telemetry for unauthorized data access and exfiltration.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    doc = (
        db.query(ConfidentialDocument)
        .filter(ConfidentialDocument.doc_id == doc_id)
        .first()
    )

    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    is_unauthorized_access = doc.owner_id != user_id
    severity = (
        EventSeverity.MEDIUM
        if is_unauthorized_access
        else EventSeverity.INFORMATIONAL
    )

    telemetry.send_event(
        action="portal.doc.access",
        category=EventCategory.WEB,
        severity=severity,
        outcome=EventOutcome.SUCCESS,
        message=f"Document '{doc_id}' accessed by user_id {user_id} (Owner: {doc.owner_id})",
        source_ip=client_ip,
        http_method="GET",
        http_url=f"/api/v1/documents/{doc_id}",
        http_status=200,
        custom={
            "doc_id": doc_id,
            "owner_id": doc.owner_id,
            "requester_id": user_id,
            "unauthorized_bola": is_unauthorized_access,
        },
    )

    return {
        "doc_id": doc.doc_id,
        "title": doc.title,
        "classification": doc.classification,
        "content": doc.content,
        "owner_id": doc.owner_id,
    }


@router.get(
    "/api/v1/auth/directory-lookup", tags=["Vulnerable: LDAP Injection"]
)
def directory_lookup(
    user: str = Query(..., description="LDAP user query string"),
    request: Request = None,
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """Simulated Active Directory LDAP lookup endpoint.

    [INTENTIONAL VULNERABILITY]: LDAP Injection
    - Target: Corporate Active Directory Domain Controller (dc01.corp.enterprise.local)
    - Vulnerability: Unsanitized filter concatenation in LDAP query.
    - Detection Signal: LDAP wildcard query (*), filter break characters (&, |, !).
    - Purpose: Generate telemetry for LDAP enumeration and active directory probing.
    """
    client_ip = request.client.host if request and request.client else "127.0.0.1"
    is_suspicious = any(c in user for c in ["*", ")(", ")|(", "|", "&", "!"])

    severity = (
        EventSeverity.HIGH if is_suspicious else EventSeverity.INFORMATIONAL
    )

    telemetry.send_event(
        action="portal.ad.ldap.lookup",
        category=EventCategory.DIRECTORY_SERVICE,
        severity=severity,
        outcome=EventOutcome.SUCCESS,
        message=f"LDAP directory lookup query: '{user}'",
        source_ip=client_ip,
        http_method="GET",
        http_url=f"/api/v1/auth/directory-lookup?user={urllib.parse.quote(user)}",
        http_status=200,
        custom={"ldap_filter": user, "ldap_injection": is_suspicious},
    )

    # Simulated LDAP response
    if is_suspicious or user == "*":
        return {
            "filter": f"(&(objectClass=user)(sAMAccountName={user}))",
            "results_count": 5,
            "entries": [
                {
                    "sAMAccountName": "Administrator",
                    "displayName": "Built-in Administrator",
                    "mail": "administrator@corp.enterprise.local",
                },
                {
                    "sAMAccountName": "da_johnson",
                    "displayName": "David Johnson (Domain Admin)",
                    "mail": "djohnson.admin@corp.enterprise.local",
                },
                {
                    "sAMAccountName": "jdoe",
                    "displayName": "John Doe",
                    "mail": "jdoe@corp.enterprise.local",
                },
                {
                    "sAMAccountName": "svc_sql",
                    "displayName": "Service Account - MSSQL",
                    "spn": "MSSQLSvc/db01.corp.enterprise.local:1433",
                },
            ],
        }
    else:
        return {
            "filter": f"(&(objectClass=user)(sAMAccountName={user}))",
            "results_count": 1,
            "entries": [
                {
                    "sAMAccountName": user,
                    "displayName": f"Corporate User ({user})",
                    "mail": f"{user}@corp.enterprise.local",
                }
            ],
        }


@router.post("/api/v1/integrations/webhook-test", tags=["Vulnerable: SSRF"])
def test_webhook(
    req: WebhookTestRequest,
    request: Request,
    telemetry: AppTelemetryClient = Depends(get_telemetry_client),
) -> Dict[str, Any]:
    """Test outbound webhook connectivity.

    [INTENTIONAL VULNERABILITY]: Server-Side Request Forgery (SSRF)
    - Target: Internal enterprise network and cloud metadata
    - Vulnerability: Unrestricted outbound HTTP requests allowing internal subnet probing.
    - Detection Signal: Requests to 127.0.0.1, 169.254.169.254, 172.28.20.0/24 (Corp Net), or 172.28.90.0/24 (SIEM).
    - Purpose: Generate telemetry for SSRF and internal reconnaissance detection.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    target_url = req.url

    is_internal_target = any(
        internal in target_url
        for internal in [
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            "172.28.20.",
            "172.28.90.",
            "dc01.corp.enterprise.local",
        ]
    )

    severity = (
        EventSeverity.CRITICAL
        if is_internal_target
        else EventSeverity.INFORMATIONAL
    )

    telemetry.send_event(
        action="portal.integration.webhook.dispatch",
        category=EventCategory.NETWORK,
        severity=severity,
        outcome=EventOutcome.SUCCESS,
        message=f"Webhook test dispatched to destination URL: '{target_url}'",
        source_ip=client_ip,
        http_method="POST",
        http_url="/api/v1/integrations/webhook-test",
        http_status=200,
        custom={"target_url": target_url, "ssrf_detected": is_internal_target},
    )

    return {
        "url": target_url,
        "status": "simulated_dispatch_success",
        "ssrf_target_detected": is_internal_target,
        "response_code": 200,
        "latency_ms": 12.4,
    }
