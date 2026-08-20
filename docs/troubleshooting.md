# Enterprise Attack Detection & Response Lab: Troubleshooting & Operations Guide

## 1. Overview

This troubleshooting guide addresses common operational scenarios, diagnostic procedures, port binding conflicts, and remediation steps encountered during lab operation.

---

## 2. Common Issues & Remediation Steps

### Issue 1: Port Binding Conflict (EADDRINUSE)
**Symptoms:** Uvicorn or SIEM Collector fails to start with `[Errno 98] Address already in use`.

**Remediation:**
1. Check which process is occupying the conflicting port:
   ```bash
   sudo lsof -i :8088  # SIEM Collector & Web Dashboard
   sudo lsof -i :8000  # Enterprise Web Application
   sudo lsof -i :2222  # Linux SSH Server
   sudo lsof -i :5514  # Syslog UDP Listener
   ```
2. Terminate the conflicting process or modify default port settings in your environment:
   ```bash
   export LAB_SIEM_HTTP_PORT=8090
   export LAB_APP_PORT=8001
   ```

---

### Issue 2: Missed Detections or Zero Alerts Generated
**Symptoms:** Running `python3 cli.py simulate` finishes with 0 alerts in `alert_store`.

**Diagnosis & Remediation:**
1. Ensure the detection rules engine is evaluating the correct event store:
   ```bash
   python3 cli.py detections
   ```
2. Verify that telemetry events were successfully ingested and normalized:
   ```bash
   curl http://localhost:8088/api/v1/stats
   ```
3. Trigger manual detection rule re-evaluation:
   ```bash
   curl -X POST http://localhost:8088/api/v1/detections/evaluate
   ```

---

### Issue 3: In-Memory Stores Reset or Empty After CLI Invocations
**Symptoms:** Alerts generated in a previous one-off CLI command are not visible in subsequent commands.

**Explanation & Remediation:**
- One-off CLI commands (e.g. `simulate`, `investigate`) instantiate isolated ephemeral stores for deterministic testing.
- To maintain persistent live state across simulations, start the centralized background server daemon:
  ```bash
  python3 cli.py serve --port 8088
  ```
  Then interact with the platform through the Web Dashboard at `http://localhost:8088/dashboard` or REST API endpoints.

---

### Issue 4: Health Check Diagnostics Reporting DEGRADED
**Symptoms:** `python3 cli.py health` reports one or more degraded components.

**Remediation:**
Run the deep diagnostic suite to inspect specific subsystem latency and errors:
```bash
curl http://localhost:8088/api/v1/health/deep
```
- **Active Directory Failure:** Verify that `dc01.corp.enterprise.local` host configuration is loaded in `src/core/config.py`.
- **Database Failure:** Reset SQLite test database by removing temporary test files in `tests/fixtures/`.
