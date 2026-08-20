# Enterprise Attack Detection & Response Lab: Testing & Quality Assurance Guide

## 1. Overview

The platform implements a multi-tiered test suite ensuring that all infrastructure models, ECS telemetry normalization pipelines, detection rules, automated investigation engines, and SOAR response playbooks function reliably and predictably.

```
       Unit Tests (Pytest) ───────────► Infrastructure & Normalization Tests
              │                                      │
              ▼                                      ▼
    Security Hardening Tests ─────────► MITRE ATT&CK Simulation Tests
              │                                      │
              ▼                                      ▼
   End-to-End SOC Workflow ───────────► Deep Health & Isolation Scripts
```

---

## 2. Running Automated Tests

### 2.1 Full Pytest Test Suite
To run all unit, security, and integration tests with verbose output:

```bash
python3 -m pytest -v
```

### 2.2 Subsystem-Specific Test Suites

| Component | Target Test Path | Description |
|---|---|---|
| **SOC Metrics Engine** | `pytest tests/unit/test_soc_metrics.py -v` | Validates MTTD, MTTR, detection rate, false positive rate, coverage calculations. |
| **Deep Health Diagnostics** | `pytest tests/unit/test_system_health.py -v` | Validates health checks across all 7 lab infrastructure components. |
| **Multi-Format Incident Reporting** | `pytest tests/unit/test_incident_reporting.py -v` | Validates Markdown, JSON, and self-contained HTML report synthesis across 12 sections. |
| **SOC Web Dashboard & API** | `pytest tests/unit/test_soc_dashboard.py -v` | Validates dashboard HTML UI and all REST endpoints (`/metrics`, `/alerts`, `/incidents`, `/audit`). |
| **Security Hardening & Isolation** | `pytest tests/unit/test_security_hardening.py -v` | Validates secret hygiene, safety guardrails, and non-overlapping subnets. |
| **End-to-End SOC Lifecycle** | `pytest tests/integration/test_end_to_end_soc_workflow.py -v` | Executes full workflow: Simulation -> Alert -> Incident -> Response -> Report -> Metrics. |

---

## 3. Automated Validation & Diagnostic Scripts

### 3.1 Network Isolation Verification
Validates that firewall policies, trust zones, and IP allocations strictly isolate internal subnets from untrusted networks:

```bash
python3 cli.py validate
# or
python3 scripts/validate_isolation.py
```

### 3.2 Deep System Health Diagnostics
Validates operational readiness of Active Directory, Linux SSH, Web App, SIEM Ingestion, and Detection Engine:

```bash
python3 cli.py health
# or
python3 scripts/healthcheck.py
```

### 3.3 Attack Simulation & MITRE Coverage Validation
Executes all 24 attack scenarios and 6 benign controls, generating a live MITRE ATT&CK coverage table:

```bash
python3 cli.py coverage
# Export JSON matrix
python3 cli.py coverage --json
```
