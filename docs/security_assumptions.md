# Enterprise Attack Detection & Response Lab: Security Assumptions & Design Invariants

## 1. Executive Summary

This document establishes the security assumptions, design invariants, trust boundaries, and operational constraints governing the Enterprise Attack Detection & Response Lab.

---

## 2. Network & Boundary Assumptions

1. **Non-Routable Lab Subnets:** All lab communication takes place strictly within RFC 1918 private subnets allocated under `172.28.0.0/16`:
   - `172.28.10.0/24`: Simulation / DMZ Network (Trust Level: Untrusted)
   - `172.28.30.0/24`: Application Tier (Trust Level: App DMZ)
   - `172.28.20.0/24`: Corporate Internal & Directory Services (Trust Level: Internal Core)
   - `172.28.90.0/24`: Security Monitoring & SIEM (Trust Level: Isolated)

2. **Strict Safety Guardrail Enforcement (`LabSafetyGuardrail`):**
   - The platform strictly prohibits network interactions with any IP address outside `172.28.0.0/16` or `127.0.0.1`.
   - Public IP ranges (e.g., `8.8.8.8`, `1.1.1.1`), corporate external networks, and public domain names are rejected immediately at the automation boundary.

3. **Subnet Isolation:**
   - External nodes cannot initiate direct TCP/UDP sessions to internal nodes (`172.28.20.0/24`) without passing through the application gateway or reverse proxy in the DMZ.
   - Cross-subnet lateral movement generates high-severity telemetry alerts (`DET-AUTH-003`).

---

## 3. Telemetry & Detection Invariants

1. **Schema Normalization to Elastic Common Schema (ECS):**
   - All telemetry from disparate endpoints (Windows EventLog, Linux Auditd, Syslog, Web Application, Network Flow) is parsed and mapped into normalized ECS data structures prior to rule evaluation.
   - Fields such as `@timestamp`, `event.category`, `event.action`, `source.ip`, `destination.ip`, `user.name`, and `process.command_line` adhere to standardized types.

2. **Idempotent & Replayable Detections:**
   - Detection rules are pure evaluators over the `EventStore`. Running detection evaluations multiple times over identical event sets yields identical alert results without state mutation.

3. **Negative Control Baseline:**
   - A detection rule is not considered production-ready unless it has been validated against both positive attack scenarios and negative benign controls, confirming a 0% false positive rate under standard operational conditions.

---

## 4. Automated Incident Response & SOAR Guardrails

1. **Explicit Audit Logging for Every Action:**
   - Every containment, isolation, account lockout, or process termination action executed by the SOAR engine (`ResponseAutomationEngine`) writes an immutable entry to `AuditStore`.
   - Audit logs capture: `audit_id`, `timestamp`, `action_type`, `actor`, `target`, `result`, and `context`.

2. **Rollback Capability & Reversibility:**
   - Destructive or isolating actions (e.g., firewall IP block, host network isolation, account disablement) maintain undo state and implement reversible handlers.

3. **Protection of Critical Infrastructure (Crown Jewels):**
   - Safety checks prevent automated playbooks from disabling Tier 0 services (e.g., locking out `krbtgt` or shutting down `dc01.corp.enterprise.local`).
