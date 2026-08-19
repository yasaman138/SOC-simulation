# Intentional Vulnerabilities Catalog & Threat Modeling

## Overview

This repository represents a defensive security research lab. Specific application and infrastructure vulnerabilities are intentionally introduced to serve as realistic attack simulation targets for telemetry generation, detection engineering, and incident response testing in subsequent phases.

All intentionally vulnerable components are strictly isolated within the Application Tier (`172.28.30.0/24`) and configured so they cannot compromise the host system or external networks.

---

## Catalog of Intentional Lab Vulnerabilities

### 1. SQL Injection (SQLi)
- **Component / Endpoint**: `GET /api/v1/employees/search?query=...`
- **Target**: Internal Application Database (`db01.app.local` / `172.28.30.20`)
- **Vulnerability Mechanism**: Dynamic string concatenation in SQL queries without parameterization.
- **Attack Vector**:
  ```http
  GET /api/v1/employees/search?query=' UNION SELECT id, emp_id, full_name, email, department, role, salary, ssn FROM employees --
  ```
- **MITRE ATT&CK Mapping**:
  - Tactic: *Initial Access* / *Credential Access* / *Collection*
  - Technique: `T1190` (Exploit Public-Facing Application) / `T1005` (Data from Local System)
- **Telemetry & Detection Signal**:
  - Web application emits structured event `portal.db.query.search` (Category: `database`).
  - Presence of SQL keywords (`UNION`, `SELECT`, `OR 1=1`), comment characters (`--`), and query execution errors.
- **Remediation Strategy**: Use parameterized SQL queries (`db.execute(stmt, {'q': query})`) and ORM-backed access controls.
- **Isolation Safeguards**: Database container is isolated in `app_tier_net` without external exposure.

---

### 2. Command Injection (OS RCE)
- **Component / Endpoint**: `POST /api/v1/tools/ping` (Payload: `{"target": "127.0.0.1; whoami"}`)
- **Target**: Application Host Container (`portal.app.local` / `172.28.30.10`)
- **Vulnerability Mechanism**: Unsanitized user input passed into shell command execution.
- **Attack Vector**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/tools/ping -H 'Content-Type: application/json' -d '{"target": "127.0.0.1; whoami"}'
  ```
- **MITRE ATT&CK Mapping**:
  - Tactic: *Execution*
  - Technique: `T1059.004` (Command and Scripting Interpreter: Unix Shell)
- **Telemetry & Detection Signal**:
  - Application emits structured event `portal.tool.ping.exec` (Category: `process`, Severity: `critical`).
  - Linux auditd execve logs and process tree spawns (`sh`, `bash`, `whoami`, `id`).
- **Remediation Strategy**: Avoid invoking subshells; sanitize and validate strict IP formats (`re.match(r"^[0-9\.]+$", ip)`); use dedicated system ping libraries.
- **Isolation Safeguards**: Container runs as unprivileged `www-data` without root elevation or host filesystem mounts.

---

### 3. Broken Object-Level Authorization (BOLA / IDOR)
- **Component / Endpoint**: `GET /api/v1/documents/{doc_id}?user_id=...`
- **Target**: Confidential Document Repository
- **Vulnerability Mechanism**: Application fails to verify that the requesting user's identity owns or has authorized access to the requested document ID.
- **Attack Vector**:
  ```http
  GET /api/v1/documents/DOC-9003?user_id=1
  ```
- **MITRE ATT&CK Mapping**:
  - Tactic: *Collection* / *Exfiltration*
  - Technique: `T1530` (Data from Cloud / Web Application Storage)
- **Telemetry & Detection Signal**:
  - Application emits event `portal.doc.access` (Category: `web`) indicating `owner_id != requester_id`.
  - High volume access to non-sequential document IDs by a single user session.
- **Remediation Strategy**: Implement server-side authorization checks comparing document ownership and role-based access control (RBAC) before returning object data.

---

### 4. LDAP Injection / Directory Enumeration
- **Component / Endpoint**: `GET /api/v1/auth/directory-lookup?user=...`
- **Target**: Active Directory Domain Controller (`dc01.corp.enterprise.local`)
- **Vulnerability Mechanism**: Unsanitized search filter concatenation allowing wildcard directory enumeration.
- **Attack Vector**:
  ```http
  GET /api/v1/auth/directory-lookup?user=*
  ```
- **MITRE ATT&CK Mapping**:
  - Tactic: *Discovery*
  - Technique: `T1087.002` (Account Discovery: Domain Account) / `T1069.002` (Permission Groups Discovery: Domain Groups)
- **Telemetry & Detection Signal**:
  - Event `portal.ad.ldap.lookup` (Category: `directory_service`, Severity: `high`).
  - High-frequency LDAP queries containing wildcards (`*`) or complex logical operators (`|`, `&`, `!`).
- **Remediation Strategy**: Escape LDAP filter metacharacters (`*`, `(`, `)`, `\`, `NUL`) and enforce strict search scopes.

---

### 5. Server-Side Request Forgery (SSRF)
- **Component / Endpoint**: `POST /api/v1/integrations/webhook-test` (Payload: `{"url": "http://172.28.20.10:8088"}`)
- **Target**: Corporate Internal & Security Management Subnets
- **Vulnerability Mechanism**: Unrestricted outbound HTTP requests allowing clients to query internal network services.
- **Attack Vector**:
  ```json
  {"url": "http://169.254.169.254/latest/meta-data/"}
  ```
- **MITRE ATT&CK Mapping**:
  - Tactic: *Reconnaissance* / *Lateral Movement*
  - Technique: `T1595` (Active Scanning) / `T1090` (Proxy)
- **Telemetry & Detection Signal**:
  - Event `portal.integration.webhook.dispatch` (Category: `network`, Severity: `critical`).
  - Outbound requests targeting RFC 1918 private subnets or cloud metadata IPs.
- **Remediation Strategy**: Implement URL allowlists and block internal IP ranges (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`).
- **Isolation Safeguards**: Firewall policies block outbound connections to arbitrary Internet addresses.
