# Enterprise Attack Detection & Response Lab: Threat Model

## 1. Overview & System Scope

This document defines the formal threat model for the Enterprise Attack Detection & Response Lab. The threat model follows the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) and evaluates trust boundaries, adversary profiles, vulnerable entry points, and defensive security controls across all lab network zones.

---

## 2. System Assets & Criticality Classification

| Asset Category | Target System | IP Address | Trust Level | Security Sensitivity | Description |
|---|---|---|---|---|---|
| **Identity / Core** | `dc01.corp.enterprise.local` | `172.28.20.10` | Tier 0 (Highest) | **CRITICAL** | Active Directory Domain Controller, Kerberos KDC, LDAP directory, SAM/NTDS database. |
| **Corporate Server** | `linux-srv01.corp.enterprise.local` | `172.28.20.15` | Tier 1 (Internal) | **HIGH** | Linux server hosting administrative bastion services, SSH daemon, and Linux audit logging. |
| **Application Tier** | `app.corp.enterprise.local` | `172.28.30.10` | Tier 2 (App DMZ) | **HIGH** | Enterprise Web Portal and REST API handling business workflows and database access. |
| **Data Storage** | `db01.corp.enterprise.local` | `172.28.30.20` | Tier 1 (Internal) | **CRITICAL** | Core relational database store containing employee, financial, and operational records. |
| **Monitoring** | `siem.corp.enterprise.local` | `172.28.90.10` | Tier 0 (Isolated) | **CRITICAL** | Central telemetry ingestion hub, ECS normalization pipeline, detection engine, and alert store. |
| **External DMZ** | `attacker-node.lab.local` | `172.28.10.100` | Untrusted | **LOW** | Attack simulation execution node and offensive traffic source. |

---

## 3. Trust Boundaries & Network Segmentation

The lab enforces strict trust segmentation across four distinct subnets:

```
[ External DMZ (172.28.10.0/24) ] ── (Untrusted) ──> [ Edge Reverse Proxy (172.28.10.5) ]
                                                              │ (HTTP:8000 Forwarding)
                                                              ▼
                                              [ Application Tier (172.28.30.0/24) ]
                                                  │ (SQL:5432)        │ (LDAP:389)
                                                  ▼                   ▼
                                      [ Core DB (172.28.30.20) ]  [ AD Domain Controller (172.28.20.10) ]
                                                                          ▲
                                                                          │ (SSH:2222 / Syslog)
                                                                  [ Corporate Core (172.28.20.0/24) ]
                                                                          │
                                                                          │ (HTTP:8088 / UDP:5514)
                                                                          ▼
                                                                  [ SIEM Monitoring (172.28.90.0/24) ]
```

### Trust Boundary Rules:
1. **External to Internal Traffic:** All direct external traffic to `172.28.20.0/24` (Corporate Core) is dropped by firewall policies. Inbound external access is restricted to the Edge Reverse Proxy in the DMZ.
2. **App-Tier to Directory Services:** Web application nodes in `172.28.30.0/24` may communicate with `dc01` strictly on TCP port 389 (LDAP) for authentication lookups.
3. **Management Egress to SIEM:** All nodes across all subnets have unidirectional egress access to `172.28.90.10` for security telemetry ingestion (HTTP port 8088, Syslog UDP port 5514). Reverse connections from SIEM to endpoints are prohibited except for authorized SOC management interfaces.

---

## 4. Threat Actor Profiles

| Threat Actor | Motivation | Capabilities & Tools | Target Objectives |
|---|---|---|---|
| **External Cybercriminal** | Financial extortion, data theft | Automated web scanners, SQLMap, Burp Suite, Hydra | Initial access via web app vulnerabilities, ransomware deployment, database exfiltration. |
| **Advanced Persistent Threat (APT)** | Espionage, persistence, credential harvesting | Mimikatz, Impacket, ProcDump, BloodHound, Living-off-the-Land Binaries (LOLBins) | Active Directory domain dominance, Kerberoasting, Golden Ticket creation, cross-subnet lateral movement. |
| **Malicious Insider / Rogue Operator** | Sabotage, privilege abuse | Sudo abuse, unauthorized SSH access, audit log destruction | Privilege escalation on Linux infrastructure, deletion of forensic evidence. |

---

## 5. STRIDE Threat Analysis Matrix

| Threat Category | Target Subsystem | Attack Scenario / Vector | Defensive Countermeasure | Detection Rule |
|---|---|---|---|---|
| **Spoofing** | Active Directory (Kerberos) | Pass-the-Hash / Ticket Forgery / Golden Ticket | Kerberos PAC validation, KDC ticket encryption enforcement (AES-256) | `DET-CRED-001`, `DET-CRED-003` |
| **Tampering** | Linux Host (`linux-srv01`) | Sudoers modification, audit log shredding (`shred /var/log/audit/audit.log`) | Immutable auditd kernel rules, remote rsyslog forwarding to SIEM | `DET-DEF-001`, `DET-DEF-002`, `DET-IMP-002` |
| **Repudiation** | Enterprise Web Portal | Unauthenticated API abuse, BOLA/IDOR object tampering | Structured ECS logging with source IP, session ID, user agent | `DET-INIT-001`, `DET-INIT-002` |
| **Information Disclosure** | Active Directory / Database | Kerberoasting SPN ticket extraction, SQL injection database dumping | Strict SPN auditing, parameterized queries, DB encryption | `DET-CRED-002`, `DET-INIT-001` |
| **Denial of Service** | Application / Core Services | SYN flood, resource exhaustion, database lockouts | Rate limiting, connection limits, SOAR auto-containment | `DET-IMP-001` |
| **Elevation of Privilege** | Linux Bastion / Workstations | Sudo abuse, SUID binary exploitation, LSASS process memory dump | Least privilege group policies, EDR process injection blocking | `DET-PRV-001`, `DET-PRV-002`, `DET-CRED-004` |

---

## 6. Security Assumptions & Residual Risks

### Architectural Assumptions:
- All offensive simulations are strictly confined to the allocated `172.28.0.0/16` lab address space.
- The SIEM collector event store and detection rules engine operate as trusted security control components.
- Automated SOAR playbooks require explicit analyst verification before applying permanent destructive recovery actions.

### Residual Risks in Lab Context:
- Lab components emulate enterprise protocols in software (e.g., simulated Active Directory KDC and Linux SSH service) for reproducible testing in CI/CD and container environments.
- In-memory event stores are sized for development and portfolio demonstration; production scaling requires distributed streaming backends (e.g., Kafka, OpenSearch).
