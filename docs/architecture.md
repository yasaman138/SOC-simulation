# Enterprise Attack Detection & Response Lab - Target Architecture

## 1. Executive Overview

The **Enterprise Attack Detection & Response Lab** provides a reproducible, isolated miniature enterprise environment for simulating realistic cyber attacks, engineering telemetry pipelines, developing behavioral detection rules, and executing automated incident response workflows.

Phase 1 establishes the foundational infrastructure, network segmentation, identity services, compute targets, intentionally vulnerable applications, and centralized security monitoring stack.

---

## 2. Architectural Tiers and Zones

The lab is divided into four distinct network security zones, each with dedicated trust levels and firewall enforcement policies:

```
+-----------------------------------------------------------------------------------+
|                        Simulation / External DMZ (172.28.10.0/24)                |
|  - Attacker Simulation Node / External Client                                     |
|  - Edge Reverse Proxy (edge-proxy.lab.local: 172.28.10.5)                         |
+------------------------------------------+----------------------------------------+
                                           | HTTP (80/443)
                                           v
+-----------------------------------------------------------------------------------+
|                      Application & Data Tier (172.28.30.0/24)                     |
|  - Enterprise Web Portal & API (portal.app.local: 172.28.30.10:8000)              |
|  - Relational Database (db01.app.local: 172.28.30.20:5432)                        |
|  * Intentionally Vulnerable Testing Targets (SQLi, CMDi, BOLA, LDAPi, SSRF)       |
+----------------------+-----------------------------------+------------------------+
                       | LDAP Auth (389)                   | Structured Telemetry
                       v                                   v
+----------------------------------------------+ +----------------------------------+
|    Corporate Internal (172.28.20.0/24)       | | Security Monitoring (172.28.90/24|
|  - AD Domain Controller (dc01: 172.28.20.10) | | - Centralized SIEM & Telemetry   |
|  - Linux Server (linux-srv01: 172.28.20.15)  | |   Aggregator (siem: 172.28.90.10)|
|  - Windows Workstation (wkstn-win10)         | |   * HTTP Ingest (8088)           |
+----------------------+-----------------------+ |   * Syslog UDP (5514)            |
                       | Syslog / Auditd Logs  | |   * ECS Normalization Engine     |
                       +-----------------------> +----------------------------------+
```

### 2.1 Simulation / External DMZ (`172.28.10.0/24`)
- **Trust Level**: `UNTRUSTED` (0)
- **Role**: Simulates external attacker vantage points and public Internet clients.
- **Components**:
  - `edge-proxy.lab.local` (`172.28.10.5`): Reverse proxy routing simulation traffic to internal web services without directly exposing backend infrastructure.

### 2.2 Application & Data Tier (`172.28.30.0/24`)
- **Trust Level**: `SEMI_TRUSTED_APP` (10)
- **Role**: Houses web application frontends and internal database backends. Isolated from direct corporate internal domain access except for specific authentication queries.
- **Components**:
  - `portal.app.local` (`172.28.30.10`): FastAPI enterprise web portal and intentionally vulnerable target.
  - `db01.app.local` (`172.28.30.20`): Relational database storage.

### 2.3 Corporate Internal Network (`172.28.20.0/24`)
- **Trust Level**: `INTERNAL_TRUSTED` (50)
- **Role**: Core enterprise infrastructure hosting identity services, Domain Controllers, internal file/bastion servers, and administrative workstations.
- **Components**:
  - `dc01.corp.enterprise.local` (`172.28.20.10`): Active Directory Domain Controller (`CORP.ENTERPRISE.LOCAL`).
  - `linux-srv01.corp.enterprise.local` (`172.28.20.15`): Enterprise Linux server with SSH daemon and auditd.
  - `wkstn-win10.corp.enterprise.local` (`172.28.20.25`): Windows 10 workstation.

### 2.4 Security & Monitoring Management Network (`172.28.90.0/24`)
- **Trust Level**: `SECURITY_MANAGEMENT` (100)
- **Role**: Dedicated out-of-band management subnet for telemetry collection, SIEM aggregation, and security analytics.
- **Components**:
  - `siem.secmon.local` (`172.28.90.10`): Centralized SIEM aggregator receiving Syslog (5514/UDP) and JSON HTTP events (8088/TCP).

---

## 3. Trust Boundaries and Isolation Policy

1. **External Isolation**: The External Simulation network cannot directly route traffic to Corporate Internal (`172.28.20.0/24`) or Security Management (`172.28.90.0/24`).
2. **Application Isolation**: The Application Tier cannot access SSH (2222) or administrative interfaces on the Corporate Internal network.
3. **Security Ingestion**: All tiers can forward telemetry to the SIEM on designated ports (8088/TCP, 5514/UDP). The SIEM cannot be manipulated from external networks.
