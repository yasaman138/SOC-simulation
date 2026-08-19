# Centralized Logging & Telemetry Architecture

## 1. Overview

The lab implements a centralized telemetry ingestion pipeline designed around the **Elastic Common Schema (ECS)** standard. All infrastructure components, application tiers, identity services, and operating systems emit normalized security events to the central SIEM Collector (`siem.secmon.local` / `172.28.90.10`).

---

## 2. Telemetry Ingestion & Detection Pipeline

```
+--------------------------+
|  Enterprise Web Portal   |----(HTTP JSON / POST /api/v1/events)----+
+--------------------------+                                          |
                                                                      v
+--------------------------+                               +--------------------+
| Active Directory (dc01)  |----(HTTP / Windows Security EventLog)-+ SIEM Collector |
+--------------------------+                               |  Port 8088 (HTTP)  |
                                                           |  Port 5514 (Syslog)|
+--------------------------+                               +---------+----------+
|  Linux Server (srv01)    |----(Syslog UDP RFC 3164 / 5424)----------+          |
+--------------------------+                                                    |
                                                                                v
                                                                   +--------------------+
                                                                   |  ECS Normalization |
                                                                   |     & Storage      |
                                                                   +---------+----------+
                                                                                |
                                                                                v
                                                                   +--------------------+
                                                                   |  Detection Engine  |
                                                                   | (21+ MITRE Rules)  |
                                                                   +---------+----------+
                                                                                |
                                                                                v
                                                                   +--------------------+
                                                                   |    Alert Store     |
                                                                   |  & Triage Endpoints|
                                                                   +--------------------+
```

---

## 3. Normalized ECS Event Schema

Every ingested event conforms to the following core ECS structure:

```json
{
  "timestamp": "2026-08-19T12:00:00.000Z",
  "event": {
    "id": "e4f0a28b-1132-4d2b-980b-1934981fa012",
    "kind": "event",
    "category": "authentication",
    "action": "ad.logon.failed",
    "outcome": "failure",
    "severity": "medium",
    "dataset": "windows.security_auditing"
  },
  "host": {
    "name": "dc01.corp.enterprise.local",
    "ip": "172.28.20.10",
    "os": "Windows Server 2022 Datacenter"
  },
  "source": {
    "ip": "172.28.20.25",
    "port": 49152
  },
  "destination": {
    "ip": "172.28.20.10",
    "port": 88
  },
  "user": {
    "name": "jdoe",
    "domain": "CORP"
  },
  "process": {
    "name": "lsass.exe",
    "pid": 680
  },
  "message": "Logon failure for user 'jdoe': Bad password.",
  "raw_event": "<Event xmlns=...>",
  "tags": ["active_directory", "authentication"],
  "custom": {
    "windows": {
      "event_id": 4625,
      "channel": "Security"
    }
  }
}
```

---

## 4. Telemetry Data Sources

| Source Identifier | Source Host | Protocol | Event Categories | Telemetry Emitted |
| :--- | :--- | :--- | :--- | :--- |
| `app-portal` | `172.28.30.10` | HTTP (`/api/v1/events`) | `web`, `database`, `process`, `network` | Authentication events, SQL queries, ping utility execution, document access, webhook dispatches |
| `corp-ad-dc01` | `172.28.20.10` | HTTP / Syslog | `authentication`, `directory_service` | Windows Security Events (4624 Logon, 4625 Failed Logon, 4768 Kerberos TGT, 4769 Kerberos TGS SPN ticket) |
| `corp-linux-srv01` | `172.28.20.15` | Syslog (UDP 5514) | `authentication`, `process`, `system` | OpenSSH daemon auth logs, Linux auditd execve process creation, Sudo elevation logs |

---

## 5. SIEM Collector API Endpoints

- `GET /health`: Healthcheck and status of event ingestion, detection engine, and alert count.
- `POST /api/v1/events`: Ingest single ECS event and evaluate detection rules in real time.
- `POST /api/v1/events/batch`: Ingest multiple ECS events in batch.
- `GET /api/v1/events`: Filtered query of stored security events (filter by category, action, severity, hostname, username, IP, or search string).
- `GET /api/v1/stats`: Telemetry count summary grouped by category and severity.
- `DELETE /api/v1/events`: Reset event store during lab reset and testing.

---

## 6. Detection & Alerting API Endpoints

- `GET /api/v1/detections`: List all registered detection rules with MITRE ATT&CK mappings.
- `GET /api/v1/detections/{rule_id}`: Retrieve metadata for a specific detection rule.
- `POST /api/v1/detections/evaluate`: Trigger detection analysis across stored telemetry events.
- `GET /api/v1/alerts`: Query generated security alerts with multi-attribute filtering.
- `GET /api/v1/alerts/{alert_id}`: Retrieve detailed alert record with context and source events.
- `PATCH /api/v1/alerts/{alert_id}`: Update alert triage status (`triaged`, `investigating`, `contained`, `closed`, `false_positive`).
- `GET /api/v1/alerts/stats`: Metrics summary of alerts grouped by severity, tactic, and rule.
- `DELETE /api/v1/alerts`: Reset alert store during lab reset and testing.
