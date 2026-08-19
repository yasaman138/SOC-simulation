# Detection Engineering & Analytics Reference

## 1. Overview

The Enterprise Attack Detection & Response Lab features an analytics and detection pipeline capable of turning normalized security telemetry across all enterprise tiers into high-fidelity, actionable security alerts mapped to the **MITRE ATT&CK** framework.

---

## 2. Detection Pipeline Architecture

```
+-----------------------------------------------------------------------------------+
|                              Telemetry Sources                                    |
|   Windows/Sysmon     Active Directory       Linux/auditd/SSH     Enterprise Web   |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        Telemetry Ingestion & Parsers                              |
|   Syslog Parser      Windows Event Parser   Auditd Normalizer    HTTP Web API     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                       Central SIEM & Normalized Event Store                       |
|   Elastic Common Schema (ECS) Normalized Events + Searchable Store                |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                 Detection Engine                                  |
|   Rule Registry      Sliding Windows        Contextual Evaluator MITRE ATT&CK     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             Alerting & Triage Store                               |
|   Alert Store        REST API Endpoints     Triage & Timeline    Incident Records |
+-----------------------------------------------------------------------------------+
```

---

## 3. Normalized Telemetry Schema

Events conform to the Elastic Common Schema (ECS) standard with full context preservation:

| Field | Type | Description |
| :--- | :--- | :--- |
| `timestamp` | UTC DateTime | ISO-8601 UTC timestamp of event generation |
| `event.id` | UUID String | Unique event identifier |
| `event.category` | Enum | Category (`authentication`, `process`, `web`, `database`, `file`, `registry`, `dns`, `system`) |
| `event.action` | String | Specific activity action (e.g. `ad.logon.failed`, `linux.process.created`) |
| `event.outcome` | Enum | Outcome (`success`, `failure`, `unknown`) |
| `event.severity` | Enum | Severity rating (`informational`, `low`, `medium`, `high`, `critical`) |
| `host` | HostInfo | Target host details (`name`, `ip`, `os`) |
| `source` | EndpointInfo | Originating IP, port, or domain |
| `destination` | EndpointInfo | Target destination IP, port, or domain |
| `user` | UserInfo | Account name, domain, user ID, and assigned roles |
| `process` | ProcessInfo | Name, PID, PPID, command line, executable, parent name, hash |
| `http` | HTTPInfo | Method, URL, status code, user agent |
| `network` | NetworkInfo | Transport protocol, direction, bytes, packets |
| `dns` | DNSInfo | Query name, record type, resolved IPs, response code |
| `file` | FileInfo | File path, name, extension, size, hash, file action |
| `registry` | RegistryInfo | Registry key, value name, value data, action |
| `raw_event` | String | Unaltered original raw log string for forensic fidelity |
| `custom` | Dictionary | Source-specific extended metadata (Windows Event IDs, auditd records) |

---

## 4. Detection Rules Catalog

The detection engine implements 21 behavioral rules covering the adversary lifecycle:

### Authentication Abuse
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-AUTH-001` | Multiple Failed Logon Attempts | HIGH | T1110.001 | Detects repeated failed logons from single source or targeting accounts within correlation window. |
| `DET-AUTH-002` | Unauthorized / Disabled Account Logon | HIGH | T1078.003 | Detects interactive logon attempts against root or disabled accounts. |
| `DET-AUTH-003` | Suspicious Cross-Zone Remote Logon | HIGH | T1078 | Detects logon attempts to Domain Controllers originating from untrusted DMZ subnets. |

### PowerShell Abuse
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-PS-001` | Suspicious Encoded PowerShell Execution | HIGH | T1059.001 | Detects PowerShell executing with `-enc` / `-EncodedCommand` Base64 flags. |
| `DET-PS-002` | PowerShell Remote Download Cradle | HIGH | T1059.001 | Detects `DownloadString`, `Net.WebClient`, or `IEX` pulling remote scripts into memory. |
| `DET-PS-003` | PowerShell Execution Policy Bypass | MEDIUM | T1562.001 | Detects `-ExecutionPolicy Bypass` combined with `-w hidden` or `-nop`. |

### Credential Access
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-CRED-001` | Kerberoasting TGS Request | HIGH | T1558.003 | Detects Kerberos TGS-REQ (Event 4769) requesting weak RC4 encryption for user SPNs. |
| `DET-CRED-002` | Linux Sensitive Credential File Access | HIGH | T1003.008 | Detects unauthorized commands reading `/etc/shadow` or `/etc/gshadow`. |
| `DET-CRED-003` | LSASS Memory Dump & SAM Hive Export | CRITICAL | T1003.001 | Detects procdump targeting LSASS, comsvcs minidump, mimikatz, or `reg save HKLM\SAM`. |

### Process Execution
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-PROC-001` | Interactive Reverse Shell Execution | CRITICAL | T1059.004 | Detects `bash -i >& /dev/tcp`, `nc -e`, and socket redirection reverse shells. |
| `DET-PROC-002` | Living Off the Land Binary (LOLBin) Abuse | HIGH | T1218 | Detects certutil `-urlcache`, mshta http, bitsadmin, and curl/wget piping to shell. |
| `DET-PROC-003` | Web Server Spawning Command Shell | HIGH | T1059 | Detects web application workers spawning system shells or diagnostic tools. |

### Privilege Escalation
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-PRIVESC-001` | Sudoers File Modification | HIGH | T1548.003 | Detects edits to `/etc/sudoers` or `/etc/sudoers.d` configuring passwordless elevation. |
| `DET-PRIVESC-002` | SUID / SGID Bit Modification | HIGH | T1548.001 | Detects `chmod +s` or `chmod 4755` elevating executable file permissions. |
| `DET-PRIVESC-003` | Web Application SQL Injection | HIGH | T1190 | Detects SQL injection exploit patterns (`UNION SELECT`, authentication bypass) in web queries. |

### Lateral Movement
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-LAT-001` | Remote Service Creation / PsExec | HIGH | T1021.002 | Detects remote Windows service creation (`sc.exe create`) or PsExec execution. |
| `DET-LAT-002` | Cross-Subnet SSH Lateral Movement | HIGH | T1021.004 | Detects SSH connections originating from DMZ web servers into internal servers. |
| `DET-LAT-003` | Remote WinRM Lateral Execution | MEDIUM | T1021.006 | Detects `Enter-PSSession` or remote WinRM execution across internal endpoints. |

### Persistence
| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `DET-PERSIST-001` | Linux Cron Job Persistence | HIGH | T1053.003 | Detects scheduled task creation via `/etc/cron*` or systemd service units. |
| `DET-PERSIST-002` | Windows Registry Run Key Persistence | HIGH | T1547.001 | Detects additions to `CurrentVersion\Run` and `RunOnce` autostart registry keys. |
| `DET-PERSIST-003` | Unauthorized Local Account Creation | HIGH | T1136.001 | Detects local backdoor user creation (`useradd`, `net user /add`, Windows Event 4720). |

---

## 5. Synthetic Replayable Fixtures

Every detection rule is verified using synthetic test fixtures:
- **Positive Test Case**: Ingests realistic malicious telemetry that must trigger an alert.
- **Negative Test Case**: Ingests legitimate administrative telemetry that must NOT trigger an alert.
- **Validation**: Verifies alert metadata, severity rating, and MITRE technique association.

Fixtures are located in `src/detection/fixtures.py` and evaluated automatically via `tests/unit/test_detection_rules.py`.
