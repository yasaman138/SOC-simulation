# Enterprise Attack Detection & Response Lab: MITRE ATT&CK Coverage Matrix

## 1. Executive Summary

This document provides a comprehensive mapping of the Enterprise Detection Engine's 30 Sigma-aligned detection rules and corresponding automated simulation scenarios to the **MITRE ATT&CK Framework (Enterprise v14)**.

The lab achieves **100% detection coverage** across 10 distinct MITRE ATT&CK tactics, backed by deterministic attack simulation scenarios and negative control tests.

```
       Initial Access ────────► Execution ────────► Persistence
            │                       │                   │
            ▼                       ▼                   ▼
    Privilege Escalation ──► Defense Evasion ──► Credential Access
            │                       │                   │
            ▼                       ▼                   ▼
        Discovery ────────► Lateral Movement ──► Collection
                                    │                   │
                                    ▼                   ▼
                              Command & Control ──► Impact
```

---

## 2. Complete Tactic & Technique Coverage Matrix

| Tactic | Technique ID | Technique Name | Subtechnique | Rule ID | Rule Severity | Telemetry Data Source | Simulation Scenario ID |
|---|---|---|---|---|---|---|---|
| **Initial Access** | `T1190` | Exploit Public-Facing Application | N/A | `DET-INIT-001` | High | `enterprise.web_portal` | `SCN-INIT-001` |
| **Initial Access** | `T1133` | External Remote Services | N/A | `DET-INIT-002` | High | `linux.sshd` | `SCN-INIT-002` |
| **Execution** | `T1059` | Command and Scripting Interpreter | `T1059.004` (Unix Shell) | `DET-EXEC-001` | High | `linux.auditd` | `SCN-EXEC-001` |
| **Execution** | `T1059` | Command and Scripting Interpreter | `T1059.001` (PowerShell) | `DET-EXEC-002` | Medium | `windows.sysmon` | `SCN-EXEC-002` |
| **Execution** | `T1569` | System Services | `T1569.002` (Service Execution) | `DET-EXEC-003` | High | `windows.security_auditing` | `SCN-EXEC-003` |
| **Persistence** | `T1053` | Scheduled Task/Job | `T1053.003` (Cron) | `DET-PERSIST-001` | Medium | `linux.auditd` | `SCN-PERSIST-001` |
| **Persistence** | `T1078` | Valid Accounts | `T1078.002` (Domain Accounts) | `DET-PERSIST-002` | High | `windows.security_auditing` | `SCN-PERSIST-002` |
| **Persistence** | `T1543` | Create or Modify System Process | `T1543.002` (systemd Service) | `DET-PERSIST-003` | High | `linux.auditd` | `SCN-PERSIST-003` |
| **Privilege Escalation** | `T1548` | Abuse Elevation Control Mechanism | `T1548.003` (Sudo Abuse) | `DET-PRV-001` | High | `linux.syslog_auth` | `SCN-PRIVESC-001` |
| **Privilege Escalation** | `T1068` | Exploitation for Privilege Escalation | N/A | `DET-PRV-002` | Critical | `linux.auditd` | `SCN-PRIVESC-002` |
| **Defense Evasion** | `T1070` | Indicator Removal | `T1070.002` (Clear Linux Logs) | `DET-DEF-001` | High | `linux.auditd` | `SCN-DEF-001` |
| **Defense Evasion** | `T1562` | Impair Defenses | `T1562.001` (Disable Security Tools) | `DET-DEF-002` | Critical | `linux.auditd` | `SCN-DEF-002` |
| **Defense Evasion** | `T1027` | Obfuscated/Encrypted Files | `T1027.002` (Software Packing) | `DET-DEF-003` | Medium | `windows.sysmon` | `SCN-DEF-003` |
| **Credential Access** | `T1110` | Brute Force | `T1110.001` (Password Guessing) | `DET-AUTH-001` | High | `windows.security_auditing` | `SCN-CRED-001` |
| **Credential Access** | `T1558` | Steal or Forge Kerberos Tickets | `T1558.003` (Kerberoasting) | `DET-CRED-002` | High | `windows.security_auditing` | `SCN-CRED-002` |
| **Credential Access** | `T1003` | OS Credential Dumping | `T1003.008` (`/etc/shadow`) | `DET-CRED-003` | Critical | `linux.auditd` | `SCN-CRED-003` |
| **Credential Access** | `T1003` | OS Credential Dumping | `T1003.001` (LSASS Memory) | `DET-CRED-004` | Critical | `windows.sysmon` | `SCN-CRED-004` |
| **Discovery** | `T1087` | Account Discovery | `T1087.002` (Domain Account) | `DET-DISC-001` | Low | `windows.security_auditing` | `SCN-DISC-001` |
| **Discovery** | `T1082` | System Information Discovery | N/A | `DET-DISC-002` | Low | `linux.auditd` | `SCN-DISC-002` |
| **Discovery** | `T1046` | Network Service Discovery | N/A | `DET-DISC-003` | Medium | `enterprise.web_portal` | `SCN-DISC-003` |
| **Lateral Movement** | `T1021` | Remote Services | `T1021.004` (SSH Lateral Pivot) | `DET-AUTH-003` | High | `linux.sshd` | `SCN-LAT-001` |
| **Lateral Movement** | `T1021` | Remote Services | `T1021.002` (SMB/Windows Admin Shares) | `DET-LAT-002` | High | `windows.security_auditing` | `SCN-LAT-002` |
| **Lateral Movement** | `T1570` | Lateral Tool Transfer | N/A | `DET-LAT-003` | Medium | `linux.auditd` | `SCN-LAT-003` |
| **Lateral Movement** | `T1021` | Remote Services | `T1021.006` (WinRM) | `DET-LAT-004` | High | `windows.sysmon` | `SCN-LAT-004` |
| **Collection** | `T1560` | Archive Collected Data | `T1560.001` (Archive via Utility) | `DET-COLL-001` | Medium | `linux.auditd` | `SCN-COLL-001` |
| **Collection** | `T1005` | Data from Local System | N/A | `DET-COLL-002` | Medium | `enterprise.web_portal` | `SCN-COLL-002` |
| **Command and Control** | `T1071` | Application Layer Protocol | `T1071.001` (Web Protocols) | `DET-C2-001` | High | `enterprise.web_portal` | `SCN-C2-001` |
| **Command and Control** | `T1573` | Encrypted Channel | `T1573.002` (Asymmetric Cryptography) | `DET-C2-002` | High | `linux.auditd` | `SCN-C2-002` |
| **Command and Control** | `T1572` | Protocol Tunneling | N/A | `DET-C2-003` | High | `linux.sshd` | `SCN-C2-003` |
| **Impact** | `T1499` | Endpoint Denial of Service | `T1499.004` (Application Exhaustion) | `DET-IMP-001` | High | `enterprise.web_portal` | `SCN-IMP-001` |
| **Impact** | `T1485` | Data Destruction | N/A | `DET-IMP-002` | Critical | `linux.auditd` | `SCN-IMP-002` |

---

## 3. Benign Negative Control Scenarios (False Positive Validation)

To ensure high-fidelity alerting without false-positive fatigue, the platform tests 6 benign operational workflows:

| Control ID | Operational Activity | Expected Detection Result | Verification Status |
|---|---|---|---|
| `SCN-BENIGN-001` | Routine System Administrator SSH Login and Health Query | **NO ALERT** (0 alerts) | Verified Clean |
| `SCN-BENIGN-002` | Automated Scheduled Backup Job via Rsync/Tar | **NO ALERT** (0 alerts) | Verified Clean |
| `SCN-BENIGN-003` | Legitimate User Web Portal Browsing & Search | **NO ALERT** (0 alerts) | Verified Clean |
| `SCN-BENIGN-004` | Standard Service Account Kerberos TGT Renewal | **NO ALERT** (0 alerts) | Verified Clean |
| `SCN-BENIGN-005` | Developer Git Pull & Package Compilation | **NO ALERT** (0 alerts) | Verified Clean |
| `SCN-BENIGN-006` | Monitoring Agent Metric Polling over HTTP API | **NO ALERT** (0 alerts) | Verified Clean |
