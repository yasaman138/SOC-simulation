# Attack Simulation & Detection Validation Framework

## Overview

The **Attack Simulation & Detection Validation Framework** provides a safe, deterministic, and isolated mechanism for simulating real-world enterprise cyber attacks and validating the detection capabilities of the SIEM and detection engineering pipeline.

All simulations execute strictly against locally controlled laboratory infrastructure (`172.28.0.0/16`, `127.0.0.1`, and `*.corp.enterprise.local`) and generate realistic enterprise security telemetry across Active Directory, Linux auditd/SSHD, Windows Sysmon/PowerShell, and enterprise web application tiers.

---

## Safety Guardrails & Containment

Simulations adhere to containment boundaries enforced by the `LabSafetyGuardrail` component:

- **Approved Subnets**:
  - `172.28.10.0/24` (Simulation & DMZ)
  - `172.28.20.0/24` (Corporate Internal)
  - `172.28.30.0/24` (Web Application Tier)
  - `172.28.90.0/24` (Security Monitoring / SIEM)
  - `127.0.0.0/8` (Loopback)
  - `198.51.100.0/24` / `203.0.113.0/24` (RFC 5737 Synthetic Test Ranges)
- **Approved Domains**: `*.lab.local`, `*.corp.enterprise.local`, `*.app.local`
- **Boundary Enforcement**: Any operation targeting public or non-lab IP addresses raises a `SafetyBoundaryViolation` and immediately aborts execution.
- **Determinism & Cleanup**: Every scenario implements automated post-execution cleanup handlers to restore target systems to baseline state.

---

## MITRE ATT&CK Scenario Matrix

The framework provides comprehensive coverage across all 10 enterprise MITRE ATT&CK tactics:

| Tactic | Technique | Scenario ID | Scenario Name | Target Host | Expected Detection Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | T1190 | `SCN-INIT-001` | Web SQL Injection Exploitation | `portal.app.local` | `DET-PRIVESC-003` |
| **Initial Access** | T1078.003 | `SCN-INIT-002` | Unauthorized Direct Root SSH Logon | `srv01.corp.enterprise.local` | `DET-AUTH-002` |
| **Execution** | T1059 | `SCN-EXEC-001` | Web Diagnostic Command Injection | `portal.app.local` | `DET-PROC-003` |
| **Execution** | T1059.004 | `SCN-EXEC-002` | Interactive Network Reverse Shell | `srv01.corp.enterprise.local` | `DET-PROC-001` |
| **Execution** | T1059.001 | `SCN-EXEC-003` | Encoded Base64 PowerShell Execution | `wkstn01.corp.enterprise.local` | `DET-PS-001` |
| **Persistence** | T1053.003 | `SCN-PERSIST-001` | Linux Cron Job Backdoor Installation | `srv01.corp.enterprise.local` | `DET-PERSIST-001` |
| **Persistence** | T1547.001 | `SCN-PERSIST-002` | Registry Run Key Autostart Configuration | `wkstn01.corp.enterprise.local` | `DET-PERSIST-002` |
| **Persistence** | T1136.001 | `SCN-PERSIST-003` | Backdoor Local User Account Creation | `srv01.corp.enterprise.local` | `DET-PERSIST-003` |
| **Privilege Escalation** | T1548.003 | `SCN-PRIVESC-001` | Sudoers Configuration Tampering | `srv01.corp.enterprise.local` | `DET-PRIVESC-001` |
| **Privilege Escalation** | T1548.001 | `SCN-PRIVESC-002` | SUID Binary Permission Elevation | `srv01.corp.enterprise.local` | `DET-PRIVESC-002` |
| **Credential Access** | T1558.003 | `SCN-CRED-001` | Kerberoasting SPN Ticket Extraction | `dc01.corp.enterprise.local` | `DET-CRED-001` |
| **Credential Access** | T1003.008 | `SCN-CRED-002` | Linux /etc/shadow File Access | `srv01.corp.enterprise.local` | `DET-CRED-002` |
| **Credential Access** | T1003.001 | `SCN-CRED-003` | LSASS Process Memory Dump (Procdump) | `wkstn01.corp.enterprise.local` | `DET-CRED-003` |
| **Credential Access** | T1110.001 | `SCN-CRED-004` | Active Directory Password Guessing / Brute Force | `dc01.corp.enterprise.local` | `DET-AUTH-001` |
| **Discovery** | T1087.002 | `SCN-DISC-001` | Active Directory Domain Account Discovery | `portal.app.local` | `DET-DISC-001` |
| **Discovery** | T1046 | `SCN-DISC-002` | Internal Network Port Scanning (SSRF) | `portal.app.local` | `DET-DISC-002` |
| **Discovery** | T1082 | `SCN-DISC-003` | System & Security Configuration Discovery | `srv01.corp.enterprise.local` | `DET-DISC-003` |
| **Lateral Movement** | T1021.004 | `SCN-LAT-001` | Cross-Subnet SSH Lateral Movement from DMZ | `srv01.corp.enterprise.local` | `DET-LAT-002` |
| **Lateral Movement** | T1021.002 | `SCN-LAT-002` | Remote Service Creation / PsExec Execution | `dc01.corp.enterprise.local` | `DET-LAT-001` |
| **Lateral Movement** | T1021.006 | `SCN-LAT-003` | Remote WinRM / PowerShell Lateral Execution | `dc01.corp.enterprise.local` | `DET-LAT-003` |
| **Lateral Movement** | T1078 | `SCN-LAT-004` | Suspicious Cross-Zone Domain Controller Logon | `dc01.corp.enterprise.local` | `DET-AUTH-003` |
| **Command & Control** | T1105 | `SCN-C2-001` | Ingress Tool Transfer (Remote Payload Download) | `srv01.corp.enterprise.local` | `DET-C2-001` |
| **Command & Control** | T1105 | `SCN-C2-002` | PowerShell In-Memory Download Cradle | `wkstn01.corp.enterprise.local` | `DET-PS-002` |
| **Command & Control** | T1071.001 | `SCN-C2-003` | Outbound Encrypted C2 Beaconing Channel | `srv01.corp.enterprise.local` | `DET-C2-002` |
| **Collection** | T1560.001 | `SCN-COLL-001` | Sensitive Data Staging in Compressed Archive | `srv01.corp.enterprise.local` | `DET-COLL-001` |
| **Collection** | T1005 | `SCN-COLL-002` | Unauthorized BOLA Strategic Document Harvesting | `portal.app.local` | `DET-COLL-002` |
| **Impact** | T1489 | `SCN-IMP-001` | Critical Security Auditing Service Stop | `srv01.corp.enterprise.local` | `DET-IMP-001` |
| **Impact** | T1485 | `SCN-IMP-002` | Destructive Audit Log Shredding | `srv01.corp.enterprise.local` | `DET-IMP-002` |

---

## Benign Controls (False Positive Validation)

To guarantee high signal-to-noise ratio in detection rules, the framework executes negative control scenarios simulating normal enterprise traffic and administrative operations.

| Scenario ID | Scenario Name | Target Host | Simulated Legitimate Activity | Expected Alerts |
| :--- | :--- | :--- | :--- | :--- |
| `SCN-BENIGN-001` | Legitimate Portal Authentication | `portal.app.local` | Valid login with correct credentials | **0 (None)** |
| `SCN-BENIGN-002` | Authorized Admin SSH Session | `srv01.corp.enterprise.local` | SSH login from authorized management subnet | **0 (None)** |
| `SCN-BENIGN-003` | Clean Network Ping Diagnostic | `portal.app.local` | Diagnostic ping with standard IP/hostname | **0 (None)** |
| `SCN-BENIGN-004` | Normal Employee Search | `portal.app.local` | Keyword search without SQL metacharacters | **0 (None)** |
| `SCN-BENIGN-005` | Routine Linux Commands | `srv01.corp.enterprise.local` | System maintenance (`uptime`, `df -h`, `ls`) | **0 (None)** |
| `SCN-BENIGN-006` | Single User Directory Lookup | `portal.app.local` | LDAP query for single specific username | **0 (None)** |
| `SCN-BENIGN-007` | Application Package Extraction | `srv01.corp.enterprise.local` | Unarchiving package into `/opt/app` | **0 (None)** |

---

## CLI Usage

### 1. Run Complete Simulation Suite
```bash
python3 cli.py simulate
```

### 2. Execute Specific Scenario
```bash
python3 cli.py simulate --scenario SCN-CRED-001
```

### 3. Execute Attack or Benign Scenarios Only
```bash
# Run only offensive attack scenarios
python3 cli.py simulate --attack

# Run only benign false positive validation controls
python3 cli.py simulate --benign
```

### 4. Dry Run Mode
```bash
python3 cli.py simulate --dry-run
```

### 5. Generate Coverage Matrix Report
```bash
# ASCII Table format
python3 cli.py coverage

# Machine-readable JSON output
python3 cli.py coverage --json
```
