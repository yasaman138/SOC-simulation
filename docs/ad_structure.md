# Active Directory Domain Structure & Identity Architecture

## 1. Domain Overview

- **Forest / Domain Root**: `CORP.ENTERPRISE.LOCAL`
- **NetBIOS Name**: `CORP`
- **Primary Domain Controller**: `dc01.corp.enterprise.local` (`172.28.20.10`)
- **Functional Level**: Windows Server 2022

---

## 2. Organizational Unit (OU) Hierarchy

The Active Directory environment follows the Microsoft Enterprise Access Model (Tiered Administrative Architecture):

```
DC=corp,DC=enterprise,DC=local
├── OU=Domain Controllers
│   └── DC01$ (Primary Domain Controller)
├── OU=Administration (Tier 0)
│   ├── OU=Tier-0-Admins
│   │   ├── Administrator (Built-in Domain Admin)
│   │   ├── da_johnson (Lead Infrastructure Architect)
│   │   └── ea_miller (Enterprise Admin / CISO)
│   └── Groups: Domain Admins, Enterprise Admins
├── OU=Identities
│   ├── OU=Enterprise-Users (Standard Corporate Users)
│   │   ├── jdoe (Senior Financial Analyst - Finance)
│   │   ├── asmith (HR Operations Lead - HR)
│   │   └── bwayne (Senior Systems Support - IT Operations)
│   └── OU=Service-Accounts (Managed & Service Accounts with SPNs)
│       ├── svc_sql (MSSQL Database Service Account)
│       └── svc_backup (Enterprise Backup Service Account)
├── OU=Computers
│   ├── OU=Tier-1-Servers
│   │   └── LINUX-SRV01$ (Linux SSH Bastion & App Server)
│   └── OU=Tier-2-Workstations
│       └── WKSTN-WIN10$ (Corporate Employee Workstation)
└── OU=Security-Groups
    ├── Server Operators (Tier 1)
    ├── HelpDesk (Tier 2)
    ├── Finance-Department
    ├── HR-Department
    └── Domain Users
```

---

## 3. Account Registry and Privilege Tiers

| Username (sAMAccountName) | Display Name | Department / Role | Administrative Tier | SPNs Configured |
| :--- | :--- | :--- | :--- | :--- |
| `Administrator` | Built-in Administrator | IT Security | **Tier 0** (Domain Admin) | - |
| `da_johnson` | David Johnson | Lead Infrastructure Architect | **Tier 0** (Domain Admin) | - |
| `ea_miller` | Emma Miller | Enterprise Admin / CISO | **Tier 0** (Enterprise Admin)| - |
| `bwayne` | Bruce Wayne | Senior Systems Support | **Tier 2** (HelpDesk/ServerOps)| - |
| `jdoe` | John Doe | Senior Financial Analyst | Standard User (Finance) | - |
| `asmith` | Alice Smith | HR Operations Lead | Standard User (HR) | - |
| `svc_sql` | Service Account - MSSQL | Database Operations | Service Identity | `MSSQLSvc/db01.corp.enterprise.local:1433`<br/>`MSSQLSvc/db01.corp.enterprise.local` |
| `svc_backup` | Service Account - Backup | Infrastructure Operations | Service Identity | `BackupSvc/backup01.corp.enterprise.local` |

---

## 4. Kerberoasting and SPN Configuration

Service accounts `svc_sql` and `svc_backup` have registered Service Principal Names (SPNs). These accounts serve as targets for Kerberoasting attack simulations (TGS-REQ ticket harvesting and offline hash cracking).

When Kerberos TGS tickets are requested for these SPNs, the Domain Controller emits Windows Event ID `4769` (*A Kerberos service ticket was requested*), providing telemetry for detection engineering.
