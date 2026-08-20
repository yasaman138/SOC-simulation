# Enterprise Attack Detection & Response Lab: Known Limitations & Architectural Trade-offs

## 1. Overview

This document transparently outlines the architectural boundaries, design trade-offs, and known technical limitations of the Enterprise Attack Detection & Response Lab.

---

## 2. Infrastructure & Virtualization Scope

| Architectural Area | Lab Implementation | Production Enterprise Equivalent | Rationale & Trade-off |
|---|---|---|---|
| **Active Directory & Kerberos** | Software-defined Active Directory & KDC service (`ActiveDirectoryServer`) in Python | Windows Server 2022 Domain Controller VM with full NTDS.dit | Enables instant headless bootstrapping, deterministic CI/CD testing, and sub-second test execution without requiring 16GB+ RAM or Windows Server licensing. |
| **Linux Host & Audit Subsystem** | Emulated Linux Server Service (`LinuxServerService`) emitting RFC-compliant auditd & auth logs | Linux Kernel VM with active `auditd` daemon and eBPF sensors | Eliminates kernel privilege requirements (`CAP_SYS_ADMIN`), enabling secure containerized execution in sandboxed environments. |
| **Network Segmentation** | Python-enforced subnet routing & firewall policy validation (`EnterpriseLabTopology`) | Physical/Virtual VLANs, pfSense / Fortinet Next-Gen Firewalls | Provides reproducible network isolation testing and policy verification across platforms without hypervisor dependencies. |

---

## 3. Telemetry Storage & Ingestion Throughput

1. **In-Memory & Local Storage Sizing:**
   - The default `EventStore` and `AlertStore` utilize ring buffers (default: 5,000 events) designed for real-time development, scenario simulation, and automated test suites.
   - For multi-gigabyte production workloads, events should be bridged to a distributed streaming backend (such as Kafka, Elasticsearch, or OpenSearch).

2. **Synchronous vs Asynchronous Detection Rule Processing:**
   - Detection rules evaluate in-memory against recent sliding event windows. High-volume stream processing (>10,000 events/sec) in enterprise deployments would require stream processing engines like Apache Flink or Kafka Streams.

---

## 4. Threat Intelligence & Enrichment Limitations

1. **Local Enrichment vs Live Cloud TI:**
   - Threat intelligence IOC lookups utilize curated local reputation datasets and scoring heuristics rather than live external API queries (e.g., VirusTotal, AbuseIPDB) to guarantee deterministic offline lab testing.

2. **Domain Controller Credential Attacks:**
   - While Kerberoasting, AS-REP roasting, and brute-force events generate accurate Windows Security EventLogs (Event IDs 4768, 4769, 4624, 4625), real NTDS extraction against encrypted DPAPI blobs is simulated at the event telemetry layer.
