# Enterprise Attack Detection & Response Lab: Future Improvements & Roadmap

## 1. Overview

This document outlines architectural enhancements, engineering extensions, and technical roadmap milestones for future iterations of the platform.

---

## 2. Technical Roadmap

```
         ┌─────────────────────────────────────────────────────────────┐
         │                    FUTURE ROADMAP                           │
         ├──────────────────────────────┬──────────────────────────────┤
         │ Phase A: Scalability         │ Phase B: Advanced Telemetry  │
         │ • OpenSearch / Kafka Backend │ • Linux eBPF Kernel Probes   │
         │ • Distributed SIEM Collector │ • Windows Sysmon Driver Hook │
         ├──────────────────────────────┼──────────────────────────────┤
         │ Phase C: Intelligent Triage  │ Phase D: Virtualization      │
         │ • LLM / RAG Analyst Copilot  │ • Automated Vagrant/Terraform│
         │ • Real-time Threat Intel API │ • Real Windows Server DC     │
         └──────────────────────────────┴──────────────────────────────┘
```

---

## 3. Detailed Milestone Descriptions

### 3.1 Distributed Streaming & Persistent SIEM Storage
- **Kafka Telemetry Bus:** Ingest high-volume ECS events into distributed partitioned topics for decoupled consumption.
- **OpenSearch / Elasticsearch Backend:** Replace in-memory ring buffers with persistent multi-node OpenSearch clusters supporting Lucene search, index lifecycles, and Grafana dashboarding.

### 3.2 Advanced Endpoint Telemetry & Kernel Sensing
- **Linux eBPF Sensors:** Implement native eBPF kernel probes for process execution tracing (`sys_enter_execve`), network socket opens (`tcp_connect`), and file manipulation without user-space overhead.
- **Windows Sysmon Integration:** Ingest live XML EventLogs from physical or virtual Windows endpoints running the SwiftOnSecurity Sysmon configuration.

### 3.3 LLM-Powered SOC Analyst Co-Pilot
- **Autonomous RAG Incident Synthesis:** Augment the `InvestigationEngine` with a Retrieval-Augmented Generation (RAG) assistant indexing MITRE ATT&CK knowledge bases, Sigma rules, and past incident post-mortems to deliver automated root cause explanations and defense recommendations.
- **Interactive Chat Workbench:** Enable SOC analysts to query incident evidence and telemetry via natural language in the Web Dashboard.

### 3.4 Hybrid Cloud & Terraform Infrastructure Automation
- **Multi-Cloud Terraform Blueprints:** Automated deployment of real Linux (Ubuntu/RHEL) and Windows Server VMs on AWS, Azure, or GCP with automated WireGuard VPN tunneling and domain joining.
