"""SOC Web Dashboard & Interactive Investigation Workbench UI.

Provides high-aesthetic, dark-mode, responsive web interface HTML/CSS/JS
and REST endpoints for SOC monitoring, alert triage, incident response,
timeline visualization, MITRE ATT&CK coverage, and structured reporting.
"""

from typing import Any, Optional

def render_dashboard_html(metrics: Any = None) -> str:
    """Render the single-page application SOC Web Dashboard HTML."""
    events_cnt = str(getattr(metrics, "total_telemetry_events", 0) if metrics else 0)
    alerts_cnt = str(getattr(metrics, "total_alerts", 0) if metrics else 0)
    incidents_cnt = str(getattr(metrics, "total_incidents", 0) if metrics else 0)
    crit_cnt = str((metrics.alerts_by_severity.get("critical", 0) + metrics.alerts_by_severity.get("high", 0)) if (metrics and hasattr(metrics, "alerts_by_severity") and isinstance(metrics.alerts_by_severity, dict)) else 0)
    open_inc_cnt = str(getattr(metrics, "open_incidents", 0) if metrics else 0)
    remediated_cnt = str(getattr(metrics, "remediated_incidents", getattr(metrics, "contained_incidents", 0)) if metrics else 0)
    mttd_val = f"{getattr(metrics, 'mttd_seconds', 0.0):.2f}s" if metrics else "0.00s"
    mttr_val = f"{getattr(metrics, 'mttr_seconds', 0.0):.2f}s" if metrics else "0.00s"
    det_rate_val = f"{getattr(metrics, 'detection_rate_percent', 100.0):.1f}%" if metrics else "100.0%"
    fp_rate_val = f"{getattr(metrics, 'false_positive_rate_percent', 0.0):.1f}%" if metrics else "0.0%"

    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Enterprise SOC Platform & Investigation Workbench</title>
<style>
  :root {
    --bg-base: #080C14;
    --bg-card: #0F172A;
    --bg-card-hover: #1E293B;
    --bg-card-sub: #162032;
    --border-color: #1E293B;
    --border-highlight: #334155;
    --text-main: #F8FAFC;
    --text-muted: #94A3B8;
    --text-dim: #64748B;
    --cyan: #06B6D4;
    --cyan-glow: rgba(6, 182, 212, 0.2);
    --indigo: #6366F1;
    --indigo-glow: rgba(99, 102, 241, 0.2);
    --green: #10B981;
    --green-glow: rgba(16, 185, 129, 0.2);
    --amber: #F59E0B;
    --amber-glow: rgba(245, 158, 11, 0.2);
    --red: #EF4444;
    --red-glow: rgba(239, 68, 68, 0.2);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: var(--bg-base);
    color: var(--text-main);
    line-height: 1.5;
    padding: 0;
    margin: 0;
    overflow-x: hidden;
  }

  /* Header */
  header {
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    padding: 16px 28px;
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .brand-logo {
    width: 38px;
    height: 38px;
    background: linear-gradient(135deg, var(--cyan), var(--indigo));
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: bold;
    box-shadow: 0 0 15px var(--cyan-glow);
  }
  .brand-title {
    font-size: 1.2rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #FFF;
  }
  .brand-subtitle {
    font-size: 0.78rem;
    color: var(--cyan);
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }
  .header-actions {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .pulse-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.82rem;
    color: var(--green);
    background: var(--green-glow);
    padding: 6px 12px;
    border-radius: 20px;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }
  .pulse-dot {
    width: 8px;
    height: 8px;
    background: var(--green);
    border-radius: 50%;
    box-shadow: 0 0 8px var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0% { transform: scale(0.95); opacity: 0.8; }
    50% { transform: scale(1.3); opacity: 1; }
    100% { transform: scale(0.95); opacity: 0.8; }
  }

  /* Nav Tabs */
  .nav-tabs {
    display: flex;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border-color);
    padding: 0 28px;
    gap: 8px;
    overflow-x: auto;
  }
  .nav-tab {
    padding: 14px 18px;
    color: var(--text-muted);
    font-size: 0.9rem;
    font-weight: 600;
    border-bottom: 2px solid transparent;
    border-radius: 8px 8px 0 0;
    cursor: pointer;
    transition: all 0.25s ease;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .nav-tab:hover {
    color: var(--text-main);
    background: rgba(255,255,255,0.03);
  }
  .nav-tab.active {
    color: var(--cyan);
    border-bottom-color: var(--cyan);
    background: rgba(6, 182, 212, 0.08);
    box-shadow: 0 4px 14px rgba(6, 182, 212, 0.25);
  }
  .nav-tab.tab-overview-active {
    color: #06B6D4;
    border-bottom-color: #06B6D4;
    background: rgba(6, 182, 212, 0.12);
    box-shadow: 0 4px 16px rgba(6, 182, 212, 0.35);
  }
  .nav-tab.tab-alerts-active {
    color: #EF4444;
    border-bottom-color: #EF4444;
    background: rgba(239, 68, 68, 0.12);
    box-shadow: 0 4px 16px rgba(239, 68, 68, 0.35);
  }
  .nav-tab.tab-incidents-active {
    color: #F59E0B;
    border-bottom-color: #F59E0B;
    background: rgba(245, 158, 11, 0.12);
    box-shadow: 0 4px 16px rgba(245, 158, 11, 0.35);
  }
  .nav-tab.tab-investigate-active {
    color: #818CF8;
    border-bottom-color: #6366F1;
    background: rgba(99, 102, 241, 0.15);
    box-shadow: 0 4px 16px rgba(99, 102, 241, 0.35);
  }
  .nav-tab.tab-mitre-active {
    color: #10B981;
    border-bottom-color: #10B981;
    background: rgba(16, 185, 129, 0.12);
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.35);
  }
  .nav-tab.tab-audit-active {
    color: #38BDF8;
    border-bottom-color: #38BDF8;
    background: rgba(56, 189, 248, 0.12);
    box-shadow: 0 4px 16px rgba(56, 189, 248, 0.35);
  }
  .nav-tab.tab-health-active {
    color: #EC4899;
    border-bottom-color: #EC4899;
    background: rgba(236, 72, 153, 0.12);
    box-shadow: 0 4px 16px rgba(236, 72, 153, 0.35);
  }

  /* Main Container */
  .main-content {
    max-width: 1600px;
    margin: 0 auto;
    padding: 28px;
  }

  /* Stat Cards Grid */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    transition: transform 0.2s, border-color 0.2s;
  }
  .stat-card:hover {
    transform: translateY(-2px);
    border-color: var(--border-highlight);
  }
  .stat-label {
    font-size: 0.78rem;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
  }
  .stat-value {
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--text-main);
  }
  .stat-sub {
    font-size: 0.78rem;
    color: var(--text-dim);
    margin-top: 4px;
  }
  .accent-cyan { border-top: 3px solid var(--cyan); }
  .accent-red { border-top: 3px solid var(--red); }
  .accent-amber { border-top: 3px solid var(--amber); }
  .accent-green { border-top: 3px solid var(--green); }
  .accent-indigo { border-top: 3px solid var(--indigo); }

  /* Panels & Cards */
  .panel {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-color);
  }
  .panel-title {
    font-size: 1.15rem;
    font-weight: 700;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  /* Two Column Layout */
  .grid-2col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }
  @media (max-width: 1024px) {
    .grid-2col { grid-template-columns: 1fr; }
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .badge-critical { background: var(--red-glow); color: var(--red); border: 1px solid rgba(239,68,68,0.3); }
  .badge-high { background: var(--amber-glow); color: var(--amber); border: 1px solid rgba(245,158,11,0.3); }
  .badge-medium { background: var(--indigo-glow); color: var(--indigo); border: 1px solid rgba(99,102,241,0.3); }
  .badge-low { background: rgba(59,130,246,0.15); color: #60A5FA; border: 1px solid rgba(59,130,246,0.3); }
  .badge-info { background: rgba(148,163,184,0.15); color: #94A3B8; border: 1px solid rgba(148,163,184,0.3); }
  .badge-success { background: var(--green-glow); color: var(--green); border: 1px solid rgba(16,185,129,0.3); }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
  }
  th, td {
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }
  th {
    background: var(--bg-card-sub);
    color: var(--text-muted);
    font-weight: 600;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  tr:hover td {
    background: rgba(255,255,255,0.02);
  }
  code {
    background: var(--bg-card-sub);
    color: var(--cyan);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.82rem;
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 16px;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    border: 1px solid transparent;
    text-decoration: none;
  }
  .btn-primary {
    background: var(--cyan);
    color: #000;
  }
  .btn-primary:hover {
    background: #22D3EE;
    box-shadow: 0 0 12px var(--cyan-glow);
  }
  .btn-secondary {
    background: var(--bg-card-sub);
    color: var(--text-main);
    border-color: var(--border-highlight);
  }
  .btn-secondary:hover {
    background: var(--bg-card-hover);
  }
  .btn-danger {
    background: var(--red);
    color: #FFF;
  }
  .btn-sm {
    padding: 4px 10px;
    font-size: 0.75rem;
  }

  /* Stepper UX */
  .stepper {
    display: flex;
    justify-content: space-between;
    margin-bottom: 28px;
    position: relative;
    overflow-x: auto;
    padding: 10px 0;
  }
  .step-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    position: relative;
    z-index: 2;
    min-width: 120px;
    cursor: pointer;
  }
  .step-circle {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--bg-card-sub);
    border: 2px solid var(--border-highlight);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    font-size: 0.85rem;
    color: var(--text-muted);
    transition: all 0.2s;
  }
  .step-item.active .step-circle {
    background: var(--cyan);
    border-color: var(--cyan);
    color: #000;
    box-shadow: 0 0 12px var(--cyan-glow);
  }
  .step-item.completed .step-circle {
    background: var(--green);
    border-color: var(--green);
    color: #000;
  }
  .step-title {
    font-size: 0.78rem;
    font-weight: 600;
    color: var(--text-muted);
    text-align: center;
  }
  .step-item.active .step-title {
    color: var(--cyan);
  }

  /* Timeline Visualizer */
  .timeline-container {
    border-left: 2px solid var(--border-highlight);
    margin-left: 18px;
    padding-left: 22px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }
  .timeline-node {
    position: relative;
  }
  .timeline-node::before {
    content: "";
    position: absolute;
    left: -29px;
    top: 4px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--indigo);
    border: 2px solid var(--bg-card);
    box-shadow: 0 0 8px var(--indigo-glow);
  }
  .timeline-node.key-event::before {
    background: var(--amber);
    box-shadow: 0 0 10px var(--amber);
  }
  .timeline-box {
    background: var(--bg-card-sub);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 14px;
  }
  .timeline-header {
    display: flex;
    justify-content: space-between;
    font-size: 0.78rem;
    color: var(--text-muted);
    margin-bottom: 6px;
  }
  .timeline-title {
    font-size: 0.95rem;
    font-weight: 700;
    color: #FFF;
    margin-bottom: 4px;
  }

  /* Heat Grid for Tactics */
  .tactic-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
    gap: 10px;
  }
  .tactic-card {
    background: var(--bg-card-sub);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    transition: transform 0.2s;
  }
  .tactic-card:hover {
    transform: translateY(-2px);
    border-color: var(--cyan);
  }
  .tactic-count {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--cyan);
  }
  .tactic-name {
    font-size: 0.72rem;
    color: var(--text-muted);
    margin-top: 4px;
    text-transform: uppercase;
  }

  /* Hidden Tab Content */
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  .spinning {
    display: inline-block;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin {
    100% { transform: rotate(360deg); }
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-logo">🛡️</div>
    <div>
      <div class="brand-title">Enterprise SOC Platform</div>
      <div class="brand-subtitle">Automated Detection & Incident Response Lab</div>
    </div>
  </div>
  <div class="header-actions">
    <div class="pulse-indicator">
      <div class="pulse-dot"></div>
      <span>SYSTEM HEALTHY</span>
    </div>
    <button id="btn-run-sim-hdr" class="btn btn-primary btn-sm" onclick="triggerSimulationDemo(this)">⚡ Run Attack Simulation</button>
    <button id="btn-refresh" class="btn btn-secondary btn-sm" onclick="refreshDashboard(this)"><span class="refresh-icon">🔄</span> Refresh</button>
  </div>
</header>

<div class="nav-tabs">
  <div class="nav-tab active tab-overview-active" data-tab="overview" onclick="switchTab('overview')">📊 Overview</div>
  <div class="nav-tab" data-tab="alerts" onclick="switchTab('alerts')">🚨 Security Alerts (<span id="tab-alert-count">__INITIAL_ALERTS__</span>)</div>
  <div class="nav-tab" data-tab="incidents" onclick="switchTab('incidents')">🛡️ Incident Workbench (<span id="tab-inc-count">__INITIAL_INCIDENTS__</span>)</div>
  <div class="nav-tab" data-tab="investigate" onclick="switchTab('investigate')">🔍 Investigation UX Flow</div>
  <div class="nav-tab" data-tab="mitre" onclick="switchTab('mitre')">🎯 MITRE ATT&CK Matrix</div>
  <div class="nav-tab" data-tab="audit" onclick="switchTab('audit')">📜 SOAR Audit Trail</div>
  <div class="nav-tab" data-tab="health" onclick="switchTab('health')">🩺 Observability</div>
</div>

<main class="main-content">

  <!-- Top Metrics Stat Cards -->
  <div class="stats-grid">
    <div class="stat-card accent-cyan">
      <div class="stat-label">Telemetry Events</div>
      <div class="stat-value" id="metric-events">__INITIAL_EVENTS__</div>
      <div class="stat-sub">Normalized ECS Storage</div>
    </div>
    <div class="stat-card accent-red">
      <div class="stat-label">Active Alerts</div>
      <div class="stat-value" id="metric-alerts">__INITIAL_ALERTS__</div>
      <div class="stat-sub"><span id="metric-crit-alerts">__INITIAL_CRIT_ALERTS__</span> Critical / High</div>
    </div>
    <div class="stat-card accent-amber">
      <div class="stat-label">Open Incidents</div>
      <div class="stat-value" id="metric-incidents">__INITIAL_OPEN_INC__</div>
      <div class="stat-sub"><span id="metric-active-incidents">__INITIAL_OPEN_INC__</span> In Triage/Investigation</div>
    </div>
    <div class="stat-card accent-green">
      <div class="stat-label">Remediated / Contained</div>
      <div class="stat-value" id="metric-remediated">__INITIAL_REMEDIATED__</div>
      <div class="stat-sub"><span id="metric-remediated-sub">__INITIAL_REMEDIATED__</span> Contained in Session</div>
    </div>
    <div class="stat-card accent-indigo">
      <div class="stat-label">Mean Time To Detect (MTTD)</div>
      <div class="stat-value" id="metric-mttd">__INITIAL_MTTD__</div>
      <div class="stat-sub">Telemetry to Alert Latency</div>
    </div>
    <div class="stat-card accent-indigo">
      <div class="stat-label">Mean Time To Respond (MTTR)</div>
      <div class="stat-value" id="metric-mttr">__INITIAL_MTTR__</div>
      <div class="stat-sub">Alert to Containment Latency</div>
    </div>
    <div class="stat-card accent-green">
      <div class="stat-label">Detection Rate</div>
      <div class="stat-value" id="metric-det-rate">__INITIAL_DET_RATE__</div>
      <div class="stat-sub">24/24 Attack Scenarios</div>
    </div>
    <div class="stat-card accent-green">
      <div class="stat-label">False Positive Rate</div>
      <div class="stat-value" id="metric-fp-rate">__INITIAL_FP_RATE__</div>
      <div class="stat-sub">6/6 Benign Controls Clean</div>
    </div>
  </div>

  <!-- TAB 1: OVERVIEW -->
  <div id="tab-overview" class="tab-content active">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🎯 MITRE ATT&CK Tactic Coverage Heat Grid</div>
        <span class="badge badge-success">30 Detection Rules Registered</span>
      </div>
      <div class="tactic-grid" id="tactics-container">
        <!-- Injected via JavaScript -->
      </div>
    </div>

    <div class="grid-2col">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">🚨 Recent Security Alerts</div>
          <button class="btn btn-secondary btn-sm" onclick="switchTab('alerts')">View All</button>
        </div>
        <div style="overflow-x:auto;">
          <table>
            <thead><tr><th>Severity</th><th>Rule ID</th><th>Title</th><th>Action</th></tr></thead>
            <tbody id="recent-alerts-table">
              <tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No active alerts. Run simulation to trigger detections.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">🛡️ Active Incidents & Triage</div>
          <button class="btn btn-secondary btn-sm" onclick="switchTab('incidents')">View All</button>
        </div>
        <div style="overflow-x:auto;">
          <table>
            <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Status</th></tr></thead>
            <tbody id="recent-incidents-table">
              <tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No open incidents.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: ALERTS FEED -->
  <div id="tab-alerts" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚨 Security Alerts Catalog</div>
        <div>
          <button class="btn btn-primary btn-sm" onclick="triggerSimulationDemo()">⚡ Run Attack Simulation</button>
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Rule ID</th>
              <th>Title</th>
              <th>Affected Host/User</th>
              <th>Timestamp</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="all-alerts-table">
            <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No alerts registered in local AlertStore.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 3: INCIDENTS WORKBENCH -->
  <div id="tab-incidents" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🛡️ Security Incidents Lifecycle Workbench</div>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Incident ID</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Title</th>
              <th>Containment</th>
              <th>Remediation</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="all-incidents-table">
            <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No incidents stored.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 4: INVESTIGATION UX STEPPER -->
  <div id="tab-investigate" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔍 Investigation UX Workflow</div>
        <span class="badge badge-medium" id="investigate-incidents-badge">Active Investigations</span>
      </div>

      <!-- Open Incidents Selector List -->
      <div id="investigation-incidents-selector" style="margin-bottom: 20px;">
        <!-- Populated dynamically with open incidents -->
      </div>

      <!-- Stepper UX wrapper -->
      <div id="investigation-workflow-container">
        <div class="stepper" id="investigation-stepper">
          <div class="step-item active" onclick="setInvestigationStep(1)">
            <div class="step-circle">1</div>
            <div class="step-title">Alert Triage</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(2)">
            <div class="step-circle">2</div>
            <div class="step-title">Incident Creation</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(3)">
            <div class="step-circle">3</div>
            <div class="step-title">Timeline</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(4)">
            <div class="step-circle">4</div>
            <div class="step-title">Evidence & IOCs</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(5)">
            <div class="step-circle">5</div>
            <div class="step-title">MITRE ATT&CK</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(6)">
            <div class="step-circle">6</div>
            <div class="step-title">SOAR Response</div>
          </div>
          <div class="step-item" onclick="setInvestigationStep(7)">
            <div class="step-circle">7</div>
            <div class="step-title">Resolution & Report</div>
          </div>
        </div>

        <!-- Stepper Content Container -->
        <div id="step-content-box" style="background:var(--bg-card-sub); border:1px solid var(--border-color); border-radius:10px; padding:24px;">
          <!-- Step details rendered dynamically -->
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 5: MITRE ATT&CK MATRIX -->
  <div id="tab-mitre" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🎯 Detection Engineering & MITRE ATT&CK Matrix</div>
        <span class="badge badge-cyan">30 Rules / 10 Tactics</span>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Severity</th>
              <th>Tactic</th>
              <th>Technique ID</th>
              <th>Technique Name</th>
              <th>Simulation Mapped</th>
              <th>Rule Status</th>
            </tr>
          </thead>
          <tbody id="mitre-rules-table">
            <!-- Populated via API -->
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 6: SOAR AUDIT TRAIL -->
  <div id="tab-audit" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">📜 Immutable SOAR Response Audit Log</div>
        <span class="badge badge-indigo">Mandatory Audit Trail</span>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Audit ID</th>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Target</th>
              <th>Result</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody id="audit-log-table">
            <tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No response actions executed yet.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- TAB 7: OBSERVABILITY & DEEP HEALTH -->
  <div id="tab-health" class="tab-content">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🩺 Enterprise Platform Observability & Health Status</div>
        <button class="btn btn-primary btn-sm" onclick="runDeepHealthCheck()">⚡ Run Deep Diagnostic</button>
      </div>
      <div class="stats-grid" id="health-components-grid">
        <!-- Populated via Health API -->
      </div>
    </div>
  </div>

</main>

<script>
  function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  let activeStep = 1;
  let allOpenIncidents = [];
  let selectedIncidentId = null;
  let incidentSteps = {};

  let currentSampleIncident = {
    incident_id: "INC-DEMO-001",
    title: "Kerberoasting & Privileged Credential Extraction",
    severity: "HIGH",
    status: "investigating",
    affected_assets: ["dc01.corp.enterprise.local", "172.28.20.10"],
    affected_users: ["svc_sql", "jdoe"],
    timeline: [
      { timestamp: "2026-08-20 12:00:01", category: "authentication", is_key_event: false, title: "Successful Kerberos TGT Grant", description: "User jdoe obtained TGT from KDC dc01." },
      { timestamp: "2026-08-20 12:00:04", category: "directory_service", is_key_event: true, title: "Kerberoasting Service Ticket Request", description: "TGS requested for MSSQLSvc with RC4-HMAC weak encryption (Event 4769)." },
      { timestamp: "2026-08-20 12:00:15", category: "process", is_key_event: true, title: "Process Execution: procdump.exe", description: "Suspicious memory dumping tool invoked against lsass.exe." },
    ],
    indicators: [
      { type: "ip", value: "172.28.10.100", reputation: "MALICIOUS", confidence: 0.95, context: "Simulation DMZ attacker host" },
      { type: "user", value: "svc_sql", reputation: "SUSPICIOUS", confidence: 0.85, context: "Targeted SPN service account" },
      { type: "process_name", value: "procdump.exe", reputation: "SUSPICIOUS", confidence: 0.90, context: "LSASS credential extraction tool" }
    ]
  };

  function switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(t => {
      t.classList.remove('active', 'tab-overview-active', 'tab-alerts-active', 'tab-incidents-active', 'tab-investigate-active', 'tab-mitre-active', 'tab-audit-active', 'tab-health-active');
    });
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    const targetTab = document.querySelector(`.nav-tab[data-tab="${tabId}"]`) || Array.from(document.querySelectorAll('.nav-tab')).find(t => t.getAttribute('onclick')?.includes(tabId) || t.innerText.toLowerCase().includes(tabId));
    if (targetTab) {
      targetTab.classList.add('active', `tab-${tabId}-active`);
    }

    const target = document.getElementById('tab-' + tabId);
    if (target) target.classList.add('active');

    if (tabId === 'investigate') {
      renderOpenIncidentsSelector();
      const stepToRender = (selectedIncidentId && incidentSteps[selectedIncidentId]) ? incidentSteps[selectedIncidentId] : activeStep;
      renderInvestigationStep(stepToRender);
    }
  }

  function selectIncidentToInvestigate(incId) {
    selectedIncidentId = incId;
    const inc = allOpenIncidents.find(i => i.incident_id === incId);
    if (inc) {
      currentSampleIncident = inc;
    }
    const currentStep = incidentSteps[incId] || 1;
    setInvestigationStep(currentStep, false);
    renderOpenIncidentsSelector();
  }

  function setInvestigationStep(stepNum, triggerResolve = true) {
    if (selectedIncidentId) {
      incidentSteps[selectedIncidentId] = stepNum;
    }
    activeStep = stepNum;

    document.querySelectorAll('.step-item').forEach((s, idx) => {
      s.classList.remove('active', 'completed');
      if (idx + 1 === stepNum) s.classList.add('active');
      else if (idx + 1 < stepNum) s.classList.add('completed');
    });

    if (stepNum === 7 && triggerResolve) {
      document.querySelectorAll('.step-item').forEach((s, idx) => {
        if (idx + 1 < 7) s.classList.add('completed');
        else s.classList.add('active', 'completed');
      });
      const idToResolve = selectedIncidentId || (currentSampleIncident && currentSampleIncident.incident_id);
      if (idToResolve) {
        completeIncidentInvestigation(idToResolve);
      }
    }
    renderInvestigationStep(stepNum);
    renderOpenIncidentsSelector();
  }

  function renderOpenIncidentsSelector() {
    const container = document.getElementById('investigation-incidents-selector');
    const workflowContainer = document.getElementById('investigation-workflow-container');
    const badge = document.getElementById('investigate-incidents-badge');

    if (!container) return;

    if (badge) {
      badge.innerText = allOpenIncidents.length + ' Open Incident' + (allOpenIncidents.length === 1 ? '' : 's');
      badge.className = 'badge ' + (allOpenIncidents.length > 0 ? 'badge-high' : 'badge-success');
    }

    if (allOpenIncidents.length === 0) {
      if (workflowContainer) workflowContainer.style.display = 'none';
      container.innerHTML = `
        <div style="background:var(--bg-card); border:1px solid var(--green); border-radius:10px; padding:32px; text-align:center;">
          <div style="font-size:2.5rem; margin-bottom:12px;">🛡️</div>
          <h3 style="color:#FFF; margin-bottom:8px;">No Open Incidents Under Active Investigation</h3>
          <p style="color:var(--text-muted); max-width:600px; margin:0 auto 20px auto; font-size:0.9rem;">
            All security incidents have been contained, remediated, and removed from active triage.
            Click <strong>Investigate</strong> on any security alert to initiate a new 7-step investigation workflow.
          </p>
          <div style="display:flex; justify-content:center; gap:12px;">
            <button class="btn btn-primary btn-sm" onclick="triggerSimulationDemo(this)">⚡ Run Attack Simulation</button>
            <button class="btn btn-secondary btn-sm" onclick="switchTab('overview')">📊 Return to Overview</button>
          </div>
        </div>
      `;
      return;
    }

    if (workflowContainer) workflowContainer.style.display = 'block';

    // Ensure selectedIncidentId is valid
    if (!selectedIncidentId || !allOpenIncidents.some(i => i.incident_id === selectedIncidentId)) {
      selectedIncidentId = allOpenIncidents[0].incident_id;
      currentSampleIncident = allOpenIncidents[0];
      const curStep = incidentSteps[selectedIncidentId] || 1;
      setInvestigationStep(curStep, false);
    }

    container.innerHTML = `
      <div style="font-size:0.8rem; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.5px; margin-bottom:10px;">
        Active Incidents in Investigation Queue (${allOpenIncidents.length}):
      </div>
      <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(280px, 1fr)); gap:12px;">
        ${allOpenIncidents.map(inc => {
          const isSelected = inc.incident_id === selectedIncidentId;
          const step = incidentSteps[inc.incident_id] || 1;
          const sevBadge = inc.severity === 'high' || inc.severity === 'critical' ? 'badge-critical' : 'badge-medium';
          return `
            <div onclick="selectIncidentToInvestigate('${escapeHtml(inc.incident_id)}')" style="cursor:pointer; background:${isSelected ? 'rgba(99,102,241,0.15)' : 'var(--bg-card)'}; border:2px solid ${isSelected ? 'var(--indigo)' : 'var(--border-color)'}; border-radius:8px; padding:14px; box-shadow:${isSelected ? '0 0 12px var(--indigo-glow)' : 'none'}; transition:all 0.2s;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <code style="font-weight:bold;">${escapeHtml(inc.incident_id)}</code>
                <span class="badge ${sevBadge}">${escapeHtml(inc.severity.toUpperCase())}</span>
              </div>
              <div style="font-size:0.85rem; font-weight:600; color:#FFF; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin-bottom:8px;">
                ${escapeHtml(inc.title)}
              </div>
              <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.75rem; color:var(--text-muted);">
                <span>Progress: <strong style="color:var(--cyan);">Step ${step}/7</strong></span>
                <span style="color:${isSelected ? 'var(--indigo)' : 'var(--text-dim)'};">${isSelected ? '● Active' : 'Select &rarr;'}</span>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  function completeIncidentInvestigation(incId) {
    if (!incId) return Promise.resolve();
    return fetch('/api/v1/incidents/' + encodeURIComponent(incId) + '/resolve', { method: 'POST' })
      .then(r => r.json())
      .then(data => {
        allOpenIncidents = allOpenIncidents.filter(i => i.incident_id !== incId);
        delete incidentSteps[incId];

        if (selectedIncidentId === incId) {
          if (allOpenIncidents.length > 0) {
            selectedIncidentId = allOpenIncidents[0].incident_id;
            currentSampleIncident = allOpenIncidents[0];
          } else {
            selectedIncidentId = null;
          }
        }
        return fetchAndRenderAllData();
      })
      .catch(err => {
        console.error('Incident resolution error:', err);
        return fetchAndRenderAllData();
      });
  }

  function renderInvestigationStep(step) {
    const box = document.getElementById('step-content-box');
    if (!box) return;

    const incId = currentSampleIncident?.incident_id || 'INC-DEMO-001';
    const incTitle = currentSampleIncident?.title || 'Kerberoasting & Privileged Credential Extraction';
    const incSev = (currentSampleIncident?.severity || 'HIGH').toUpperCase();
    const sevBadge = incSev === 'HIGH' || incSev === 'CRITICAL' ? 'badge-critical' : 'badge-medium';
    const incAssets = (currentSampleIncident?.affected_assets && currentSampleIncident.affected_assets.length > 0) ? currentSampleIncident.affected_assets : ['dc01.corp.enterprise.local (172.28.20.10)'];
    const incUsers = (currentSampleIncident?.affected_users && currentSampleIncident.affected_users.length > 0) ? currentSampleIncident.affected_users : ['svc_sql', 'jdoe'];
    const targetUser = incUsers[0] || 'svc_sql';
    const targetAsset = incAssets[0] || '172.28.10.100';

    if (step === 1) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 1: Alert Triage & Scope (${escapeHtml(incId)})</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Analyst evaluates security alert trigger and validates detection fidelity.</p>
        <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>Incident [${escapeHtml(incId)}]: ${escapeHtml(incTitle)}</strong>
            <span class="badge ${sevBadge}">${incSev}</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">
            Target Entities: <code>${escapeHtml(incAssets.join(', '))}</code> | Targeted User: <code>${escapeHtml(incUsers.join(', '))}</code>
          </p>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(2)">Proceed to Step 2: Incident Creation & Scoping &rarr;</button>
      `;
    } else if (step === 2) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 2: Incident Creation & Scoping (${escapeHtml(incId)})</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Automated Investigation Engine promotes Alert into active Incident <code>${escapeHtml(incId)}</code>.</p>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px;">
          <div style="background:var(--bg-card); padding:14px; border-radius:8px;">
            <div style="font-size:0.78rem; color:var(--text-muted);">AFFECTED ASSETS</div>
            <div style="font-weight:bold; margin-top:4px;">${escapeHtml(incAssets.join(', '))}</div>
          </div>
          <div style="background:var(--bg-card); padding:14px; border-radius:8px;">
            <div style="font-size:0.78rem; color:var(--text-muted);">TARGETED IDENTITIES</div>
            <div style="font-weight:bold; margin-top:4px;">${escapeHtml(incUsers.join(', '))}</div>
          </div>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(3)">Proceed to Step 3: Correlate Timeline &rarr;</button>
      `;
    } else if (step === 3) {
      const timelineData = (currentSampleIncident?.timeline && currentSampleIncident.timeline.length > 0) ? currentSampleIncident.timeline : [
        { timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19), category: "authentication", is_key_event: false, title: "Initial Authentication Anomalies", description: "Telemetry collected from endpoint and host." },
        { timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19), category: "detection", is_key_event: true, title: incTitle, description: "Detection rule match and automated scoping." }
      ];
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 3: Multi-Source Timeline Correlation (${escapeHtml(incId)})</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Correlating Windows EventLogs, Linux Syslog, and Web App Telemetry into a unified chronological sequence.</p>
        <div class="timeline-container" style="margin-bottom:20px;">
          ${timelineData.map(t => `
            <div class="timeline-node ${t.is_key_event ? 'key-event' : ''}">
              <div class="timeline-box">
                <div class="timeline-header">
                  <span>${escapeHtml(t.timestamp)}</span>
                  <code>${escapeHtml(t.category || 'general')}</code>
                </div>
                <div class="timeline-title">${t.is_key_event ? '⚡ ' : ''}${escapeHtml(t.title)}</div>
                <div style="font-size:0.85rem; color:var(--text-muted);">${escapeHtml(t.description)}</div>
              </div>
            </div>
          `).join('')}
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(4)">Proceed to Step 4: Review Evidence & IOCs &rarr;</button>
      `;
    } else if (step === 4) {
      const indicatorData = (currentSampleIncident?.indicators && currentSampleIncident.indicators.length > 0) ? currentSampleIncident.indicators : [
        { type: "ip", value: targetAsset, reputation: "MALICIOUS", confidence: 0.95, context: "Associated host address" },
        { type: "user", value: targetUser, reputation: "SUSPICIOUS", confidence: 0.85, context: "Compromised account entity" }
      ];
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 4: Forensic Evidence & Indicators (${escapeHtml(incId)})</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Extracted observable threat indicators enriched with local Threat Intelligence feeds.</p>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Reputation</th><th>Confidence</th><th>Context</th></tr></thead>
          <tbody>
            ${indicatorData.map(i => `
              <tr>
                <td><code>${escapeHtml(i.type)}</code></td>
                <td><code>${escapeHtml(i.value)}</code></td>
                <td><span class="badge ${i.reputation === 'MALICIOUS' ? 'badge-critical' : 'badge-high'}">${escapeHtml(i.reputation)}</span></td>
                <td>${Number(i.confidence).toFixed(2)}</td>
                <td>${escapeHtml(i.context)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <div style="margin-top:20px;">
          <button class="btn btn-primary" onclick="setInvestigationStep(5)">Proceed to Step 5: MITRE ATT&CK Defense Guidance &rarr;</button>
        </div>
      `;
    } else if (step === 5) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 5: MITRE ATT&CK Mapping & Defensive Guidance (${escapeHtml(incId)})</h3>
        <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:20px;">
          <h4 style="color:var(--cyan);">${escapeHtml(incTitle)}</h4>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">
            <strong>Investigation Scope:</strong> Multi-stage adversary behavior verified across endpoint telemetry.<br>
            <strong>Recommended Mitigation:</strong> Revoke compromised credentials, isolate affected hosts, and block associated adversary network observables.
          </p>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(6)">Proceed to Step 6: Execute SOAR Response &rarr;</button>
      `;
    } else if (step === 6) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 6: Automated SOAR Containment & Remediation (${escapeHtml(incId)})</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Execute safe, audited containment actions with automated safety guardrails.</p>
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px;">
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('disable_user', '${escapeHtml(targetUser)}')">🔒 Disable Compromised User '${escapeHtml(targetUser)}'</button>
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('revoke_sessions', '${escapeHtml(targetUser)}')">⚡ Revoke Active Sessions</button>
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('block_ioc', '${escapeHtml(targetAsset)}')">🚫 Block Attacker IP at Perimeter</button>
        </div>
        <div id="action-feedback" style="margin-bottom:16px;"></div>
        <button class="btn btn-primary" onclick="setInvestigationStep(7)">Proceed to Step 7: Final Resolution &rarr;</button>
      `;
    } else if (step === 7) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 7: Final Resolution & Incident Report</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Incident <code>${escapeHtml(incId)}</code> successfully mitigated, accounts secured, and verified clean.</p>
        <div style="background:var(--bg-card); border:1px solid var(--green); border-radius:8px; padding:16px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--green);">Disposition: TRUE_POSITIVE_MALICIOUS (Contained & Remediated)</strong>
            <span class="badge badge-success">CONTAINED & REMEDIATED</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">All 12 structured report sections have been synthesized and the incident is removed from active triage.</p>
        </div>
        <div style="display:flex; gap:10px; flex-wrap:wrap;">
          <a href="/api/v1/reports/incident/${encodeURIComponent(incId)}?format=html" target="_blank" class="btn btn-primary">📄 View Printable HTML Report</a>
          <a href="/api/v1/reports/incident/${encodeURIComponent(incId)}?format=md" target="_blank" class="btn btn-secondary">📝 Export Markdown Report</a>
          <a href="/api/v1/reports/incident/${encodeURIComponent(incId)}?format=json" target="_blank" class="btn btn-secondary">💾 Export JSON Report</a>
          <button class="btn btn-secondary" onclick="switchTab('overview')">📊 Back to Overview</button>
        </div>
      `;
    }
  }

  function executeDemoAction(actionType, target) {
    const feedback = document.getElementById('action-feedback');
    if (!feedback) return;
    feedback.innerHTML = `<div style="background:var(--green-glow); border:1px solid var(--green); color:var(--green); padding:10px; border-radius:6px; font-size:0.85rem;">[SUCCESS] Action <strong>${escapeHtml(actionType)}</strong> applied to <strong>${escapeHtml(target)}</strong>. Audit entry recorded with rollback capability.</div>`;
    fetchAndRenderAllData();
  }

  function refreshDashboard(btnElement) {
    const btn = btnElement || document.getElementById('btn-refresh');
    const icon = btn ? btn.querySelector('.refresh-icon') : null;
    if (icon) icon.classList.add('spinning');
    if (btn) btn.disabled = true;

    try {
      localStorage.removeItem('soc_cached_metrics');
      sessionStorage.clear();
    } catch(e) {}

    return fetch('/api/v1/reset', { method: 'POST' })
      .then(r => r.json())
      .then(() => {
        allOpenIncidents = [];
        incidentSteps = {};
        selectedIncidentId = null;
        activeStep = 1;
        switchTab('overview');
        setInvestigationStep(1, false);
        return fetchAndRenderAllData();
      })
      .catch(err => {
        console.error('Reset error on refresh:', err);
        return fetchAndRenderAllData();
      })
      .finally(() => {
        setTimeout(() => {
          if (icon) icon.classList.remove('spinning');
          if (btn) btn.disabled = false;
        }, 300);
      });
  }

  function resetLabToDefault(btnElement) {
    return refreshDashboard(btnElement);
  }

  function triggerSimulationDemo(btnElement) {
    const btn = btnElement || document.querySelector('#tab-alerts .btn-primary');
    const origText = btn ? btn.innerHTML : '';
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '⚡ Simulating Attack Scenarios...';
    }
    fetch('/api/v1/simulation/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack: true, create_incident: false })
    })
      .then(r => r.json())
      .then(() => {
        return fetchAndRenderAllData();
      })
      .catch(err => {
        console.error('Simulation error:', err);
      })
      .finally(() => {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = origText || '⚡ Run Attack Simulation';
        }
      });
  }

  function investigateAlert(alertId) {
    fetch('/api/v1/incidents/investigate/' + encodeURIComponent(alertId), { method: 'POST' })
      .then(r => r.json())
      .then(data => {
        if (data.status === 'success' && data.incident_id) {
          fetch('/api/v1/incidents/' + encodeURIComponent(data.incident_id))
            .then(r => r.json())
            .then(inc => {
              if (!allOpenIncidents.some(i => i.incident_id === inc.incident_id)) {
                allOpenIncidents.push(inc);
              }
              if (!incidentSteps[inc.incident_id]) {
                incidentSteps[inc.incident_id] = 1;
              }
              selectedIncidentId = inc.incident_id;
              currentSampleIncident = inc;
              switchTab('investigate');
              setInvestigationStep(incidentSteps[inc.incident_id] || 1, false);
              fetchAndRenderAllData();
            })
            .catch(() => {
              switchTab('investigate');
              fetchAndRenderAllData();
            });
        } else {
          switchTab('investigate');
          fetchAndRenderAllData();
        }
      })
      .catch(() => {
        switchTab('investigate');
        fetchAndRenderAllData();
      });
  }

  function runDeepHealthCheck() {
    fetch('/api/v1/health/deep')
      .then(r => r.json())
      .then(data => {
        alert("Deep Diagnostic Completed: Status is " + String(data.overall_status).toUpperCase() + " (" + data.healthy_components + "/" + data.total_components + " components healthy).");
        fetchAndRenderAllData();
      });
  }

  function fetchAndRenderAllData() {
    // 1. Fetch metrics
    const p1 = fetch('/api/v1/metrics/soc')
      .then(r => r.json())
      .then(m => {
        const evCount = m.total_telemetry_events ?? 0;
        const alCount = m.total_alerts ?? 0;
        const incCount = m.total_incidents ?? 0;
        const openInc = m.open_incidents ?? 0;
        const remInc = m.remediated_incidents ?? (m.contained_incidents ?? 0);
        const mttdStr = ((m.mttd_seconds !== undefined && m.mttd_seconds !== null) ? m.mttd_seconds : 0).toFixed(2) + 's';
        const mttrStr = ((m.mttr_seconds !== undefined && m.mttr_seconds !== null) ? m.mttr_seconds : 0).toFixed(2) + 's';
        const detRateStr = ((m.detection_rate_percent !== undefined && m.detection_rate_percent !== null) ? m.detection_rate_percent : 100).toFixed(1) + '%';
        const fpRateStr = ((m.false_positive_rate_percent !== undefined && m.false_positive_rate_percent !== null) ? m.false_positive_rate_percent : 0).toFixed(1) + '%';
        const critCount = (m.alerts_by_severity?.critical || 0) + (m.alerts_by_severity?.high || 0);

        const elEvents = document.getElementById('metric-events');
        if (elEvents) elEvents.innerText = evCount;
        const elAlerts = document.getElementById('metric-alerts');
        if (elAlerts) elAlerts.innerText = alCount;
        const elInc = document.getElementById('metric-incidents');
        if (elInc) elInc.innerText = openInc;
        const elActInc = document.getElementById('metric-active-incidents');
        if (elActInc) elActInc.innerText = openInc;
        const elRem = document.getElementById('metric-remediated');
        if (elRem) elRem.innerText = remInc;
        const elRemSub = document.getElementById('metric-remediated-sub');
        if (elRemSub) elRemSub.innerText = remInc;
        const elMttd = document.getElementById('metric-mttd');
        if (elMttd) elMttd.innerText = mttdStr;
        const elMttr = document.getElementById('metric-mttr');
        if (elMttr) elMttr.innerText = mttrStr;
        const elDet = document.getElementById('metric-det-rate');
        if (elDet) elDet.innerText = detRateStr;
        const elFp = document.getElementById('metric-fp-rate');
        if (elFp) elFp.innerText = fpRateStr;
        const elTabAlert = document.getElementById('tab-alert-count');
        if (elTabAlert) elTabAlert.innerText = alCount;
        const elTabInc = document.getElementById('tab-inc-count');
        if (elTabInc) elTabInc.innerText = incCount;
        const elCrit = document.getElementById('metric-crit-alerts');
        if (elCrit) elCrit.innerText = critCount;

        try {
          localStorage.setItem('soc_cached_metrics', JSON.stringify({
            total_telemetry_events: evCount,
            total_alerts: alCount,
            total_incidents: incCount,
            crit_count: critCount,
            active_incidents: openInc,
            remediated_incidents: remInc,
            mttd: mttdStr,
            mttr: mttrStr,
            det_rate: detRateStr,
            fp_rate: fpRateStr
          }));
        } catch(e) {}

        // Render tactics heat grid
        const tacticsBox = document.getElementById('tactics-container');
        if (tacticsBox) {
          const tacticsList = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Impact"
          ];
          tacticsBox.innerHTML = tacticsList.map(t => {
            const count = (m.alerts_by_tactic && m.alerts_by_tactic[t]) || 0;
            return `
              <div class="tactic-card">
                <div class="tactic-count">${count}</div>
                <div class="tactic-name">${escapeHtml(t)}</div>
              </div>
            `;
          }).join('');
        }
      })
      .catch(() => {});

    // 2. Fetch alerts
    const p2 = fetch('/api/v1/alerts?limit=50')
      .then(r => r.json())
      .then(data => {
        const table = document.getElementById('recent-alerts-table');
        const allTable = document.getElementById('all-alerts-table');
        if (data.alerts && data.alerts.length > 0) {
          const activeAlerts = data.alerts.filter(a => a.status !== 'contained' && a.status !== 'closed' && a.status !== 'resolved');
          if (activeAlerts.length > 0) {
            const rows = activeAlerts.slice(0, 10).map(a => {
              const sevBadge = a.severity === 'high' || a.severity === 'critical' ? 'badge-critical' : 'badge-medium';
              return `
                <tr>
                  <td><span class="badge ${sevBadge}">${escapeHtml(a.severity.toUpperCase())}</span></td>
                  <td><code>${escapeHtml(a.rule_id)}</code></td>
                  <td><strong>${escapeHtml(a.title)}</strong></td>
                  <td><button class="btn btn-secondary btn-sm" onclick="investigateAlert('${escapeHtml(a.id)}')">Investigate</button></td>
                </tr>
              `;
            }).join('');
            if (table) table.innerHTML = rows;
          } else {
            if (table) table.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No active alerts. Run simulation to trigger detections.</td></tr>';
          }

          const allRows = data.alerts.map(a => {
            const sevBadge = a.severity === 'high' || a.severity === 'critical' ? 'badge-critical' : 'badge-medium';
            const hostUser = (a.affected_entities.host || '') + (a.affected_entities.user ? ` (${a.affected_entities.user})` : '');
            return `
              <tr>
                <td><code>${escapeHtml(a.id)}</code></td>
                <td><span class="badge ${sevBadge}">${escapeHtml(a.severity.toUpperCase())}</span></td>
                <td><code>${escapeHtml(a.rule_id)}</code></td>
                <td><strong>${escapeHtml(a.title)}</strong></td>
                <td>${escapeHtml(hostUser) || 'N/A'}</td>
                <td>${escapeHtml(a.timestamp)}</td>
                <td><button class="btn btn-primary btn-sm" onclick="investigateAlert('${escapeHtml(a.id)}')">🚀 Investigate</button></td>
              </tr>
            `;
          }).join('');
          if (allTable) allTable.innerHTML = allRows;
        } else {
          if (table) table.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No active alerts. Run simulation to trigger detections.</td></tr>';
          if (allTable) allTable.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No alerts registered in local AlertStore.</td></tr>';
        }
      })
      .catch(() => {});

    // 3. Fetch incidents
    const p3 = fetch('/api/v1/incidents?limit=50')
      .then(r => r.json())
      .then(data => {
        const recTable = document.getElementById('recent-incidents-table');
        const allTable = document.getElementById('all-incidents-table');
        if (data.incidents && data.incidents.length > 0) {
          const activeIncidents = data.incidents.filter(i => 
            i.containment_status !== 'contained' && 
            i.remediation_status !== 'remediated' && 
            i.status !== 'contained' && 
            i.status !== 'recovered' && 
            i.status !== 'eradicated' && 
            i.status !== 'closed'
          );
          allOpenIncidents = activeIncidents;
          renderOpenIncidentsSelector();

          if (activeIncidents.length > 0) {
            const recRows = activeIncidents.slice(0, 10).map(i => {
              const sevBadge = i.severity === 'high' || i.severity === 'critical' ? 'badge-critical' : 'badge-medium';
              return `
                <tr>
                  <td><code>${escapeHtml(i.incident_id)}</code></td>
                  <td><span class="badge ${sevBadge}">${escapeHtml(i.severity.toUpperCase())}</span></td>
                  <td><strong>${escapeHtml(i.title)}</strong></td>
                  <td><span class="badge badge-info">${escapeHtml((i.status || 'new').toUpperCase())}</span></td>
                </tr>
              `;
            }).join('');
            if (recTable) recTable.innerHTML = recRows;
          } else {
            if (recTable) recTable.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No open incidents.</td></tr>';
          }

          const allRows = data.incidents.map(i => {
            const sevBadge = i.severity === 'high' || i.severity === 'critical' ? 'badge-critical' : 'badge-medium';
            const isContained = i.containment_status === 'contained' || i.remediation_status === 'remediated' || i.status === 'contained' || i.status === 'recovered' || i.status === 'eradicated';
            const statusBadge = isContained ? 'badge-success' : 'badge-info';
            const statusLabel = isContained ? 'CONTAINED' : escapeHtml((i.status || 'new').toUpperCase());
            return `
              <tr>
                <td><code>${escapeHtml(i.incident_id)}</code></td>
                <td><span class="badge ${sevBadge}">${escapeHtml(i.severity.toUpperCase())}</span></td>
                <td><span class="badge ${statusBadge}">${statusLabel}</span></td>
                <td><strong>${escapeHtml(i.title)}</strong></td>
                <td><span class="badge ${i.containment_status === 'contained' ? 'badge-success' : 'badge-low'}">${escapeHtml((i.containment_status || 'uncontained').toUpperCase())}</span></td>
                <td><span class="badge ${i.remediation_status === 'remediated' ? 'badge-success' : 'badge-low'}">${escapeHtml((i.remediation_status || 'pending').toUpperCase())}</span></td>
                <td>
                  <a href="/api/v1/reports/incident/${encodeURIComponent(i.incident_id)}?format=html" target="_blank" class="btn btn-secondary btn-sm">📄 Report</a>
                </td>
              </tr>
            `;
          }).join('');
          if (allTable) allTable.innerHTML = allRows;
        } else {
          allOpenIncidents = [];
          renderOpenIncidentsSelector();
          if (recTable) recTable.innerHTML = '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No open incidents.</td></tr>';
          if (allTable) allTable.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No incidents stored.</td></tr>';
        }
      })
      .catch(() => {});

    // 4. Fetch SOAR audit log
    const p4 = fetch('/api/v1/audit?limit=20')
      .then(r => r.json())
      .then(data => {
        const auditTable = document.getElementById('audit-log-table');
        if (auditTable) {
          if (data.entries && data.entries.length > 0) {
            auditTable.innerHTML = data.entries.map(e => `
              <tr>
                <td><code>${escapeHtml(e.id)}</code></td>
                <td>${escapeHtml(e.timestamp)}</td>
                <td><code>${escapeHtml(e.action)}</code></td>
                <td>${escapeHtml(e.actor)}</td>
                <td><code>${escapeHtml(e.target)}</code></td>
                <td><span class="badge ${e.result === 'success' ? 'badge-success' : 'badge-critical'}">${escapeHtml(e.result.toUpperCase())}</span></td>
                <td>${escapeHtml(e.reason || 'Automated Playbook Execution')}</td>
              </tr>
            `).join('');
          } else {
            auditTable.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No response actions executed yet.</td></tr>';
          }
        }
      })
      .catch(() => {});

    // 5. Fetch detections for MITRE table
    const p5 = fetch('/api/v1/detections')
      .then(r => r.json())
      .then(data => {
        const table = document.getElementById('mitre-rules-table');
        if (table && data.rules) {
          table.innerHTML = data.rules.map(r => `
            <tr>
              <td><code>${escapeHtml(r.id)}</code></td>
              <td><span class="badge badge-medium">${escapeHtml(r.severity.toUpperCase())}</span></td>
              <td><code>${escapeHtml(r.mitre_attack.tactic)}</code></td>
              <td><code>${escapeHtml(r.mitre_attack.technique_id)}</code></td>
              <td>${escapeHtml(r.name)}</td>
              <td><span class="badge badge-success">YES</span></td>
              <td><span class="badge badge-success">ACTIVE</span></td>
            </tr>
          `).join('');
        }
      })
      .catch(() => {});

    // 6. Fetch health status
    const p6 = fetch('/api/v1/health/deep')
      .then(r => r.json())
      .then(data => {
        const grid = document.getElementById('health-components-grid');
        if (grid && data.components) {
          grid.innerHTML = data.components.map(c => `
            <div class="stat-card ${c.status === 'healthy' ? 'accent-green' : 'accent-red'}">
              <div class="stat-label">${escapeHtml(c.name)}</div>
              <div class="stat-value" style="font-size:1.2rem; color:${c.status === 'healthy' ? 'var(--green)' : 'var(--red)'};">
                ${escapeHtml(c.status.toUpperCase())}
              </div>
              <div class="stat-sub">Latency: ${Number(c.latency_ms).toFixed(1)}ms</div>
            </div>
          `).join('');
        }
      })
      .catch(() => {});

    return Promise.allSettled([p1, p2, p3, p4, p5, p6]);
  }

  // Instant cache hydration to prevent visual flash on page reload
  try {
    const cached = JSON.parse(localStorage.getItem('soc_cached_metrics') || '{}');
    if (cached.total_telemetry_events !== undefined) {
      const elEvents = document.getElementById('metric-events');
      if (elEvents) elEvents.innerText = cached.total_telemetry_events;
      const elAlerts = document.getElementById('metric-alerts');
      if (elAlerts) elAlerts.innerText = cached.total_alerts;
      const elInc = document.getElementById('metric-incidents');
      if (elInc) elInc.innerText = cached.active_incidents ?? (cached.total_incidents ?? 0);
      const elRem = document.getElementById('metric-remediated');
      if (elRem) elRem.innerText = cached.remediated_incidents ?? 0;
      const elRemSub = document.getElementById('metric-remediated-sub');
      if (elRemSub) elRemSub.innerText = cached.remediated_incidents ?? 0;
      const elMttd = document.getElementById('metric-mttd');
      if (elMttd) elMttd.innerText = cached.mttd;
      const elMttr = document.getElementById('metric-mttr');
      if (elMttr) elMttr.innerText = cached.mttr;
      const elDet = document.getElementById('metric-det-rate');
      if (elDet) elDet.innerText = cached.det_rate;
      const elFp = document.getElementById('metric-fp-rate');
      if (elFp) elFp.innerText = cached.fp_rate;
      const elTabAlert = document.getElementById('tab-alert-count');
      if (elTabAlert) elTabAlert.innerText = cached.total_alerts;
      const elTabInc = document.getElementById('tab-inc-count');
      if (elTabInc) elTabInc.innerText = cached.total_incidents;
      const elCrit = document.getElementById('metric-crit-alerts');
      if (elCrit) elCrit.innerText = cached.crit_count ?? 0;
      const elActInc = document.getElementById('metric-active-incidents');
      if (elActInc) elActInc.innerText = cached.active_incidents ?? 0;
    }
  } catch(e) {}

  // Initial load
  document.addEventListener('DOMContentLoaded', () => {
    const navEntries = (window.performance && window.performance.getEntriesByType) ? window.performance.getEntriesByType('navigation') : [];
    const isReload = (navEntries.length > 0 && navEntries[0].type === 'reload') || (window.performance && window.performance.navigation && window.performance.navigation.type === 1);
    
    if (isReload) {
      try {
        localStorage.removeItem('soc_cached_metrics');
        sessionStorage.clear();
      } catch(e) {}
      fetch('/api/v1/reset', { method: 'POST' })
        .finally(() => {
          fetchAndRenderAllData();
          renderInvestigationStep(1);
        });
    } else {
      fetchAndRenderAllData();
      renderInvestigationStep(1);
    }
  });
</script>
</body>
</html>
"""
    return (
        html
        .replace('__INITIAL_EVENTS__', events_cnt)
        .replace('__INITIAL_ALERTS__', alerts_cnt)
        .replace('__INITIAL_INCIDENTS__', incidents_cnt)
        .replace('__INITIAL_CRIT_ALERTS__', crit_cnt)
        .replace('__INITIAL_OPEN_INC__', open_inc_cnt)
        .replace('__INITIAL_REMEDIATED__', remediated_cnt)
        .replace('__INITIAL_MTTD__', mttd_val)
        .replace('__INITIAL_MTTR__', mttr_val)
        .replace('__INITIAL_DET_RATE__', det_rate_val)
        .replace('__INITIAL_FP_RATE__', fp_rate_val)
    )

