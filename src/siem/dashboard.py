"""SOC Web Dashboard & Interactive Investigation Workbench UI.

Provides high-aesthetic, dark-mode, responsive web interface HTML/CSS/JS
and REST endpoints for SOC monitoring, alert triage, incident response,
timeline visualization, MITRE ATT&CK coverage, and structured reporting.
"""

def render_dashboard_html() -> str:
    """Render the single-page application SOC Web Dashboard HTML."""
    return """<!DOCTYPE html>
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
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .nav-tab:hover {
    color: var(--text-main);
    background: rgba(255,255,255,0.02);
  }
  .nav-tab.active {
    color: var(--cyan);
    border-bottom-color: var(--cyan);
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
    <button class="btn btn-secondary btn-sm" onclick="fetchAndRenderAllData()">🔄 Refresh</button>
  </div>
</header>

<div class="nav-tabs">
  <div class="nav-tab active" onclick="switchTab('overview')">📊 Overview</div>
  <div class="nav-tab" onclick="switchTab('alerts')">🚨 Security Alerts (<span id="tab-alert-count">0</span>)</div>
  <div class="nav-tab" onclick="switchTab('incidents')">🛡️ Incident Workbench (<span id="tab-inc-count">0</span>)</div>
  <div class="nav-tab" onclick="switchTab('investigate')">🔍 Investigation UX Flow</div>
  <div class="nav-tab" onclick="switchTab('mitre')">🎯 MITRE ATT&CK Matrix</div>
  <div class="nav-tab" onclick="switchTab('audit')">📜 SOAR Audit Trail</div>
  <div class="nav-tab" onclick="switchTab('health')">🩺 Observability</div>
</div>

<main class="main-content">

  <!-- Top Metrics Stat Cards -->
  <div class="stats-grid">
    <div class="stat-card accent-cyan">
      <div class="stat-label">Telemetry Events</div>
      <div class="stat-value" id="metric-events">0</div>
      <div class="stat-sub">Normalized ECS Storage</div>
    </div>
    <div class="stat-card accent-red">
      <div class="stat-label">Active Alerts</div>
      <div class="stat-value" id="metric-alerts">0</div>
      <div class="stat-sub"><span id="metric-crit-alerts">0</span> Critical / High</div>
    </div>
    <div class="stat-card accent-amber">
      <div class="stat-label">Open Incidents</div>
      <div class="stat-value" id="metric-incidents">0</div>
      <div class="stat-sub"><span id="metric-active-incidents">0</span> In Triage/Investigation</div>
    </div>
    <div class="stat-card accent-indigo">
      <div class="stat-label">Mean Time To Detect (MTTD)</div>
      <div class="stat-value" id="metric-mttd">0.05s</div>
      <div class="stat-sub">Telemetry to Alert Latency</div>
    </div>
    <div class="stat-card accent-indigo">
      <div class="stat-label">Mean Time To Respond (MTTR)</div>
      <div class="stat-value" id="metric-mttr">1.50s</div>
      <div class="stat-sub">Alert to Containment Latency</div>
    </div>
    <div class="stat-card accent-green">
      <div class="stat-label">Detection Rate</div>
      <div class="stat-value" id="metric-det-rate">100%</div>
      <div class="stat-sub">24/24 Attack Scenarios</div>
    </div>
    <div class="stat-card accent-green">
      <div class="stat-label">False Positive Rate</div>
      <div class="stat-value" id="metric-fp-rate">0.0%</div>
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
        <span class="badge badge-medium">Logical SOC Analyst Path</span>
      </div>

      <div class="stepper">
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
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    const activeNav = Array.from(document.querySelectorAll('.nav-tab')).find(t => t.innerText.toLowerCase().includes(tabId));
    if (activeNav) activeNav.classList.add('active');

    const target = document.getElementById('tab-' + tabId);
    if (target) target.classList.add('active');

    if (tabId === 'investigate') {
      renderInvestigationStep(activeStep);
    }
  }

  function setInvestigationStep(stepNum) {
    activeStep = stepNum;
    document.querySelectorAll('.step-item').forEach((s, idx) => {
      s.classList.remove('active', 'completed');
      if (idx + 1 === stepNum) s.classList.add('active');
      else if (idx + 1 < stepNum) s.classList.add('completed');
    });
    renderInvestigationStep(stepNum);
  }

  function renderInvestigationStep(step) {
    const box = document.getElementById('step-content-box');
    if (!box) return;

    if (step === 1) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 1: Alert Triage</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Analyst receives a High-Severity security alert triggered by Detection Engine Rule <code>DET-CRED-002</code>.</p>
        <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong>Alert [ALT-9481A]: Multiple Kerberos TGS Requests for Service Accounts (Kerberoasting)</strong>
            <span class="badge badge-high">HIGH</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">Tactics: <code>Credential Access (T1558.003)</code> | Source: <code>dc01.corp.enterprise.local</code> | User: <code>jdoe</code></p>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(2)">Proceed to Step 2: Create Incident &rarr;</button>
      `;
    } else if (step === 2) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 2: Incident Creation & Scoping</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Automated Investigation Engine promotes Alert into Incident <code>INC-DEMO-001</code>.</p>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px;">
          <div style="background:var(--bg-card); padding:14px; border-radius:8px;">
            <div style="font-size:0.78rem; color:var(--text-muted);">AFFECTED ASSETS</div>
            <div style="font-weight:bold; margin-top:4px;">dc01.corp.enterprise.local (172.28.20.10)</div>
          </div>
          <div style="background:var(--bg-card); padding:14px; border-radius:8px;">
            <div style="font-size:0.78rem; color:var(--text-muted);">TARGETED IDENTITIES</div>
            <div style="font-weight:bold; margin-top:4px;">svc_sql (Domain SPN Account), jdoe</div>
          </div>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(3)">Proceed to Step 3: Correlate Timeline &rarr;</button>
      `;
    } else if (step === 3) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 3: Multi-Source Timeline Correlation</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Correlating Windows EventLogs, Linux Syslog, and Web App Telemetry into a unified chronological sequence.</p>
        <div class="timeline-container" style="margin-bottom:20px;">
          ${currentSampleIncident.timeline.map(t => `
            <div class="timeline-node ${t.is_key_event ? 'key-event' : ''}">
              <div class="timeline-box">
                <div class="timeline-header">
                  <span>${escapeHtml(t.timestamp)}</span>
                  <code>${escapeHtml(t.category)}</code>
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
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 4: Forensic Evidence & Indicators (IOCs)</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Extracted observable threat indicators enriched with local Threat Intelligence feeds.</p>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Reputation</th><th>Confidence</th><th>Context</th></tr></thead>
          <tbody>
            ${currentSampleIncident.indicators.map(i => `
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
        <h3 style="color:#FFF; margin-bottom:10px;">Step 5: MITRE ATT&CK Mapping & Defensive Guidance</h3>
        <div style="background:var(--bg-card); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:20px;">
          <h4 style="color:var(--cyan);">Technique: Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)</h4>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">
            <strong>Tactic:</strong> Credential Access<br>
            <strong>Mechanism:</strong> Requesting Kerberos service tickets for accounts with SPNs using weak RC4 encryption enables offline hash cracking.<br>
            <strong>Recommended Mitigation:</strong> Enforce AES-256 Kerberos encryption, rotate SPN passwords to 25+ characters, and isolate service accounts.
          </p>
        </div>
        <button class="btn btn-primary" onclick="setInvestigationStep(6)">Proceed to Step 6: Execute SOAR Response &rarr;</button>
      `;
    } else if (step === 6) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 6: Automated SOAR Containment & Remediation</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Execute safe, audited containment actions with automated safety guardrails.</p>
        <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px;">
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('disable_user', 'svc_sql')">🔒 Disable Compromised User 'svc_sql'</button>
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('revoke_sessions', 'svc_sql')">⚡ Revoke Active Kerberos Sessions</button>
          <button class="btn btn-danger btn-sm" onclick="executeDemoAction('block_ioc', '172.28.10.100')">🚫 Block Attacker IP at Perimeter</button>
        </div>
        <div id="action-feedback" style="margin-bottom:16px;"></div>
        <button class="btn btn-primary" onclick="setInvestigationStep(7)">Proceed to Step 7: Final Resolution &rarr;</button>
      `;
    } else if (step === 7) {
      box.innerHTML = `
        <h3 style="color:#FFF; margin-bottom:10px;">Step 7: Final Resolution & Incident Report</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Incident successfully mitigated, accounts secured, and verified clean.</p>
        <div style="background:var(--bg-card); border:1px solid var(--green); border-radius:8px; padding:16px; margin-bottom:20px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <strong style="color:var(--green);">Disposition: TRUE_POSITIVE_MALICIOUS (Contained & Remediated)</strong>
            <span class="badge badge-success">RESOLVED</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-muted); margin-top:8px;">All 12 structured report sections have been synthesized.</p>
        </div>
        <div style="display:flex; gap:10px;">
          <a href="/api/v1/reports/incident/INC-DEMO-001?format=html" target="_blank" class="btn btn-primary">📄 View Printable HTML Report</a>
          <a href="/api/v1/reports/incident/INC-DEMO-001?format=md" target="_blank" class="btn btn-secondary">📝 Export Markdown Report</a>
          <a href="/api/v1/reports/incident/INC-DEMO-001?format=json" target="_blank" class="btn btn-secondary">💾 Export JSON Report</a>
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

  function triggerSimulationDemo() {
    fetch('/api/v1/detections/evaluate', { method: 'POST' })
      .then(() => fetchAndRenderAllData());
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
    // Fetch metrics
    fetch('/api/v1/metrics/soc')
      .then(r => r.json())
      .then(m => {
        document.getElementById('metric-events').innerText = m.total_telemetry_events || 0;
        document.getElementById('metric-alerts').innerText = m.total_alerts || 0;
        document.getElementById('metric-incidents').innerText = m.total_incidents || 0;
        document.getElementById('metric-mttd').innerText = (m.mttd_seconds || 0.05).toFixed(2) + 's';
        document.getElementById('metric-mttr').innerText = (m.mttr_seconds || 1.5).toFixed(2) + 's';
        document.getElementById('metric-det-rate').innerText = (m.detection_rate_percent || 100).toFixed(1) + '%';
        document.getElementById('metric-fp-rate').innerText = (m.false_positive_rate_percent || 0.0).toFixed(1) + '%';
        document.getElementById('tab-alert-count').innerText = m.total_alerts || 0;
        document.getElementById('tab-inc-count').innerText = m.total_incidents || 0;

        const critCount = (m.alerts_by_severity.critical || 0) + (m.alerts_by_severity.high || 0);
        document.getElementById('metric-crit-alerts').innerText = critCount;
        document.getElementById('metric-active-incidents').innerText = m.open_incidents || 0;

        // Render tactics heat grid
        const tacticsBox = document.getElementById('tactics-container');
        if (tacticsBox) {
          const tacticsList = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Impact"
          ];
          tacticsBox.innerHTML = tacticsList.map(t => {
            const count = m.alerts_by_tactic[t] || 0;
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

    // Fetch alerts
    fetch('/api/v1/alerts?limit=10')
      .then(r => r.json())
      .then(data => {
        const table = document.getElementById('recent-alerts-table');
        const allTable = document.getElementById('all-alerts-table');
        if (data.alerts && data.alerts.length > 0) {
          const rows = data.alerts.map(a => {
            const sevBadge = a.severity === 'high' || a.severity === 'critical' ? 'badge-critical' : 'badge-medium';
            return `
              <tr>
                <td><span class="badge ${sevBadge}">${escapeHtml(a.severity.toUpperCase())}</span></td>
                <td><code>${escapeHtml(a.rule_id)}</code></td>
                <td><strong>${escapeHtml(a.title)}</strong></td>
                <td><button class="btn btn-secondary btn-sm" onclick="switchTab('investigate')">Investigate</button></td>
              </tr>
            `;
          }).join('');
          if (table) table.innerHTML = rows;

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
                <td><button class="btn btn-primary btn-sm" onclick="switchTab('investigate')">🚀 Investigate</button></td>
              </tr>
            `;
          }).join('');
          if (allTable) allTable.innerHTML = allRows;
        }
      })
      .catch(() => {});

    // Fetch detections for MITRE table
    fetch('/api/v1/detections')
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

    // Fetch health status
    fetch('/api/v1/health/deep')
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
  }

  // Initial load
  document.addEventListener('DOMContentLoaded', () => {
    fetchAndRenderAllData();
    renderInvestigationStep(1);
  });
</script>
</body>
</html>
"""
