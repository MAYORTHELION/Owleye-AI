"""
OwlEye AI - Flask Dashboard with Approve/Reject
"""

import sqlite3
import json
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)
DB_PATH = Path(__file__).parent / "owleye.db"

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OwlEye AI - SOC Dashboard</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0a0e1a; color:#e0e6f0; font-family:'Courier New',monospace; font-size:13px; }
  header { background:#0f3460; padding:16px 30px; display:flex; align-items:center; justify-content:space-between; border-bottom:2px solid #1a73e8; }
  header h1 { font-size:20px; color:#fff; letter-spacing:2px; }
  header h1 span { color:#f5a623; }
  .live { display:flex; align-items:center; gap:8px; font-size:12px; color:#7effa0; }
  .dot { width:8px; height:8px; border-radius:50%; background:#7effa0; animation:pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

  .stats { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; padding:20px 30px; }
  .stat-card { background:#111827; border:1px solid #1e293b; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .number { font-size:36px; font-weight:bold; }
  .stat-card .label { font-size:11px; color:#94a3b8; margin-top:4px; text-transform:uppercase; letter-spacing:1px; }
  .red{color:#f87171} .orange{color:#fb923c} .yellow{color:#facc15} .green{color:#4ade80} .blue{color:#60a5fa}

  .section { padding:0 30px 24px; }
  .section h2 { font-size:13px; letter-spacing:2px; color:#94a3b8; text-transform:uppercase; margin-bottom:12px; border-left:3px solid #1a73e8; padding-left:10px; }

  .pipeline { display:flex; background:#111827; border:1px solid #1e293b; border-radius:8px; overflow:hidden; margin-bottom:20px; }
  .stage { flex:1; padding:12px 8px; text-align:center; border-right:1px solid #1e293b; font-size:11px; text-transform:uppercase; letter-spacing:1px; }
  .stage:last-child { border-right:none; }
  .stage .count { font-size:22px; font-weight:bold; display:block; margin-bottom:3px; }
  .stage-label { color:#64748b; }

  table { width:100%; border-collapse:collapse; }
  th { background:#0f172a; color:#64748b; font-size:11px; text-transform:uppercase; letter-spacing:1px; padding:10px 12px; text-align:left; border-bottom:1px solid #1e293b; }
  td { padding:10px 12px; border-bottom:1px solid #0f172a; vertical-align:middle; }
  tr:hover td { background:#111827; }

  .badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10px; font-weight:bold; text-transform:uppercase; letter-spacing:1px; }
  .badge-critical{background:#7f1d1d;color:#fca5a5}
  .badge-high{background:#7c2d12;color:#fdba74}
  .badge-medium{background:#713f12;color:#fde047}
  .badge-low{background:#14532d;color:#86efac}
  .badge-contained{background:#14532d;color:#86efac}
  .badge-documented{background:#1e3a5f;color:#93c5fd}
  .badge-pending_approval{background:#4a1d96;color:#c4b5fd}
  .badge-investigated{background:#064e3b;color:#6ee7b7}
  .badge-open{background:#7f1d1d;color:#fca5a5}
  .badge-new{background:#1e293b;color:#94a3b8}
  .badge-escalated{background:#422006;color:#fde68a}

  .btn { padding:4px 12px; border:none; border-radius:4px; font-size:11px; font-weight:bold; cursor:pointer; letter-spacing:1px; text-transform:uppercase; }
  .btn-approve { background:#14532d; color:#86efac; margin-right:4px; }
  .btn-approve:hover { background:#166534; }
  .btn-reject { background:#7f1d1d; color:#fca5a5; }
  .btn-reject:hover { background:#991b1b; }
  .btn:disabled { opacity:0.3; cursor:not-allowed; }

  .toast { position:fixed; bottom:30px; right:30px; background:#1e293b; border:1px solid #334155; border-radius:8px; padding:14px 20px; font-size:13px; display:none; z-index:999; }
  .toast.show { display:block; }
  .toast.success { border-color:#16a34a; color:#86efac; }
  .toast.error { border-color:#dc2626; color:#fca5a5; }

  .no-data { color:#334155; padding:20px; text-align:center; }
  .footer { text-align:center; padding:20px; color:#334155; font-size:11px; }
  #last-updated { font-size:11px; color:#475569; }
</style>
</head>
<body>

<header>
  <h1>🦉 Owl<span>Eye</span> AI &nbsp;|&nbsp; SOC Intelligence Dashboard</h1>
  <div style="display:flex;gap:24px;align-items:center;">
    <span id="last-updated">Loading...</span>
    <div class="live"><div class="dot"></div> LIVE</div>
  </div>
</header>

<div class="stats" id="stats"></div>

<div class="section">
  <h2>Agent Pipeline Status</h2>
  <div class="pipeline" id="pipeline"></div>
</div>

<div class="section">
  <h2>Active Incidents</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Event Type</th><th>Severity</th><th>Score</th><th>Source IP</th><th>Target User</th><th>Status</th><th>Time</th><th>Action</th></tr>
    </thead>
    <tbody id="incidents-body"><tr><td colspan="9" class="no-data">Loading...</td></tr></tbody>
  </table>
</div>

<div class="section">
  <h2>Recent Alerts</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Event Type</th><th>Severity</th><th>Source</th><th>Status</th><th>Time</th></tr>
    </thead>
    <tbody id="alerts-body"><tr><td colspan="6" class="no-data">Loading...</td></tr></tbody>
  </table>
</div>

<div class="section">
  <h2>Blocked IPs</h2>
  <table>
    <thead>
      <tr><th>IP Address</th><th>Reason</th><th>Blocked At</th></tr>
    </thead>
    <tbody id="blocklist-body"><tr><td colspan="3" class="no-data">Loading...</td></tr></tbody>
  </table>
</div>

<div class="footer">OwlEye AI &nbsp;|&nbsp; Autonomous SOC Intelligence &nbsp;|&nbsp; Built by Solomon Omakun</div>
<div class="toast" id="toast"></div>

<script>
function showToast(msg, type) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 3000);
}

function approveIncident(id) {
  fetch('/api/approve/' + id, {method:'POST'})
    .then(r => r.json())
    .then(d => {
      if (d.success) showToast('Incident #' + id + ' approved', 'success');
      else showToast('Error: ' + d.error, 'error');
      refresh();
    });
}

function rejectIncident(id) {
  fetch('/api/reject/' + id, {method:'POST'})
    .then(r => r.json())
    .then(d => {
      if (d.success) showToast('Incident #' + id + ' rejected', 'error');
      else showToast('Error: ' + d.error, 'error');
      refresh();
    });
}

function sevBadge(s) { return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`; }
function statusBadge(s) { return `<span class="badge badge-${s.toLowerCase()}">${s}</span>`; }

function refresh() {
  fetch('/api/data')
    .then(r => r.json())
    .then(data => {
      document.getElementById('last-updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();

      const s = data.stats;
      document.getElementById('stats').innerHTML = `
        <div class="stat-card"><div class="number red">${s.total_alerts}</div><div class="label">Total Alerts</div></div>
        <div class="stat-card"><div class="number orange">${s.total_incidents}</div><div class="label">Incidents</div></div>
        <div class="stat-card"><div class="number yellow">${s.pending_approval}</div><div class="label">Pending Approval</div></div>
        <div class="stat-card"><div class="number green">${s.contained}</div><div class="label">Contained</div></div>
        <div class="stat-card"><div class="number blue">${s.documented}</div><div class="label">Documented</div></div>
      `;

      document.getElementById('pipeline').innerHTML = `
        <div class="stage"><span class="count blue">${s.pipeline.new}</span><span class="stage-label">Monitor</span></div>
        <div class="stage"><span class="count yellow">${s.pipeline.triaged}</span><span class="stage-label">Triage</span></div>
        <div class="stage"><span class="count orange">${s.pipeline.investigated}</span><span class="stage-label">Investigated</span></div>
        <div class="stage"><span class="count" style="color:#c4b5fd">${s.pipeline.pending_approval}</span><span class="stage-label">Approval Gate</span></div>
        <div class="stage"><span class="count green">${s.pipeline.contained}</span><span class="stage-label">Contained</span></div>
        <div class="stage"><span class="count blue">${s.pipeline.documented}</span><span class="stage-label">Documented</span></div>
      `;

      const ib = document.getElementById('incidents-body');
      if (!data.incidents.length) {
        ib.innerHTML = '<tr><td colspan="9" class="no-data">No incidents yet.</td></tr>';
      } else {
        ib.innerHTML = data.incidents.map(i => {
          const raw = i.raw_data || {};
          const src = raw.source_ip || (raw.raw && raw.raw.source_ip) || '-';
          const usr = raw.target_user || (raw.raw && raw.raw.target_user) || '-';
          const canAct = i.status === 'pending_approval';
          const btns = canAct
            ? `<button class="btn btn-approve" onclick="approveIncident(${i.id})">Approve</button>
               <button class="btn btn-reject" onclick="rejectIncident(${i.id})">Reject</button>`
            : `<button class="btn btn-approve" disabled>Approve</button>
               <button class="btn btn-reject" disabled>Reject</button>`;
          return `<tr>
            <td>#${i.id}</td>
            <td>${i.event_type}</td>
            <td>${sevBadge(i.severity)}</td>
            <td><b>${i.triage_score}</b>/100</td>
            <td style="color:#f87171">${src}</td>
            <td>${usr}</td>
            <td>${statusBadge(i.status)}</td>
            <td style="color:#475569">${i.created_at}</td>
            <td>${btns}</td>
          </tr>`;
        }).join('');
      }

      const ab = document.getElementById('alerts-body');
      if (!data.alerts.length) {
        ab.innerHTML = '<tr><td colspan="6" class="no-data">No alerts yet.</td></tr>';
      } else {
        ab.innerHTML = data.alerts.map(a => `<tr>
          <td>#${a.id}</td><td>${a.event_type}</td><td>${sevBadge(a.severity)}</td>
          <td style="color:#475569">${a.source}</td><td>${statusBadge(a.status)}</td>
          <td style="color:#475569">${a.created_at}</td>
        </tr>`).join('');
      }

      const bl = document.getElementById('blocklist-body');
      if (!data.blocklist.length) {
        bl.innerHTML = '<tr><td colspan="3" class="no-data">No blocked IPs yet.</td></tr>';
      } else {
        bl.innerHTML = data.blocklist.map(b => `<tr>
          <td style="color:#f87171">${b.ip_address}</td><td>${b.reason}</td>
          <td style="color:#475569">${b.added_at}</td>
        </tr>`).join('');
      }
    });
}

refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""


def query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(sql, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def execute(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(sql, params)
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/approve/<int:incident_id>", methods=["POST"])
def approve(incident_id):
    try:
        execute("UPDATE incidents SET status='approved' WHERE id=? AND status='pending_approval'", (incident_id,))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/reject/<int:incident_id>", methods=["POST"])
def reject(incident_id):
    try:
        execute("UPDATE incidents SET status='rejected' WHERE id=? AND status='pending_approval'", (incident_id,))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/data")
def api_data():
    alerts = query("SELECT id, event_type, severity, source, status, created_at FROM alerts ORDER BY id DESC LIMIT 20")

    incidents_raw = query("SELECT id, event_type, severity, triage_score, raw_data, status, created_at FROM incidents ORDER BY id DESC LIMIT 20")
    incidents = []
    for i in incidents_raw:
        try:
            i["raw_data"] = json.loads(i["raw_data"])
        except Exception:
            i["raw_data"] = {}
        incidents.append(i)

    blocklist = query("SELECT ip_address, reason, added_at FROM blocklist ORDER BY id DESC LIMIT 20")

    def count(table, where="1=1"):
        try:
            return query(f"SELECT COUNT(*) as n FROM {table} WHERE {where}")[0]["n"]
        except Exception:
            return 0

    stats = {
        "total_alerts": count("alerts"),
        "total_incidents": count("incidents"),
        "pending_approval": count("incidents", "status='pending_approval'"),
        "contained": count("incidents", "status='contained'"),
        "documented": count("incidents", "status='documented'"),
        "pipeline": {
            "new": count("alerts", "status='new'"),
            "triaged": count("incidents", "status='open'"),
            "investigated": count("incidents", "status='investigated'"),
            "pending_approval": count("incidents", "status='pending_approval'"),
            "contained": count("incidents", "status='contained'"),
            "documented": count("incidents", "status='documented'"),
        }
    }

    return jsonify({"alerts": alerts, "incidents": incidents, "blocklist": blocklist, "stats": stats})


if __name__ == "__main__":
    print("=" * 55)
    print("  OwlEye AI - SOC Dashboard")
    print("  Open: http://localhost:5000")
    print("=" * 55)
    app.run(debug=False, port=5000)