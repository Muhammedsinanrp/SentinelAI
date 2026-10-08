// CYBERSHIELD X - Frontend Application Logic

let currentVulns = [];

// Initialize dashboard on load
document.addEventListener("DOMContentLoaded", async () => {
  await seedDemoDataIfEmpty();
  await refreshAllData();
});

function switchTab(tabName) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach(b => {
    b.classList.remove("border-cyan-400", "text-cyan-400", "font-semibold");
    b.classList.add("border-transparent", "text-slate-400");
  });

  const targetPanel = document.getElementById(`panel-${tabName}`);
  const targetTab = document.getElementById(`tab-${tabName}`);
  if (targetPanel) targetPanel.classList.remove("hidden");
  if (targetTab) {
    targetTab.classList.remove("border-transparent", "text-slate-400");
    targetTab.classList.add("border-cyan-400", "text-cyan-400", "font-semibold");
  }

  // Refresh tab-specific data
  if (tabName === "asm") fetchAsmData();
  if (tabName === "vulns") fetchVulnsData();
  if (tabName === "siem") fetchSiemData();
  if (tabName === "ai") runAiInvestigation();
}

async function refreshAllData() {
  await fetchDashboardStats();
  await fetchAsmData();
  await fetchVulnsData();
  await fetchSiemData();
  await runAiInvestigation();
}

async function seedDemoDataIfEmpty() {
  try {
    const res = await fetch("/api/dashboard/stats");
    const data = await res.json();
    if (data.total_assets === 0) {
      await fetch("/api/dashboard/seed-demo", { method: "POST" });
    }
  } catch (err) {
    console.warn("Could not check seed status:", err);
  }
}

async function seedDemoData() {
  try {
    const btn = document.getElementById("btn-seed");
    btn.innerText = "Seeding...";
    await fetch("/api/dashboard/seed-demo", { method: "POST" });
    btn.innerText = "Seeded!";
    setTimeout(() => btn.innerText = "Seed Demo Telemetry", 1500);
    await refreshAllData();
  } catch (err) {
    alert("Error seeding data: " + err);
  }
}

// -----------------------------------------------------------------
// 1. Dashboard Stats
// -----------------------------------------------------------------
async function fetchDashboardStats() {
  try {
    const res = await fetch("/api/dashboard/stats");
    const data = await res.json();

    document.getElementById("metric-assets").innerText = data.total_assets.toLocaleString();
    document.getElementById("metric-critical").innerText = data.critical_vulnerabilities;
    document.getElementById("metric-alerts").innerText = data.total_alerts;
    document.getElementById("metric-risk").innerText = data.risk_score;

    // Severity breakdown
    const sev = data.severity_breakdown || {};
    const total = (sev.Critical || 0) + (sev.High || 0) + (sev.Medium || 0) + (sev.Low || 0) || 1;

    document.getElementById("bar-crit-num").innerText = sev.Critical || 0;
    document.getElementById("bar-high-num").innerText = sev.High || 0;
    document.getElementById("bar-med-num").innerText = sev.Medium || 0;
    document.getElementById("bar-low-num").innerText = sev.Low || 0;

    document.getElementById("bar-crit").style.width = `${Math.min(100, ((sev.Critical || 0) / total) * 100 * 2)}%`;
    document.getElementById("bar-high").style.width = `${Math.min(100, ((sev.High || 0) / total) * 100 * 2)}%`;
    document.getElementById("bar-med").style.width = `${Math.min(100, ((sev.Medium || 0) / total) * 100 * 2)}%`;
    document.getElementById("bar-low").style.width = `${Math.min(100, ((sev.Low || 0) / total) * 100 * 2)}%`;

    // Recent Incidents Feed
    const feed = document.getElementById("incident-feed-list");
    feed.innerHTML = "";
    (data.recent_incidents || []).forEach(inc => {
      const isCrit = inc.severity === "CRITICAL";
      const badgeClass = isCrit ? "badge-critical" : inc.severity === "HIGH" ? "badge-high" : "badge-medium";
      const icon = isCrit ? "🔴" : inc.severity === "HIGH" ? "🟠" : "🟡";

      const item = document.createElement("div");
      item.className = "p-3 bg-slate-900/60 border border-slate-800/90 rounded-lg flex items-center justify-between hover:border-slate-700 transition";
      item.innerHTML = `
        <div class="flex items-center gap-3">
          <span class="text-lg">${icon}</span>
          <div>
            <div class="flex items-center gap-2">
              <span class="font-bold text-xs text-white">${inc.title}</span>
              <span class="badge ${badgeClass} text-[9px]">${inc.severity}</span>
            </div>
            <p class="text-xs text-slate-400 mt-0.5">Target: <code class="text-cyan-400">${inc.target_host || 'N/A'}</code> &bull; Source: <code class="text-amber-400">${inc.source_ip || 'N/A'}</code> &bull; Rule: ${inc.alert_rule}</p>
          </div>
        </div>
        <button onclick="investigateSpecificAlert(${inc.id})" class="btn btn-secondary text-[11px] py-1 px-2.5">
          Investigate &rarr;
        </button>
      `;
      feed.appendChild(item);
    });
  } catch (err) {
    console.error("Dashboard fetch error:", err);
  }
}

// -----------------------------------------------------------------
// 2. Attack Surface Management
// -----------------------------------------------------------------
async function checkScopeAction() {
  const target = document.getElementById("asm-target-input").value.trim();
  const badge = document.getElementById("scope-status-badge");
  try {
    const res = await fetch("/api/asm/check-scope", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    const data = await res.json();
    if (data.is_in_scope) {
      badge.className = "absolute right-3 top-2.5 badge badge-low text-[10px]";
      badge.innerText = "Authorized (In Scope)";
    } else {
      badge.className = "absolute right-3 top-2.5 badge badge-critical text-[10px]";
      badge.innerText = "OUT OF SCOPE";
    }
  } catch (e) {
    badge.innerText = "Error";
  }
}

async function triggerAsmScan() {
  const domain = document.getElementById("asm-target-input").value.trim();
  const spinner = document.getElementById("asm-scan-spinner");
  const btn = document.getElementById("btn-asm-scan");

  spinner.classList.remove("hidden");
  btn.disabled = true;

  try {
    const res = await fetch("/api/asm/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, run_vuln_scan: true })
    });
    const data = await res.json();
    if (res.ok) {
      await fetchAsmData();
      await fetchDashboardStats();
    } else {
      alert(data.detail || "Scan failed");
    }
  } catch (err) {
    alert("Scan error: " + err);
  } finally {
    spinner.classList.add("hidden");
    btn.disabled = false;
  }
}

async function fetchAsmData() {
  try {
    const res = await fetch("/api/asm/assets");
    const assets = await res.json();
    document.getElementById("asset-count-tag").innerText = `${assets.length} Discovered Assets`;

    const tbody = document.getElementById("assets-tbody");
    tbody.innerHTML = "";
    assets.forEach(a => {
      const ports = (a.open_ports || []).map(p => `<span class="badge badge-low text-[10px]">${p.port}/${p.service}</span>`).join(" ") || '<span class="text-slate-500 text-xs">None detected</span>';
      const ips = (a.ip_addresses || []).join(", ") || "N/A";
      const techs = (a.technologies || []).slice(0, 3).join(", ") || "Web Service";
      const tls = a.tls_info?.tls_version ? `<span class="text-emerald-400 font-mono text-xs">${a.tls_info.tls_version}</span>` : '<span class="text-slate-500 text-xs">N/A</span>';

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="font-bold text-white flex items-center gap-2">
          <span class="w-2 h-2 rounded-full ${a.status === 'active' ? 'bg-emerald-400' : 'bg-slate-500'}"></span>
          ${a.domain}
        </td>
        <td class="font-mono text-xs text-slate-300">${ips}</td>
        <td><div class="flex flex-wrap gap-1">${ports}</div></td>
        <td class="text-xs text-slate-300">${techs}</td>
        <td>${tls}</td>
        <td><span class="badge ${a.is_in_scope ? 'badge-low' : 'badge-critical'} text-[10px]">${a.status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load assets:", err);
  }
}

// -----------------------------------------------------------------
// 3. Vulnerability Management
// -----------------------------------------------------------------
async function fetchVulnsData() {
  try {
    const res = await fetch("/api/vulns");
    currentVulns = await res.json();
    renderVulns(currentVulns);
  } catch (err) {
    console.error("Failed to load vulns:", err);
  }
}

function filterVulns(sev) {
  if (sev === "ALL") {
    renderVulns(currentVulns);
  } else {
    renderVulns(currentVulns.filter(v => v.severity === sev));
  }
}

function renderVulns(vulns) {
  const container = document.getElementById("vulns-container");
  container.innerHTML = "";

  if (vulns.length === 0) {
    container.innerHTML = `<div class="p-4 text-center text-xs text-slate-500">No vulnerabilities recorded for this filter.</div>`;
    return;
  }

  vulns.forEach(v => {
    const isCrit = v.severity === "CRITICAL";
    const badgeClass = isCrit ? "badge-critical" : v.severity === "HIGH" ? "badge-high" : v.severity === "MEDIUM" ? "badge-medium" : "badge-low";

    const card = document.createElement("div");
    card.className = "p-4 bg-slate-900/60 border border-slate-800 rounded-lg space-y-3";
    card.innerHTML = `
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
        <div class="flex items-center gap-2">
          <span class="badge ${badgeClass}">${v.severity}</span>
          <span class="font-bold text-sm text-white">${v.title}</span>
          ${v.cve_id ? `<span class="badge badge-info font-mono text-[10px]">${v.cve_id}</span>` : ''}
        </div>
        <div class="flex items-center gap-2 text-xs">
          <span class="text-slate-400">Target:</span>
          <code class="text-cyan-400">${v.asset_target}</code>
          <span class="text-slate-500">|</span>
          <span class="text-slate-400">CVSS:</span>
          <span class="font-bold ${isCrit ? 'text-red-400' : 'text-amber-400'} font-mono">${v.cvss_score}</span>
          <span class="text-slate-500">|</span>
          <span class="badge badge-info text-[9px]">${v.tool_source}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <div>
          <span class="text-slate-400 font-semibold block mb-1">Evidence / Proof:</span>
          <div class="code-block text-[11px]">${v.evidence || 'Header observation'}</div>
        </div>
        <div class="space-y-2">
          <div>
            <span class="text-slate-400 font-semibold">Business Impact:</span>
            <p class="text-slate-300 mt-0.5">${v.business_impact || 'Potential unauthorized access.'}</p>
          </div>
          <div>
            <span class="text-slate-400 font-semibold text-emerald-400">Remediation:</span>
            <p class="text-slate-300 mt-0.5">${v.remediation || 'Apply vendor security patch.'}</p>
          </div>
        </div>
      </div>
    `;
    container.appendChild(card);
  });
}

// -----------------------------------------------------------------
// 4. SIEM / SOC Telemetry
// -----------------------------------------------------------------
async function fetchSiemData() {
  try {
    // 1. Logs
    const logRes = await fetch("/api/siem/logs?limit=40");
    const logs = await logRes.json();
    const terminal = document.getElementById("siem-logs-terminal");
    terminal.innerHTML = "";
    logs.forEach(l => {
      const line = document.createElement("div");
      line.className = "flex gap-2 text-[11px]";
      const timeStr = l.timestamp ? l.timestamp.substring(11, 19) : "00:00:00";
      const color = l.severity === "HIGH" ? "text-amber-400" : l.severity === "CRITICAL" ? "text-red-400" : "text-slate-400";
      line.innerHTML = `<span class="text-slate-600">[${timeStr}]</span> <span class="font-bold uppercase ${color}">[${l.source_type}]</span> <span class="text-slate-300">${l.raw_message}</span>`;
      terminal.appendChild(line);
    });

    // 2. Alerts
    const alertRes = await fetch("/api/siem/alerts");
    const alerts = await alertRes.json();
    const stream = document.getElementById("siem-alerts-stream");
    stream.innerHTML = "";
    alerts.slice(0, 4).forEach(al => {
      const isCrit = al.severity === "CRITICAL";
      const div = document.createElement("div");
      div.className = `p-3 rounded-lg border flex items-center justify-between text-xs ${isCrit ? 'bg-red-950/30 border-red-500/40' : 'bg-amber-950/20 border-amber-500/30'}`;
      div.innerHTML = `
        <div class="flex items-center gap-2">
          <span>${isCrit ? '🚨' : '⚠️'}</span>
          <div>
            <span class="font-bold ${isCrit ? 'text-red-300' : 'text-amber-300'}">${al.title}</span>
            <p class="text-slate-400 text-[11px]">${al.description}</p>
          </div>
        </div>
        <button onclick="investigateSpecificAlert(${al.id})" class="btn btn-secondary text-[10px] py-1 px-2">Analyze</button>
      `;
      stream.appendChild(div);
    });
  } catch (err) {
    console.error("SIEM data fetch error:", err);
  }
}

function injectLogPreset(type) {
  const ip = "185.220.101.5";
  if (type === "failed_ssh") {
    document.getElementById("siem-source-type").value = "linux";
    document.getElementById("siem-raw-input").value = `sshd[${Math.floor(Math.random()*9000)+1000}]: Failed password for root from ${ip} port ${Math.floor(Math.random()*20000)+30000} ssh2`;
  } else if (type === "success_ssh") {
    document.getElementById("siem-source-type").value = "linux";
    document.getElementById("siem-raw-input").value = `sshd[${Math.floor(Math.random()*9000)+1000}]: Accepted password for root from ${ip} port ${Math.floor(Math.random()*20000)+30000} ssh2`;
  } else if (type === "sudo_priv") {
    document.getElementById("siem-source-type").value = "linux";
    document.getElementById("siem-raw-input").value = `sudo: deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash`;
  } else if (type === "sqli_probe") {
    document.getElementById("siem-source-type").value = "web";
    document.getElementById("siem-raw-input").value = `${ip} - - [08/Oct/2026:12:00:00 +0000] "GET /api/v1/users?id=1' UNION SELECT null,username,password_hash FROM users-- HTTP/1.1" 200`;
  }
}

async function submitSiemLog() {
  const source_type = document.getElementById("siem-source-type").value;
  const raw_message = document.getElementById("siem-raw-input").value.trim();
  if (!raw_message) return;

  try {
    const res = await fetch("/api/siem/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source_type, raw_message })
    });
    const data = await res.json();
    await fetchSiemData();
    await fetchDashboardStats();
    if (data.alerts_triggered > 0) {
      alert(`🚨 SIEM Correlation Alert Triggered: ${data.alerts[0].title}`);
    }
  } catch (err) {
    alert("Failed to ingest log: " + err);
  }
}

async function simulateAttackKillchain() {
  const btn = document.getElementById("btn-simulate");
  btn.innerText = "Simulating Kill-Chain...";
  try {
    const res = await fetch("/api/siem/simulate-attack", { method: "POST" });
    const data = await res.json();
    btn.innerText = "Simulated!";
    setTimeout(() => btn.innerText = "Simulate Attack Kill-Chain", 1500);
    await refreshAllData();
    switchTab("ai");
  } catch (err) {
    alert("Attack simulation error: " + err);
  }
}

// -----------------------------------------------------------------
// 5. AI Security Analyst & Timeline
// -----------------------------------------------------------------
async function runAiInvestigation(alertId = null) {
  try {
    const payload = alertId ? { alert_id: alertId } : {};
    const res = await fetch("/api/ai/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    const dossier = data.dossier || {};
    const timeline = data.timeline || [];

    // Render Timeline
    const tlContainer = document.getElementById("attack-timeline-container");
    tlContainer.innerHTML = "";

    if (timeline.length === 0) {
      tlContainer.innerHTML = `<p class="text-xs text-slate-500">No attack timeline recorded yet.</p>`;
    } else {
      timeline.forEach((item, idx) => {
        const isLast = idx === timeline.length - 1;
        const isCritical = item.phase === "Command and Control" || item.phase === "Privilege Escalation" || item.event_name.includes("Successful");

        const step = document.createElement("div");
        step.className = "timeline-item";
        step.innerHTML = `
          <div class="timeline-dot ${isCritical ? 'critical' : ''}"></div>
          <div class="text-xs">
            <div class="flex items-center gap-2">
              <span class="font-mono text-cyan-400 font-bold">${item.time}</span>
              <span class="font-bold text-white">${item.event_name}</span>
            </div>
            <p class="text-slate-400 text-[11px] mt-0.5">${item.description}</p>
            <div class="flex items-center gap-2 mt-1">
              <span class="badge badge-info text-[9px]">${item.phase}</span>
              <span class="badge badge-low font-mono text-[9px]">${item.mitre_id}</span>
            </div>
          </div>
        `;
        tlContainer.appendChild(step);
      });
    }

    // Render Dossier
    document.getElementById("ai-severity-badge").innerText = `${dossier.assessed_severity || 'HIGH'} ASSESSED`;
    document.getElementById("ai-incident-summary").innerText = dossier.incident_summary || "Investigation summary generated.";
    document.getElementById("ai-potential-attack").innerText = dossier.potential_attack_type || "SSH Brute Force with Compromise";
    document.getElementById("ai-root-cause").innerText = dossier.root_cause_analysis || "Weak exposed administrative services.";

    // Render MITRE ATT&CK Tags
    const mitreBox = document.getElementById("ai-mitre-tags");
    mitreBox.innerHTML = "";
    (dossier.mitre_att_ck || []).forEach(m => {
      const tag = document.createElement("span");
      tag.className = "badge badge-low text-xs";
      tag.innerText = `${m.technique_id} - ${m.name} (${m.phase})`;
      mitreBox.appendChild(tag);
    });

    // Render Containment Actions
    const contList = document.getElementById("ai-containment-list");
    contList.innerHTML = "";
    (dossier.immediate_containment_actions || []).forEach(act => {
      const li = document.createElement("li");
      li.innerText = act;
      contList.appendChild(li);
    });

    // Render Remediation Actions
    const remList = document.getElementById("ai-remediation-list");
    remList.innerHTML = "";
    (dossier.eradication_and_remediation || []).forEach(act => {
      const li = document.createElement("li");
      li.innerText = act;
      remList.appendChild(li);
    });

  } catch (err) {
    console.error("AI Investigation error:", err);
  }
}

function investigateSpecificAlert(alertId) {
  switchTab("ai");
  runAiInvestigation(alertId);
}
