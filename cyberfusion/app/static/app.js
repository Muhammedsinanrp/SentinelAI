// CYBERFUSION X - Unified Frontend Logic

document.addEventListener("DOMContentLoaded", async () => {
  await loadDashboardData();
  await loadPentestTools();
  await loadAsmData();
  await loadSiemData();
  await loadCspmData();
  await loadApiSecData();
  await runAiInvestigation();
});

function switchTab(tabName) {
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".tab-btn").forEach(b => {
    b.classList.remove("border-cyan-400", "text-cyan-400");
    b.classList.add("border-transparent", "text-slate-400");
  });

  const targetPanel = document.getElementById(`panel-${tabName}`);
  const targetTab = document.getElementById(`tab-${tabName}`);
  if (targetPanel) targetPanel.classList.remove("hidden");
  if (targetTab) {
    targetTab.classList.remove("border-transparent", "text-slate-400");
    targetTab.classList.add("border-cyan-400", "text-cyan-400");
  }

  if (tabName === "ai") runAiInvestigation();
  if (tabName === "tools") loadPentestTools();
}

async function loadDashboardData() {
  try {
    const res = await fetch("/api/dashboard/stats");
    const data = await res.json();
  } catch (err) {
    console.error("Dashboard fetch error:", err);
  }
}

async function loadPentestTools() {
  try {
    const res = await fetch("/api/tools/suite");
    const data = await res.json();
    const grid = document.getElementById("tool-inventory-grid");
    if (!grid) return;
    grid.innerHTML = "";
    (data.tools || []).forEach(t => {
      const card = document.createElement("div");
      card.className = "p-4 bg-slate-900/60 border border-slate-800 rounded-lg text-xs space-y-2";
      card.innerHTML = `
        <div class="flex justify-between items-center">
          <span class="font-bold text-white text-sm">${t.name}</span>
          <span class="badge ${t.installed ? 'badge-low' : 'badge-med'}">${t.installed ? 'ACTIVE' : 'READY'}</span>
        </div>
        <p class="text-slate-400 text-[11px]">${t.description}</p>
        <div class="pt-1 flex flex-wrap gap-1">
          ${(t.capabilities || []).map(c => `<span class="badge badge-low text-[9px]">${c}</span>`).join(" ")}
        </div>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    console.error("Tools load error:", err);
  }
}

async function executeNmapScanAction() {
  const target = document.getElementById("nmap-target").value.trim();
  const ports = document.getElementById("nmap-ports").value.trim();
  const btn = document.getElementById("btn-nmap-scan");
  const box = document.getElementById("nmap-results-box");

  btn.innerText = "Running Nmap Scan...";
  btn.disabled = true;

  try {
    const res = await fetch("/api/tools/nmap/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, ports, script_scan: true })
    });
    const data = await res.json();
    box.classList.remove("hidden");
    let out = `[Nmap Engine: ${data.engine}] Target: ${data.target}\n`;
    (data.open_services || []).forEach(s => {
      out += `• PORT ${s.port}/tcp: ${s.service.toUpperCase()} - ${s.product} ${s.version || ''}\n`;
    });
    if ((data.vulnerabilities_detected || []).length > 0) {
      out += `\n[Findings Detected]:\n`;
      data.vulnerabilities_detected.forEach(f => {
        out += `  ⚠️ [${f.severity}] ${f.title}\n`;
      });
    }
    box.innerText = out;
  } catch (err) {
    alert("Nmap error: " + err);
  } finally {
    btn.innerText = "Run Authorized Nmap Scan";
    btn.disabled = false;
  }
}

async function checkCaidoAction() {
  try {
    const res = await fetch("/api/tools/caido/status");
    const data = await res.json();
    const badge = document.getElementById("caido-badge");
    if (data.caido.connected) {
      badge.className = "badge badge-low";
      badge.innerText = `Connected @ ${data.caido.proxy_url}`;
    } else {
      badge.className = "badge badge-high";
      badge.innerText = `Upstream Config: 127.0.0.1:8080`;
    }
    alert(`Caido Status: ${data.caido.note || 'Connected to proxy successfully.'}\nProxy URL: ${data.proxy_config.http}`);
  } catch (err) {
    alert("Caido check error: " + err);
  }
}

async function ingestDemoCaidoTraffic() {
  try {
    const res = await fetch("/api/tools/caido/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        traffic_items: [
          {
            request: { method: "POST", url: "https://api.example.com/api/v1/auth/token" },
            response: { status: 200, body: '{"access_token": "ey..."}' }
          },
          {
            request: { method: "GET", url: "https://api.example.com/api/admin/users?debug=true" },
            response: { status: 200, body: '{"admin_secrets": "exposed"}' }
          }
        ]
      })
    });
    const data = await res.json();
    const feed = document.getElementById("caido-traffic-feed");
    feed.innerHTML = "";
    (data.findings || []).forEach(f => {
      const div = document.createElement("div");
      div.className = "p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-cyan-300 font-mono";
      div.innerText = `[Intercepted] ${f.title} (${f.evidence})`;
      feed.appendChild(div);
    });
    alert(`Ingested ${data.ingested_count} requests and findings from Caido proxy session!`);
  } catch (err) {
    alert("Ingestion error: " + err);
  }
}

async function loadAsmData() {
  try {
    const res = await fetch("/api/asm/assets");
    const assets = await res.json();
    const container = document.getElementById("asm-assets-list");
    if (!container) return;
    container.innerHTML = "";
    assets.forEach(a => {
      const item = document.createElement("div");
      item.className = "p-3 bg-slate-900/60 rounded border border-slate-800 flex justify-between items-center text-xs";
      const ports = (a.open_ports || []).map(p => `${p.port}/${p.service}`).join(", ") || "None";
      item.innerHTML = `
        <div>
          <span class="font-bold text-white">${a.domain}</span>
          <span class="text-slate-400 ml-2 font-mono">(${a.asset_type})</span>
          <p class="text-slate-400 text-[11px] mt-0.5">IPs: ${(a.ip_addresses || []).join(", ") || "93.184.216.34"} &bull; Open Ports: <span class="text-cyan-400 font-mono">${ports}</span></p>
        </div>
        <span class="badge badge-low text-[10px]">${a.status || 'Active'}</span>
      `;
      container.appendChild(item);
    });
  } catch (err) {
    console.error("ASM load error:", err);
  }
}

async function runAsmScan() {
  const target = document.getElementById("asm-target").value.trim();
  try {
    const res = await fetch("/api/asm/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: target })
    });
    const data = await res.json();
    alert(`Discovery completed for ${target}! Found subdomains & ports.`);
    await loadAsmData();
  } catch (err) {
    alert("Scan error: " + err);
  }
}

async function loadSiemData() {
  try {
    const res = await fetch("/api/siem/logs");
    const logs = await res.json();
    const terminal = document.getElementById("siem-terminal");
    if (!terminal) return;
    terminal.innerHTML = "";
    logs.forEach(l => {
      const div = document.createElement("div");
      div.className = "text-[11px] py-0.5";
      div.innerHTML = `<span class="text-slate-500">[${l.timestamp}]</span> <span class="text-cyan-400 font-bold">[${l.source_type.toUpperCase()}]</span> <span class="text-slate-300">${l.raw_message}</span>`;
      terminal.appendChild(div);
    });
  } catch (err) {
    console.error("SIEM load error:", err);
  }
}

async function loadCspmData() {
  try {
    const res = await fetch("/api/cspm/findings");
    const findings = await res.json();
    const container = document.getElementById("cspm-findings");
    if (!container) return;
    container.innerHTML = "";
    findings.forEach(f => {
      const isCrit = f.severity === "CRITICAL";
      const div = document.createElement("div");
      div.className = `p-3 rounded-lg border text-xs space-y-1 ${isCrit ? 'bg-red-950/20 border-red-500/30' : 'bg-slate-900/60 border-slate-800'}`;
      div.innerHTML = `
        <div class="flex justify-between items-center">
          <span class="font-bold text-white">${f.title}</span>
          <span class="badge ${isCrit ? 'badge-crit' : 'badge-high'}">${f.severity}</span>
        </div>
        <p class="text-slate-400 text-[11px]">Resource: <code class="text-cyan-400">${f.resource_id}</code> &bull; Rule: ${f.rule_id}</p>
        <p class="text-emerald-400 text-[11px]">Remediation: ${f.remediation}</p>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error("CSPM load error:", err);
  }
}

async function loadApiSecData() {
  try {
    const res = await fetch("/api/apisec/inventory");
    const data = await res.json();
    const container = document.getElementById("api-findings-list");
    if (!container) return;
    container.innerHTML = "";
    (data.findings || []).forEach(f => {
      const div = document.createElement("div");
      div.className = "p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-xs space-y-1";
      div.innerHTML = `
        <div class="flex justify-between items-center">
          <span class="font-bold text-white"><code class="text-amber-400">${f.method} ${f.endpoint_path}</code> - ${f.finding_type}</span>
          <span class="badge badge-high">${f.severity} (CVSS ${f.cvss_score})</span>
        </div>
        <p class="text-slate-300 text-[11px]">${f.details}</p>
        <p class="text-emerald-400 text-[11px]">Remediation: ${f.remediation}</p>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error("API Sec error:", err);
  }
}

async function runAiInvestigation() {
  try {
    const res = await fetch("/api/ai/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({})
    });
    const data = await res.json();
    const dossier = data.dossier || {};
    const timeline = data.timeline || [];

    const tlBox = document.getElementById("ai-timeline-container");
    if (tlBox) {
      tlBox.innerHTML = "";
      timeline.forEach(t => {
        const isCrit = t.phase === "Impact" || t.phase === "Initial Access" || t.event_name.includes("Ransomware");
        const step = document.createElement("div");
        step.className = "timeline-step";
        step.innerHTML = `
          <div class="timeline-dot ${isCrit ? 'critical' : ''}"></div>
          <div class="text-xs">
            <div class="flex items-center gap-2">
              <span class="font-mono text-cyan-400 font-bold">${t.time}</span>
              <span class="font-bold text-white">${t.event_name}</span>
            </div>
            <p class="text-slate-400 text-[11px] mt-0.5">${t.description}</p>
            <div class="flex items-center gap-2 mt-1">
              <span class="badge badge-low text-[9px]">${t.module_source}</span>
              <span class="badge badge-high font-mono text-[9px]">${t.mitre_id}</span>
            </div>
          </div>
        `;
        tlBox.appendChild(step);
      });
    }

    const summaryElem = document.getElementById("ai-summary");
    if (summaryElem) summaryElem.innerText = dossier.executive_summary || "Multi-stage incident investigation active.";

    const mitreBox = document.getElementById("ai-mitre-box");
    if (mitreBox) {
      mitreBox.innerHTML = "";
      (dossier.mitre_att_ck_mapping || []).forEach(m => {
        const tag = document.createElement("span");
        tag.className = "badge badge-low text-[10px]";
        tag.innerText = `${m.technique} - ${m.name} (${m.phase})`;
        mitreBox.appendChild(tag);
      });
    }

    const contBox = document.getElementById("ai-containment");
    if (contBox) {
      contBox.innerHTML = "";
      (dossier.immediate_containment_actions || []).forEach(a => {
        const li = document.createElement("li");
        li.innerText = a;
        contBox.appendChild(li);
      });
    }

    const remBox = document.getElementById("ai-remediation");
    if (remBox) {
      remBox.innerHTML = "";
      (dossier.long_term_remediation_playbook || []).forEach(a => {
        const li = document.createElement("li");
        li.innerText = a;
        remBox.appendChild(li);
      });
    }

  } catch (err) {
    console.error("AI Investigation error:", err);
  }
}

async function simulateCrossKillchain() {
  try {
    const res = await fetch("/api/dashboard/simulate-killchain", { method: "POST" });
    const data = await res.json();
    alert("⚡ Unified 7-Vector Kill-Chain Simulated! Correlating in AI Console...");
    switchTab("ai");
  } catch (err) {
    alert("Simulation error: " + err);
  }
}
