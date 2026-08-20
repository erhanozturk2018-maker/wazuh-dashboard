/* ================================================================
   Wazuh Console v2 — client logic
   Backend contract (unchanged): GET /api/alerts · POST /api/clear
   Alert fields: received_at, received_epoch, wazuh_timestamp, level,
   rule_id, description, agent, groups, ip, raw_log, raw_json
   ================================================================ */
"use strict";

const ORIGINAL_TITLE = document.title;
const POLL_MS = 2000;
const RANGE_SECONDS = { "5m": 300, "1h": 3600, "24h": 86400 };

let allAlerts = [];
let lastCount = 0;
let unseenCount = 0;
let chart = null;
let currentRange = "all";

/* ---------- helpers ---------- */
const $ = (id) => document.getElementById(id);

function esc(s) {
  const d = document.createElement("div");
  d.innerText = s === undefined || s === null ? "" : s;
  return d.innerHTML;
}

function bucket(level) {
  const l = parseInt(level, 10);
  if (isNaN(l)) return "unknown";
  if (l >= 10) return "high";
  if (l >= 5) return "mid";
  return "low";
}

const PLACEHOLDERS = new Set(["Not specified", "IP not found", "No group info", "Unknown agent"]);

/* ---------- filtering ---------- */
function applyRange(data) {
  if (currentRange === "all") return data;
  const cutoff = Date.now() / 1000 - RANGE_SECONDS[currentRange];
  return data.filter((a) => (a.received_epoch || 0) >= cutoff);
}

function getFiltered() {
  const q = $("f-search").value.trim().toLowerCase();
  const lvl = $("f-level").value;
  const agent = $("f-agent").value;

  let data = applyRange(allAlerts);
  if (lvl !== "all") data = data.filter((a) => bucket(a.level) === lvl);
  if (agent !== "all") data = data.filter((a) => a.agent === agent);
  if (q) {
    data = data.filter((a) =>
      [a.description, a.agent, a.rule_id, a.groups, a.ip]
        .some((v) => String(v || "").toLowerCase().includes(q))
    );
  }
  return data;
}

/* ---------- KPI band ---------- */
function renderKpis(data) {
  $("kpi-total").textContent = data.length;
  $("kpi-high").textContent = data.filter((a) => bucket(a.level) === "high").length;
  $("kpi-mid").textContent = data.filter((a) => bucket(a.level) === "mid").length;
  $("kpi-low").textContent = data.filter((a) => bucket(a.level) === "low").length;
}

/* ---------- ranked lists ---------- */
function renderRank(containerId, data, keyFn, limit = 10) {
  const box = $(containerId);
  const counts = {};
  data.forEach((a) => {
    const k = keyFn(a);
    if (!k || PLACEHOLDERS.has(k)) return;
    counts[k] = (counts[k] || 0) + 1;
  });

  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, limit);
  if (!entries.length) {
    box.innerHTML = '<div class="empty-mini">No data in this range yet.</div>';
    return;
  }
  const max = entries[0][1];
  box.innerHTML = entries
    .map(
      ([label, n]) => `
      <div class="rank-row">
        <div class="rank-fill" style="width:${(n / max) * 100}%"></div>
        <div class="rank-in">
          <span class="rank-label" title="${esc(label)}">${esc(label)}</span>
          <span class="rank-n">${n}</span>
        </div>
      </div>`
    )
    .join("");
}

function ipCounts(data) {
  const c = {};
  data.forEach((a) => {
    if (!a.ip || a.ip === "IP not found") return;
    c[a.ip] = (c[a.ip] || 0) + 1;
  });
  return c;
}

/* ---------- chart ---------- */
function renderChart(data) {
  const canvas = $("chart");
  const emptyEl = $("chart-empty");
  if (!canvas || typeof Chart === "undefined") return;

  const points = data.filter((a) => a.received_epoch);

  if (!points.length) {
    canvas.style.display = "none";
    if (emptyEl) emptyEl.style.display = "flex";
    return;
  }
  canvas.style.display = "block";
  if (emptyEl) emptyEl.style.display = "none";

  const buckets = {};
  points.forEach((a) => {
    const key = Math.floor(a.received_epoch / 60) * 60;
    buckets[key] = (buckets[key] || 0) + 1;
  });

  const WINDOW = 24; // the last 24 minutes, gaps included
  const maxKey = Math.max(...Object.keys(buckets).map(Number));
  const keys = [];
  for (let i = WINDOW - 1; i >= 0; i--) keys.push(maxKey - i * 60);

  const labels = keys.map((k) =>
    new Date(k * 1000).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false })
  );
  const values = keys.map((k) => buckets[k] || 0); // veri olmayan dakika = 0

  if (chart) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update("none");
    return;
  }

  const ctx = canvas.getContext("2d");
  const grad = ctx.createLinearGradient(0, 0, 0, 260);
  grad.addColorStop(0, "rgba(124,111,255,0.30)");
  grad.addColorStop(1, "rgba(124,111,255,0.00)");

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Alerts / min",
          data: values,
          borderColor: "#9a90ff",
          borderWidth: 2,
          backgroundColor: grad,
          fill: true,
          tension: 0.38,
          pointRadius: 0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: "#9a90ff",
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#15181f",
          borderColor: "#2a2f3b",
          borderWidth: 1,
          titleColor: "#edeef2",
          bodyColor: "#b4b9c6",
          titleFont: { family: "JetBrains Mono", size: 11 },
          bodyFont: { family: "JetBrains Mono", size: 11 },
          padding: 10,
          displayColors: false,
        },
      },
      scales: {
        x: {
          ticks: { color: "#545a69", maxTicksLimit: 8, font: { family: "JetBrains Mono", size: 10 } },
          grid: { color: "rgba(30,34,43,0.6)" },
          border: { display: false },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#545a69", precision: 0, font: { family: "JetBrains Mono", size: 10 } },
          grid: { color: "rgba(30,34,43,0.6)" },
          border: { display: false },
        },
      },
    },
  });
}
/* ---------- table ---------- */
function groupChips(groups) {
  if (!groups || groups === "No group info") return '<span class="empty-mini">—</span>';
  const parts = String(groups).split(",").map((g) => g.trim()).filter(Boolean);
  const shown = parts.slice(0, 2).map((g) => `<span class="gchip">${esc(g)}</span>`).join("");
  const extra = parts.length > 2 ? `<span class="gchip">+${parts.length - 2}</span>` : "";
  return shown + extra;
}

function emptyRow(title, sub) {
  return `
    <tr><td colspan="8">
      <div class="tbl-empty">
        <div class="ei"><svg data-lucide="radar"></svg></div>
        <div class="et">${esc(title)}</div>
        <div class="es">${esc(sub)}</div>
      </div>
    </td></tr>`;
}

function renderTable(data) {
  const body = $("alert-body");
  const ips = ipCounts(data);

  if (!data.length) {
    body.innerHTML = allAlerts.length
      ? emptyRow("No matches", "Nothing matches the current filters — try widening the time range.")
      : emptyRow("Listening for alerts", "Rows appear the moment the Wazuh manager forwards an event.");
    if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
    return;
  }

  body.innerHTML = "";
  data.forEach((a, idx) => {
    const tr = document.createElement("tr");
    tr.className = "row" + (idx === 0 && allAlerts.length > lastCount ? " flash" : "");
    const hot = a.ip && ips[a.ip] > 1;
    tr.innerHTML = `
      <td class="td-mono">${esc(a.received_at)}</td>
      <td class="td-mono">${esc(a.wazuh_timestamp)}</td>
      <td><span class="pill pill-${bucket(a.level)}">${esc(a.level)}</span></td>
      <td class="td-mono">${esc(a.rule_id)}</td>
      <td class="td-desc"><span class="desc-clip">${esc(a.description)}</span></td>
      <td>${esc(a.agent)}</td>
      <td><span class="iptag${hot ? " hot" : ""}">${esc(a.ip)}</span></td>
      <td>${groupChips(a.groups)}</td>`;
    tr.addEventListener("click", () => openDrawer(a));
    body.appendChild(tr);
  });
}

/* ---------- agent options ---------- */
function refreshAgents(data) {
  const sel = $("f-agent");
  const cur = sel.value;
  const agents = Array.from(new Set(data.map((a) => a.agent).filter(Boolean))).sort();
  sel.innerHTML =
    '<option value="all">All agents</option>' +
    agents.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join("");
  if (agents.includes(cur)) sel.value = cur;
}

/* ---------- drawer ---------- */
function openDrawer(a) {
  $("drawer-body").innerHTML = `
    <div class="dgrid">
      <div class="dfield"><div class="dk">Severity</div><div class="dv"><span class="pill pill-${bucket(a.level)}">${esc(a.level)}</span></div></div>
      <div class="dfield"><div class="dk">Rule ID</div><div class="dv mono">${esc(a.rule_id)}</div></div>
      <div class="dfield wide"><div class="dk">Description</div><div class="dv">${esc(a.description)}</div></div>
      <div class="dfield"><div class="dk">Agent</div><div class="dv">${esc(a.agent)}</div></div>
      <div class="dfield"><div class="dk">Source IP</div><div class="dv"><span class="iptag">${esc(a.ip)}</span></div></div>
      <div class="dfield"><div class="dk">Received</div><div class="dv mono">${esc(a.received_at)}</div></div>
      <div class="dfield"><div class="dk">Wazuh timestamp</div><div class="dv mono">${esc(a.wazuh_timestamp)}</div></div>
      <div class="dfield wide"><div class="dk">Groups</div><div class="dv">${groupChips(a.groups)}</div></div>
    </div>

    <div class="dsec">
      <div class="dsec-head"><span class="dsec-title">Raw log</span></div>
      <pre class="codeblock">${esc(a.raw_log)}</pre>
    </div>

    <div class="dsec">
      <div class="dsec-head">
        <span class="dsec-title">Full payload</span>
        <button type="button" class="copy-btn" id="copy-json">copy</button>
      </div>
      <pre class="codeblock">${esc(JSON.stringify(a.raw_json, null, 2))}</pre>
    </div>`;

  const cp = $("copy-json");
  if (cp) {
    cp.addEventListener("click", () => {
      navigator.clipboard.writeText(JSON.stringify(a.raw_json, null, 2)).then(() => {
        cp.textContent = "copied";
        setTimeout(() => (cp.textContent = "copy"), 1400);
      });
    });
  }

  showDrawer();
}

/* ---------- drawer: shared open/close focus handling ----------
   Both alert and agent drawers reuse the same #drawer/#scrim markup, so
   focus trapping, initial focus, and focus restore on close live here
   once rather than being duplicated per drawer type. */
let drawerLastFocused = null;

function trapDrawerFocus(e) {
  if (e.key !== "Tab") return;
  const focusables = $("drawer").querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  if (!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function showDrawer() {
  drawerLastFocused = document.activeElement;
  $("scrim").classList.add("open");
  $("drawer").classList.add("open");
  $("drawer").addEventListener("keydown", trapDrawerFocus);
  $("drawer-close").focus();
}

function closeDrawer() {
  $("scrim").classList.remove("open");
  $("drawer").classList.remove("open");
  $("drawer").removeEventListener("keydown", trapDrawerFocus);
  if (drawerLastFocused && typeof drawerLastFocused.focus === "function") {
    drawerLastFocused.focus();
  }
  drawerLastFocused = null;
}

/* ---------- CSV export ---------- */
function exportCSV() {
  const data = getFiltered();
  if (!data.length) return;
  const headers = ["received_at", "wazuh_timestamp", "level", "rule_id", "description", "agent", "ip", "groups"];
  const rows = data.map((a) =>
    headers.map((h) => '"' + String(a[h] ?? "").replace(/"/g, '""') + '"').join(",")
  );
  const blob = new Blob([headers.join(",") + "\n" + rows.join("\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "wazuh_alerts_" + new Date().toISOString().slice(0, 19).replace(/:/g, "-") + ".csv";
  link.click();
  URL.revokeObjectURL(url);
}

/* ---------- title counter ---------- */
function updateTitle() {
  document.title = unseenCount > 0 ? `(${unseenCount}) ${ORIGINAL_TITLE}` : ORIGINAL_TITLE;
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    unseenCount = 0;
    updateTitle();
  }
});

/* ---------- render pipeline ---------- */
function renderAll() {
  const data = getFiltered();
  renderKpis(data);
  renderTable(data);
  renderRank("list-rules", data, (a) => a.rule_id);
  renderRank("list-ips", data, (a) => a.ip);
  renderChart(data);
  $("alert-count").textContent = data.length;
}

/* ---------- data ---------- */
async function fetchAlerts() {
  try {
    const res = await fetch("/api/alerts");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json();

    if (data.length > lastCount) {
      const added = data.length - lastCount;
      const top = data[0];
      const announcer = $("sr-announcer");
      if (announcer) {
        announcer.textContent =
          (added === 1 ? "1 new alert" : added + " new alerts") +
          (top ? ". Latest: level " + top.level + " — " + top.description : "");
      }
      if (document.hidden) {
        unseenCount += added;
        updateTitle();
      }
    }

    allAlerts = data;
    refreshAgents(data);
    renderAll();
    lastCount = data.length;
    $("status-text").textContent =
      "updated " + new Date().toLocaleTimeString("en-US", { hour12: false });
  } catch (e) {
    $("status-text").textContent = "connection error";
  }
}

async function clearAlerts() {
  await fetch("/api/clear", { method: "POST" });
  lastCount = 0;
  unseenCount = 0;
  updateTitle();
  fetchAlerts();
}

/* ---------- wiring: drawer (shared by every page with a drawer) ---------- */
if ($("scrim")) $("scrim").addEventListener("click", closeDrawer);
if ($("drawer-close")) $("drawer-close").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeDrawer();
});

/* ---------- wiring: Overview page only ----------
   This file is loaded by every page (the project keeps all first-party JS
   in one file), so page-specific wiring is guarded by an element that only
   that page renders. */
if ($("alert-body")) {
  $("f-search").addEventListener("input", renderAll);
  $("f-level").addEventListener("change", renderAll);
  $("f-agent").addEventListener("change", renderAll);

  document.querySelectorAll(".seg-btn").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll(".seg-btn").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      currentRange = b.dataset.range;
      renderAll();
    });
  });

  $("auto-refresh").addEventListener("change", () => {
    $("live-badge").classList.toggle("paused", !$("auto-refresh").checked);
  });

  $("btn-export").addEventListener("click", exportCSV);
  $("btn-clear").addEventListener("click", clearAlerts);

  fetchAlerts();
  setInterval(() => {
    if ($("auto-refresh").checked) fetchAlerts();
  }, POLL_MS);
}

/* ================================================================
   AGENTS PAGE (templates/agents.html)
   Backend contract: GET /api/agents · GET /api/agents/<id> ·
   POST /api/agents · POST /api/agents/<id>/key · POST /api/agents/<id>/delete

   The per-agent detail call is made ONLY when a row is clicked — never
   while rendering the list. `list` is one Wazuh API call for all agents;
   `get` is one call per agent, so fetching detail per row would turn
   every page load into O(n) API calls against a manager whose individual
   calls have been measured taking tens of seconds (see
   docs/architecture/execution-flow.md, Flow 4).
   ================================================================ */
if ($("agents-body")) {
  let agentList = [];

  /* ---------- transport ---------- */
  async function agentApi(url, fields) {
    const opts = fields
      ? {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(fields).toString(),
        }
      : {};
    const res = await fetch(url, opts);
    if (res.status === 401) {
      window.location.href = "/login";
      throw new Error("unauthorized");
    }
    let payload = {};
    try {
      payload = await res.json();
    } catch (e) {
      // Not JSON — almost always an unhandled server-side exception, which
      // uvicorn returns as plain text. Surface the status so it is
      // debuggable from the browser instead of just "something broke".
      throw new Error("Console returned a non-JSON response (HTTP " + res.status + ").");
    }
    if (!res.ok) throw new Error(payload.error || "Request failed.");
    return payload;
  }

  /* ---------- page-level message ---------- */
  function pageMsg(text, kind) {
    const box = $("agents-msg");
    if (!text) {
      box.style.display = "none";
      return;
    }
    box.className = "msg " + (kind === "ok" ? "msg-ok" : "msg-err");
    box.textContent = text;
    box.style.display = "block";
  }

  /* ---------- formatting ---------- */
  function statusPill(status) {
    const s = String(status || "").toLowerCase();
    if (s === "active") return "pill-agent-active";
    if (s === "disconnected") return "pill-agent-disconnected";
    if (s === "pending") return "pill-agent-pending";
    return "pill-agent-unknown";
  }

  function fmtKeepAlive(value) {
    if (!value) return "—";
    const s = String(value).trim();
    // A never-seen agent comes back as a year-9999 sentinel or "Unknown".
    if (!s || s.startsWith("9999") || s === "Unknown") return "—";
    // agent_control reports lastKeepAlive as a Unix epoch *string*
    // (e.g. "1785149045"), not a formatted date — Date() cannot parse that
    // on its own, it has to be multiplied into milliseconds first.
    if (/^\d{9,13}$/.test(s)) {
      const n = Number(s);
      const d = new Date(s.length > 10 ? n : n * 1000);
      return isNaN(d.getTime()) ? s : d.toLocaleString("en-US", { hour12: false });
    }
    const d = new Date(s.includes("T") ? s : s.replace(" ", "T"));
    if (isNaN(d.getTime())) return s;
    return d.toLocaleString("en-US", { hour12: false });
  }

  function osText(os) {
    if (!os) return "—";
    if (typeof os === "string") return os;
    const parts = [os.name, os.version, os.arch].filter(Boolean);
    return parts.length ? parts.join(" · ") : JSON.stringify(os);
  }

  function wireCopy(btn, getText) {
    btn.addEventListener("click", () => {
      navigator.clipboard.writeText(getText()).then(() => {
        btn.textContent = "copied";
        setTimeout(() => (btn.textContent = "copy"), 1400);
      });
    });
  }

  /* ---------- list ---------- */
  function agentsEmptyRow(title, sub) {
    return `
      <tr><td colspan="4">
        <div class="tbl-empty">
          <div class="ei"><svg data-lucide="server"></svg></div>
          <div class="et">${esc(title)}</div>
          <div class="es">${esc(sub)}</div>
        </div>
      </td></tr>`;
  }

  function renderAgents() {
    const body = $("agents-body");
    $("agents-count").textContent = agentList.length;

    if (!agentList.length) {
      body.innerHTML = agentsEmptyRow(
        "No agents registered",
        "Use the form above to register the first agent on the manager."
      );
      if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
      return;
    }

    body.innerHTML = "";
    agentList.forEach((a) => {
      const tr = document.createElement("tr");
      tr.className = "row";
      tr.innerHTML = `
        <td class="td-mono">${esc(a.id)}</td>
        <td class="td-desc">${esc(a.name)}</td>
        <td><span class="iptag">${esc(a.ip)}</span></td>
        <td><span class="pill ${statusPill(a.status)}">${esc(a.status || "unknown")}</span></td>`;
      tr.addEventListener("click", () => openAgentDrawer(a));
      body.appendChild(tr);
    });
  }

  async function fetchAgents() {
    $("agents-status").textContent = "loading…";
    try {
      const data = await agentApi("/api/agents");
      agentList = data.agents || [];
      renderAgents();
      $("agents-status").textContent =
        "updated " + new Date().toLocaleTimeString("en-US", { hour12: false });
    } catch (e) {
      $("agents-body").innerHTML = agentsEmptyRow("Could not reach the manager", e.message);
      if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
      $("agents-status").textContent = "error";
    }
  }

  /* ---------- detail drawer ---------- */
  // Agent id "000" is the Wazuh manager's own entry, not an enrolled agent:
  // it has no key to extract and must not be removed. Both sections are
  // replaced with an explanatory note for it.
  const isManagerEntry = (a) => String(a.id) === "000";

  function managerNoteSection() {
    return `
      <div class="dsec">
        <div class="dsec-head"><span class="dsec-title">Manager entry</span></div>
        <div class="notice">
          <svg data-lucide="info"></svg>
          <span>This is the Wazuh manager's own entry, not an enrolled agent. It has
          no key to extract and cannot be removed from here.</span>
        </div>
      </div>`;
  }

  function keyAndDangerSections(a) {
    return `
      <div class="dsec">
        <div class="dsec-head"><span class="dsec-title">Agent key</span></div>
        <p class="hint" style="margin-bottom: var(--s3);">
          The key is what the monitored host authenticates with. It is shown here on
          request and never stored by this console.
        </p>
        <button type="button" class="btn btn-ghost btn-sm" id="agent-key-btn">
          <svg data-lucide="key-round"></svg> Show key
        </button>
        <div id="agent-key-out"></div>
      </div>

      <div class="dsec">
        <div class="dsec-head"><span class="dsec-title">Danger zone</span></div>
        <p class="hint" style="margin-bottom: var(--s3);">
          Removing an agent from the manager cannot be undone — the host has to be
          re-registered and re-keyed afterwards. After deleting, the host will usually
          re-register automatically once its <code>client.keys</code> file is removed
          and the Wazuh service is restarted — no manual key transfer needed if
          auto-enrollment (authd) is active on this manager.
        </p>
        <button type="button" class="btn btn-danger btn-sm" id="agent-del-btn">
          <svg data-lucide="trash-2"></svg> Delete agent
        </button>
        <div class="confirm-box" id="agent-del-confirm" hidden>
          <div class="f">
            <label for="agent-del-input">Type <code>${esc(a.name)}</code> to confirm</label>
            <input type="text" id="agent-del-input" class="mono" autocomplete="off" placeholder="${esc(a.name)}">
          </div>
          <div class="item-form-actions">
            <button type="button" class="btn btn-ghost btn-sm" id="agent-del-cancel">Cancel</button>
            <button type="button" class="btn btn-danger btn-sm" id="agent-del-go" disabled>Delete permanently</button>
          </div>
        </div>
      </div>`;
  }

  function openAgentDrawer(a) {
    $("drawer-body").innerHTML = `
      <div class="dgrid">
        <div class="dfield"><div class="dk">Agent ID</div><div class="dv mono">${esc(a.id)}</div></div>
        <div class="dfield"><div class="dk">Status</div><div class="dv"><span class="pill ${statusPill(a.status)}">${esc(a.status || "unknown")}</span></div></div>
        <div class="dfield"><div class="dk">Name</div><div class="dv">${esc(a.name)}</div></div>
        <div class="dfield"><div class="dk">IP</div><div class="dv"><span class="iptag">${esc(a.ip)}</span></div></div>
        <div class="dfield wide"><div class="dk">Operating system</div><div class="dv" id="agent-d-os">loading…</div></div>
        <div class="dfield"><div class="dk">Version</div><div class="dv mono" id="agent-d-version">loading…</div></div>
        <div class="dfield"><div class="dk">Last keep-alive</div><div class="dv mono" id="agent-d-keepalive">loading…</div></div>
      </div>
      ${isManagerEntry(a) ? "" : `
      <div class="dsec">
        <div class="dsec-head"><span class="dsec-title">Groups</span></div>
        <p class="hint" style="margin-bottom: var(--s3);">
          Which shared configurations this agent receives. Changes reach the machine on
          its next sync, not immediately.
        </p>
        <div id="agent-d-groups">loading…</div>
      </div>`}
      ${isManagerEntry(a) ? managerNoteSection() : keyAndDangerSections(a)}`;

    // Marks which agent the drawer currently shows, so a detail response
    // that arrives after the operator moved on is discarded, not painted
    // into another agent's panel.
    $("drawer-body").dataset.agentId = String(a.id);

    if (!isManagerEntry(a)) {
      wireKeyReveal(a);
      wireDelete(a);
    }

    if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
    showDrawer();

    // Detail is fetched here — on open — and nowhere else.
    loadAgentDetail(a.id);
  }

  function detailStillShown(agentId) {
    return $("agent-d-os") && $("drawer-body").dataset.agentId === String(agentId);
  }

  // This manager answers most calls in well under a second but some in
  // tens of seconds, with nothing in between (see docs). An unqualified
  // "loading…" through a 40-second wait is indistinguishable from a hung
  // panel, so after a few seconds it says so instead of pretending the
  // delay is normal.
  const SLOW_CALL_MS = 4000;

  function markSlowAfterDelay(agentId) {
    return setTimeout(() => {
      if (!detailStillShown(agentId)) return;
      ["agent-d-os", "agent-d-version", "agent-d-keepalive"].forEach((id) => {
        if ($(id) && $(id).textContent === "loading…") {
          $(id).textContent = "still waiting for the manager…";
        }
      });
      const groups = $("agent-d-groups");
      if (groups && groups.textContent.trim() === "loading…") {
        groups.innerHTML =
          '<span class="soft">Still waiting for the manager — this call is ' +
          "occasionally slow on this deployment.</span>";
      }
    }, SLOW_CALL_MS);
  }

  async function loadAgentDetail(agentId) {
    const slowTimer = markSlowAfterDelay(agentId);
    try {
      const data = await agentApi("/api/agents/" + encodeURIComponent(agentId));
      const d = data.agent || {};
      if (!detailStillShown(agentId)) return;
      $("agent-d-os").textContent = osText(d.os);
      $("agent-d-version").textContent = d.version || "—";
      $("agent-d-keepalive").textContent = fmtKeepAlive(d.lastKeepAlive);
      // Membership comes from this same response - the detail call already
      // carries `group` and `group_config_status`, so showing it costs no
      // extra request.
      renderMembership(agentId, d.group, d.group_config_status);
    } catch (e) {
      if (!detailStillShown(agentId)) return;
      ["agent-d-version", "agent-d-keepalive"].forEach((id) => {
        $(id).textContent = "—";
      });
      $("agent-d-os").textContent = "Detail unavailable: " + e.message;
      if ($("agent-d-groups")) $("agent-d-groups").textContent = "—";
    } finally {
      clearTimeout(slowTimer);
    }
  }

  function wireKeyReveal(a) {
    const btn = $("agent-key-btn");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "fetching…";
      try {
        const data = await agentApi("/api/agents/" + encodeURIComponent(a.id) + "/key", {});
        const key = data.key || "";
        $("agent-key-out").innerHTML = `
          <div class="dsec-head" style="margin-top: var(--s3);">
            <span class="dsec-title">Key for ${esc(a.name)}</span>
            <button type="button" class="copy-btn" id="agent-key-copy">copy</button>
          </div>
          <pre class="codeblock">${esc(key)}</pre>`;
        wireCopy($("agent-key-copy"), () => key);
        btn.remove();
      } catch (e) {
        btn.disabled = false;
        btn.textContent = "Show key";
        $("agent-key-out").innerHTML =
          '<div class="msg msg-err">' + esc(e.message) + "</div>";
      }
    });
  }

  function wireDelete(a) {
    // Two-step by design: the Wazuh API's agent delete asks for no
    // confirmation of its own, so the "are you sure" has to live here.
    const openBtn = $("agent-del-btn");
    const box = $("agent-del-confirm");
    const input = $("agent-del-input");
    const go = $("agent-del-go");

    openBtn.addEventListener("click", () => {
      box.hidden = false;
      openBtn.hidden = true;
      input.focus();
    });
    $("agent-del-cancel").addEventListener("click", () => {
      box.hidden = true;
      openBtn.hidden = false;
      input.value = "";
      go.disabled = true;
    });
    input.addEventListener("input", () => {
      go.disabled = input.value.trim() !== a.name;
    });

    go.addEventListener("click", async () => {
      go.disabled = true;
      go.textContent = "deleting…";
      try {
        // confirm_name is re-checked against the manager's current record —
        // a stale id from an older list is rejected there, not here.
        const data = await agentApi("/api/agents/" + encodeURIComponent(a.id) + "/delete", {
          confirm_name: input.value.trim(),
        });
        closeDrawer();
        pageMsg(data.message || "Agent removed.", "ok");
        fetchAgents();
      } catch (e) {
        go.disabled = false;
        go.textContent = "Delete permanently";
        box.insertAdjacentHTML(
          "beforeend",
          '<div class="msg msg-err">' + esc(e.message) + "</div>"
        );
      }
    });
  }

  /* ---------- add agent ---------- */
  $("agent-add-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const ip = $("agent-add-ip").value.trim();
    const name = $("agent-add-name").value.trim();
    pageMsg("");

    try {
      const data = await agentApi("/api/agents", { ip: ip, name: name });
      const agent = data.agent || {};
      const key = agent.key || "";
      const box = $("agent-add-result");
      box.hidden = false;
      box.innerHTML = `
        <div class="msg msg-ok" style="margin:0;">
          Agent <strong>${esc(agent.name)}</strong> registered with ID
          <strong>${esc(agent.id)}</strong>.
        </div>
        <div class="key-warn">
          <svg data-lucide="triangle-alert"></svg>
          <span>Copy this key now — it is shown here only once. Carry it to
          ${esc(agent.ip)} and import it there with
          <code>manage_agents -i &lt;key&gt;</code>. You can re-issue it later from
          the agent's detail panel if it is lost.</span>
        </div>
        <div class="dsec-head">
          <span class="dsec-title">Agent key</span>
          <button type="button" class="copy-btn" id="agent-add-copy">copy</button>
        </div>
        <pre class="codeblock">${esc(key)}</pre>`;
      wireCopy($("agent-add-copy"), () => key);
      if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });

      $("agent-add-ip").value = "";
      $("agent-add-name").value = "";
      fetchAgents();
    } catch (e) {
      pageMsg(e.message, "err");
    }
  });

  /* ================================================================
     GROUPS
     Backend contract: GET /api/groups · POST /api/groups ·
     POST /api/groups/<name>/delete · POST /api/agents/<id>/group

     Membership lives in the drawer rather than here, because it is a
     property of one agent; this section owns only which groups exist.
     The group list is also what the drawer offers to join, so it is
     kept in `groupList` and refreshed whenever it changes.
     ================================================================ */
  let groupList = [];

  function renderGroups() {
    const body = $("groups-body");
    if (!body) return;

    if (!groupList.length) {
      body.innerHTML =
        '<div class="glist-empty"><div class="empty-mini">No groups yet.</div></div>';
      return;
    }

    body.innerHTML = "";
    groupList.forEach((g) => {
      const isDefault = g.name === "default";
      const row = document.createElement("div");
      row.className = "glist-row";
      row.dataset.itemCard = "";
      row.innerHTML = `
        <div class="item-view">
          <span class="scard-ic"><svg data-lucide="box"></svg></span>
          <div class="item-summary">
            <h3 class="scard-title">${esc(g.name)}</h3>
            <p class="scard-desc">${g.count} agent${g.count === 1 ? "" : "s"}</p>
          </div>
          <div class="item-actions">
            ${
              isDefault
                ? `<span class="soft" title="Every agent belongs to default; the manager recreates it.">built-in</span>`
                : `<button type="button" class="btn btn-danger btn-sm" data-group-del="${esc(g.name)}" title="Delete group">
                     <svg data-lucide="trash-2"></svg>
                   </button>`
            }
          </div>
        </div>
        <div class="scard-body item-edit" hidden data-group-confirm="${esc(g.name)}">
          <div class="notice">
            <svg data-lucide="triangle-alert"></svg>
            <span>Deleting <strong>${esc(g.name)}</strong> removes its shared
            configuration from the ${g.count} agent${g.count === 1 ? "" : "s"} in it.
            They keep running — they simply stop receiving what this group was
            distributing.</span>
          </div>
          <div class="f">
            <label>Type <code>${esc(g.name)}</code> to confirm</label>
            <input type="text" class="mono" autocomplete="off"
                   data-group-confirm-input placeholder="${esc(g.name)}">
          </div>
          <div class="item-form-actions">
            <button type="button" class="btn btn-ghost btn-sm" data-group-del-cancel>Cancel</button>
            <button type="button" class="btn btn-danger btn-sm" data-group-del-go disabled>
              Delete group
            </button>
          </div>
        </div>`;
      body.appendChild(row);
      wireGroupDelete(row, g);
    });

    if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
  }

  function wireGroupDelete(row, group) {
    const openBtn = row.querySelector("[data-group-del]");
    if (!openBtn) return; // the built-in group has no delete control

    const panel = row.querySelector("[data-group-confirm]");
    const input = row.querySelector("[data-group-confirm-input]");
    const go = row.querySelector("[data-group-del-go]");
    const cancel = row.querySelector("[data-group-del-cancel]");

    openBtn.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) input.focus();
    });
    cancel.addEventListener("click", () => {
      panel.hidden = true;
      input.value = "";
      go.disabled = true;
    });
    // The typed name must match before the button becomes usable - the
    // server checks this too, but making it unclickable is what stops the
    // accident rather than reporting it afterwards.
    input.addEventListener("input", () => {
      go.disabled = input.value.trim() !== group.name;
    });
    go.addEventListener("click", async () => {
      go.disabled = true;
      pageMsg("");
      try {
        const data = await agentApi(
          "/api/groups/" + encodeURIComponent(group.name) + "/delete",
          { confirm_name: input.value.trim() }
        );
        pageMsg(data.message || "Group deleted.", "ok");
        await fetchGroups();
      } catch (e) {
        pageMsg(e.message, "err");
        go.disabled = false;
      }
    });
  }

  async function fetchGroups() {
    if (!$("groups-body")) return;
    try {
      const data = await agentApi("/api/groups");
      groupList = data.groups || [];
      renderGroups();
    } catch (e) {
      $("groups-body").innerHTML =
        '<div class="glist-empty"><div class="empty-mini">' +
        esc("Could not read the groups: " + e.message) +
        "</div></div>";
    }
  }

  /* ---------- create group ---------- */
  if ($("group-add-toggle")) {
    const panel = $("group-add-panel");
    $("group-add-toggle").addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) $("group-add-name").focus();
    });
    $("group-add-cancel").addEventListener("click", () => {
      panel.hidden = true;
      $("group-add-name").value = "";
    });
    $("group-add-form").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const name = $("group-add-name").value.trim();
      pageMsg("");
      try {
        const data = await agentApi("/api/groups", { name: name });
        pageMsg(data.message || "Group created.", "ok");
        $("group-add-name").value = "";
        panel.hidden = true;
        await fetchGroups();
      } catch (e) {
        pageMsg(e.message, "err");
      }
    });
  }

  /* ---------- membership, inside the agent drawer ---------- */
  function renderMembership(agentId, current, configStatus) {
    const box = $("agent-d-groups");
    if (!box) return;

    const joined = Array.isArray(current) ? current : [];
    const available = groupList
      .map((g) => g.name)
      .filter((name) => joined.indexOf(name) === -1);

    // "synced" means the agent has actually picked up what its groups
    // distribute. Without it, an operator who just assigned a group has
    // no way to tell whether anything reached the machine yet.
    const syncPill =
      configStatus === "synced"
        ? '<span class="pill pill-agent-active">synced</span>'
        : `<span class="pill pill-agent-pending">${esc(configStatus || "not synced")}</span>`;

    box.innerHTML = `
      <div class="chips" style="margin-bottom: var(--s3);">
        ${
          joined.length
            ? joined
                .map(
                  (name) => `
                  <span class="chip">${esc(name)}${
                    name === "default"
                      ? ""
                      : ` <button type="button" class="copy-btn" data-leave="${esc(
                          name
                        )}" title="Remove from ${esc(name)}">remove</button>`
                  }</span>`
                )
                .join("")
            : '<span class="soft">No groups.</span>'
        }
      </div>
      <div class="dfield" style="margin-bottom: var(--s3);">
        <div class="dk">Configuration</div><div class="dv">${syncPill}</div>
      </div>
      ${
        available.length
          ? `<div class="f2" style="align-items:end;">
               <div class="f">
                 <label for="agent-group-pick">Add to a group</label>
                 <select id="agent-group-pick" class="mono">
                   ${available.map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("")}
                 </select>
               </div>
               <div class="item-form-actions" style="margin:0;">
                 <button type="button" class="btn btn-ghost btn-sm" id="agent-group-join">
                   <svg data-lucide="plus"></svg> Add
                 </button>
               </div>
             </div>`
          : '<p class="hint">This agent is already in every group.</p>'
      }`;

    box.querySelectorAll("[data-leave]").forEach((btn) => {
      btn.addEventListener("click", () =>
        changeMembership(agentId, btn.dataset.leave, "unassign")
      );
    });
    const join = $("agent-group-join");
    if (join) {
      join.addEventListener("click", () =>
        changeMembership(agentId, $("agent-group-pick").value, "assign")
      );
    }
    if (window.lucide) lucide.createIcons({ nameAttr: "data-lucide" });
  }

  async function changeMembership(agentId, group, action) {
    pageMsg("");
    try {
      await agentApi("/api/agents/" + encodeURIComponent(agentId) + "/group", {
        group: group,
        action: action,
      });
      // Re-read rather than patching the local copy: the manager decides
      // the resulting membership (removing an agent's last group puts it
      // back in default), so guessing here would drift from the truth.
      await Promise.all([fetchGroups(), loadAgentDetail(agentId)]);
      pageMsg(
        action === "assign"
          ? `Added to ${group}. The agent applies it on its next sync.`
          : `Removed from ${group}.`,
        "ok"
      );
    } catch (e) {
      pageMsg(e.message, "err");
    }
  }

  /* ---------- wiring ---------- */
  $("agents-refresh").addEventListener("click", () => {
    pageMsg("");
    fetchAgents();
    fetchGroups();
  });

  fetchAgents();
  fetchGroups();
}
