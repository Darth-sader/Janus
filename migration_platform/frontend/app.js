/* Janus web frontend: a small hash-routed app on top of the platform API. */
"use strict";

const view = document.getElementById("view");

// ---------------------------------------------------------------- helpers

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const label = (value) => esc(String(value ?? "—").replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase()));

const ICONS = {
  server: '<rect x="3" y="4" width="18" height="6" rx="1.5"/><rect x="3" y="14" width="18" height="6" rx="1.5"/><path d="M7 7h.01M7 17h.01"/>',
  alert: '<path d="M12 3l9.5 17h-19L12 3z"/><path d="M12 10v4M12 17h.01"/>',
  flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
  shield: '<path d="M12 3l8 3.5v5.5c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6.5L12 3z"/><path d="M9 12l2 2 4-4"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  play: '<circle cx="12" cy="12" r="9"/><path d="M10 8.5l5 3.5-5 3.5z"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
  wrench: '<path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.5 2.5-2.5-2.5 2.5-2.5z"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  refresh: '<path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>',
};
const icon = (name) => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;

/** Plain-language explanations for jargon, shown as tooltips. */
const GLOSSARY = {
  "ML-DSA": "Post-quantum digital signature standard (NIST FIPS 204). Janus's primary PQ algorithm.",
  "SLH-DSA": "Hash-based post-quantum signature standard (NIST FIPS 205). Very conservative, but large signatures.",
  hybrid: "Certificate signed with both RSA and ML-DSA. Both signatures must verify, so it stays secure if either algorithm is broken.",
  classical: "Certificate signed with RSA or ECDSA only. A large quantum computer could forge it.",
  pq: "Certificate signed with a post-quantum algorithm only (ML-DSA).",
  "quantum-vulnerable": "Breakable by a cryptographically relevant quantum computer (Shor's algorithm).",
};
const term = (text, key = text) => `<span class="term" title="${esc(GLOSSARY[key] || "")}">${esc(text)}</span>`;

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: {} };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    const detail = data && data.detail ? data.detail : `${response.status} ${response.statusText}`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

let toastTimer;
function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = "show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = ""), isError ? 6000 : 3200);
}

/** Run an async action from a button: disable it while running, report errors. */
async function act(button, work, success) {
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = "Working…";
  try {
    await work();
    if (success) toast(success);
    await route();
  } catch (error) {
    toast(error.message, true);
    button.disabled = false;
    button.innerHTML = original;
  }
}

// ---------------------------------------------------------------- administrator identity

function operator() {
  try { return localStorage.getItem("janus.operator") || "grid-admin"; } catch { return "grid-admin"; }
}
function setOperator(name) {
  try { localStorage.setItem("janus.operator", name); } catch { /* storage unavailable */ }
  renderUser();
}
function renderUser() {
  const name = operator();
  document.getElementById("user-name").textContent = name;
  document.getElementById("avatar").textContent = name.split(/[\s._-]+/).filter(Boolean).slice(0, 2).map((p) => p[0].toUpperCase()).join("") || "A";
}
document.getElementById("user").onclick = () => {
  const name = prompt("Administrator name recorded on approvals and checklist sign-offs:", operator());
  if (name && name.trim()) setOperator(name.trim());
};

function crumbs(items) {
  document.getElementById("crumbs").innerHTML = items
    .map(([text, href], i) => (i === items.length - 1 ? `<span class="current">${esc(text)}</span>` : `<a href="${href}">${esc(text)}</a><span>/</span>`))
    .join("");
  document.title = `${items[items.length - 1][0]} · Janus`;
}

// ---------------------------------------------------------------- badges & charts

const MODE_TEXT = { classical: "Classical", hybrid: "Hybrid", pq: "PQ ready" };
const modePill = (mode) =>
  mode ? `<span class="pill mode-${esc(mode)}" title="${esc(GLOSSARY[mode] || "")}">${MODE_TEXT[mode] || label(mode)}</span>` : `<span class="pill plain">No certificate</span>`;
const priorityPill = (p) => `<span class="pill p-${esc(p)}">${label(p)}</span>`;
const outcomePill = (o) => `<span class="pill o-${esc(String(o || "").split(" ")[0])}">${label(o)}</span>`;

function bars(counts, colors = {}) {
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return `<p class="empty">No data yet.</p>`;
  const max = Math.max(...entries.map(([, n]) => n));
  return `<div class="bars">${entries.map(([key, n]) => `
    <div class="bar-row">
      <span title="${label(key)}">${label(key)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(n / max) * 100}%;background:${colors[key] || "var(--accent)"}"></div></div>
      <span class="n">${n}</span>
    </div>`).join("")}</div>`;
}

const OUTCOME_COLORS = {
  "HYBRID MIGRATION": "var(--warning)",
  "PQ MIGRATION": "var(--accent)",
  "REPLACEMENT REQUIRED": "var(--danger)",
  "MAINTAIN": "var(--success)",
  "MONITOR": "var(--neutral)",
};
const PRIORITY_COLORS = {
  CRITICAL: "var(--danger)", HIGH: "var(--warning)", MEDIUM: "var(--accent)",
  LOW: "var(--success)", NORMAL: "var(--success)", UNASSESSED: "var(--neutral)",
};
const PLAN_COLORS = { COMPLETED: "var(--success)", IN_PROGRESS: "var(--accent)", DRAFT: "var(--neutral)" };
const PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL", "UNASSESSED"];
const NEEDS_MIGRATION = ["HYBRID MIGRATION", "PQ MIGRATION", "REPLACEMENT REQUIRED"];

function kpi(iconName, tone, soft, value, text, hint = "") {
  return `<div class="card kpi" style="--tone:${tone};--soft:${soft}">
    <div class="kpi-icon">${icon(iconName)}</div>
    <div><div class="label">${text}</div><div class="value">${value}</div>${hint ? `<div class="hint">${hint}</div>` : ""}</div>
  </div>`;
}

// ---------------------------------------------------------------- overview

async function renderDashboard() {
  crumbs([["Overview"]]);
  const { posture, summary, assets } = await api("/ui/overview");

  if (!assets.length) {
    view.innerHTML = `
      <div class="page-head"><div><h1>Cryptographic posture</h1><p>Inventory, assess and migrate your estate to post-quantum cryptography.</p></div></div>
      <div class="card empty-state">
        <img src="assets/logo-navy.png" alt="">
        <h2>Your inventory is empty</h2>
        <p>Load a sample grid-operator estate (substations, SCADA, protection relays, meters) to see Janus assess quantum risk and plan each migration. Or register your own assets.</p>
        <div class="actions" style="justify-content:center">
          <button class="primary" id="seed">${icon("play")}Load demo estate</button>
          <a class="button" href="#/assets?new=1">${icon("plus")}Register an asset</a>
        </div>
      </div>`;
    document.getElementById("seed").onclick = (e) => act(e.currentTarget, () => api("/ui/seed-demo", { method: "POST" }), "Demo estate loaded");
    return;
  }

  const modes = posture.certificates_by_mode;
  const totalCerts = modes.classical + modes.hybrid + modes.pq;
  const seg = (n, color) => (n ? `<div style="flex:${n};background:${color}"></div>` : "");
  const checklist = summary.checklists;
  const pct = Math.round(checklist.completion_percentage || 0);
  const circumference = 2 * Math.PI * 40;
  const pqShare = totalCerts ? Math.round((posture.pq_protected / totalCerts) * 100) : 0;

  const todo = assets
    .filter((a) => NEEDS_MIGRATION.includes(a.recommendation) && a.migration_status !== "COMPLETED")
    .sort((a, b) => PRIORITY_ORDER.indexOf(a.migration_priority) - PRIORITY_ORDER.indexOf(b.migration_priority));

  view.innerHTML = `
    <div class="page-head">
      <div>
        <h1>Cryptographic posture</h1>
        <p>Quantum exposure and migration progress across ${posture.total_assets} assets.</p>
      </div>
      <div class="actions">
        <a class="button" href="/reports/migration">${icon("download")}Export report</a>
        <button class="danger" id="reset">${icon("refresh")}Reset demo</button>
      </div>
    </div>

    <div class="grid grid-4">
      ${kpi("server", "var(--text-2)", "var(--neutral-soft)", posture.total_assets, "Total assets", `${summary.cryptographic_inventory.total_crypto_configs} crypto configurations`)}
      ${kpi("alert", "var(--warning)", "var(--warning-soft)", posture.need_migration, "Need migration", "Hybrid, PQ or replacement")}
      ${kpi("flag", "var(--danger)", "var(--danger-soft)", posture.high_priority, "High or critical priority", "Act on these first")}
      ${kpi("shield", "var(--success)", "var(--success-soft)", posture.pq_protected, "PQ-protected certificates", `${pqShare}% of active certificates`)}
    </div>

    <div class="grid grid-3" style="margin-top:16px">
      <div class="card span-2">
        <div class="card-head"><h3>Certificate migration state</h3><span class="muted">${totalCerts} active certificates</span></div>
        <div class="stacked" role="img" aria-label="Classical ${modes.classical}, hybrid ${modes.hybrid}, PQ ready ${modes.pq}">
          ${seg(modes.classical, "var(--mode-classical)")}${seg(modes.hybrid, "var(--mode-hybrid)")}${seg(modes.pq, "var(--mode-pq)")}
        </div>
        <div class="legend">
          <div class="item"><span><i style="background:var(--mode-classical)"></i>${term("Classical", "classical")}</span><b>${modes.classical}</b></div>
          <div class="item"><span><i style="background:var(--mode-hybrid)"></i>${term("Hybrid", "hybrid")}</span><b>${modes.hybrid}</b></div>
          <div class="item"><span><i style="background:var(--mode-pq)"></i>${term("PQ ready", "pq")}</span><b>${modes.pq}</b></div>
        </div>
      </div>
      <div class="card">
        <h3>Verification checklists</h3>
        <div class="progress-ring">
          <svg viewBox="0 0 100 100" aria-hidden="true">
            <circle cx="50" cy="50" r="40" fill="none" stroke="var(--neutral-soft)" stroke-width="10"/>
            <circle cx="50" cy="50" r="40" fill="none" stroke="var(--success)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="${circumference}" stroke-dashoffset="${circumference * (1 - pct / 100)}"/>
          </svg>
          <div><div class="pct">${pct}%</div><div class="muted">${checklist.completed_items} of ${checklist.total_items} steps signed off</div></div>
        </div>
      </div>
    </div>

    <div class="grid grid-3" style="margin-top:16px">
      <div class="card"><h3>Recommendations</h3>${bars(summary.recommendations.by_outcome, OUTCOME_COLORS)}</div>
      <div class="card"><h3>Migration priority</h3>${bars(summary.assessments.by_migration_priority, PRIORITY_COLORS)}</div>
      <div class="card"><h3>Migration plans</h3>${bars(summary.migrations.by_status, PLAN_COLORS)}</div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h3>Needs action</h3><a href="#/assets" class="plain-link">View all assets →</a></div>
      ${todo.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Asset</th><th>Current algorithm</th><th>Priority</th><th>Recommendation</th><th>Plan status</th></tr></thead>
        <tbody>${todo.map((a) => `
          <tr class="clickable" data-asset="${esc(a.asset_id)}">
            <td class="asset-name">${esc(a.name)}<small>${esc(a.asset_type)}</small></td>
            <td class="mono">${esc(a.current_algorithms || "—")}</td>
            <td>${priorityPill(a.migration_priority)}</td>
            <td>${outcomePill(a.recommendation)}</td>
            <td>${a.migration_status === "NO_PLAN" ? `<span class="muted">Not planned</span>` : label(a.migration_status)}</td>
          </tr>`).join("")}</tbody></table></div>` : `<p class="empty">Nothing outstanding. Every asset is maintained or migrated.</p>`}
    </div>`;

  bindAssetRows();
  document.getElementById("reset").onclick = (e) => {
    if (confirm("Delete every asset, assessment, plan and certificate record? The algorithm catalog is kept.")) {
      act(e.currentTarget, () => api("/ui/reset", { method: "POST" }), "Inventory cleared");
    }
  };
}

function bindAssetRows() {
  view.querySelectorAll("tr[data-asset]").forEach((row) => {
    row.tabIndex = 0;
    const open = () => (location.hash = `#/asset/${row.dataset.asset}`);
    row.onclick = open;
    row.onkeydown = (e) => { if (e.key === "Enter") open(); };
  });
}

// ---------------------------------------------------------------- inventory

let catalogCache = null;
async function catalog() {
  if (!catalogCache) catalogCache = await api("/ui/algorithms");
  return catalogCache;
}

async function renderAssets(params) {
  crumbs([["Asset inventory"]]);
  const [{ assets }, algorithms] = await Promise.all([api("/ui/overview"), catalog()]);

  view.innerHTML = `
    <div class="page-head">
      <div><h1>Asset inventory</h1><p>Every asset, the cryptography it runs and the certificate it holds.</p></div>
      <div class="actions"><button class="primary" id="add">${icon("plus")}Register asset</button></div>
    </div>
    <div class="card">
      <div class="filters">
        <div class="search">${icon("search")}<input type="search" id="q" placeholder="Search by name, type, algorithm…" aria-label="Search assets"></div>
        <select id="f" aria-label="Filter by recommendation">
          <option value="">All recommendations</option>
          ${[...new Set(assets.map((a) => a.recommendation))].map((o) => `<option value="${esc(o)}">${label(o)}</option>`).join("")}
        </select>
        <span class="count" id="count"></span>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Asset</th><th>Criticality</th><th>Algorithm</th><th>Certificate</th><th>Priority</th><th>Recommendation</th><th>Plan</th></tr></thead>
        <tbody id="rows"></tbody>
      </table></div>
      ${assets.length ? "" : `<p class="empty" style="margin-top:16px">No assets yet. Register one, or load the demo estate from the overview.</p>`}
    </div>
    ${assetDialog(algorithms)}`;

  const draw = () => {
    const q = document.getElementById("q").value.toLowerCase();
    const f = document.getElementById("f").value;
    const shown = assets.filter((a) => (!f || a.recommendation === f) && JSON.stringify(a).toLowerCase().includes(q));
    document.getElementById("count").textContent = `${shown.length} of ${assets.length} assets`;
    document.getElementById("rows").innerHTML = shown.map((a) => `
        <tr class="clickable" data-asset="${esc(a.asset_id)}">
          <td class="asset-name">${esc(a.name)}<small>${esc(a.asset_type)}${a.protocol ? ` · ${esc(a.protocol)}` : ""}</small></td>
          <td>${priorityPill(a.criticality)}</td>
          <td class="mono">${esc(a.current_algorithms || "—")}</td>
          <td>${modePill(a.certificate_mode)}</td>
          <td>${priorityPill(a.migration_priority)}</td>
          <td>${outcomePill(a.recommendation)}</td>
          <td>${a.migration_status === "NO_PLAN" ? `<span class="muted">—</span>` : label(a.migration_status)}</td>
        </tr>`).join("");
    bindAssetRows();
  };
  document.getElementById("q").oninput = draw;
  document.getElementById("f").onchange = draw;
  draw();

  const dialog = document.getElementById("asset-dialog");
  document.getElementById("add").onclick = () => dialog.showModal();
  if (params.get("new")) dialog.showModal();
  bindAssetForm(dialog);
}

function assetDialog(algorithms) {
  const options = algorithms
    .map((a) => `<option value="${esc(a.algorithm_id)}" ${a.algorithm_id === "rsa2048" ? "selected" : ""}>${esc(a.name)}${a.quantum_vulnerable ? " (quantum-vulnerable)" : ""}</option>`)
    .join("");
  return `
  <dialog id="asset-dialog" aria-labelledby="asset-dialog-title">
    <form id="asset-form" method="dialog">
      <div class="dialog-head">
        <h2 id="asset-dialog-title">Register an asset</h2>
        <p>Janus records the asset, issues its current certificate from the PKI, then assesses it and recommends a migration path.</p>
      </div>
      <div class="dialog-body form-grid">
        <div class="form-section" style="border:none;padding-top:0">Asset</div>
        <label class="full">Host name<input name="cn" required placeholder="substation-042.grid.test" pattern="[A-Za-z0-9.\\-]+" title="Letters, digits, dots and hyphens only"><span class="help">Used as the certificate subject.</span></label>
        <label>Asset type<input name="asset_type" required placeholder="Substation gateway"></label>
        <label>Criticality<select name="criticality"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <label>Remaining lifetime (years)<input name="lifetime" type="number" min="0" max="60" value="10"></label>
        <label>Protocol<input name="protocol" placeholder="IEC 61850"></label>
        <label>Firmware version<input name="firmware" placeholder="1.0"></label>
        <label class="checkbox"><input type="checkbox" name="updatable" checked> Supports firmware updates</label>
        <div class="form-section">Current cryptography</div>
        <label>Algorithm<select name="algorithm">${options}</select></label>
        <label>Key size (bits)<input name="key_size" type="number" min="0" placeholder="2048"></label>
        <label>Certificate type<select name="mode"><option value="classical" selected>Classical (RSA)</option><option value="hybrid">Hybrid (RSA + ML-DSA)</option><option value="pq">Post-quantum (ML-DSA)</option></select></label>
      </div>
      <div class="dialog-foot">
        <button type="button" id="cancel-asset">Cancel</button>
        <button type="submit" class="primary" id="save-asset">Register and assess</button>
      </div>
    </form>
  </dialog>`;
}

function bindAssetForm(dialog) {
  document.getElementById("cancel-asset").onclick = () => dialog.close();
  document.getElementById("asset-form").onsubmit = (event) => {
    event.preventDefault();
    const f = new FormData(event.target);
    const button = document.getElementById("save-asset");
    act(button, async () => {
      const asset = await api("/assets/", {
        method: "POST",
        body: {
          asset_type: f.get("asset_type"),
          criticality: f.get("criticality"),
          operational_lifetime: Number(f.get("lifetime")) || null,
          update_capability: f.get("updatable") === "on",
          protocol: f.get("protocol") || null,
          firmware_version: f.get("firmware") || null,
        },
      });
      await api("/crypto-configs/", {
        method: "POST",
        body: { asset_id: asset.asset_id, algorithm: f.get("algorithm"), key_size: Number(f.get("key_size")) || null },
      });
      await api("/certificates/issue", { method: "POST", body: { asset_id: asset.asset_id, common_name: f.get("cn"), mode: f.get("mode") } });
      await api(`/assessments/asset/${asset.asset_id}`, { method: "POST" });
      await api(`/recommendations/asset/${asset.asset_id}`, { method: "POST" });
      dialog.close();
      location.hash = `#/asset/${asset.asset_id}`;
    }, "Asset registered and assessed");
  };
}

// ---------------------------------------------------------------- asset detail

const STATUS_TONES = {
  HIGH_RISK: "var(--danger)", LOWER_QUANTUM_RISK: "var(--success)", VERY_HIGH: "var(--danger)", HIGH: "var(--warning)",
  MEDIUM: "var(--accent)", LOW: "var(--success)", LONG: "var(--warning)", MEDIUM_TERM: "var(--accent)", SHORT: "var(--success)",
  UPDATE_CAPABLE: "var(--success)", RESTRICTED: "var(--danger)", MEASURED: "var(--success)",
};

const DIMENSIONS = [
  ["Security", "security", (e) => `${e.current_algorithm || "Unknown algorithm"}${e.quantum_vulnerable ? " · quantum-vulnerable" : ""}`],
  ["Criticality", "criticality", (e) => `Operational role: ${label(e.value)}`],
  ["Lifetime", "lifecycle", (e) => (e.remaining_years != null ? `${e.remaining_years} years remaining` : "Unknown lifetime")],
  ["Compatibility", "compatibility", (e) => [e.protocol, e.firmware_version && `fw ${e.firmware_version}`, e.update_capability === false ? "no updates" : "updatable"].filter(Boolean).join(" · ")],
  ["Performance", "performance", (e) => (e.profile_available ? "Measured" : "Not measured yet")],
];

/** The latest plan is complete and the re-assessment needs no further migration. */
function migrationFinished(d) {
  const { recommendation: r, plan: p } = d;
  return !!(p && p.status === "COMPLETED" && r && (p.recommendation_id === r.recommendation_id || !r.requires_human_approval));
}

function workflow(d) {
  const { assessment: a, recommendation: r, plan: p, certificates } = d;
  const cert = certificates[0];
  const planCurrent = p && r && p.recommendation_id === r.recommendation_id;
  const finished = migrationFinished(d);
  const migrated = finished || (planCurrent && cert && cert.mode === p.target_mode);
  const steps = [
    ["Discover", "Inventory", d.crypto_configs.length > 0 || certificates.length > 0],
    ["Assess", "5 dimensions", !!a],
    ["Recommend", "Rule engine", !!r],
    ["Approve", "Administrator", finished || (planCurrent && p.approval_status === "APPROVED")],
    ["Migrate", "PKI reissue", !!migrated],
    ["Verify", "Checklist", finished],
  ];
  const currentIndex = steps.findIndex((s) => !s[2]);
  return steps.map(([name, sub, done], i) =>
    `<div class="step ${done ? "done" : i === currentIndex ? "current" : ""}"><span class="dot">${done ? "✓" : i + 1}</span>${name}<small>${sub}</small></div>`).join("");
}

function nextAction(d) {
  const { asset, assessment: a, recommendation: r, plan: p, checklist, certificates } = d;
  const cert = certificates[0];
  const planCurrent = p && r && p.recommendation_id === r.recommendation_id;

  if (!a) return { icon: "play", title: "Assess this asset", text: "Evaluate security, criticality, lifetime, compatibility and performance.", button: ["Run assessment", "assess"] };
  if (!r) return { icon: "play", title: "Generate a recommendation", text: "The deterministic rule engine turns the assessment into an explainable decision.", button: ["Generate recommendation", "recommend"] };
  if (migrationFinished(d)) {
    return { icon: "check", tone: "done", title: "Migration complete", text: `Certificate reissued as ${MODE_TEXT[p.target_mode] || p.target_mode}, checklist signed off and inventory updated to ${p.target_algorithm}. Re-assessment: ${label(r.outcome)}.`, button: ["Re-assess", "reassess"], secondary: true };
  }
  if (!r.requires_human_approval) return { icon: "check", tone: "done", title: `No migration needed: ${label(r.outcome)}`, text: "Re-assess whenever the inventory or the algorithm catalog changes.", button: ["Re-assess", "reassess"], secondary: true };
  if (r.outcome === "REPLACEMENT REQUIRED") return { icon: "wrench", tone: "warn", title: "Hardware replacement required", text: "This device cannot take a firmware update, so it cannot move to hybrid or post-quantum certificates in place. Plan a replacement through procurement.", button: ["Re-assess", "reassess"], secondary: true };
  if (!planCurrent) return { icon: "arrow", title: "Create a migration plan", text: `Prepare a plan to move to ${r.target_algorithm} (${MODE_TEXT[r.migration_mode] || r.migration_mode}). Nothing changes until an administrator approves it.`, button: ["Create migration plan", "plan"] };
  if (p.approval_status === "PENDING") return { icon: "user", tone: "warn", title: "Awaiting administrator approval", text: `Review the evidence below. Approval is the safety boundary: Janus never changes production credentials on its own. You are approving as ${operator()}.`, button: ["Approve plan", "approve"] };
  if (p.status === "DRAFT") return { icon: "play", title: "Start the migration", text: "Creates the verification checklist and opens the change window.", button: ["Start migration", "start"] };
  if (cert && cert.mode !== p.target_mode) {
    const cn = cert.subject ? (cert.subject.split("CN=")[1] || "").split(",")[0] : asset.name;
    return { icon: "key", title: "Reissue the certificate", text: `The PKI issues a new ${MODE_TEXT[p.target_mode] || p.target_mode} certificate for ${cn}, revokes the old one as superseded and validates the chain.`, button: [`Reissue as ${MODE_TEXT[p.target_mode] || p.target_mode}`, "migrate"] };
  }
  const open = checklist.filter((i) => i.status !== "COMPLETED").length;
  if (open) return { icon: "check", title: `Verify: ${open} checklist step${open > 1 ? "s" : ""} remaining`, text: `Sign off each step below, or all remaining steps at once as ${operator()}.`, button: ["Sign off all remaining", "tickall"] };
  return { icon: "check", title: "Complete the migration", text: `Closes the plan, updates the inventory to ${p.target_algorithm} and re-assesses the asset.`, button: ["Complete and update inventory", "complete"] };
}

const lastValidation = {};

async function runAction(kind, d, button) {
  const id = d.asset.asset_id;
  const p = d.plan;
  const actions = {
    assess: [() => api(`/assessments/asset/${id}`, { method: "POST" }), "Assessment complete"],
    recommend: [() => api(`/recommendations/asset/${id}`, { method: "POST" }), "Recommendation generated"],
    reassess: [async () => {
      await api(`/assessments/asset/${id}`, { method: "POST" });
      await api(`/recommendations/asset/${id}`, { method: "POST" });
    }, "Asset re-assessed"],
    plan: [() => api(`/migration-plans/recommendation/${d.recommendation.recommendation_id}`, { method: "POST" }), "Migration plan drafted"],
    approve: [() => api(`/migration-plans/${p.migration_id}/approve`, { method: "POST", body: { approved_by: operator() } }), `Plan approved by ${operator()}`],
    start: [async () => {
      if (!d.checklist.length) await api(`/migration-plans/${p.migration_id}/checklist`, { method: "POST" });
      await api(`/migration-plans/${p.migration_id}/start`, { method: "POST" });
    }, "Migration started"],
    migrate: [async () => {
      const result = await api(`/certificates/${d.certificates[0].certificate_id}/migrate`, { method: "POST", body: { migration_id: p.migration_id } });
      lastValidation[d.certificates[0].certificate_id] = result.validation;
    }, "Certificate reissued and validated"],
    tickall: [async () => {
      for (const item of d.checklist.filter((i) => i.status !== "COMPLETED")) {
        await api(`/migration-plans/${p.migration_id}/checklist/${item.sort_order}/complete`, { method: "POST", body: { completed_by: operator() } });
      }
    }, "Checklist signed off"],
    complete: [async () => {
      await api(`/migration-plans/${p.migration_id}/complete`, { method: "POST" });
      for (const config of d.crypto_configs.filter((c) => c.status === "ACTIVE")) {
        await api(`/crypto-configs/${config.config_id}`, { method: "PUT", body: { algorithm: p.target_algorithm, key_size: null } });
      }
      await api(`/assessments/asset/${id}`, { method: "POST" });
      await api(`/recommendations/asset/${id}`, { method: "POST" });
    }, "Migration complete, inventory updated"],
  };
  const [work, message] = actions[kind];
  await act(button, work, message);
}

async function renderAsset(id) {
  const d = await api(`/ui/assets/${encodeURIComponent(id)}`);
  const { asset, assessment: a, recommendation: r, plan: p, checklist, certificates } = d;
  crumbs([["Asset inventory", "#/assets"], [asset.name]]);
  const next = nextAction(d);
  const cert = certificates[0];
  const showPlan = (p && r && p.recommendation_id === r.recommendation_id) || migrationFinished(d);
  const validation = cert && lastValidation[cert.certificate_id];

  view.innerHTML = `
    <div class="page-head">
      <div>
        <h1>${esc(asset.name)}</h1>
        <p>${esc(asset.asset_type)} · ${esc(asset.protocol || "unknown protocol")} · firmware ${esc(asset.firmware_version || "—")}</p>
      </div>
      <div class="actions">Criticality ${priorityPill(asset.criticality)} ${modePill(cert && cert.mode)}</div>
    </div>

    <div class="card"><div class="stepper">${workflow(d)}</div></div>

    <div class="card next-action ${next.tone || ""}" style="margin-top:16px">
      <div class="na-icon">${icon(next.icon)}</div>
      <div class="na-body">
        <div class="na-kicker">Next step</div>
        <h2>${esc(next.title)}</h2>
        <p>${esc(next.text)}</p>
        <button class="${next.secondary ? "" : "primary"}" id="next">${esc(next.button[0])}</button>
      </div>
    </div>

    <div class="grid grid-2" style="margin-top:16px">
      <div class="stack">
        ${r ? `<div class="card">
          <h3>Recommendation</h3>
          <div class="decision">
            <span class="big">${label(r.outcome)}</span>
            ${r.target_algorithm ? `<span class="arrow-chip mono">${esc(r.current_algorithm || "?")} ${icon("arrow")} ${esc(r.target_algorithm)}</span>` : ""}
            ${priorityPill(r.priority)}
          </div>
          <h3 style="margin:4px 0 6px">Why</h3>
          <ul class="why">${(r.evidence.decision_factors || []).map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
        </div>` : ""}

        ${a ? `<div class="card">
          <div class="card-head"><h3>Assessment</h3><span>Priority ${priorityPill(a.migration_priority)}</span></div>
          <div class="dims">${DIMENSIONS.map(([name, key, describe]) => {
            const e = (a.evidence || {})[key] || {};
            return `<div class="dim" style="--tone:${STATUS_TONES[e.status] || "var(--neutral)"}"><div class="k">${name}</div><div class="v">${label(e.status)}</div><div class="d">${esc(describe(e))}</div></div>`;
          }).join("")}</div>
        </div>` : ""}

        <div class="card">
          <h3>Cryptographic inventory</h3>
          ${d.crypto_configs.length ? `<div class="table-wrap"><table><thead><tr><th>Algorithm</th><th>Key size</th><th>Status</th></tr></thead><tbody>
            ${d.crypto_configs.map((c) => `<tr><td class="mono">${esc(c.algorithm)}</td><td>${esc(c.key_size ?? "—")}</td><td>${label(c.status)}</td></tr>`).join("")}
          </tbody></table></div>` : `<p class="empty">No cryptographic configuration recorded.</p>`}
        </div>
      </div>

      <div class="stack">
        <div class="card">
          <div class="card-head"><h3>Certificate</h3>${cert ? modePill(cert.mode) : ""}</div>
          ${cert ? `
            <dl class="kv">
              <dt>Subject</dt><dd class="mono">${esc(cert.subject)}</dd>
              <dt>Issuer</dt><dd class="mono">${esc(cert.issuer)}</dd>
              <dt>Public key</dt><dd>${esc(cert.public_key_algorithm)}</dd>
              <dt>Signature</dt><dd>${esc(cert.signature_algorithm)}</dd>
              <dt>Serial</dt><dd class="mono">${esc((cert.serial_number || "").slice(0, 24))}…</dd>
              <dt>Valid until</dt><dd>${esc((cert.expires_at || "").slice(0, 10))}</dd>
              <dt>State</dt><dd>${label(cert.status)}</dd>
            </dl>
            <div class="actions" style="margin-top:16px">
              <button class="small" id="validate">${icon("shield")}Verify chain and signatures</button>
              <button class="small" id="history">Lifecycle history</button>
            </div>
            <div id="validation">${validation ? validationBox(validation) : ""}</div>
            <div id="history-box"></div>` : `<p class="empty">No certificate issued for this asset.</p>`}
        </div>

        ${showPlan ? `<div class="card">
          <h3>Migration plan</h3>
          <dl class="kv">
            <dt>Target</dt><dd class="mono">${esc(p.target_algorithm)} (${esc(MODE_TEXT[p.target_mode] || p.target_mode)})</dd>
            <dt>Status</dt><dd>${label(p.status)}</dd>
            <dt>Approval</dt><dd>${label(p.approval_status)}${p.approved_by ? ` by <b>${esc(p.approved_by)}</b>` : ""}</dd>
          </dl>
          ${checklist.length ? `<h3 style="margin:18px 0 4px">Verification checklist</h3><ol class="checklist">
            ${checklist.map((i) => `<li class="${i.status === "COMPLETED" ? "done" : ""}">
              <span class="num">${i.status === "COMPLETED" ? "✓" : i.sort_order}</span>
              <span class="t">${esc(i.title)}<small>${i.status === "COMPLETED" ? `Signed off by ${esc(i.completed_by)}` : esc(i.description)}</small></span>
              ${i.status !== "COMPLETED" && p.status === "IN_PROGRESS" ? `<button class="small" data-tick="${i.sort_order}">Sign off</button>` : ""}
            </li>`).join("")}</ol>` : ""}
        </div>` : ""}
      </div>
    </div>`;

  document.getElementById("next").onclick = (e) => runAction(next.button[1], d, e.currentTarget);

  view.querySelectorAll("[data-tick]").forEach((btn) => {
    btn.onclick = () => act(btn, () => api(`/migration-plans/${p.migration_id}/checklist/${btn.dataset.tick}/complete`, { method: "POST", body: { completed_by: operator() } }), "Step signed off");
  });

  if (cert) {
    document.getElementById("validate").onclick = async (e) => {
      const button = e.currentTarget;
      button.disabled = true;
      try {
        const result = await api(`/certificates/${cert.certificate_id}/validate`, { method: "POST" });
        lastValidation[cert.certificate_id] = result;
        document.getElementById("validation").innerHTML = validationBox(result);
      } catch (error) {
        toast(error.message, true);
      }
      button.disabled = false;
    };
    document.getElementById("history").onclick = async () => {
      try {
        const record = await api(`/certificates/${cert.certificate_id}/pki`);
        document.getElementById("history-box").innerHTML = `<h3 style="margin:18px 0 8px">Lifecycle</h3><ul class="history">${record.history
          .map((h) => `<li><b>${esc(h.to)}</b> <span>· ${esc((h.at || "").slice(0, 19).replace("T", " "))}</span><br>${esc(h.note || "")}</li>`)
          .join("")}</ul>`;
      } catch (error) {
        toast(error.message, true);
      }
    };
  }
}

function validationBox(v) {
  const sigs = v.mode === "hybrid" ? "RSA and ML-DSA signatures both verified" : v.mode === "pq" ? "ML-DSA signature verified" : "RSA signature verified";
  return v.valid
    ? `<div class="validation ok">${icon("check")}<div><b>Valid ${esc(MODE_TEXT[v.mode] || v.mode)} certificate.</b> ${sigs}. Chain: ${esc((v.chain || []).join(" → "))}. Not revoked.</div></div>`
    : `<div class="validation bad">${icon("alert")}<div><b>${label(v.reason)}</b><br>${(v.issues || []).map((i) => esc(i.message)).join("<br>")}</div></div>`;
}

// ---------------------------------------------------------------- algorithms

const FAMILY_TEXT = { classical: "Classical", hybrid: "Hybrid", pq: "Post-quantum" };

async function renderAlgorithms() {
  crumbs([["Algorithms"]]);
  const algorithms = await catalog();
  const groups = [
    ["Migration targets", "Implemented through the CryptoProvider interface. Benchmarks run live on this machine.", algorithms.filter((a) => a.implemented)],
    ["Legacy and candidate algorithms", "Recognised in the inventory but never offered as a migration target (no silent fallback).", algorithms.filter((a) => !a.implemented)],
  ];
  const nameCell = (a) => {
    const base = a.name.startsWith("ML-DSA") ? "ML-DSA" : a.name.startsWith("SLH-DSA") ? "SLH-DSA" : null;
    return base ? term(a.name, base) : esc(a.name);
  };
  view.innerHTML = `
    <div class="page-head">
      <div><h1>Algorithm catalog</h1><p>Synchronised from the crypto-agility registry. One interface for every algorithm.</p></div>
    </div>
    ${groups.map(([title, sub, list], gi) => `
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><div><h3>${title}</h3><p class="muted" style="margin:2px 0 0;font-size:13px">${sub}</p></div><span class="muted">${list.length}</span></div>
        <div class="table-wrap"><table>
          <thead><tr><th>Algorithm</th><th>Family</th><th>Standard</th><th>Security level</th><th>Public key</th><th>Signature</th><th>Quantum</th>${gi === 0 ? "<th>Keygen / sign / verify</th>" : ""}</tr></thead>
          <tbody>${list.map((a) => `
            <tr>
              <td class="nowrap"><span class="asset-name">${nameCell(a)}</span><br><span class="mono muted">${esc(a.algorithm_id)}</span></td>
              <td><span class="pill mode-${esc(a.family)}">${FAMILY_TEXT[a.family] || label(a.family)}</span></td>
              <td>${esc(a.standard)}</td>
              <td>${esc(a.security_level || "—")}</td>
              <td>${a.key_size ? `${a.key_size.toLocaleString()} B` : "—"}</td>
              <td>${a.signature_size ? `${a.signature_size.toLocaleString()} B` : "—"}</td>
              <td>${a.quantum_vulnerable ? `<span class="pill bad" title="${esc(GLOSSARY["quantum-vulnerable"])}">Vulnerable</span>` : `<span class="pill ok">Resistant</span>`}</td>
              ${gi === 0 ? `<td id="m-${esc(a.algorithm_id)}"><button class="small" data-measure="${esc(a.algorithm_id)}">Run benchmark</button></td>` : ""}
            </tr>`).join("")}</tbody>
        </table></div>
      </div>`).join("")}`;

  view.querySelectorAll("[data-measure]").forEach((button) => {
    button.onclick = async () => {
      const id = button.dataset.measure;
      button.disabled = true;
      button.textContent = "Running…";
      try {
        const result = (await api("/ui/algorithms/measure", { method: "POST", body: [id] }))[id];
        const ms = (v) => (v == null ? "—" : `${Number(v).toFixed(v < 10 ? 2 : 0)} ms`);
        document.getElementById(`m-${id}`).innerHTML = `<span class="mono">${ms(result.keygen_ms)} / ${ms(result.sign_ms)} / ${ms(result.verify_ms)}</span>`;
      } catch (error) {
        toast(error.message, true);
        button.disabled = false;
        button.textContent = "Run benchmark";
      }
    };
  });
}

// ---------------------------------------------------------------- router

async function route() {
  const [path, query] = (location.hash.slice(1) || "/dashboard").split("?");
  const params = new URLSearchParams(query || "");
  const [, page, id] = path.split("/");
  document.querySelectorAll("[data-nav]").forEach((a) =>
    a.classList.toggle("active", a.dataset.nav === page || (page === "asset" && a.dataset.nav === "assets") || (!page && a.dataset.nav === "dashboard")));
  try {
    if (page === "assets") await renderAssets(params);
    else if (page === "asset" && id) await renderAsset(id);
    else if (page === "algorithms") await renderAlgorithms();
    else await renderDashboard();
  } catch (error) {
    view.innerHTML = `<div class="card empty-state"><h2>Something went wrong</h2><p>${esc(error.message)}</p><a class="button" href="#/dashboard">Back to overview</a></div>`;
  }
}

let lastPath = null;
window.addEventListener("hashchange", () => {
  const path = location.hash.split("?")[0];
  if (path !== lastPath) window.scrollTo(0, 0);
  lastPath = path;
  route();
});
renderUser();
route();
