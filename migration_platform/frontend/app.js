/* Janus web frontend: a small hash-routed app on top of the platform API. */
"use strict";

const view = document.getElementById("view");

// ---------------------------------------------------------------- helpers

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const label = (value) => esc(String(value ?? "—").replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase()));

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

function operator() {
  try { return localStorage.getItem("janus.operator") || "grid-admin"; } catch { return "grid-admin"; }
}
function setOperator(name) {
  try { localStorage.setItem("janus.operator", name); } catch { /* storage unavailable */ }
}

const modePill = (mode) =>
  mode ? `<span class="pill mode-${esc(mode)}">${mode === "pq" ? "PQ ready" : label(mode)}</span>` : `<span class="pill">No certificate</span>`;
const priorityPill = (p) => `<span class="pill p-${esc(p)}">${label(p)}</span>`;
const outcomePill = (o) => `<span class="pill o-${esc(String(o || "").split(" ")[0])}">${label(o)}</span>`;

function bars(counts, colors = {}) {
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return `<p class="empty">No data yet.</p>`;
  const max = Math.max(...entries.map(([, n]) => n));
  return `<div class="bars">${entries.map(([key, n]) => `
    <div class="bar-row">
      <span>${label(key)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(n / max) * 100}%;background:${colors[key] || "var(--teal)"}"></div></div>
      <span class="n">${n}</span>
    </div>`).join("")}</div>`;
}

const OUTCOME_COLORS = {
  "HYBRID MIGRATION": "var(--orange)",
  "PQ MIGRATION": "var(--purple)",
  "REPLACEMENT REQUIRED": "var(--coral)",
  "MAINTAIN": "var(--teal)",
  "MONITOR": "var(--muted)",
};
const PRIORITY_COLORS = { CRITICAL: "var(--coral)", HIGH: "var(--orange)", MEDIUM: "var(--purple)", LOW: "var(--teal)", NORMAL: "var(--teal)" };

// ---------------------------------------------------------------- dashboard

async function renderDashboard() {
  const data = await api("/ui/overview");
  const { posture, summary, assets } = data;

  if (!assets.length) {
    view.innerHTML = `
      <div class="page-head"><div><h1>Cryptographic posture</h1></div></div>
      <div class="card empty-state">
        <h2>The inventory is empty</h2>
        <p>Load a sample grid-operator estate (substations, SCADA, relays, meters…) to see Janus assess and plan its post-quantum migration, or add your own assets.</p>
        <div class="actions" style="justify-content:center">
          <button class="accent" id="seed">Load demo data</button>
          <a class="button" href="#/assets?new=1">Add an asset</a>
        </div>
      </div>`;
    document.getElementById("seed").onclick = (e) => act(e.currentTarget, () => api("/ui/seed-demo", { method: "POST" }), "Demo inventory loaded");
    return;
  }

  const modes = posture.certificates_by_mode;
  const totalCerts = modes.classical + modes.hybrid + modes.pq;
  const seg = (n, color, text) => (n ? `<div style="flex:${n};background:${color}" title="${text}: ${n}">${n}</div>` : "");
  const checklist = summary.checklists;
  const pct = Math.round(checklist.completion_percentage || 0);
  const circumference = 2 * Math.PI * 40;

  const todo = assets
    .filter((a) => ["HYBRID MIGRATION", "PQ MIGRATION", "REPLACEMENT REQUIRED"].includes(a.recommendation) && a.migration_status !== "COMPLETED")
    .sort((a, b) => ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(a.migration_priority) - ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(b.migration_priority));

  view.innerHTML = `
    <div class="page-head">
      <div>
        <h1>Cryptographic posture</h1>
        <p>Live view of the estate's quantum exposure and migration progress.</p>
      </div>
      <div class="actions">
        <a class="button" href="/reports/migration">Download CSV report</a>
        <button class="danger" id="reset">Reset demo</button>
      </div>
    </div>

    <div class="grid grid-4">
      <div class="card tile" style="--accent:var(--deep)"><div class="value">${posture.total_assets}</div><div class="label">Total assets</div></div>
      <div class="card tile" style="--accent:var(--orange)"><div class="value">${posture.need_migration}</div><div class="label">Need migration</div></div>
      <div class="card tile" style="--accent:var(--coral)"><div class="value">${posture.high_priority}</div><div class="label">High / critical priority</div></div>
      <div class="card tile" style="--accent:var(--teal)"><div class="value">${posture.pq_protected}</div><div class="label">PQ-protected certificates</div></div>
    </div>

    <div class="grid grid-3" style="margin-top:16px">
      <div class="card span-2">
        <h3>Certificate migration state</h3>
        <div class="stacked">
          ${seg(modes.classical, "var(--coral)", "Classical")}${seg(modes.hybrid, "var(--teal)", "Hybrid")}${seg(modes.pq, "var(--purple)", "PQ ready")}
        </div>
        <div class="legend">
          <span><i style="background:var(--coral)"></i>Classical ${modes.classical}</span>
          <span><i style="background:var(--teal)"></i>Hybrid ${modes.hybrid}</span>
          <span><i style="background:var(--purple)"></i>PQ ready ${modes.pq}</span>
          <span style="color:var(--muted)">${totalCerts} active certificates</span>
        </div>
      </div>
      <div class="card">
        <h3>Checklist completion</h3>
        <div class="progress-ring">
          <svg viewBox="0 0 100 100" aria-hidden="true">
            <circle cx="50" cy="50" r="40" fill="none" stroke="var(--bg)" stroke-width="12"/>
            <circle cx="50" cy="50" r="40" fill="none" stroke="var(--teal)" stroke-width="12" stroke-linecap="round"
              stroke-dasharray="${circumference}" stroke-dashoffset="${circumference * (1 - pct / 100)}"/>
          </svg>
          <div><div class="pct">${pct}%</div><div class="label" style="color:var(--muted)">${checklist.completed_items} of ${checklist.total_items} steps</div></div>
        </div>
      </div>
    </div>

    <div class="grid grid-3" style="margin-top:16px">
      <div class="card"><h3>Recommendations</h3>${bars(summary.recommendations.by_outcome, OUTCOME_COLORS)}</div>
      <div class="card"><h3>Migration priority</h3>${bars(summary.assessments.by_migration_priority, PRIORITY_COLORS)}</div>
      <div class="card"><h3>Migration plans</h3>${bars(summary.migrations.by_status)}</div>
    </div>

    <div class="card" style="margin-top:16px">
      <h3>Needs action</h3>
      ${todo.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Asset</th><th>Current crypto</th><th>Priority</th><th>Recommendation</th><th>Plan</th></tr></thead>
        <tbody>${todo.map((a) => `
          <tr class="clickable" data-asset="${esc(a.asset_id)}">
            <td class="asset-name">${esc(a.name)}<small>${esc(a.asset_type)}</small></td>
            <td class="mono">${esc(a.current_algorithms || "—")}</td>
            <td>${priorityPill(a.migration_priority)}</td>
            <td>${outcomePill(a.recommendation)}</td>
            <td>${label(a.migration_status === "NO_PLAN" ? "Not planned" : a.migration_status)}</td>
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
  const [{ assets }, algorithms] = await Promise.all([api("/ui/overview"), catalog()]);

  view.innerHTML = `
    <div class="page-head">
      <div><h1>Asset inventory</h1><p>Discover: every asset, its cryptography and its credential.</p></div>
      <div class="actions"><button class="accent" id="add">+ Add asset</button></div>
    </div>
    <div class="card">
      <div class="filters">
        <input type="search" id="q" placeholder="Search assets, algorithms…" aria-label="Search assets">
        <select id="f" aria-label="Filter by recommendation">
          <option value="">All recommendations</option>
          ${[...new Set(assets.map((a) => a.recommendation))].map((o) => `<option>${esc(o)}</option>`).join("")}
        </select>
      </div>
      <div class="table-wrap"><table>
        <thead><tr><th>Asset</th><th>Criticality</th><th>Algorithm</th><th>Certificate</th><th>Priority</th><th>Recommendation</th><th>Plan</th></tr></thead>
        <tbody id="rows"></tbody>
      </table></div>
      ${assets.length ? "" : `<p class="empty">No assets yet. Add one, or load demo data from the dashboard.</p>`}
    </div>
    ${assetDialog(algorithms)}`;

  const draw = () => {
    const q = document.getElementById("q").value.toLowerCase();
    const f = document.getElementById("f").value;
    document.getElementById("rows").innerHTML = assets
      .filter((a) => (!f || a.recommendation === f) && JSON.stringify(a).toLowerCase().includes(q))
      .map((a) => `
        <tr class="clickable" data-asset="${esc(a.asset_id)}">
          <td class="asset-name">${esc(a.name)}<small>${esc(a.asset_type)} · ${esc(a.protocol || "")}</small></td>
          <td>${priorityPill(a.criticality)}</td>
          <td class="mono">${esc(a.current_algorithms || "—")}</td>
          <td>${modePill(a.certificate_mode)}</td>
          <td>${priorityPill(a.migration_priority)}</td>
          <td>${outcomePill(a.recommendation)}</td>
          <td>${label(a.migration_status === "NO_PLAN" ? "—" : a.migration_status)}</td>
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
    .map((a) => `<option value="${esc(a.algorithm_id)}" ${a.algorithm_id === "rsa2048" ? "selected" : ""}>${esc(a.name)}${a.quantum_vulnerable ? " · quantum-vulnerable" : ""}</option>`)
    .join("");
  return `
  <dialog id="asset-dialog" aria-labelledby="asset-dialog-title">
    <form id="asset-form" method="dialog">
      <h2 id="asset-dialog-title">Register an asset</h2>
      <p style="color:var(--muted);margin:6px 0 18px">Janus records the asset, issues its current certificate from the PKI, then assesses it and recommends a migration path.</p>
      <div class="form-grid">
        <label class="full">Host name (certificate subject)<input name="cn" required placeholder="substation-042.grid.test" pattern="[A-Za-z0-9.-]+"></label>
        <label>Asset type<input name="asset_type" required placeholder="Substation gateway"></label>
        <label>Criticality<select name="criticality"><option>CRITICAL</option><option selected>HIGH</option><option>MEDIUM</option><option>LOW</option></select></label>
        <label>Remaining lifetime (years)<input name="lifetime" type="number" min="0" max="60" value="10"></label>
        <label>Protocol<input name="protocol" placeholder="IEC 61850"></label>
        <label>Firmware version<input name="firmware" placeholder="1.0"></label>
        <label class="checkbox"><input type="checkbox" name="updatable" checked> Supports firmware updates</label>
        <label>Current algorithm<select name="algorithm">${options}</select></label>
        <label>Key size (bits)<input name="key_size" type="number" min="0" placeholder="2048"></label>
        <label>Current certificate<select name="mode"><option value="classical" selected>Classical (RSA)</option><option value="hybrid">Hybrid (RSA + ML-DSA)</option><option value="pq">PQ only (ML-DSA)</option></select></label>
      </div>
      <div class="actions">
        <button type="button" value="cancel" id="cancel-asset">Cancel</button>
        <button type="submit" class="primary" id="save-asset">Register & assess</button>
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

const DIMENSIONS = [
  ["Security", "security", (e) => `${e.current_algorithm || "unknown"}${e.quantum_vulnerable ? " · quantum-vulnerable" : ""}`],
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
  const { assessment: a, recommendation: r, plan: p, checklist, certificates } = d;
  const cert = certificates[0];
  const planCurrent = p && r && p.recommendation_id === r.recommendation_id;
  const finished = migrationFinished(d);
  const migrated = finished || (planCurrent && cert && cert.mode === p.target_mode);
  const steps = [
    ["Discover", "Inventory", d.crypto_configs.length > 0 || certificates.length > 0],
    ["Assess", "5 dimensions", !!a],
    ["Recommend", "Rule engine", !!r],
    ["Approve", "Human", finished || (planCurrent && p.approval_status === "APPROVED")],
    ["Migrate", "PKI reissue", !!migrated],
    ["Verify", "Checklist", finished],
  ];
  const currentIndex = steps.findIndex((s) => !s[2]);
  return steps.map(([name, sub, done], i) =>
    `<div class="step ${done ? "done" : i === currentIndex ? "current" : ""}"><span class="dot"></span>${name}<small>${sub}</small></div>`).join("");
}

function nextAction(d) {
  const { asset, assessment: a, recommendation: r, plan: p, checklist, certificates } = d;
  const cert = certificates[0];
  const planCurrent = p && r && p.recommendation_id === r.recommendation_id;
  const operatorInput = `<label style="max-width:260px">Administrator<input id="operator" value="${esc(operator())}"></label>`;

  if (!a) return { title: "Assess this asset", text: "Evaluate security, criticality, lifetime, compatibility and performance.", button: ["Run assessment", "assess"] };
  if (!r) return { title: "Generate a recommendation", text: "The deterministic rule engine turns the assessment into an explainable decision.", button: ["Generate recommendation", "recommend"] };
  if (migrationFinished(d)) {
    return { title: "Migration complete", text: `Certificate reissued as ${p.target_mode}, checklist verified and inventory updated to ${p.target_algorithm}. Re-assessment: ${label(r.outcome)}.`, button: ["Re-assess asset", "reassess"], done: true };
  }
  if (!r.requires_human_approval) return { title: `No migration needed: ${label(r.outcome)}`, text: "Re-assess whenever the inventory or the algorithm catalog changes.", button: ["Re-assess asset", "reassess"], done: true };
  if (r.outcome === "REPLACEMENT REQUIRED") return { title: "Hardware replacement required", text: "This device cannot take a firmware update, so it cannot move to hybrid or PQ certificates in place. Plan a replacement through procurement.", button: ["Re-assess asset", "reassess"] };
  if (!planCurrent) return { title: "Create a migration plan", text: `Prepare a plan to move to ${r.target_algorithm} (${r.migration_mode}). Nothing changes until an administrator approves it.`, button: ["Create migration plan", "plan"] };
  if (p.approval_status === "PENDING") return { title: "Waiting for human approval", text: "Review the evidence above. Approval is the safety boundary: Janus never changes production credentials on its own.", button: ["Approve plan", "approve"], extra: operatorInput };
  if (p.status === "DRAFT") return { title: "Start the migration", text: "Creates the migration checklist and opens the change window.", button: ["Start migration", "start"] };
  if (cert && cert.mode !== p.target_mode) return { title: "Reissue the certificate", text: `The PKI issues a new ${p.target_mode} certificate for ${cert.subject ? cert.subject.split("CN=")[1]?.split(",")[0] : asset.name}, revokes the old one (superseded) and validates the chain.`, button: [`Migrate certificate to ${p.target_mode}`, "migrate"] };
  const open = checklist.filter((i) => i.status !== "COMPLETED").length;
  if (open) return { title: `Verify: ${open} checklist step${open > 1 ? "s" : ""} left`, text: "Work through the checklist below, then complete the migration.", button: ["Mark all remaining complete", "tickall"], extra: operatorInput };
  return { title: "Complete the migration", text: `Closes the plan and updates the inventory to ${p.target_algorithm}, then re-assesses the asset.`, button: ["Complete & update inventory", "complete"] };
}

async function runAction(kind, d, button) {
  const id = d.asset.asset_id;
  const p = d.plan;
  const who = () => {
    const input = document.getElementById("operator");
    const name = (input ? input.value : operator()).trim() || "grid-admin";
    setOperator(name);
    return name;
  };
  const actions = {
    assess: [() => api(`/assessments/asset/${id}`, { method: "POST" }), "Assessment complete"],
    recommend: [() => api(`/recommendations/asset/${id}`, { method: "POST" }), "Recommendation generated"],
    reassess: [async () => {
      await api(`/assessments/asset/${id}`, { method: "POST" });
      await api(`/recommendations/asset/${id}`, { method: "POST" });
    }, "Asset re-assessed"],
    plan: [() => api(`/migration-plans/recommendation/${d.recommendation.recommendation_id}`, { method: "POST" }), "Migration plan drafted"],
    approve: [() => api(`/migration-plans/${p.migration_id}/approve`, { method: "POST", body: { approved_by: who() } }), "Plan approved"],
    start: [async () => {
      if (!d.checklist.length) await api(`/migration-plans/${p.migration_id}/checklist`, { method: "POST" });
      await api(`/migration-plans/${p.migration_id}/start`, { method: "POST" });
    }, "Migration started"],
    migrate: [async () => {
      const result = await api(`/certificates/${d.certificates[0].certificate_id}/migrate`, { method: "POST", body: { migration_id: p.migration_id } });
      lastValidation[d.certificates[0].certificate_id] = result.validation;
    }, "Certificate reissued and validated"],
    tickall: [async () => {
      const name = who();
      for (const item of d.checklist.filter((i) => i.status !== "COMPLETED")) {
        await api(`/migration-plans/${p.migration_id}/checklist/${item.sort_order}/complete`, { method: "POST", body: { completed_by: name } });
      }
    }, "Checklist completed"],
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

const lastValidation = {};

async function renderAsset(id) {
  const d = await api(`/ui/assets/${encodeURIComponent(id)}`);
  const { asset, assessment: a, recommendation: r, plan: p, checklist, certificates } = d;
  const next = nextAction(d);
  const cert = certificates[0];
  const planCurrent = p && r && p.recommendation_id === r.recommendation_id;
  const validation = cert && lastValidation[cert.certificate_id];

  view.innerHTML = `
    <a class="back" href="#/assets">← Asset inventory</a>
    <div class="page-head" style="margin-top:8px">
      <div>
        <h1>${esc(asset.name)}</h1>
        <p>${esc(asset.asset_type)} · ${esc(asset.protocol || "unknown protocol")} · firmware ${esc(asset.firmware_version || "—")}</p>
      </div>
      <div class="actions">${priorityPill(asset.criticality)} ${modePill(cert && cert.mode)}</div>
    </div>

    <div class="card"><div class="stepper">${workflow(d)}</div></div>

    <div class="card next-action" style="margin-top:16px">
      <h2>${esc(next.title)}</h2>
      <p>${esc(next.text)}</p>
      <div class="actions" style="align-items:flex-end">${next.extra || ""}
        <button class="${next.done ? "" : "primary"}" id="next">${esc(next.button[0])}</button>
      </div>
    </div>

    <div class="grid grid-2" style="margin-top:16px">
      <div class="stack">
        ${a ? `<div class="card">
          <h3>Assessment</h3>
          <div class="dims">${DIMENSIONS.map(([name, key, describe]) => {
            const e = (a.evidence || {})[key] || {};
            return `<div class="dim"><div class="k">${name}</div><div class="v">${label(e.status)}</div><div class="d">${esc(describe(e))}</div></div>`;
          }).join("")}</div>
          <p style="margin:14px 0 0;font-size:14px">Migration priority: ${priorityPill(a.migration_priority)}</p>
        </div>` : ""}

        ${r ? `<div class="card">
          <h3>Recommendation</h3>
          <div class="decision">
            <span class="big">${label(r.outcome)}</span>
            ${r.target_algorithm ? `<span class="mono">${esc(r.current_algorithm || "?")} → ${esc(r.target_algorithm)}</span>` : ""}
          </div>
          <h3 style="margin:14px 0 6px">Why?</h3>
          <ul class="why">${(r.evidence.decision_factors || []).map((f) => `<li>${esc(f)}</li>`).join("")}</ul>
        </div>` : ""}

        <div class="card">
          <h3>Cryptographic inventory</h3>
          ${d.crypto_configs.length ? `<table><thead><tr><th>Algorithm</th><th>Key size</th><th>Status</th></tr></thead><tbody>
            ${d.crypto_configs.map((c) => `<tr><td class="mono">${esc(c.algorithm)}</td><td>${esc(c.key_size ?? "—")}</td><td>${label(c.status)}</td></tr>`).join("")}
          </tbody></table>` : `<p class="empty">No cryptographic configuration recorded.</p>`}
        </div>
      </div>

      <div class="stack">
        <div class="card">
          <h3>Certificate</h3>
          ${cert ? `
            <dl class="kv">
              <dt>Mode</dt><dd>${modePill(cert.mode)}</dd>
              <dt>Subject</dt><dd class="mono">${esc(cert.subject)}</dd>
              <dt>Issuer</dt><dd class="mono">${esc(cert.issuer)}</dd>
              <dt>Public key</dt><dd>${esc(cert.public_key_algorithm)}</dd>
              <dt>Signature</dt><dd>${esc(cert.signature_algorithm)}</dd>
              <dt>Serial</dt><dd class="mono">${esc((cert.serial_number || "").slice(0, 24))}…</dd>
              <dt>Expires</dt><dd>${esc((cert.expires_at || "").slice(0, 10))}</dd>
              <dt>State</dt><dd>${label(cert.status)}</dd>
            </dl>
            <div class="actions" style="margin-top:14px">
              <button class="small" id="validate">Verify chain & signatures</button>
              <button class="small" id="history">Lifecycle history</button>
            </div>
            <div id="validation">${validation ? validationBox(validation) : ""}</div>
            <div id="history-box"></div>` : `<p class="empty">No certificate issued for this asset.</p>`}
        </div>

        ${planCurrent || migrationFinished(d) ? `<div class="card">
          <h3>Migration plan</h3>
          <dl class="kv">
            <dt>Target</dt><dd class="mono">${esc(p.target_algorithm)} (${esc(p.target_mode)})</dd>
            <dt>Status</dt><dd>${label(p.status)}</dd>
            <dt>Approval</dt><dd>${label(p.approval_status)}${p.approved_by ? ` by <b>${esc(p.approved_by)}</b>` : ""}</dd>
          </dl>
          ${checklist.length ? `<h3 style="margin:16px 0 4px">Checklist</h3><ol class="checklist">
            ${checklist.map((i) => `<li class="${i.status === "COMPLETED" ? "done" : ""}">
              <span class="num">${i.status === "COMPLETED" ? "✓" : i.sort_order}</span>
              <span class="t">${esc(i.title)}<small>${i.status === "COMPLETED" ? `Done by ${esc(i.completed_by)}` : esc(i.description)}</small></span>
              ${i.status !== "COMPLETED" && p.status === "IN_PROGRESS" ? `<button class="small" data-tick="${i.sort_order}">Done</button>` : ""}
            </li>`).join("")}</ol>` : ""}
        </div>` : ""}
      </div>
    </div>`;

  document.getElementById("next").onclick = (e) => runAction(next.button[1], d, e.currentTarget);

  view.querySelectorAll("[data-tick]").forEach((btn) => {
    btn.onclick = () => act(btn, () => api(`/migration-plans/${p.migration_id}/checklist/${btn.dataset.tick}/complete`, { method: "POST", body: { completed_by: operator() } }), "Step completed");
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
        document.getElementById("history-box").innerHTML = `<h3 style="margin:16px 0 6px">Lifecycle</h3><ul class="history">${record.history
          .map((h) => `<li><b>${esc(h.to_state || h.to)}</b> · ${esc((h.at || h.timestamp || "").slice(0, 19).replace("T", " "))} · ${esc(h.note || "")}</li>`)
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
    ? `<div class="validation ok"><b>✓ Valid ${esc(v.mode)} certificate.</b> ${sigs}; chain ${esc((v.chain || []).join(" → "))}; not revoked.</div>`
    : `<div class="validation bad"><b>✕ ${label(v.reason)}</b><br>${(v.issues || []).map((i) => esc(i.message)).join("<br>")}</div>`;
}

// ---------------------------------------------------------------- algorithms

async function renderAlgorithms() {
  const algorithms = await catalog();
  const groups = [
    ["Implemented: migration targets", algorithms.filter((a) => a.implemented)],
    ["Legacy & candidates: inventory only", algorithms.filter((a) => !a.implemented)],
  ];
  view.innerHTML = `
    <div class="page-head">
      <div><h1>Algorithm catalog</h1><p>From the crypto-agility registry. One CryptoProvider interface for every algorithm, with no silent fallback.</p></div>
    </div>
    ${groups.map(([title, list]) => `
      <div class="card" style="margin-bottom:16px">
        <h3>${title}</h3>
        <div class="table-wrap"><table>
          <thead><tr><th>Algorithm</th><th>Family</th><th>Standard</th><th>Security</th><th>Public key</th><th>Signature</th><th>Quantum</th>${title.startsWith("Impl") ? "<th>Measured (keygen / sign / verify)</th>" : ""}</tr></thead>
          <tbody>${list.map((a) => `
            <tr>
              <td><b>${esc(a.name)}</b><br><span class="mono" style="color:var(--muted)">${esc(a.algorithm_id)}</span></td>
              <td><span class="pill mode-${esc(a.family)}">${a.family === "pq" ? "Post-quantum" : label(a.family)}</span></td>
              <td>${esc(a.standard)}</td>
              <td>${esc(a.security_level || "—")}</td>
              <td>${a.key_size ? `${a.key_size.toLocaleString()} B` : "—"}</td>
              <td>${a.signature_size ? `${a.signature_size.toLocaleString()} B` : "—"}</td>
              <td>${a.quantum_vulnerable ? `<span class="pill bad">Vulnerable</span>` : `<span class="pill ok">Resistant</span>`}</td>
              ${a.implemented ? `<td id="m-${esc(a.algorithm_id)}"><button class="small" data-measure="${esc(a.algorithm_id)}">Measure</button></td>` : ""}
            </tr>`).join("")}</tbody>
        </table></div>
      </div>`).join("")}`;

  view.querySelectorAll("[data-measure]").forEach((button) => {
    button.onclick = async () => {
      const id = button.dataset.measure;
      button.disabled = true;
      button.textContent = "Measuring…";
      try {
        const result = (await api("/ui/algorithms/measure", { method: "POST", body: [id] }))[id];
        const ms = (v) => (v == null ? "—" : `${Number(v).toFixed(v < 10 ? 2 : 0)} ms`);
        document.getElementById(`m-${id}`).innerHTML = `<span class="mono">${ms(result.keygen_ms)} / ${ms(result.sign_ms)} / ${ms(result.verify_ms)}</span>`;
      } catch (error) {
        toast(error.message, true);
        button.disabled = false;
        button.textContent = "Measure";
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
    a.classList.toggle("active", a.dataset.nav === page || (page === "asset" && a.dataset.nav === "assets")));
  try {
    if (page === "assets") await renderAssets(params);
    else if (page === "asset" && id) await renderAsset(id);
    else if (page === "algorithms") await renderAlgorithms();
    else await renderDashboard();
  } catch (error) {
    view.innerHTML = `<div class="card"><h2>Something went wrong</h2><p>${esc(error.message)}</p><p><a href="#/dashboard">Back to dashboard</a></p></div>`;
  }
}

let lastPath = null;
window.addEventListener("hashchange", () => {
  const path = location.hash.split("?")[0];
  if (path !== lastPath) view.scrollTop = 0, window.scrollTo(0, 0);
  lastPath = path;
  route();
});
route();
