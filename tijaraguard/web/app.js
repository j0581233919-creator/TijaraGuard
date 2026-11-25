"use strict";

// Keep operator API key and approval leases strictly in-memory (no web storage persistence)
let currentApiKey = "";
const issuedLeases = new Map();

function showNotice(msg, isError = false) {
  const el = document.getElementById("noticeBanner");
  el.textContent = msg;
  el.className = isError ? "err" : "ok";
}

function clearNotice() {
  const el = document.getElementById("noticeBanner");
  el.textContent = "";
  el.className = "";
}

function getHeaders() {
  const h = { "Content-Type": "application/json" };
  if (currentApiKey) h["Authorization"] = "Bearer " + currentApiKey;
  return h;
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...getHeaders(), ...(opts.headers || {}) },
  });
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const detail = typeof body === "string" ? body : (body.detail || body.error || JSON.stringify(body));
    throw new Error(`HTTP ${res.status}: ${detail}`);
  }
  return body;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

async function refreshAll(preserveNotice = false) {
  try {
    if (!preserveNotice) clearNotice();
    const stateVal = document.getElementById("stateFilter").value;
    const qs = stateVal ? "?state=" + encodeURIComponent(stateVal) : "";
    const [st, usage, drafts] = await Promise.all([
      api("/api/v1/status"),
      api("/api/v1/usage"),
      api("/api/v1/drafts" + qs),
    ]);
    renderStatus(st, usage);
    renderDrafts(drafts.drafts || []);
  } catch (err) {
    showNotice(err.message, true);
  }
}

function renderStatus(st, usage) {
  const sc = st.state_counts || {};
  document.getElementById("statusStats").innerHTML = `
    <div class="stat"><div class="label">Mode</div><div class="val">${escapeHtml(st.mode)}</div></div>
    <div class="stat"><div class="label">Tenant</div><div class="val">${escapeHtml(st.tenant_id)}</div></div>
    <div class="stat"><div class="label">Audit Chain</div><div class="val">${st.audit_chain_valid ? "VALID" : "INVALID"}</div></div>
    <div class="stat"><div class="label">Pending</div><div class="val">${sc.PENDING_APPROVAL || 0}</div></div>
    <div class="stat"><div class="label">Approved</div><div class="val">${sc.APPROVED || 0}</div></div>
    <div class="stat"><div class="label">Delivered</div><div class="val">${sc.DELIVERED || 0}</div></div>
    <div class="stat"><div class="label">Unknown</div><div class="val">${sc.UNKNOWN_DELIVERY || 0}</div></div>
  `;
  document.getElementById("infraPanel").innerHTML = `
    <div><strong>Providers:</strong> ${escapeHtml(JSON.stringify((st.providers || {}).providers || []))}</div>
    <div><strong>Routing:</strong> ${escapeHtml(JSON.stringify((st.providers || {}).routing || {}))}</div>
    <div><strong>Usage:</strong> calls=${usage.total_calls || 0}, tokens=${usage.total_tokens || 0}, est_usd=${usage.estimated_cost_usd || 0}</div>
    <div><strong>Channels:</strong> ${escapeHtml(JSON.stringify(st.channels || {}))}</div>
  `;
}

function renderDrafts(list) {
  const tb = document.getElementById("draftsBody");
  tb.innerHTML = "";
  for (const d of list) {
    const tr = document.createElement("tr");
    const tdId = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = d.draft_id;
    tdId.appendChild(code);

    const tdCh = document.createElement("td");
    tdCh.textContent = d.contact_channel;

    const tdSku = document.createElement("td");
    tdSku.textContent = d.sku || "-";

    const tdAi = document.createElement("td");
    tdAi.textContent = d.ai_provider || "-";

    const tdSt = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge b-${d.state}`;
    badge.textContent = d.state;
    tdSt.appendChild(badge);

    const tdAct = document.createElement("td");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "secondary";
    btn.textContent = "Inspect";
    btn.dataset.action = "inspect";
    btn.dataset.draftId = d.draft_id;
    tdAct.appendChild(btn);

    tr.append(tdId, tdCh, tdSku, tdAi, tdSt, tdAct);
    tb.appendChild(tr);
  }
}

async function loadDrafts() {
  try {
    const f = document.getElementById("stateFilter").value;
    const res = await api("/api/v1/drafts" + (f ? "?state=" + encodeURIComponent(f) : ""));
    renderDrafts(res.drafts || []);
  } catch (err) {
    showNotice(err.message, true);
  }
}

async function inspectDraft(draftId) {
  try {
    const data = await api("/api/v1/drafts/" + encodeURIComponent(draftId));
    const d = data.draft;
    const cachedLease = issuedLeases.get(d.draft_id);
    document.getElementById("auditOutput").textContent = JSON.stringify(data.audit_events || [], null, 2);

    const root = document.getElementById("draftInspector");
    root.innerHTML = `
      <div><strong>${escapeHtml(d.draft_id)}</strong> | <span class="badge b-${escapeHtml(d.state)}">${escapeHtml(d.state)}</span> | Verification: <strong>${escapeHtml(d.verification_status)}</strong></div>
      <div class="muted">Channel: ${escapeHtml(d.contact_channel)} | ContactRef: ${escapeHtml(d.contact_ref)} | SHA256: <code>${escapeHtml(d.payload_sha256)}</code></div>
      <p><strong>Redacted Inquiry:</strong></p>
      <pre class="rtl" id="inspInquiry"></pre>
      <p><strong>Draft Body (Editable):</strong></p>
      <textarea id="editBodyBox" rows="5" style="width:100%;" class="rtl"></textarea>
      <div style="display:grid; gap:6px; margin-top:8px;">
        <input id="dispatchLeaseInput" type="text" placeholder="Approval Lease ID (from Approve)" />
        <input id="dispatchMacInput" type="password" placeholder="Approval MAC (from Approve)" autocomplete="off" />
        <input id="dispatchTargetInput" type="text" placeholder="Optional explicit recipient target (for LIVE)" />
      </div>
      <div class="row-actions" id="inspectorActions"></div>
    `;
    document.getElementById("inspInquiry").textContent = d.redacted_inquiry || "";
    document.getElementById("editBodyBox").value = d.body || "";
    if (cachedLease) {
      document.getElementById("dispatchLeaseInput").value = cachedLease.lease_id;
      document.getElementById("dispatchMacInput").value = cachedLease.approval_mac;
    }

    const actionsEl = document.getElementById("inspectorActions");
    const buttons = [
      { label: "Save & Re-Verify", cls: "secondary", action: "edit" },
      { label: "Approve", cls: "ok", action: "approve" },
      { label: "Dispatch", cls: "", action: "dispatch" },
      { label: "Recover", cls: "secondary", action: "recover" },
      { label: "Escalate", cls: "secondary", action: "escalate" },
      { label: "Reject", cls: "danger", action: "reject" },
    ];
    for (const spec of buttons) {
      const b = document.createElement("button");
      b.type = "button";
      if (spec.cls) b.className = spec.cls;
      b.textContent = spec.label;
      b.dataset.action = spec.action;
      b.dataset.draftId = d.draft_id;
      b.dataset.payloadSha = d.payload_sha256;
      actionsEl.appendChild(b);
    }
  } catch (err) {
    showNotice(err.message, true);
  }
}

async function handleInspectorAction(btn) {
  const action = btn.dataset.action;
  const draftId = btn.dataset.draftId;
  const payloadSha = btn.dataset.payloadSha;
  const reviewer = document.getElementById("reviewerInput").value.trim() || "supervisor_operator";
  try {
    clearNotice();
    if (action === "edit") {
      await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/edit`, {
        method: "POST",
        body: JSON.stringify({ new_body: document.getElementById("editBodyBox").value, actor: reviewer }),
      });
      issuedLeases.delete(draftId);
      showNotice(`Draft ${draftId} edited and re-verified.`);
    } else if (action === "approve") {
      const lease = await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/approve`, {
        method: "POST",
        body: JSON.stringify({ reviewer_id: reviewer, expected_payload_sha256: payloadSha }),
      });
      issuedLeases.set(draftId, lease);
      showNotice(`Issued approval lease ${lease.lease_id}.`);
    } else if (action === "dispatch") {
      const leaseId = document.getElementById("dispatchLeaseInput").value.trim();
      const mac = document.getElementById("dispatchMacInput").value.trim();
      const target = document.getElementById("dispatchTargetInput").value.trim();
      const payload = {
        lease_id: leaseId,
        approval_mac: mac,
        payload_sha256: payloadSha,
      };
      if (target) payload.recipient_target = target;
      const out = await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/dispatch`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      issuedLeases.delete(draftId);
      showNotice(`Dispatch result: ${out.state}`);
    } else if (action === "recover") {
      const out = await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/recover`, {
        method: "POST",
        body: "{}",
      });
      showNotice(`Recovery result: ${out.state}`);
    } else if (action === "escalate") {
      await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/escalate`, {
        method: "POST",
        body: JSON.stringify({ actor: reviewer, reason: "operator_escalated" }),
      });
      issuedLeases.delete(draftId);
      showNotice(`Draft ${draftId} escalated.`);
    } else if (action === "reject") {
      await api(`/api/v1/drafts/${encodeURIComponent(draftId)}/reject`, {
        method: "POST",
        body: JSON.stringify({ reviewer_id: reviewer, reason: "operator_rejected" }),
      });
      issuedLeases.delete(draftId);
      showNotice(`Draft ${draftId} rejected.`);
    }
    await refreshAll(true);
    await inspectDraft(draftId);
  } catch (err) {
    showNotice(err.message, true);
  }
}

document.getElementById("connectBtn").addEventListener("click", () => {
  currentApiKey = document.getElementById("apiKeyInput").value.trim();
  refreshAll();
});

document.getElementById("dirBtn").addEventListener("click", () => {
  document.documentElement.dir = document.documentElement.dir === "rtl" ? "ltr" : "rtl";
});

document.getElementById("stateFilter").addEventListener("change", loadDrafts);
document.getElementById("reloadDraftsBtn").addEventListener("click", loadDrafts);

document.getElementById("draftsBody").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-action='inspect']");
  if (btn) inspectDraft(btn.dataset.draftId);
});

document.getElementById("draftInspector").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button[data-action]");
  if (btn) handleInspectorAction(btn);
});

document.getElementById("catalogBtn").addEventListener("click", async () => {
  try {
    const q = document.getElementById("catalogQuery").value.trim();
    const res = await api("/api/v1/catalog/search?q=" + encodeURIComponent(q));
    document.getElementById("catalogResult").textContent = JSON.stringify(res);
  } catch (err) {
    showNotice(err.message, true);
  }
});

document.getElementById("submitInqBtn").addEventListener("click", async () => {
  try {
    clearNotice();
    const payload = {
      customer_handle: document.getElementById("inqCustomer").value,
      raw_contact_target: document.getElementById("inqTarget").value,
      contact_channel: document.getElementById("inqChannel").value,
      preferred_language: document.getElementById("inqLang").value,
      consent_evidence: document.getElementById("inqEvidence").value,
      consent_to_contact: document.getElementById("inqConsent").checked,
      raw_text: document.getElementById("inqText").value,
    };
    const res = await api("/api/v1/inquiries", { method: "POST", body: JSON.stringify(payload) });
    showNotice(`Draft ${res.draft_id} created (${res.state}).`);
    await refreshAll(true);
    await inspectDraft(res.draft_id);
  } catch (err) {
    showNotice(err.message, true);
  }
});

document.getElementById("healthBtn").addEventListener("click", async () => {
  try {
    const res = await api("/api/v1/providers/health", { method: "POST", body: "{}" });
    showNotice("Provider health: " + JSON.stringify(res.results));
  } catch (err) {
    showNotice(err.message, true);
  }
});

document.getElementById("backupBtn").addEventListener("click", async () => {
  try {
    const res = await api("/api/v1/maintenance/backup", { method: "POST", body: "{}" });
    showNotice(`Backup created: ${res.backup_path} (SHA256 ${res.sha256})`);
  } catch (err) {
    showNotice(err.message, true);
  }
});

document.getElementById("exportCsvBtn").addEventListener("click", async () => {
  try {
    const res = await fetch("/api/v1/audit/export.csv", { headers: getHeaders() });
    if (!res.ok) {
      throw new Error(`CSV export failed (HTTP ${res.status})`);
    }
    const text = await res.text();
    const blob = new Blob([text], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "tijaraguard_audit.csv";
    a.click();
  } catch (err) {
    showNotice(err.message, true);
  }
});
