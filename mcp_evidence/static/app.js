const state = {
  events: [],
  sessions: [],
};

const byId = (id) => document.getElementById(id);
const tokenInput = byId("admin-token");
tokenInput.value = localStorage.getItem("mcpEvidenceAdminToken") || "";

function authHeaders() {
  const token = tokenInput.value.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function fetchJson(url) {
  const response = await fetch(url, { headers: authHeaders() });
  if (response.status === 401) {
    throw new Error("Admin token required or invalid");
  }
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function load() {
  const params = new URLSearchParams();
  params.set("limit", "100");
  if (byId("search").value.trim()) params.set("q", byId("search").value.trim());
  if (byId("session").value.trim()) params.set("session_id", byId("session").value.trim());
  if (byId("risk").value) params.set("risk", byId("risk").value);

  const [health, stats, events, sessions] = await Promise.all([
    fetch("/health").then((r) => r.json()),
    fetchJson("/api/stats"),
    fetchJson(`/api/events?${params}`),
    fetchJson("/api/sessions"),
  ]);

  byId("target").textContent = `Proxy target: ${health.target_mcp_url}`;
  tokenInput.hidden = !health.admin_auth_enabled;
  byId("chain").textContent = stats.chain.ok ? "Verified" : `Broken at #${stats.chain.first_bad_event_id}`;
  byId("chain").className = stats.chain.ok ? "" : "deny";
  byId("event-count").textContent = String(stats.stats.total_events);
  byId("risk-count").textContent = String(stats.stats.risky_events);
  byId("denied-count").textContent = String(stats.stats.denied_events);
  state.events = events.events || [];
  state.sessions = sessions.sessions || [];
  renderEvents();
  renderSessions();
}

function renderEvents() {
  const container = byId("events");
  const template = byId("event-template");
  container.innerHTML = "";
  if (!state.events.length) {
    container.innerHTML = '<div class="event-meta">No events recorded yet.</div>';
    return;
  }

  for (const event of state.events) {
    const node = template.content.cloneNode(true);
    const title = event.tool_name || event.method || "HTTP request";
    node.querySelector(".event-title").textContent = `#${event.id} ${title}`;
    node.querySelector(".event-time").textContent = new Date(event.created_at).toLocaleString();
    const risks = event.risks
      .map((risk) => `<span class="risk">${escapeHtml(risk)}</span>`)
      .join("");
    const denied = event.policy_decision === "deny" ? '<span class="risk deny">denied</span>' : "";
    node.querySelector(".event-meta").innerHTML = [
      `status ${event.status_code}`,
      `${event.latency_ms} ms`,
      `session ${escapeHtml(event.session_id || "unknown")}`,
      `hash ${event.event_hash.slice(0, 12)}`,
    ].join(" · ") + denied + risks;
    node.querySelector("pre").textContent = JSON.stringify(
      { request: event.request_body, response: event.response_body },
      null,
      2,
    );
    container.appendChild(node);
  }
}

function renderSessions() {
  const container = byId("sessions");
  container.innerHTML = "";
  if (!state.sessions.length) {
    container.innerHTML = '<div class="session-meta">No sessions yet.</div>';
    return;
  }
  for (const session of state.sessions) {
    const risks = session.risks
      .map((risk) => `<span class="risk">${escapeHtml(risk)}</span>`)
      .join("");
    const div = document.createElement("div");
    div.className = "session";
    div.innerHTML = `
      <div class="session-head">
        <strong>${escapeHtml(session.session_id)}</strong>
        <span class="session-meta">${session.events} events</span>
      </div>
      <div class="session-meta">${escapeHtml(session.user_id || "unknown user")} · ${new Date(session.last_seen).toLocaleString()} ${risks}</div>
    `;
    div.addEventListener("click", () => {
      byId("session").value = session.session_id === "unknown" ? "" : session.session_id;
      load();
    });
    container.appendChild(div);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

let debounce;
for (const id of ["search", "session", "risk"]) {
  byId(id).addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(load, 250);
  });
}
byId("refresh").addEventListener("click", load);
tokenInput.addEventListener("input", () => {
  localStorage.setItem("mcpEvidenceAdminToken", tokenInput.value.trim());
});
byId("export-json").addEventListener("click", () => exportEvidence("json"));
byId("export-csv").addEventListener("click", () => exportEvidence("csv"));
byId("export-bundle").addEventListener("click", () => exportEvidence("bundle"));
load().catch((error) => {
  byId("events").innerHTML = `<div class="event-meta">Failed to load: ${escapeHtml(error.message)}</div>`;
});

async function exportEvidence(format) {
  const response = await fetch(`/api/evidence/export?format=${format}`, { headers: authHeaders() });
  if (response.status === 401) {
    byId("events").innerHTML = '<div class="event-meta">Admin token required or invalid.</div>';
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `mcp-evidence.${format === "csv" ? "csv" : format === "bundle" ? "zip" : "json"}`;
  anchor.click();
  URL.revokeObjectURL(url);
}
