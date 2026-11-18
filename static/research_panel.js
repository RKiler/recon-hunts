(() => {
  "use strict";

  const initial = window.RESEARCH_PANEL || {};
  const $ = (id) => document.getElementById(id);
  const state = {
    domains: [],
    leads: [],
    detail: null,
    selectedId: Number(initial.initialJobId) || null,
    domainId: Number(initial.initialDomainId) || null,
    tab: "why",
    outcome: "attention",
    analystStatus: "",
    search: "",
    endpointSearch: "",
  };

  const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
  const arr = (value) => Array.isArray(value) ? value : [];
  const display = (value, fallback = "-") => value === null || value === undefined || value === "" ? fallback : String(value);
  const truncate = (value, length = 150) => {
    const text = display(value, "");
    return text.length > length ? `${text.slice(0, length - 1)}…` : text;
  };
  const formatDate = (value) => {
    if (!value) return "Unknown";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  };
  const hostOf = (value) => {
    try { return new URL(value).host; } catch (_) { return display(value, "unknown"); }
  };
  const safeExternalUrl = (value) => {
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) ? url.href : null;
    } catch (_) { return null; }
  };

  let toastTimer;
  function notify(message, error = false) {
    const toast = $("toast");
    toast.textContent = message;
    toast.className = `toast show${error ? " error" : ""}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = "toast"; }, 3200);
  }

  async function fetchJson(url, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal, headers: { "Accept": "application/json", ...(options.headers || {}) } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `${response.status} ${response.statusText}`);
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }

  function query(params) {
    const output = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== null && value !== undefined && value !== "") output.set(key, value);
    });
    return output.toString();
  }

  function outcomeTone(outcome) {
    const value = String(outcome || "").toUpperCase();
    if (value.includes("CONFIRMED")) return "confirmed";
    if (value === "STRONG_CANDIDATE") return "strong";
    if (value === "NEEDS_MANUAL_REVIEW") return "manual";
    if (["BLOCKED", "INCONCLUSIVE", "LOCAL_MODEL_ONLY"].includes(value)) return "blocked";
    return "attention";
  }

  async function loadDomains() {
    const domains = await fetchJson("/api/domains");
    state.domains = arr(domains);
    const select = $("domainFilter");
    select.innerHTML = `<option value="">All domains</option>${state.domains.map((domain) =>
      `<option value="${esc(domain.id)}"${Number(domain.id) === state.domainId ? " selected" : ""}>${esc(domain.domain)}</option>`
    ).join("")}`;
  }

  async function loadLeads({ keepSelection = true } = {}) {
    $("leadList").innerHTML = `<div class="loading-state"><span></span>Loading leads</div>`;
    const suffix = query({
      domain_id: state.domainId,
      outcome: state.outcome,
      analyst_status: state.analystStatus,
      q: state.search,
      limit: 120,
    });
    try {
      const data = await fetchJson(`/api/research/leads?${suffix}`);
      state.leads = arr(data.rows);
      const summary = data.summary || {};
      $("metricConfirmed").textContent = display(summary.confirmed, "0");
      $("metricAlerts").textContent = display(summary.review_alerts, "0");
      $("metricRunning").textContent = display(summary.running, "0");
      $("metricWorker").textContent = display(summary.worker_status, "unknown");
      $("metricAttention").textContent = display(data.total, "0");
      $("queueCount").textContent = `${data.total || 0} visible · ${data.recent_days || 30} day window`;
      renderLeadList();
      if (!keepSelection || !state.selectedId) {
        state.selectedId = state.leads[0]?.id || null;
      }
      if (state.selectedId) await selectLead(state.selectedId, false);
      else showEmpty("No leads match these filters", "Try another domain, outcome, or analyst status.");
    } catch (error) {
      $("leadList").innerHTML = `<div class="empty-block">${esc(error.message)}</div>`;
      notify(`Lead queue failed: ${error.message}`, true);
    }
  }

  function renderLeadList() {
    if (!state.leads.length) {
      $("leadList").innerHTML = `<div class="empty-block">No leads match the current filters.</div>`;
      return;
    }
    $("leadList").innerHTML = state.leads.map((lead) => {
      const outcome = display(lead.display_outcome, "possible");
      return `<button class="lead-card${Number(lead.id) === Number(state.selectedId) ? " active" : ""}" data-lead-id="${esc(lead.id)}">
        <span class="lead-card-top">
          <span class="lead-card-domain">${esc(lead.domain || lead.target)}</span>
          <span class="badge ${outcomeTone(outcome)}">${esc(outcome.replaceAll("_", " "))}</span>
        </span>
        <h3>${esc(lead.display_title)}</h3>
        <p>${esc(hostOf(lead.affected_endpoint || lead.asset_value))} · ${esc(display(lead.job_type).replaceAll("_", " "))}</p>
        <span class="lead-card-meta">
          <span>Score ${esc(display(lead.priority, "0"))}</span>
          <span>Conf ${esc(display(lead.confidence, "0"))}%</span>
          <span>${esc(lead.tests_count || 0)} tests</span>
          <span class="bookmark-mini">${lead.bookmarked ? "★" : ""}</span>
        </span>
      </button>`;
    }).join("");
    document.querySelectorAll("[data-lead-id]").forEach((button) => {
      button.addEventListener("click", () => selectLead(Number(button.dataset.leadId), true));
    });
  }

  function showEmpty(title, message) {
    $("detailContent").hidden = true;
    $("detailEmpty").hidden = false;
    $("detailEmpty").querySelector("h2").textContent = title;
    $("detailEmpty").querySelector("p").textContent = message;
  }

  async function selectLead(jobId, updateHistory = true) {
    state.selectedId = Number(jobId);
    renderLeadList();
    $("detailEmpty").hidden = true;
    $("detailContent").hidden = false;
    $("sectionContent").innerHTML = `<div class="loading-state"><span></span>Loading evidence context</div>`;
    try {
      const suffix = query({ domain_id: state.domainId });
      state.detail = await fetchJson(`/api/research/leads/${encodeURIComponent(jobId)}?${suffix}`);
      renderDetail();
      if (updateHistory) {
        const location = `/research/leads/${encodeURIComponent(jobId)}${state.domainId ? `?domain_id=${encodeURIComponent(state.domainId)}` : ""}`;
        history.pushState({ jobId }, "", location);
      }
    } catch (error) {
      showEmpty("Lead context unavailable", error.message);
      notify(`Lead detail failed: ${error.message}`, true);
    }
  }

  function tabsFor(detail) {
    const result = detail.lead?.result || {};
    return [
      ["why", "target", "Why it matters", 0],
      ["hypotheses", "flask", "Attack hypotheses", arr(result.blocked_by).length],
      ["evidence", "file", "Evidence", arr(result.evidence_files).length + arr(detail.evidence_packs).length],
      ["validation", "shield", "Validation", arr(detail.validations).length],
      ["tools", "code", "Recommended tools", arr(result.skills_used).length],
      ["architecture", "route", "Architecture", arr(detail.live_hosts).length],
      ["chaining", "link", "Chaining opportunities", 0],
      ["relationships", "bot", "Related leads", arr(detail.related_leads).length],
      ["observations", "search", "Notable observations", arr(result.data_sources_used).length],
      ["recon", "radar", "Reconnaissance", arr(detail.js_assets).length + arr(detail.api_surfaces).length],
      ["cves", "shield", "Known CVEs", cveCount(detail.services)],
      ["endpoints", "route", "Endpoints", arr(detail.endpoints).length],
    ];
  }

  function renderDetail() {
    const detail = state.detail;
    const lead = detail.lead || {};
    const result = lead.result || {};
    const outcome = display(result.outcome_class || lead.finding_status || lead.status, "possible");
    $("detailEyebrow").textContent = `${display(lead.domain || lead.target)} · Job ${display(lead.id)} · ${display(lead.job_type).replaceAll("_", " ")}`;
    $("detailTitle").textContent = display(result.title || lead.hypothesis, "Untitled research lead");
    $("detailTarget").textContent = display(result.affected_endpoint || lead.asset_value);
    $("detailBadges").innerHTML = [
      `<span class="badge ${outcomeTone(outcome)}">${esc(outcome.replaceAll("_", " "))}</span>`,
      `<span class="badge">${esc(display(result.vulnerability_class || result.owasp_category || lead.job_type).replaceAll("_", " "))}</span>`,
      `<span class="badge attention">Score ${esc(display(lead.priority, "0"))}</span>`,
      `<span class="badge">Confidence ${esc(display(result.confidence ?? lead.confidence, "0"))}%</span>`,
      lead.codex_alert_kind ? `<span class="badge alert">${esc(lead.codex_alert_kind)} alert sent</span>` : "",
      lead.scope_ok ? `<span class="badge confirmed">In scope</span>` : `<span class="badge danger">Scope blocked</span>`,
    ].join("");
    $("bookmarkButton").classList.toggle("active", Boolean(detail.annotation?.bookmarked));
    renderSectionNav();
    renderSection();
    window.dispatchEvent(new CustomEvent("research:context", { detail: {
      section: "leads",
      record_id: lead.id,
      source_type: "bug_jobs",
      source_id: lead.id,
      domain: lead.domain || lead.target,
      title: result.title || lead.hypothesis,
      location: result.affected_endpoint || lead.asset_value,
      status: outcome,
      vulnerability_class: result.vulnerability_class || result.owasp_category || lead.job_type,
      summary: truncate(result.impact || result.observed_anomaly || lead.hypothesis, 1200),
      confidence: result.confidence ?? lead.confidence,
    } }));
  }

  function renderSectionNav() {
    $("sectionNav").innerHTML = tabsFor(state.detail).map(([key, iconName, label, count]) =>
      `<button class="section-tab${state.tab === key ? " active" : ""}" data-tab="${key}">${icon(iconName)}<span>${esc(label)}</span>${count ? `<em>${count}</em>` : ""}</button>`
    ).join("");
    document.querySelectorAll("[data-tab]").forEach((button) => {
      button.addEventListener("click", () => {
        state.tab = button.dataset.tab;
        renderSectionNav();
        renderSection();
      });
    });
  }

  function titleBlock(iconName, title) {
    return `<div class="content-title">${icon(iconName)}<h3>${esc(title)}</h3></div>`;
  }
  function section(title, body, className = "") {
    return `<div class="content-section ${className}">${title ? `<h4>${esc(title)}</h4>` : ""}${body}</div>`;
  }
  function paragraph(value, fallback = "No evidence recorded.") {
    return `<p>${esc(display(value, fallback))}</p>`;
  }
  function list(items, className = "") {
    const values = arr(items).filter((item) => item !== null && item !== undefined && String(item).trim());
    return values.length ? `<ul class="clean-list ${className}">${values.map((item) => `<li>${esc(typeof item === "string" ? item : JSON.stringify(item))}</li>`).join("")}</ul>` : `<div class="empty-block">No records in this section.</div>`;
  }
  function chips(items) {
    const values = arr(items).filter(Boolean);
    return values.length ? `<div class="chip-row">${values.map((item) => `<span class="chip">${esc(item)}</span>`).join("")}</div>` : `<div class="empty-block">None recorded.</div>`;
  }

  function renderSection() {
    const renderers = {
      why: renderWhy,
      hypotheses: renderHypotheses,
      evidence: renderEvidence,
      validation: renderValidation,
      tools: renderTools,
      architecture: renderArchitecture,
      chaining: renderChaining,
      relationships: renderRelationships,
      observations: renderObservations,
      recon: renderRecon,
      cves: renderCves,
      endpoints: renderEndpoints,
    };
    $("sectionContent").innerHTML = (renderers[state.tab] || renderWhy)();
    bindSectionActions();
  }

  function renderWhy() {
    const { lead, source_finding: sourceFinding } = state.detail;
    const result = lead.result || {};
    const anomaly = display(result.observed_anomaly, "No observed behavior was recorded.");
    const signalClass = /no security|not demonstrated|blocked/i.test(anomaly) ? "neutral" : lead.finding_status === "confirmed" ? "good" : "";
    return `${titleBlock("target", "Why it matters")}
      ${section("Observed behavior", `<div class="signal-box ${signalClass}">${paragraph(anomaly)}</div>`)}
      ${section("Impact assessment", paragraph(result.impact, "Impact has not been established."))}
      ${section("Lead facts", `<div class="fact-grid">
        <div class="fact"><span>Target</span><strong>${esc(lead.domain || lead.target)}</strong></div>
        <div class="fact"><span>Source</span><strong>${esc(`${display(lead.source_table)} #${display(lead.source_id)}`)}</strong></div>
        <div class="fact"><span>Requests</span><strong>${esc(display(result.active_request_count, "0"))}</strong></div>
        <div class="fact"><span>Variants</span><strong>${esc(display(result.variant_count, "0"))}</strong></div>
        <div class="fact"><span>Observed</span><strong>${esc(formatDate(lead.source_observed_at))}</strong></div>
        <div class="fact"><span>Completed</span><strong>${esc(formatDate(lead.finished_at))}</strong></div>
        <div class="fact"><span>Source finding</span><strong>${esc(sourceFinding ? `${sourceFinding.finding_type} / ${sourceFinding.severity}` : "None linked")}</strong></div>
        <div class="fact"><span>Artifact</span><strong>${esc(lead.artifact_error || "Available")}</strong></div>
      </div>`)}
      ${section("Recommended action", list([result.recommended_next_step, result.manual_review_reason].filter(Boolean)))}`;
  }

  function renderHypotheses() {
    const lead = state.detail.lead;
    const result = lead.result || {};
    const followup = result.recommended_followup_job || {};
    return `${titleBlock("flask", "Attack hypotheses")}
      ${section("Primary hypothesis", paragraph(lead.hypothesis))}
      ${section("Decisive next hypothesis", followup.hypothesis ? `${paragraph(followup.hypothesis)}${paragraph(followup.reason, "")}` : paragraph(result.recommended_next_step))}
      ${section("Current blockers", list(result.blocked_by))}
      ${section("Safety boundary", list(lead.safety_notes))}`;
  }

  function renderEvidence() {
    const result = state.detail.lead.result || {};
    const tests = arr(result.tests_performed);
    const packs = arr(state.detail.evidence_packs);
    return `${titleBlock("file", "Evidence")}
      ${section("Tests performed", tests.length ? tests.map((test) => `<div class="test-row"><strong>${esc(test.test || "Test")}</strong>${paragraph(test.result, "No result recorded.")}</div>`).join("") : `<div class="empty-block">No structured tests were recorded.</div>`)}
      ${section("Artifact files", list(result.evidence_files, "mono-list"))}
      ${section("Database evidence packs", packs.length ? `<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th class="wide-cell">Summary</th><th>Updated</th></tr></thead><tbody>${packs.map((pack) => `<tr><td>${esc(pack.severity)}</td><td>${esc(pack.title)}</td><td>${esc(pack.summary || pack.location)}</td><td>${esc(formatDate(pack.updated_at))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No database evidence pack is linked to this source.</div>`)}`;
  }

  function renderValidation() {
    const detail = state.detail;
    const result = detail.lead.result || {};
    const annotation = detail.annotation || {};
    const validations = arr(detail.validations);
    return `${titleBlock("shield", "Validation")}
      ${section("Safe reproduction", list(result.safe_reproduction_steps))}
      ${section("Validation queue", validations.length ? `<table class="data-table"><thead><tr><th>Status</th><th>Priority</th><th class="wide-cell">Location</th><th>Updated</th></tr></thead><tbody>${validations.map((item) => `<tr><td>${esc(item.status)}</td><td>${esc(item.priority)}</td><td>${esc(item.location)}</td><td>${esc(formatDate(item.updated_at))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">This lead is not in the validation queue.</div>`)}
      ${section("Analyst record", `<form class="annotation-form" id="annotationForm">
        <label>Status<select name="status"><option value="new">New</option><option value="investigating">Investigating</option><option value="needs_operator">Needs operator</option><option value="confirmed">Confirmed</option><option value="dismissed">Dismissed</option></select></label>
        <label>Severity override<select name="severity_override"><option value="">Unchanged</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></label>
        <label class="span-2">Tags<input name="tags" value="${esc(arr(annotation.tags).join(", "))}" placeholder="authz, manual-review"></label>
        <label class="span-2">Assigned to<input name="assigned_to" value="${esc(annotation.assigned_to || "")}" placeholder="Analyst name"></label>
        <label class="full">Notes<textarea name="notes" placeholder="What was checked, what remains, and the decisive next step">${esc(annotation.notes || "")}</textarea></label>
        <div class="form-actions full"><button class="button" type="button" id="annotationBookmark">${annotation.bookmarked ? "Remove bookmark" : "Bookmark"}</button><button class="button primary" type="submit">Save analyst record</button></div>
      </form>`)}`;
  }

  function toolRecommendations(jobType) {
    const type = String(jobType || "").toLowerCase();
    const common = ["Recon source verification", "Baseline and negative-control recorder"];
    if (type.includes("xss")) return [...common, "Browser source-to-sink trace", "XSS callback correlation", "CSP and render-context review"];
    if (type.includes("ssrf") || type.includes("redirect") || type.includes("webhook")) return [...common, "Controlled callback hub", "Redirect and URL-parser matrix", "DNS and response-timing correlation"];
    if (type.includes("upload") || type.includes("file") || type.includes("traversal")) return [...common, "File type and magic-byte matrix", "Owned-object download authorization check", "Parser-specific safe probes"];
    if (type.includes("graphql")) return [...common, "GraphQL operation inventory", "Two-role authorization matrix", "Field and mutation-level differential"];
    if (type.includes("idor") || type.includes("auth")) return [...common, "Owned actor/object matrix", "Cross-role replay", "Independent state read-back"];
    if (type.includes("injection")) return [...common, "Type and parser differential", "Bounded harmless canaries", "Response and timing controls"];
    return [...common, "Technology-specific validator", "Adjacent endpoint comparison"];
  }

  function renderTools() {
    const lead = state.detail.lead;
    const result = lead.result || {};
    return `${titleBlock("code", "Recommended tools")}
      ${section("Worker skills already used", chips(result.skills_used))}
      ${section("Next verification tools", list(toolRecommendations(lead.job_type)))}
      ${section("Prompt family", paragraph(result.prompt_family || lead.prompt_path, "No prompt family recorded."))}`;
  }

  function renderArchitecture() {
    const detail = state.detail;
    const lead = detail.lead;
    const result = lead.result || {};
    const nodes = [
      ["Root domain", lead.domain || lead.target],
      ["Observed host", detail.hostname || hostOf(lead.asset_value)],
      [display(lead.asset_type, "Asset"), lead.asset_value],
      ["Affected operation", result.affected_endpoint || "Needs validation"],
    ];
    return `${titleBlock("route", "Hypothesized architecture")}
      ${section("Observed relationship", `<div class="architecture">${nodes.map(([label, value]) => `<div class="architecture-node"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("")}</div>`)}
      ${section("API surfaces on this host", renderApiSurfaces())}`;
  }

  function chainSuggestions(jobType) {
    const type = String(jobType || "").toLowerCase();
    if (type.includes("xss")) return ["Confirm attacker-controlled input reaches the live render context.", "Identify the highest-privileged user who renders the value.", "Test whether the same value reaches email, export, admin, or support views."];
    if (type.includes("ssrf") || type.includes("redirect")) return ["Prove the URL is processed server-side with the controlled callback.", "Compare redirect handling and hostname validation across parser variants.", "Look for an authenticated integration, import, preview, or webhook sibling with greater privilege."];
    if (type.includes("upload") || type.includes("file")) return ["Establish an owned successful upload and retrieve it through the normal owner path.", "Compare preview, conversion, download, and deletion authorization separately.", "Trace accepted content into browser, XML, image, document, or archive processors."];
    if (type.includes("graphql") || type.includes("idor") || type.includes("auth")) return ["Map actor, tenant, parent, and child identifiers from an owned baseline.", "Replay the same operation across owned roles with one identifier changed.", "Inspect bulk, export, async result, legacy, and mobile siblings for weaker checks."];
    if (type.includes("injection")) return ["Identify the exact parser or backend sink from a stable differential.", "Retest with a matched negative control and one harmless mutation.", "Check whether the same field reaches report, export, template, search, or async processing."];
    return ["Confirm the current behavior on the exact in-scope asset.", "Map adjacent operations sharing the same trust boundary.", "Use the weakest safe primitive to establish meaningful impact."];
  }

  function renderChaining() {
    const lead = state.detail.lead;
    return `${titleBlock("link", "Chaining opportunities")}
      ${section("Next boundaries to test", list(chainSuggestions(lead.job_type)))}
      ${section("Current prerequisite", paragraph(lead.result?.manual_review_reason || lead.result?.recommended_next_step, "No explicit prerequisite recorded."))}`;
  }

  function renderRelationships() {
    const detail = state.detail;
    const related = arr(detail.related_leads);
    const authz = arr(detail.authz_observations);
    return `${titleBlock("bot", "Relationships")}
      ${section("Related leads", related.length ? `<table class="data-table"><thead><tr><th>ID</th><th>Class</th><th class="wide-cell">Lead</th><th>Confidence</th></tr></thead><tbody>${related.map((item) => `<tr class="related-row" data-related-id="${esc(item.id)}"><td>${esc(item.id)}</td><td>${esc(display(item.job_type).replaceAll("_", " "))}</td><td>${esc(item.display_title || item.asset_value)}</td><td>${esc(display(item.confidence, "0"))}%</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No recent same-class or same-source leads.</div>`)}
      ${section("Authorization observations", authz.length ? `<table class="data-table"><thead><tr><th>Actor</th><th>Method</th><th class="wide-cell">Endpoint</th><th>Status</th></tr></thead><tbody>${authz.map((item) => `<tr><td>${esc(item.actor)}</td><td>${esc(item.method)}</td><td>${esc(item.endpoint)}</td><td>${esc(display(item.status_code))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No authorization matrix rows are linked to this job.</div>`)}`;
  }

  function renderObservations() {
    const lead = state.detail.lead;
    const result = lead.result || {};
    return `${titleBlock("search", "Notable observations")}
      ${section("Observed anomaly", paragraph(result.observed_anomaly))}
      ${section("Data sources used", list(result.data_sources_used))}
      ${section("Actors and roles tested", chips(result.roles_tested))}
      ${section("Coverage", `<div class="fact-grid">
        <div class="fact"><span>DB records</span><strong>${esc(display(result.db_records_reviewed, "0"))}</strong></div>
        <div class="fact"><span>Active requests</span><strong>${esc(display(result.active_request_count, "0"))}</strong></div>
        <div class="fact"><span>Tests</span><strong>${esc(arr(result.tests_performed).length)}</strong></div>
        <div class="fact"><span>Evidence files</span><strong>${esc(arr(result.evidence_files).length)}</strong></div>
      </div>`)}
      ${section("Instructions used", list(result.instruction_files_read, "mono-list"))}`;
  }

  function renderApiSurfaces() {
    const surfaces = arr(state.detail.api_surfaces);
    if (!surfaces.length) return `<div class="empty-block">No API surface records for this host.</div>`;
    return `<table class="data-table"><thead><tr><th>Type</th><th class="wide-cell">Location</th><th>Auth</th><th>Operations</th></tr></thead><tbody>${surfaces.map((item) => `<tr><td>${esc(item.surface_type)}</td><td>${esc(item.location)}</td><td>${esc(item.auth_required === null ? "Unknown" : item.auth_required ? "Required" : "Anonymous")}</td><td>${esc(item.operations_count)}</td></tr>`).join("")}</tbody></table>`;
  }

  function renderRecon() {
    const detail = state.detail;
    const hosts = arr(detail.live_hosts);
    const tech = arr(detail.technologies);
    const jsAssets = arr(detail.js_assets);
    const leaks = arr(detail.credential_leaks);
    return `${titleBlock("radar", "Reconnaissance")}
      ${section("Live host", hosts.length ? `<table class="data-table"><thead><tr><th class="wide-cell">URL</th><th>Status</th><th>Title</th><th>Server</th><th>Last seen</th></tr></thead><tbody>${hosts.map((host) => `<tr><td>${esc(host.url)}</td><td>${esc(display(host.status_code))}</td><td>${esc(host.title)}</td><td>${esc(host.webserver)}</td><td>${esc(formatDate(host.last_seen))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No exact live-host row for ${esc(detail.hostname || "this asset")}.</div>`)}
      ${section("Technology", chips(tech.map((item) => `${item.technology}${item.version ? ` ${item.version}` : ""}`)))}
      ${section("JavaScript assets", jsAssets.length ? `<table class="data-table"><thead><tr><th class="wide-cell">Asset</th><th>Status</th><th>Size</th><th>Analyzed</th></tr></thead><tbody>${jsAssets.map((item) => `<tr><td>${esc(item.asset_url)}</td><td>${esc(display(item.http_status))}</td><td>${esc(display(item.size_bytes))}</td><td>${item.analyzed ? "Yes" : "No"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No matching JavaScript inventory.</div>`)}
      ${section("Redacted credential signals", leaks.length ? `<table class="data-table"><thead><tr><th>Detector</th><th class="wide-cell">Source</th><th>Redacted value</th><th>Verified</th></tr></thead><tbody>${leaks.map((item) => `<tr><td>${esc(item.detector_name)}</td><td>${esc(item.source_url)}</td><td>${esc(item.redacted_secret)}</td><td>${item.verified ? "Yes" : "No"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No credential signals are linked to the exact asset.</div>`)}
      ${section("API surfaces", renderApiSurfaces())}`;
  }

  function serviceCves(service) {
    const metadata = service?.metadata || {};
    const shodan = metadata.shodan || {};
    const values = shodan.cves || metadata.cves || [];
    return Array.isArray(values) ? values : Object.keys(values || {});
  }
  function cveCount(services) {
    return new Set(arr(services).flatMap(serviceCves)).size;
  }
  function renderCves() {
    const services = arr(state.detail.services);
    const allCves = [...new Set(services.flatMap(serviceCves))];
    return `${titleBlock("shield", "Known CVEs and services")}
      ${section("CVE labels", allCves.length ? chips(allCves) : `<div class="empty-block">No CVE metadata is associated with this host. Scanner labels require current service validation.</div>`)}
      ${section("Observed services", services.length ? `<table class="data-table"><thead><tr><th>IP</th><th>Port</th><th>State</th><th>Product</th><th>Version</th><th>Validated</th></tr></thead><tbody>${services.map((item) => `<tr><td>${esc(item.ip_address)}</td><td>${esc(`${item.port}/${item.protocol}`)}</td><td>${esc(item.state)}</td><td>${esc(item.product || item.service)}</td><td>${esc(item.version)}</td><td>${esc(formatDate(item.last_scanned_at))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No network service records map to this hostname.</div>`)}`;
  }

  function renderEndpoints() {
    const term = state.endpointSearch.toLowerCase();
    const endpoints = arr(state.detail.endpoints).filter((item) => !term || `${item.method} ${item.path} ${arr(item.risk_tags).join(" ")}`.toLowerCase().includes(term));
    return `${titleBlock("route", "Endpoints")}
      <input class="inline-search" id="endpointSearch" type="search" value="${esc(state.endpointSearch)}" placeholder="Filter method, path, or risk tag">
      ${section("Host endpoints", endpoints.length ? `<table class="data-table"><thead><tr><th>Method</th><th class="wide-cell">Path</th><th>Status</th><th>Source</th><th>Risk tags</th></tr></thead><tbody>${endpoints.map((item) => `<tr><td>${esc(item.method)}</td><td>${esc(item.path)}</td><td>${esc(display(item.status_code))}</td><td>${esc(item.source)}</td><td>${esc(arr(item.risk_tags).join(", "))}</td></tr>`).join("")}</tbody></table>` : `<div class="empty-block">No endpoints match this filter.</div>`)}`;
  }

  function bindSectionActions() {
    document.querySelectorAll("[data-related-id]").forEach((row) => row.addEventListener("click", () => selectLead(Number(row.dataset.relatedId), true)));
    const endpointSearch = $("endpointSearch");
    if (endpointSearch) endpointSearch.addEventListener("input", (event) => {
      state.endpointSearch = event.target.value;
      renderSection();
      const restored = $("endpointSearch");
      if (restored) { restored.focus(); restored.setSelectionRange(restored.value.length, restored.value.length); }
    });
    const form = $("annotationForm");
    if (form) {
      const annotation = state.detail.annotation || {};
      form.elements.status.value = annotation.status || "new";
      form.elements.severity_override.value = annotation.severity_override || "";
      form.addEventListener("submit", saveAnnotation);
      $("annotationBookmark")?.addEventListener("click", async () => {
        await saveAnnotation(null, !Boolean(state.detail.annotation?.bookmarked));
      });
    }
  }

  async function saveAnnotation(event, bookmarkOverride = null) {
    event?.preventDefault();
    const lead = state.detail.lead;
    const form = $("annotationForm");
    const existing = state.detail.annotation || {};
    const payload = {
      entity_type: "bug_job",
      entity_id: lead.id,
      entity_key: `bug_job:${lead.id}`,
      location: lead.result?.affected_endpoint || lead.asset_value,
      status: form?.elements.status.value || existing.status || "new",
      severity_override: form?.elements.severity_override.value || null,
      tags: form?.elements.tags.value || arr(existing.tags).join(", "),
      assigned_to: form?.elements.assigned_to.value || existing.assigned_to || "",
      notes: form?.elements.notes.value || existing.notes || "",
      bookmarked: bookmarkOverride === null ? Boolean(existing.bookmarked) : bookmarkOverride,
    };
    try {
      state.detail.annotation = await fetchJson(`/api/analyst/annotation?domain_id=${encodeURIComponent(lead.domain_id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const listLead = state.leads.find((item) => Number(item.id) === Number(lead.id));
      if (listLead) {
        listLead.bookmarked = state.detail.annotation.bookmarked;
        listLead.analyst_status = state.detail.annotation.status;
      }
      renderLeadList();
      renderDetail();
      notify("Analyst record saved");
    } catch (error) { notify(`Could not save analyst record: ${error.message}`, true); }
  }

  async function queueValidation() {
    if (!state.detail) return;
    const button = $("queueValidation");
    button.disabled = true;
    try {
      const lead = state.detail.lead;
      await fetchJson(`/api/research/leads/${encodeURIComponent(lead.id)}/validation?domain_id=${encodeURIComponent(lead.domain_id)}`, { method: "POST" });
      notify("Lead added to the validation queue");
      await selectLead(lead.id, false);
      state.tab = "validation";
      renderSectionNav();
      renderSection();
    } catch (error) { notify(`Could not queue validation: ${error.message}`, true); }
    finally { button.disabled = false; }
  }

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(String(value || ""));
      notify("Copied to clipboard");
    } catch (_) { notify("Clipboard access was blocked", true); }
  }

  function exportLead() {
    if (!state.detail) return;
    const leadId = state.detail.lead?.id || "lead";
    const blob = new Blob([JSON.stringify(state.detail, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `research-lead-${leadId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  let searchTimer;
  function bindGlobalActions() {
    $("domainFilter").addEventListener("change", async (event) => {
      state.domainId = Number(event.target.value) || null;
      state.selectedId = null;
      await loadLeads({ keepSelection: false });
    });
    $("outcomeFilter").addEventListener("change", async (event) => { state.outcome = event.target.value; state.selectedId = null; await loadLeads({ keepSelection: false }); });
    $("analystStatusFilter").addEventListener("change", async (event) => { state.analystStatus = event.target.value; state.selectedId = null; await loadLeads({ keepSelection: false }); });
    $("leadSearch").addEventListener("input", (event) => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(async () => { state.search = event.target.value.trim(); state.selectedId = null; await loadLeads({ keepSelection: false }); }, 260);
    });
    [$("refreshButton"), $("queueRefresh")].forEach((button) => button.addEventListener("click", async () => {
      await loadLeads();
      notify("Research data refreshed");
    }));
    $("copyTarget").addEventListener("click", () => copyText(state.detail?.lead?.result?.affected_endpoint || state.detail?.lead?.asset_value));
    $("bookmarkButton").addEventListener("click", () => saveAnnotation(null, !Boolean(state.detail?.annotation?.bookmarked)));
    $("queueValidation").addEventListener("click", queueValidation);
    $("exportLead").addEventListener("click", exportLead);
    $("openTarget").addEventListener("click", () => {
      const target = safeExternalUrl(state.detail?.lead?.result?.affected_endpoint || state.detail?.lead?.asset_value);
      if (target) window.open(target, "_blank", "noopener,noreferrer");
      else notify("This lead does not contain an HTTP target", true);
    });
    $("mobileMenu").addEventListener("click", () => $("globalNav").classList.toggle("open"));
    $("navClose").addEventListener("click", () => $("globalNav").classList.remove("open"));
    window.addEventListener("popstate", (event) => {
      const match = location.pathname.match(/\/research\/leads\/(\d+)/);
      const id = Number(event.state?.jobId || match?.[1]);
      if (id) selectLead(id, false);
    });
  }

  async function init() {
    bindGlobalActions();
    try {
      await loadDomains();
      await loadLeads();
    } catch (error) {
      showEmpty("Research workspace unavailable", error.message);
      notify(error.message, true);
    }
  }

  init();
})();
