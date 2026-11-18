(() => {
  "use strict";

  const initial = window.RESEARCH_PANEL || {};
  const section = initial.initialSection || "overview";
  const $ = (id) => document.getElementById(id);
  const state = { domains: [], rows: [], visible: [], selected: null, domainId: Number(initial.initialDomainId) || null, search: "", filter: "", inspectorRequest: 0 };
  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  const arr = (value) => Array.isArray(value) ? value : [];
  const show = (value, fallback = "-") => value === null || value === undefined || value === "" ? fallback : String(value);
  const truncate = (value, length = 180) => {
    const text = show(value, "");
    return text.length > length ? `${text.slice(0, length - 1)}…` : text;
  };
  const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
  const formatDate = (value) => {
    if (!value) return "Unknown";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  };
  const query = (values) => {
    const params = new URLSearchParams();
    Object.entries(values).forEach(([key, value]) => { if (value !== null && value !== undefined && value !== "") params.set(key, value); });
    return params.toString();
  };
  const safeUrl = (value) => {
    try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href : null; } catch (_) { return null; }
  };
  const tone = (value) => {
    const text = String(value || "").toLowerCase();
    if (/confirmed|validated|completed|done|200/.test(text)) return "confirmed";
    if (/high|critical|manual|possible|review|running/.test(text)) return "manual";
    if (/failed|false|error|blocked/.test(text)) return "danger";
    return "blocked";
  };

  let toastTimer;
  function notify(message, error = false) {
    const toast = $("toast");
    toast.textContent = message;
    toast.className = `toast show${error ? " error" : ""}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = "toast"; }, 3000);
  }

  async function fetchJson(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(url, { signal: controller.signal, headers: { Accept: "application/json" } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `${response.status} ${response.statusText}`);
      return payload;
    } finally { clearTimeout(timer); }
  }

  function endpointForSection() {
    const suffix = query({ domain_id: state.domainId, limit: section === "overview" ? 120 : 100 });
    const endpoints = {
      overview: `/api/research/leads?outcome=attention&${suffix}`,
      workers: `/api/codex-worker?${suffix}`,
      validation: `/api/research/validation?${suffix}`,
      evidence: `/api/research/evidence?${suffix}`,
      endpoints: `/api/results/urls?${suffix}`,
      javascript: `/api/results/js?${suffix}`,
      ffuf: `/api/ffuf/workbench/runs?${suffix}`,
    };
    return endpoints[section];
  }

  function identity(row, index) {
    return String(row.id ?? row.job_id ?? row.asset_url ?? row.full_url ?? row.location ?? `${section}-${index}`);
  }

  function normalized(row, index) {
    const result = row.result || {};
    const common = { raw: row, key: identity(row, index), domain: row.domain || row.target || "All scope" };
    if (section === "overview") return { ...common, title: row.display_title, location: row.affected_endpoint || row.asset_value, status: row.display_outcome, meta: row.vulnerability_class, summary: row.display_summary || row.hypothesis, date: row.updated_at, leadId: row.id };
    if (section === "workers") return { ...common, title: row.display_title || result.title || row.hypothesis || `${row.job_type} job`, location: row.asset_value, status: result.outcome_class || row.finding_status || row.status, meta: `${row.job_type || "worker"} · priority ${show(row.priority, "-")}`, summary: row.error || row.hypothesis, date: row.updated_at, leadId: ["possible", "confirmed"].includes(row.finding_status) ? row.id : null };
    if (section === "validation") return { ...common, title: row.location || `Validation ${row.id}`, location: row.location, status: row.status, meta: `${row.priority || "normal"} priority · ${row.source_table || "manual"}`, summary: row.notes || arr(row.validation_steps).join(" "), date: row.updated_at, leadId: row.source_table === "bug_jobs" ? row.source_id : null };
    if (section === "evidence") return { ...common, title: row.title || row.location || `Evidence ${row.id}`, location: row.location, status: row.severity || "evidence", meta: `${row.source_table || "analyst"} · ${arr(row.artifacts).length} artifacts`, summary: row.summary, date: row.updated_at, leadId: row.source_table === "bug_jobs" ? row.source_id : null };
    if (section === "endpoints") return { ...common, title: row.full_url || `${row.base_url || ""}${row.path || ""}`, location: row.full_url, status: row.status_code ?? "unknown", meta: `${row.method || "GET"} · ${row.source || "recon"}`, summary: `${arr(row.technologies).join(", ") || "Technology unknown"}${arr(row.risk_tags).length ? ` · ${arr(row.risk_tags).join(", ")}` : ""}`, date: row.last_seen };
    if (section === "javascript") return { ...common, title: row.asset_url, location: row.asset_url, status: row.http_status ?? "unknown", meta: `${row.source || "recon"} · ${row.size_bytes ? `${row.size_bytes} bytes` : "size unknown"}`, summary: row.sha256 ? `SHA-256 ${row.sha256}` : `Observed from ${row.host_url || "unknown host"}`, date: row.last_seen };
    return { ...common, title: row.host_url || `FFUF run ${row.id}`, location: row.host_url, status: row.status, meta: `${show(row.hits_count, 0)} hits · ${row.scan_lane || "workbench"}`, summary: row.error || row.wordlist_path || "Controlled content discovery run", date: row.completed_at || row.started_at };
  }

  function statusValues() {
    return [...new Set(state.rows.map((row) => show(row.status, "unknown")))].sort((a, b) => a.localeCompare(b));
  }

  function populateFilter() {
    const select = $("moduleStateFilter");
    select.innerHTML = `<option value="">All records</option>${statusValues().map((value) => `<option value="${esc(value)}">${esc(value.replaceAll("_", " "))}</option>`).join("")}`;
  }

  function applyFilters() {
    const search = state.search.toLowerCase();
    state.visible = state.rows.filter((row) => {
      const matchesState = !state.filter || show(row.status, "unknown") === state.filter;
      const haystack = `${row.domain} ${row.title} ${row.location} ${row.meta} ${row.summary}`.toLowerCase();
      return matchesState && (!search || haystack.includes(search));
    });
    $("moduleCount").textContent = `${state.visible.length} shown`;
    renderFeed();
  }

  function renderFeed() {
    const feed = $("moduleFeed");
    if (!state.visible.length) {
      feed.innerHTML = `<div class="empty-block">No records match this view.</div>`;
      $("moduleInspector").innerHTML = `<div class="detail-empty"><h2>No matching records</h2><p>Change the scope or filters.</p></div>`;
      return;
    }
    if (!state.selected || !state.visible.some((row) => row.key === state.selected)) state.selected = state.visible[0].key;
    feed.innerHTML = state.visible.map((row) => `<button class="module-row${row.key === state.selected ? " active" : ""}" data-record="${esc(row.key)}">
      <span class="module-row-head"><strong>${esc(row.domain)}</strong><span class="badge ${tone(row.status)}">${esc(show(row.status).replaceAll("_", " "))}</span></span>
      <h3>${esc(show(row.title, "Untitled record"))}</h3>
      <p>${esc(truncate(row.summary || row.location, 165))}</p>
      <span class="module-row-meta"><span>${esc(row.meta)}</span><span>${esc(formatDate(row.date))}</span></span>
    </button>`).join("");
    feed.querySelectorAll("[data-record]").forEach((button) => button.addEventListener("click", () => {
      state.selected = button.dataset.record;
      renderFeed();
    }));
    renderInspector(state.visible.find((row) => row.key === state.selected));
  }

  function field(label, value) {
    return `<div class="inspector-field"><span>${esc(label)}</span><strong>${esc(show(value))}</strong></div>`;
  }

  function ffufRunContext(raw) {
    return `<div class="ffuf-run-facts">
      ${field("Stored hits", show(raw.hits_count, 0))}
      ${field("Lane", raw.scan_lane || "workbench")}
      ${field("Wordlist", raw.wordlist_path || "Unknown")}
    </div>
    <div class="ffuf-intel" id="ffufIntel"><div class="loading-state"><span></span>Loading stored FFUF hits</div></div>`;
  }

  function ffufFiltersFromControls() {
    return {
      status: $("ffufIntelStatus")?.value.trim() || "",
      size_min: $("ffufIntelSizeMin")?.value.trim() || "",
      size_max: $("ffufIntelSizeMax")?.value.trim() || "",
      words_min: $("ffufIntelWordsMin")?.value.trim() || "",
      words_max: $("ffufIntelWordsMax")?.value.trim() || "",
    };
  }

  function renderFfufHitRows(hits) {
    if (!hits.length) return `<div class="empty-block">No stored hits match these filters.</div>`;
    return `<div class="ffuf-hit-table-wrap"><table class="data-table ffuf-hit-table">
      <thead><tr><th class="wide-cell">Result</th><th>Status</th><th>Size</th><th>Words</th><th>Lines</th><th>Redirect</th></tr></thead>
      <tbody>${hits.map((hit) => {
        const target = safeUrl(hit.url);
        const result = target
          ? `<a href="${esc(target)}" target="_blank" rel="noopener noreferrer">${esc(hit.path || hit.url)}</a><small>${esc(hit.url)}</small>`
          : `<strong>${esc(hit.path || hit.url)}</strong>`;
        const redirect = hit.redirect_location || "-";
        return `<tr><td class="wide-cell ffuf-hit-url">${result}</td><td><span class="badge ${tone(hit.status_code)}">${esc(show(hit.status_code))}</span></td><td>${esc(show(hit.content_length, 0))}</td><td>${esc(show(hit.words, 0))}</td><td>${esc(show(hit.lines, 0))}</td><td>${esc(truncate(redirect, 90))}</td></tr>`;
      }).join("")}</tbody>
    </table></div>`;
  }

  async function loadFfufRunDetails(row, requestId, offset = 0, filters = {}) {
    const runId = Number(row.raw.id);
    const limit = 50;
    const container = $("ffufIntel");
    if (!container || !runId) return;
    container.innerHTML = `<div class="loading-state"><span></span>Loading stored FFUF hits</div>`;
    try {
      const data = await fetchJson(`/api/ffuf/workbench/runs/${runId}?${query({ limit, offset, ...filters })}`);
      if (requestId !== state.inspectorRequest || state.selected !== row.key) return;
      const hits = arr(data.hits);
      const matched = Number(data.hits_total) || 0;
      const stored = Number(data.hits_unfiltered_total) || 0;
      const first = matched ? offset + 1 : 0;
      const last = Math.min(offset + hits.length, matched);
      container.innerHTML = `<div class="ffuf-intel-head">
        <div><strong>Stored results</strong><span>${esc(`${first}-${last} of ${matched} matched | ${stored} stored`)}</span></div>
        <a class="button" href="/download/ffuf/workbench/runs/${runId}?${query(filters)}">${icon("download")}Download CSV</a>
      </div>
      <div class="ffuf-hit-filters">
        <input id="ffufIntelStatus" inputmode="numeric" placeholder="Status: 200,401" value="${esc(filters.status || "")}">
        <input id="ffufIntelSizeMin" inputmode="numeric" placeholder="Min size" value="${esc(filters.size_min || "")}">
        <input id="ffufIntelSizeMax" inputmode="numeric" placeholder="Max size" value="${esc(filters.size_max || "")}">
        <input id="ffufIntelWordsMin" inputmode="numeric" placeholder="Min words" value="${esc(filters.words_min || "")}">
        <input id="ffufIntelWordsMax" inputmode="numeric" placeholder="Max words" value="${esc(filters.words_max || "")}">
        <button class="button primary" id="ffufIntelApply">Apply</button>
        <button class="button" id="ffufIntelClear">Clear</button>
      </div>
      ${renderFfufHitRows(hits)}
      <div class="ffuf-hit-pager"><span>${esc(`${first}-${last} of ${matched}`)}</span><div><button class="button" id="ffufIntelPrevious" ${offset <= 0 ? "disabled" : ""}>Previous</button><button class="button" id="ffufIntelNext" ${offset + hits.length >= matched ? "disabled" : ""}>Next</button></div></div>`;
      const apply = () => loadFfufRunDetails(row, requestId, 0, ffufFiltersFromControls());
      $("ffufIntelApply").addEventListener("click", apply);
      $("ffufIntelClear").addEventListener("click", () => loadFfufRunDetails(row, requestId, 0, {}));
      ["ffufIntelStatus", "ffufIntelSizeMin", "ffufIntelSizeMax", "ffufIntelWordsMin", "ffufIntelWordsMax"].forEach((id) => {
        $(id).addEventListener("keydown", (event) => { if (event.key === "Enter") apply(); });
      });
      $("ffufIntelPrevious").addEventListener("click", () => loadFfufRunDetails(row, requestId, Math.max(0, offset - limit), filters));
      $("ffufIntelNext").addEventListener("click", () => loadFfufRunDetails(row, requestId, offset + limit, filters));
    } catch (error) {
      if (requestId !== state.inspectorRequest || state.selected !== row.key) return;
      container.innerHTML = `<div class="empty-block">Could not load stored hits: ${esc(error.message)}</div>`;
    }
  }

  function renderInspector(row) {
    if (!row) return;
    const requestId = ++state.inspectorRequest;
    const raw = row.raw;
    const sourceTypes = {
      overview: "bug_jobs",
      workers: "bug_jobs",
      validation: "validation_queue",
      evidence: "evidence_packs",
      endpoints: "endpoints",
      javascript: "js_assets",
      ffuf: "ffuf_runs",
    };
    const sourceId = raw.id ?? raw.job_id ?? raw.endpoint_id ?? raw.js_asset_id ?? raw.source_id ?? row.key;
    const external = safeUrl(row.location);
    const actions = [
      row.leadId ? `<a class="button primary" href="/research/leads/${encodeURIComponent(row.leadId)}">${icon("target")}Investigate lead</a>` : "",
      external ? `<a class="button" href="${esc(external)}" target="_blank" rel="noopener noreferrer">${icon("external")}Open target</a>` : "",
      section === "ffuf" ? `<a class="button" href="/download/ffuf/workbench/runs/${encodeURIComponent(sourceId)}">${icon("download")}Download CSV</a>` : "",
    ].join("");
    const context = section === "overview"
      ? `<div class="overview-lanes"><div class="overview-lane"><span>Decision</span><strong>${esc(show(row.status).replaceAll("_", " "))}</strong><p>Open the lead workspace to validate or kill this hypothesis.</p></div><div class="overview-lane"><span>Research class</span><strong>${esc(row.meta)}</strong><p>${esc(truncate(row.summary, 260))}</p></div></div>`
      : section === "ffuf"
        ? ffufRunContext(raw)
        : `<pre class="json-preview">${esc(JSON.stringify(raw, null, 2))}</pre>`;
    $("moduleInspector").innerHTML = `<header class="inspector-head">
      <span class="eyebrow">${esc(row.domain)} · ${esc(section)}</span>
      <h2>${esc(show(row.title, "Untitled record"))}</h2>
      <div class="inspector-location">${esc(show(row.location))}</div>
      <div class="badge-row"><span class="badge ${tone(row.status)}">${esc(show(row.status).replaceAll("_", " "))}</span><span class="badge">${esc(row.meta)}</span></div>
      <div class="inspector-actions">${actions}</div>
    </header>
    <div class="inspector-grid">${field("Domain", row.domain)}${field("Last activity", formatDate(row.date))}${field("Record", row.key)}</div>
    <section class="inspector-block"><h3>Why this record matters</h3><p>${esc(show(row.summary, "No analyst summary is available yet."))}</p></section>
    <section class="inspector-block"><h3>${section === "overview" ? "Research direction" : "Stored recon context"}</h3>${context}</section>`;
    if (section === "ffuf") loadFfufRunDetails(row, requestId);
    window.dispatchEvent(new CustomEvent("research:context", { detail: {
      section,
      record_id: row.key,
      source_type: sourceTypes[section] || section,
      source_id: sourceId,
      domain: row.domain,
      title: row.title,
      location: row.location,
      status: row.status,
      category: row.meta,
      summary: truncate(row.summary, 1200),
    } }));
  }

  async function loadDomains() {
    const domains = await fetchJson("/api/domains");
    state.domains = arr(domains);
    $("domainFilter").innerHTML = `<option value="">All domains</option>${state.domains.map((domain) => `<option value="${esc(domain.id)}"${Number(domain.id) === state.domainId ? " selected" : ""}>${esc(domain.domain)}</option>`).join("")}`;
  }

  async function loadSummary(summaryData = null) {
    const data = summaryData || await fetchJson(`/api/research/leads?${query({ domain_id: state.domainId, outcome: "attention", limit: 120 })}`);
    const summary = data.summary || {};
    $("metricAttention").textContent = show(data.total, "0");
    $("metricConfirmed").textContent = show(summary.confirmed, "0");
    $("metricAlerts").textContent = show(summary.review_alerts, "0");
    $("metricWorker").textContent = show(summary.worker_status, "unknown");
    $("metricRunning").textContent = show(summary.running, "0");
    return data;
  }

  async function loadModule() {
    $("moduleFeed").innerHTML = `<div class="loading-state"><span></span>Loading research data</div>`;
    try {
      let data;
      if (section === "overview") {
        data = await loadSummary();
      } else {
        const results = await Promise.all([fetchJson(endpointForSection()), loadSummary()]);
        data = results[0];
      }
      const rows = arr(data.rows || data.items || data.results);
      state.rows = rows.map(normalized);
      state.selected = null;
      populateFilter();
      applyFilters();
    } catch (error) {
      $("moduleFeed").innerHTML = `<div class="empty-block">${esc(error.message)}</div>`;
      notify(`Could not load ${section}: ${error.message}`, true);
    }
  }

  function bind() {
    $("domainFilter").addEventListener("change", (event) => {
      const params = new URLSearchParams(location.search);
      const value = Number(event.target.value) || null;
      if (value) params.set("domain_id", value); else params.delete("domain_id");
      location.assign(`${location.pathname}${params.size ? `?${params}` : ""}`);
    });
    $("refreshButton").addEventListener("click", loadModule);
    $("moduleSearch").addEventListener("input", (event) => { state.search = event.target.value.trim(); applyFilters(); });
    $("moduleStateFilter").addEventListener("change", (event) => { state.filter = event.target.value; applyFilters(); });
    $("mobileMenu").addEventListener("click", () => $("globalNav").classList.toggle("open"));
    $("navClose").addEventListener("click", () => $("globalNav").classList.remove("open"));
  }

  (async () => {
    bind();
    try { await loadDomains(); await loadModule(); }
    catch (error) { notify(error.message, true); }
  })();
})();
