(() => {
  "use strict";

  const initial = window.RESEARCH_PANEL || window.RECON_DASHBOARD_ASSISTANT || {};
  const $ = (id) => document.getElementById(id);
  const state = {
    domainId: Number(initial.initialDomainId) || null,
    section: initial.initialSection || "overview",
    selectedContext: {},
    threadId: null,
    busy: false,
    pollTimer: null,
  };

  const esc = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  const arr = (value) => Array.isArray(value) ? value : [];
  const safeUrl = (value) => {
    try {
      const url = new URL(value, location.origin);
      return ["http:", "https:"].includes(url.protocol) ? url.href : null;
    } catch (_) { return null; }
  };
  const threadKey = () => `recon-ai-thread:${state.domainId || "all"}:${state.section}`;
  const makeThreadId = () => crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-0000-4000-8000-${Math.random().toString(16).slice(2, 14)}`;

  async function fetchJson(url, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: { Accept: "application/json", ...(options.headers || {}) },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `${response.status} ${response.statusText}`);
      return payload;
    } finally { clearTimeout(timer); }
  }

  function ensureThread() {
    let value = localStorage.getItem(threadKey());
    if (!value) {
      value = makeThreadId();
      localStorage.setItem(threadKey(), value);
    }
    state.threadId = value;
  }

  function setDrawer(open) {
    $("aiAssistantDrawer").classList.toggle("open", open);
    $("aiAssistantDrawer").setAttribute("aria-hidden", open ? "false" : "true");
    $("aiAssistantBackdrop").hidden = !open;
    $("aiAssistantToggle").classList.toggle("drawer-open", open);
    if (open) setTimeout(() => $("aiAssistantInput").focus(), 120);
  }

  function setHistoryOpen(open) {
    $("aiHistoryPanel").hidden = !open;
    $("aiMessages").hidden = open;
    if (open) loadConversations();
  }

  function setBusy(busy) {
    state.busy = busy;
    $("aiAssistantSubmit").disabled = busy;
    $("aiSearchForm").querySelector("button").disabled = busy;
  }

  function referenceMarkup(ref) {
    const label = ref.label || `${ref.source_type || "record"} ${ref.source_id ?? ""}`;
    const url = safeUrl(ref.url);
    if (url) return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
    return `<span>${esc(label)}</span>`;
  }

  function answerMarkup(answer) {
    if (!answer || typeof answer !== "object") return "";
    const refs = arr(answer.source_refs);
    const actions = arr(answer.next_actions);
    const limitations = arr(answer.limitations);
    const suggestions = arr(answer.suggested_questions);
    return `<div class="ai-answer-text">${esc(answer.answer || "No answer returned.")}</div>
      ${refs.length ? `<div class="ai-answer-group"><strong>Sources</strong><div class="ai-ref-list">${refs.map(referenceMarkup).join("")}</div></div>` : ""}
      ${actions.length ? `<div class="ai-answer-group"><strong>Next actions</strong><ul>${actions.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div>` : ""}
      ${limitations.length ? `<div class="ai-answer-group muted"><strong>Limits</strong><ul>${limitations.map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div>` : ""}
      ${suggestions.length ? `<div class="ai-suggestions">${suggestions.map((item) => `<button type="button" data-ai-suggestion="${esc(item)}">${esc(item)}</button>`).join("")}</div>` : ""}`;
  }

  function renderRows(rows) {
    const messages = $("aiMessages");
    if (!rows.length) {
      messages.innerHTML = `<div class="ai-empty"><svg><use href="#i-bot"></use></svg><strong>Ask about this view</strong></div>`;
      return;
    }
    messages.innerHTML = rows.map((row) => `<div class="ai-exchange">
      <div class="ai-message user"><span>You</span><p>${esc(row.question)}</p></div>
      <div class="ai-message assistant ${esc(row.status)}"><span>Codex · ${esc(row.status)}</span>
        ${row.status === "done" ? answerMarkup(row.answer) : row.status === "failed" ? `<p>${esc(row.error || "Assistant request failed.")}</p>` : `<div class="ai-wait"><i></i>${row.status === "running" ? "Analyzing dashboard context" : "Queued for analysis"}</div>`}
      </div>
    </div>`).join("");
    messages.querySelectorAll("[data-ai-suggestion]").forEach((button) => button.addEventListener("click", () => {
      $("aiAssistantInput").value = button.dataset.aiSuggestion;
      $("aiAssistantInput").focus();
    }));
    messages.scrollTop = messages.scrollHeight;
  }

  async function loadHistory() {
    ensureThread();
    const data = await fetchJson(`/api/ai-assistant/history?thread_id=${encodeURIComponent(state.threadId)}&limit=30`);
    const rows = arr(data.rows);
    renderRows(rows);
    const pending = [...rows].reverse().find((row) => ["queued", "running"].includes(row.status));
    if (pending) pollQuery(pending.id);
  }

  async function loadConversations() {
    const params = new URLSearchParams({ limit: "50" });
    if (state.domainId) params.set("domain_id", state.domainId);
    try {
      const data = await fetchJson(`/api/ai-assistant/conversations?${params}`);
      const rows = arr(data.rows);
      $("aiHistoryList").innerHTML = rows.length ? rows.map((row) => `<div class="ai-history-item">
        <button type="button" class="ai-history-open" data-ai-thread="${esc(row.thread_id)}">
          <strong>${esc(row.latest_question || "Untitled conversation")}</strong>
          <span>${esc(row.domain || "All domains")} · ${esc(row.section || "overview")} · ${esc(row.message_count || 0)} messages</span>
        </button>
        <button type="button" class="ai-history-delete" data-ai-delete-thread="${esc(row.thread_id)}" title="Delete conversation" aria-label="Delete conversation">×</button>
      </div>`).join("") : `<div class="ai-empty"><strong>No saved conversations</strong></div>`;
      $("aiHistoryList").querySelectorAll("[data-ai-thread]").forEach((button) => button.addEventListener("click", async () => {
        state.threadId = button.dataset.aiThread;
        localStorage.setItem(threadKey(), state.threadId);
        setHistoryOpen(false);
        await loadHistory();
      }));
      $("aiHistoryList").querySelectorAll("[data-ai-delete-thread]").forEach((button) => button.addEventListener("click", async () => {
        if (!confirm("Delete this AI conversation?")) return;
        await deleteThread(button.dataset.aiDeleteThread);
        if (button.dataset.aiDeleteThread === state.threadId) startNewThread();
        await loadConversations();
      }));
    } catch (error) {
      $("aiHistoryList").innerHTML = `<div class="ai-empty"><strong>${esc(error.message)}</strong></div>`;
    }
  }

  async function deleteThread(threadId) {
    return fetchJson(`/api/ai-assistant/threads/${encodeURIComponent(threadId)}`, { method: "DELETE" });
  }

  function startNewThread() {
    clearTimeout(state.pollTimer);
    state.threadId = makeThreadId();
    localStorage.setItem(threadKey(), state.threadId);
    setBusy(false);
    setHistoryOpen(false);
    renderRows([]);
  }

  async function pollQuery(queryId) {
    clearTimeout(state.pollTimer);
    try {
      const row = await fetchJson(`/api/ai-assistant/questions/${encodeURIComponent(queryId)}`);
      if (["queued", "running"].includes(row.status)) {
        state.pollTimer = setTimeout(() => pollQuery(queryId), 2200);
        return;
      }
      setBusy(false);
      await loadHistory();
      await loadStatus();
      const badge = $("aiAssistantBadge");
      if (!$("aiAssistantDrawer").classList.contains("open")) badge.hidden = false;
    } catch (error) {
      setBusy(false);
      $("aiWorkerStatus").textContent = error.message;
      $("aiWorkerDot").classList.add("error");
    }
  }

  async function ask(question, mode) {
    const clean = String(question || "").trim();
    if (clean.length < 3 || state.busy) return;
    ensureThread();
    setDrawer(true);
    setBusy(true);
    $("aiAssistantInput").value = "";
    const params = state.domainId ? `?domain_id=${encodeURIComponent(state.domainId)}` : "";
    try {
      const row = await fetchJson(`/api/ai-assistant/questions${params}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: clean,
          mode,
          section: state.section,
          thread_id: state.threadId,
          selected_context: state.selectedContext,
        }),
      });
      await loadHistory();
      pollQuery(row.id);
    } catch (error) {
      setBusy(false);
      $("aiWorkerStatus").textContent = error.message;
      $("aiWorkerDot").classList.add("error");
    }
  }

  async function loadStatus() {
    try {
      const data = await fetchJson("/api/ai-assistant/status");
      const workerState = data.worker?.status || (data.enabled ? "starting" : "disabled");
      $("aiWorkerStatus").textContent = `${workerState} · ${data.queued || 0} queued`;
      $("aiModelName").textContent = data.model || "Codex";
      $("aiWorkerDot").classList.toggle("error", !["idle", "running", "starting"].includes(workerState));
    } catch (error) {
      $("aiWorkerStatus").textContent = "Worker status unavailable";
      $("aiWorkerDot").classList.add("error");
    }
  }

  function bind() {
    $("aiAssistantToggle").addEventListener("click", () => {
      $("aiAssistantBadge").hidden = true;
      setDrawer(true);
    });
    $("aiAssistantClose").addEventListener("click", () => setDrawer(false));
    $("aiAssistantBackdrop").addEventListener("click", () => setDrawer(false));
    $("aiNewThread").addEventListener("click", startNewThread);
    $("aiHistoryToggle").addEventListener("click", () => setHistoryOpen($("aiHistoryPanel").hidden));
    $("aiClearThread").addEventListener("click", async () => {
      if (!confirm("Clear the current AI conversation?")) return;
      try {
        await deleteThread(state.threadId);
        startNewThread();
      } catch (error) {
        $("aiWorkerStatus").textContent = error.message;
      }
    });
    $("aiClearHistory").addEventListener("click", async () => {
      const scope = state.domainId ? "this root domain" : "all domains";
      if (!confirm(`Clear completed AI conversations for ${scope}?`)) return;
      const params = state.domainId ? `?domain_id=${encodeURIComponent(state.domainId)}` : "";
      try {
        await fetchJson(`/api/ai-assistant/history${params}`, { method: "DELETE" });
        startNewThread();
        setHistoryOpen(true);
      } catch (error) {
        $("aiWorkerStatus").textContent = error.message;
      }
    });
    $("aiSearchForm").addEventListener("submit", (event) => {
      event.preventDefault();
      const input = $("aiSearchInput");
      const value = input.value;
      input.value = "";
      ask(value, "global_search");
    });
    $("aiAssistantForm").addEventListener("submit", (event) => {
      event.preventDefault();
      ask($("aiAssistantInput").value, "tab_assistant");
    });
    $("aiAssistantInput").addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        $("aiAssistantForm").requestSubmit();
      }
    });
    const updateSelectedContext = (event) => {
      state.selectedContext = event.detail && typeof event.detail === "object" ? event.detail : {};
      const label = state.selectedContext.title || state.selectedContext.location || state.section;
      $("aiAssistantScope").textContent = String(label).slice(0, 120);
      $("aiSelectedNote").textContent = Object.keys(state.selectedContext).length
        ? `Selected record · ${String(label).slice(0, 140)}`
        : "No record selected · searching this domain and all recon categories";
    };
    window.addEventListener("research:context", updateSelectedContext);
    window.addEventListener("recon:context", updateSelectedContext);
    window.addEventListener("keydown", (event) => {
      if (event.key === "Escape") setDrawer(false);
    });
  }

  window.ReconAI = {
    open: () => setDrawer(true),
    ask: (question, mode = "tab_assistant") => ask(question, mode),
    setContext: (context) => window.dispatchEvent(new CustomEvent("recon:context", { detail: context || {} })),
    setSection: async (value) => {
      state.section = String(value || "overview");
      state.selectedContext = {};
      $("aiAssistantScope").textContent = state.section;
      $("aiSelectedNote").textContent = "No record selected · searching this domain and all recon categories";
      ensureThread();
      await loadHistory();
    },
  };

  (async () => {
    bind();
    ensureThread();
    await Promise.allSettled([loadHistory(), loadStatus()]);
    setInterval(loadStatus, 30000);
  })();
})();
