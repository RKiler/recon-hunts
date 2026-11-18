(() => {
  "use strict";

  const config = window.HUNT_PANEL || {};
  const $ = (id) => document.getElementById(id);
  const state = { selectedRun: null, detail: null, loading: false, accounts: [], deltaScans: [] };

  function selectedAccountIds(containerId) {
    return Array.from($(containerId).querySelectorAll("input[type=checkbox]:checked")).map((item) => Number(item.value));
  }

  function renderAccountChoices(containerId, selected = []) {
    const container = $(containerId);
    container.replaceChildren();
    if (!state.accounts.length) {
      container.append(node("span", "No owned accounts configured.", "empty-inline"));
      return;
    }
    for (const account of state.accounts) {
      const label = node("label", null, "account-option");
      const check = document.createElement("input");
      check.type = "checkbox";
      check.value = account.id;
      check.checked = selected.includes(account.id);
      label.append(check, node("span", `${account.alias} · ${account.role || account.credential_type} · ${account.host}`));
      if (containerId === "accountChoices") {
        const remove = node("button", "Remove", "remove-account");
        remove.type = "button";
        remove.title = `Remove ${account.alias} and its stored credential`;
        remove.addEventListener("click", async (event) => {
          event.preventDefault();
          if (!window.confirm(`Remove ${account.alias}? This also removes its stored credential from active hunts.`)) return;
          try {
            await request(`/api/hunt-credentials/${account.id}`, { method: "DELETE" });
            await loadAccounts();
            if (state.selectedRun) await selectRun(state.selectedRun, true);
            notify(`Removed ${account.alias}.`);
          } catch (error) { notify(error.message, true); }
        });
        label.append(remove);
      }
      container.append(label);
    }
  }

  async function loadAccounts() {
    const domainId = $("domainSelect").value;
    const selected = selectedAccountIds("accountChoices");
    state.accounts = domainId ? await request(`/api/hunt-credentials?domain_id=${encodeURIComponent(domainId)}`) : [];
    renderAccountChoices("accountChoices", selected);
    if (state.detail) renderAccountChoices("runAccountChoices", state.detail.credentials.map((item) => item.id));
  }

  function notify(message, error = false) {
    const node = $("notice");
    node.textContent = message;
    node.classList.toggle("error", error);
  }

  function date(value) {
    if (!value) return "-";
    const parsed = new Date(value.endsWith("Z") ? value : value + "Z");
    return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
  }

  function node(tag, content, className) {
    const element = document.createElement(tag);
    if (content != null) element.textContent = String(content);
    if (className) element.className = className;
    return element;
  }

  function selectedScanIds(containerId) {
    return Array.from($(containerId).querySelectorAll("input[type=checkbox]:checked"))
      .map((item) => Number(item.value));
  }

  function renderScanChoices(containerId, selected = []) {
    const container = $(containerId);
    container.replaceChildren();
    if (!state.deltaScans.length) {
      container.append(node("span", "No completed delta scans are available for this domain.", "empty"));
      return;
    }
    for (const scan of state.deltaScans) {
      const label = node("label", null, "scan-option");
      const check = document.createElement("input");
      check.type = "checkbox";
      check.value = scan.id;
      check.checked = selected.includes(scan.id);
      const counts = scan.new_counts || {};
      const summary = [
        `${Number(counts.new_urls || 0).toLocaleString()} URLs`,
        `${Number(counts.new_js_assets || 0).toLocaleString()} new JS`,
        `${Number(counts.changed_js_assets || 0).toLocaleString()} changed JS`,
      ].join(" · ");
      label.append(check, node("span", `#${scan.id} · ${date(scan.scan_finished_at)} · ${scan.scan_lane}`), node("small", summary));
      container.append(label);
    }
  }

  async function loadDeltaScans() {
    const domainId = $("domainSelect").value;
    state.deltaScans = [];
    renderScanChoices("deltaScans");
    renderScanChoices("runDeltaScans");
    if (!domainId) return;
    const scans = await request(`/api/hunts/delta-scans?domain_id=${encodeURIComponent(domainId)}`);
    if ($("domainSelect").value !== domainId) return;
    state.deltaScans = scans;
    renderScanChoices("deltaScans");
    if (state.detail) renderScanChoices("runDeltaScans", state.detail.run.delta_scan_ids || []);
  }

  function updateSourceMode() {
    const delta = $("dataSource").value === "delta";
    $("deltaScanPanel").hidden = !delta;
    const continuous = document.querySelector('input[name=mode][value="continuous"]');
    continuous.disabled = delta;
    if (delta && continuous.checked) document.querySelector('input[name=mode][value="one_time"]').checked = true;
  }

  function updateCredentialType() {
    const kind = $("accountType").value;
    const loginFile = kind === "login_file";
    $("headerField").hidden = kind !== "header";
    $("secretField").hidden = loginFile;
    $("credentialPathField").hidden = !loginFile;
    $("accountSecret").required = !loginFile;
    $("accountCredentialPath").required = loginFile;
  }

  function chip(value) {
    const normalized = String(value || "no_recon_signal");
    const labels = {
      no_recon_signal: "Unassessed",
      unverified_signal: "Unverified signal",
      needs_accounts: "Needs owned accounts",
      reviewed_sample: "Sample reviewed",
      curation_pending: "Curating",
      STRONG_CANDIDATE: "Strong lead",
      NEEDS_MANUAL_REVIEW: "Manual review",
      CONFIRMED_UNIQUE: "Confirmed",
      needs_reconciliation: "Needs reconciliation",
      uncertain: "Uncertain · reconcile",
      blocked_missing_fixture: "Missing fixture",
      blocked_human_login: "Human login blocked",
      inventory_exhausted: "Inventory exhausted",
      inventory_in_progress: "Inventory in progress",
      reconciliation_required: "Reconciliation required",
      confirmed_pending_report_review: "Confirmed; report review",
      validation_ready: "Validation ready",
      campaign_blocked: "Campaign blocked",
      no_open_hypotheses: "No open hypotheses",
      no_durable_hypotheses: "No durable hypotheses",
    };
    const display = labels[normalized] || normalized.replaceAll("_", " ");
    const tone = normalized === "CONFIRMED_UNIQUE" || normalized === "confirmed" ? "confirmed"
      : ["lead", "running", "STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW", "candidate", "supported", "needs_reconciliation"].includes(normalized) ? "lead"
      : ["blocked", "failed", "uncertain", "needs_accounts", "blocked_missing_fixture", "blocked_human_login"].includes(normalized) ? "blocked" : "";
    return node("span", display, `chip ${tone}`);
  }

  async function request(url, options) {
    const response = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      ...options,
      headers: { "Content-Type": "application/json", "X-CSRF-Token": config.csrf, ...(options && options.headers) },
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    return payload;
  }

  function renderRuns(runs) {
    const list = $("runList");
    list.replaceChildren();
    if (!runs.length) {
      list.append(node("p", "No hunts for this domain yet.", "empty"));
      return;
    }
    for (const run of runs) {
      const button = node("button", null, `run-item ${state.selectedRun === run.id ? "active" : ""}`);
      button.type = "button";
      button.append(node("strong", run.domain));
      button.append(node("span", `${run.mode === "continuous" ? "Continuous" : "One-time"} · ${run.data_source === "delta" ? `${run.delta_scan_count} delta scans` : "all data"} · ${(run.inventory_state || run.status).replaceAll("_", " ")} · ${(run.research_state || "unassessed").replaceAll("_", " ")} · ${run.pass_count} passes`));
      button.append(node("span", date(run.created_at)));
      button.addEventListener("click", () => selectRun(run.id));
      list.append(button);
    }
  }

  function renderCoverage(coverage, cursor) {
    const body = $("coverageTable").tBodies[0];
    body.replaceChildren();
    const scanned = coverage.scanned || {};
    const tables = Object.keys(scanned).sort();
    if (!tables.length) {
      const row = document.createElement("tr");
      const cell = node("td", "Coverage begins when the first pass runs.", "empty");
      cell.colSpan = 4;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const table of tables) {
      const complete = Number(cursor.next_lt?.[table] || 0) <= Number(cursor.floors?.[table] || 0) + 1;
      const row = document.createElement("tr");
      row.append(node("td", table.replaceAll("_", " ")));
      row.append(node("td", Number(scanned[table] || 0).toLocaleString()));
      row.append(node("td", coverage.cycle || 1));
      const stateCell = document.createElement("td");
      stateCell.append(chip(complete ? "reviewed_sample" : "running"));
      row.append(stateCell);
      body.append(row);
    }
  }

  function renderJobs(passes) {
    const body = $("jobsTable").tBodies[0];
    const filter = $("jobFilter").value;
    body.replaceChildren();
    const selected = passes.filter((pass) => {
      if (filter === "attention") return Boolean(pass.result?.leads?.length || pass.result?.confirmed_findings?.length);
      if (filter === "active") return ["queued", "running"].includes(pass.status);
      if (filter === "done") return pass.status === "done";
      return true;
    });
    if (!selected.length) {
      const row = document.createElement("tr");
      const cell = node("td", "No passes in this view.", "empty");
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const pass of selected) {
      const row = document.createElement("tr");
      row.append(node("td", `#${pass.sequence}${pass.action_id ? " · validation" : ""}`));
      const status = document.createElement("td");
      status.append(chip(pass.status));
      row.append(status);
      row.append(node("td", Object.values(pass.processed_counts || {}).reduce((a, b) => a + Number(b || 0), 0).toLocaleString()));
      row.append(node("td", pass.result?.leads?.length || 0));
      row.append(node("td", pass.result?.confirmed_findings?.length || 0));
      const detail = node("td", pass.error || pass.result?.summary || (pass.status === "running" ? "Investigating current packet" : "Waiting"));
      detail.append(node("span", date(pass.finished_at || pass.started_at || pass.created_at), "hypothesis"));
      row.append(detail);
      body.append(row);
    }
  }

  function renderSignals(hypotheses) {
    const body = $("signalsTable").tBodies[0];
    body.replaceChildren();
    if (!hypotheses.length) {
      const row = document.createElement("tr");
      const cell = node("td", "No durable hypotheses have been recorded yet.", "empty");
      cell.colSpan = 4;
      row.append(cell);
      body.append(row);
      return;
    }
    for (const item of hypotheses.slice(0, 100)) {
      const row = document.createElement("tr");
      const evidence = node("td", item.evidence_level || "E0");
      evidence.append(node("span", `${item.occurrence_count || 0} observation${item.occurrence_count === 1 ? "" : "s"}`, "hypothesis"));
      row.append(evidence);
      const stateCell = document.createElement("td");
      stateCell.append(chip(item.state));
      row.append(stateCell);
      const asset = node("td", item.title || item.bug_family || "Untitled hypothesis", "asset");
      asset.append(node("span", item.affected_asset || "", "hypothesis"));
      row.append(asset);
      const action = node("td", item.next_action || "No decisive next action recorded");
      if (item.missing_proof) action.append(node("span", `Missing proof: ${item.missing_proof}`, "hypothesis"));
      else if (item.evidence_paths?.length) action.append(node("span", item.evidence_paths[0], "hypothesis"));
      row.append(action);
      body.append(row);
    }
  }

  function renderOwaspCoverage(categories = []) {
    const container = $("owaspCoverage");
    container.replaceChildren();
    for (const category of categories) {
      const card = node("div", null, `owasp-card ${category.hypothesis_count ? "has-signal" : ""}`);
      card.append(node("strong", category.code));
      card.append(node("span", category.title));
      card.append(node("small", category.hypothesis_count
        ? `${category.hypothesis_count} mapped hypothesis${category.hypothesis_count === 1 ? "" : "es"}`
        : "No mapped signal · unassessed"));
      container.append(card);
    }
  }

  function renderActions(actions = [], hypotheses = []) {
    const body = $("actionsTable").tBodies[0];
    body.replaceChildren();
    if (!actions.length) {
      const row = document.createElement("tr");
      const cell = node("td", "No validation actions recorded. The research ledger may still need evidence or an owned-account fixture.", "empty");
      cell.colSpan = 4;
      row.append(cell);
      body.append(row);
      return;
    }
    const byId = new Map(hypotheses.map((item) => [Number(item.id), item]));
    for (const action of actions) {
      const row = document.createElement("tr");
      const stateCell = document.createElement("td");
      stateCell.append(chip(action.state));
      row.append(stateCell);
      const purpose = node("td", null);
      const hypothesis = byId.get(Number(action.hypothesis_id));
      purpose.append(node("strong", hypothesis?.title || `Action ${action.id}`, "asset"));
      purpose.append(node("span", action.purpose || "No action purpose recorded", "hypothesis"));
      row.append(purpose);
      const controls = node("td", null);
      controls.append(node("span", `Baseline: ${action.baseline_ref || "missing"}`, "hypothesis"));
      controls.append(node("span", `Negative control: ${action.negative_control_ref || "missing"}`, "hypothesis"));
      if (action.mutation_dimension) controls.append(node("span", `Change one dimension: ${action.mutation_dimension}`, "hypothesis"));
      controls.append(node("span", `Stop: ${action.stop_conditions || "not recorded"}`, "hypothesis"));
      row.append(controls);
      const cleanup = node("td", null);
      cleanup.append(node("span", `Cleanup: ${action.cleanup_plan || "not recorded"}`, "hypothesis"));
      const result = action.result || {};
      if (result.summary || result.reason) cleanup.append(node("span", `Result: ${result.summary || result.reason}`, "hypothesis"));
      if (action.state === "uncertain") {
        const controls = node("div", null, "reconcile-actions");
        for (const [disposition, label] of [["resolved", "Mark reconciled"], ["retry", "Authorize retry"]]) {
          const button = node("button", label, "quiet");
          button.type = "button";
          button.addEventListener("click", async () => {
            const promptText = disposition === "retry"
              ? "Review whether the interrupted request caused a side effect and complete any needed cleanup. Explain that review. This explicitly authorizes rerunning this target action."
              : "Explain how you reconciled the interrupted request and verified its side effects or cleanup.";
            const note = window.prompt(promptText);
            if (!note) return;
            if (disposition === "retry" && !window.confirm("Retry this exact target action after your reconciliation review?")) return;
            button.disabled = true;
            try {
              const detail = await request(`/api/hunts/${state.selectedRun}/actions/${action.id}/reconcile`, {
                method: "POST", body: JSON.stringify({ disposition, note }),
              });
              renderDetail(detail);
              await loadRuns(true);
              notify(disposition === "retry" ? "Action retry authorized and queued." : "Action marked reconciled; campaign remains paused.");
            } catch (error) { notify(error.message, true); button.disabled = false; }
          });
          controls.append(button);
        }
        cleanup.append(controls);
      }
      row.append(cleanup);
      body.append(row);
    }
  }

  function renderReportDrafts(drafts = []) {
    const container = $("reportDrafts");
    container.replaceChildren();
    if (!drafts.length) {
      container.append(node("p", "No report-ready finding has passed the E3 evidence gate yet.", "empty"));
      return;
    }
    for (const report of drafts) {
      const details = document.createElement("details");
      details.className = "report-draft";
      const summary = document.createElement("summary");
      summary.append(node("strong", report.title), node("span", `${report.bug_family} · ${report.affected_asset}`));
      details.append(summary);
      const copy = node("button", "Copy draft", "quiet");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(report.draft);
          notify("Report draft copied. Review redactions and severity before submission.");
        } catch (_) { notify("Clipboard access unavailable; select and copy the draft text.", true); }
      });
      details.append(copy, node("pre", report.draft));
      container.append(details);
    }
  }

  function renderHumanLogins(credentials, runId) {
    const accounts = credentials.filter((item) => item.credential_type === "login_file");
    const panel = $("humanLoginPanel");
    panel.hidden = !accounts.length;
    const list = $("humanLoginAccounts");
    list.replaceChildren();
    for (const account of accounts) {
      const row = node("div", null, "human-login-row");
      const identity = node("span", `${account.alias} · ${account.host}`);
      const status = account.login_status || "waiting_to_start";
      const labels = {
        manual_login_pending: "Needs your login",
        ready_for_identity_verification: "Session saved; identity check pending",
        blocked_host: "Login host blocked by scope",
        waiting_to_start: "Waiting for hunt worker",
      };
      row.append(identity, node("span", labels[status] || status, "human-login-status"));
      if (status === "manual_login_pending") {
        const button = node("button", "Login complete");
        button.type = "button";
        button.title = `Save the current isolated VNC session for ${account.alias}`;
        button.addEventListener("click", async () => {
          button.disabled = true;
          try {
            await request(`/api/hunts/${runId}/login/${account.id}/complete`, { method: "POST", body: "{}" });
            notify(`Capturing ${account.alias}'s browser session. Identity will be checked before testing.`);
            await selectRun(runId, true);
          } catch (error) {
            notify(error.message, true);
            button.disabled = false;
          }
        });
        row.append(button);
      }
      list.append(row);
    }
  }

  function renderDetail(detail) {
    state.detail = detail;
    const run = detail.run;
    $("runMode").textContent = run.mode === "continuous" ? "INDEPENDENT CONTINUOUS HUNT" : "INDEPENDENT ONE-TIME HUNT";
    $("runTitle").textContent = run.domain;
    $("toggleStatus").disabled = false;
    $("toggleStatus").textContent = run.status === "active" ? "Pause hunt" : "Resume hunt";
    const hasOpenAction = (detail.actions || []).some((item) => ["proposed", "ready"].includes(item.state));
    $("refreshCandidates").disabled = run.status !== "active" || Boolean(run.completed_at && run.mode === "one_time" && !(run.autonomous_validation_enabled && hasOpenAction));
    $("runApplicationContext").value = run.application_context || "";
    $("runDataScope").value = run.data_scope || "all";
    $("runDataSource").value = run.data_source || "all";
    $("runAutonomousValidation").checked = Boolean(run.autonomous_validation_enabled);
    $("runTargetSignup").checked = Boolean(run.target_signup_enabled);
    $("runTargetSignup").disabled = !run.autonomous_validation_enabled;
    $("runDataSource").querySelector('option[value="delta"]').disabled = run.mode === "continuous";
    $("runDeltaScanPanel").hidden = run.data_source !== "delta";
    renderScanChoices("runDeltaScans", run.delta_scan_ids || []);
    renderAccountChoices("runAccountChoices", detail.credentials.map((item) => item.id));
    const meta = $("runMetadata");
    meta.textContent = `Run #${run.id} · ${(detail.completion?.inventory_state || run.status).replaceAll("_", " ")} · ${(detail.completion?.research_state || "unassessed").replaceAll("_", " ")} · validation ${run.autonomous_validation_enabled ? "on" : "off"} · signup ${run.target_signup_enabled ? "on" : "off"} · ${run.worker_model || "CLI default"}/${run.worker_reasoning_effort || "default"} · ${run.data_source === "delta" ? `${run.delta_scan_ids.length} selected delta scans` : "all stored data"} · ${run.data_scope === "context" ? "context focus" : "all signals"} · ${Number(run.records_per_pass).toLocaleString()} records/pass · last queued ${date(run.last_refresh_at)}`;
    if (run.last_error) {
      meta.textContent += ` · refresh error: ${run.last_error}`;
      meta.classList.add("error");
    } else meta.classList.remove("error");
    renderHumanLogins(detail.credentials, run.id);
    const metrics = [detail.summary.passes, detail.summary.running, detail.summary.leads, detail.summary.confirmed, Number(detail.summary.records_examined || 0).toLocaleString()];
    Array.from($("summary").children).forEach((item, index) => { item.querySelector("strong").textContent = metrics[index]; });
    renderCoverage(detail.coverage, run.cursor || {});
    $("jobListCount").textContent = detail.passes.length >= 100 ? "Latest 100 · " : "";
    renderJobs(detail.passes);
    renderSignals(detail.hypotheses || []);
    renderOwaspCoverage(detail.owasp_coverage || []);
    renderReportDrafts(detail.report_drafts || []);
    renderActions(detail.actions || [], detail.hypotheses || []);
  }

  async function selectRun(id, quiet = false) {
    state.selectedRun = id;
    try {
      renderDetail(await request(`/api/hunts/${id}`));
      if (!quiet) await loadRuns(true);
    } catch (error) {
      notify(error.message, true);
    }
  }

  async function loadRuns(quiet = false) {
    const domainId = $("domainSelect").value;
    const query = domainId ? `?domain_id=${encodeURIComponent(domainId)}` : "";
    try {
      const runs = await request(`/api/hunts${query}`);
      renderRuns(runs);
      if (!quiet && !state.selectedRun && runs.length) await selectRun(runs[0].id, true);
    } catch (error) {
      notify(error.message, true);
    }
  }

  $("huntForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("startButton");
    button.disabled = true;
    notify("Starting hunt...");
    try {
      const detail = await request("/api/hunts", {
        method: "POST",
        body: JSON.stringify({
          domain_id: Number($("domainSelect").value),
          mode: document.querySelector("input[name=mode]:checked").value,
          records_per_pass: Number($("recordsPerPass").value),
          data_source: $("dataSource").value,
          delta_scan_ids: selectedScanIds("deltaScans"),
          data_scope: $("dataScope").value,
          application_context: $("applicationContext").value,
          credential_ids: selectedAccountIds("accountChoices"),
          autonomous_validation_enabled: $("autonomousValidation").checked,
          target_signup_enabled: $("targetSignup").checked,
          scope_confirmed: $("scopeConfirmed").checked,
        }),
      });
      state.selectedRun = detail.run.id;
      renderDetail(detail);
      await loadRuns(true);
      notify(`Run #${detail.run.id} started. Its first independent pass is queued.`);
    } catch (error) {
      notify(error.message, true);
    } finally {
      button.disabled = false;
    }
  });

  $("domainSelect").addEventListener("change", () => {
    state.selectedRun = null;
    state.detail = null;
    loadDeltaScans().catch((error) => notify(error.message, true));
    $("accountHost").value = $("domainSelect").selectedOptions[0]?.textContent || "";
    loadAccounts().catch((error) => notify(error.message, true));
    loadRuns();
  });
  $("accountType").addEventListener("change", updateCredentialType);
  $("autonomousValidation").addEventListener("change", () => {
    if (!$("autonomousValidation").checked) $("targetSignup").checked = false;
    $("targetSignup").disabled = !$("autonomousValidation").checked;
  });
  $("runAutonomousValidation").addEventListener("change", () => {
    if (!$("runAutonomousValidation").checked) $("runTargetSignup").checked = false;
    $("runTargetSignup").disabled = !$("runAutonomousValidation").checked;
  });
  $("dataSource").addEventListener("change", updateSourceMode);
  $("runDataSource").addEventListener("change", () => {
    $("runDeltaScanPanel").hidden = $("runDataSource").value !== "delta";
  });
  $("latestTwoScans").addEventListener("click", () => renderScanChoices("deltaScans", state.deltaScans.slice(0, 2).map((scan) => scan.id)));
  $("clearScans").addEventListener("click", () => renderScanChoices("deltaScans"));
  $("credentialForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const account = await request("/api/hunt-credentials", {
        method: "POST",
        body: JSON.stringify({
          domain_id: Number($("domainSelect").value),
          alias: $("accountAlias").value,
          host: $("accountHost").value,
          role: $("accountRole").value,
          tenant: $("accountTenant").value,
          credential_type: $("accountType").value,
          header_name: $("accountHeader").value,
          secret: $("accountSecret").value,
          credential_path: $("accountCredentialPath").value,
          authorized: $("accountAuthorized").checked,
        }),
      });
      $("accountSecret").value = "";
      $("accountCredentialPath").value = "";
      $("accountAuthorized").checked = false;
      await loadAccounts();
      const check = $("accountChoices").querySelector(`input[value="${account.id}"]`);
      if (check) check.checked = true;
      notify(`Added ${account.alias} for ${account.host}.`);
    } catch (error) { notify(error.message, true); }
  });
  $("saveRunContext").addEventListener("click", async () => {
    if (!state.selectedRun) return;
    try {
      const detail = await request(`/api/hunts/${state.selectedRun}`, {
        method: "PATCH",
        body: JSON.stringify({ application_context: $("runApplicationContext").value,
          data_scope: $("runDataScope").value, data_source: $("runDataSource").value,
          delta_scan_ids: selectedScanIds("runDeltaScans"), credential_ids: selectedAccountIds("runAccountChoices"),
          autonomous_validation_enabled: $("runAutonomousValidation").checked,
          target_signup_enabled: $("runTargetSignup").checked }),
      });
      renderDetail(detail);
      notify("Hunt settings saved. Recon coverage restarts only when its data focus changed.");
    } catch (error) { notify(error.message, true); }
  });
  $("reloadRuns").addEventListener("click", () => loadRuns());
  $("jobFilter").addEventListener("change", () => {
    if (state.detail) renderJobs(state.detail.passes);
  });
  $("refreshCandidates").addEventListener("click", async () => {
    if (!state.selectedRun || state.loading) return;
    state.loading = true;
    notify("Queueing the next hunt pass...");
    try {
      const result = await request(`/api/hunts/${state.selectedRun}/refresh`, { method: "POST", body: "{}" });
      await selectRun(state.selectedRun);
      notify(result.queued ? `Pass #${result.pass_id} queued.` : result.complete ? "This one-time hunt is complete." : "A pass is already queued or running.");
    } catch (error) { notify(error.message, true); }
    finally { state.loading = false; }
  });
  $("toggleStatus").addEventListener("click", async () => {
    if (!state.detail || state.loading) return;
    state.loading = true;
    const status = state.detail.run.status === "active" ? "paused" : "active";
    try {
      renderDetail(await request(`/api/hunts/${state.selectedRun}`, { method: "PATCH", body: JSON.stringify({ status }) }));
      await loadRuns(true);
      notify(`Hunt ${status}.`);
    } catch (error) { notify(error.message, true); }
    finally { state.loading = false; }
  });

  $("accountHost").value = $("domainSelect").selectedOptions[0]?.textContent || "";
  updateSourceMode();
  updateCredentialType();
  loadDeltaScans().catch((error) => notify(error.message, true));
  loadAccounts().catch((error) => notify(error.message, true));
  loadRuns();
  setInterval(() => {
    if (!document.hidden && state.selectedRun && !state.loading) selectRun(state.selectedRun, true);
  }, 30000);
})();
