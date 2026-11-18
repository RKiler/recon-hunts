(() => {
  const config = JSON.parse(document.getElementById('agenticConfig').textContent);
  const byId = (id) => document.getElementById(id);
  const state = {mode: 'hunt', runId: null, leadId: null, run: null};
  const request = async (path, options = {}) => {
    const response = await fetch(path, {credentials: 'same-origin', ...options,
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': config.csrf, ...(options.headers || {})}});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || (response.status === 403
      ? 'Session or CSRF check failed. Refresh this page and try again.'
      : `Request failed (${response.status})`));
    return data;
  };
  function notice(message, error = false) {
    const node = byId('message'); node.textContent = message; node.style.color = error ? 'var(--red)' : 'var(--accent)';
  }
  function setMode(mode) {
    state.mode = mode;
    document.querySelectorAll('[data-mode]').forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle('active', active); button.setAttribute('aria-selected', String(active));
    });
    byId('dataSourceField').hidden = mode === 'recon';
    byId('targetHostField').hidden = mode === 'recon';
    byId('passCountField').hidden = mode === 'recon';
    byId('requestBudgetField').hidden = mode === 'recon';
    byId('focusField').hidden = mode === 'recon';
    byId('accountField').hidden = mode === 'recon';
    byId('launchButton').textContent = mode === 'recon' ? 'Queue recon' : 'Start hunt';
  }
  function el(tag, cls, value) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }
  function selectedAccounts() {
    return [...byId('accountChoices').querySelectorAll('input:checked')].map((node) => Number(node.value));
  }
  function exactHost() {
    return byId('targetHost').value.trim().toLowerCase().replace(/\.$/, '');
  }
  function matchingRoot(host) {
    return [...byId('domain').options]
      .filter((option) => option.value && (host === option.textContent.trim().toLowerCase() ||
        host.endsWith(`.${option.textContent.trim().toLowerCase()}`)))
      .sort((a, b) => b.textContent.length - a.textContent.length)[0];
  }
  async function loadAccounts() {
    const choices = byId('accountChoices'); choices.replaceChildren();
    const domain = byId('domain').value;
    if (!domain) {choices.append(el('span', 'muted', 'Select a domain.')); return;}
    const host = state.mode === 'hunt' ? exactHost() : '';
    const accounts = (await request(`/api/hunt-credentials?domain_id=${encodeURIComponent(domain)}`))
      .filter((account) => !host || (account.host || '').toLowerCase().replace(/\.$/, '') === host);
    if (!accounts.length) {choices.append(el('span', 'muted', host ? 'No owned accounts for this exact host. Add one below, including Manual VNC login.' : 'No owned accounts saved for this domain.')); return;}
    accounts.forEach((account) => {
      const label = el('label', 'account-choice'); const input = el('input');
      input.type = 'checkbox'; input.value = account.id;
      label.append(input, el('span', '', `${account.alias} · ${account.host}`)); choices.append(label);
    });
  }
  function accountTypeChanged() {
    const type = byId('accountType').value;
    const login = type === 'login_file';
    byId('accountPathField').hidden = !login;
    byId('accountEmailField').hidden = !login;
    byId('accountPasswordField').hidden = !login;
    byId('accountSecretField').hidden = login || type === 'manual_login';
    byId('accountHeaderField').hidden = type !== 'header';
    byId('accountSecret').required = !login && type !== 'manual_login';
    byId('accountHeader').required = type === 'header';
  }
  byId('accountType').addEventListener('change', accountTypeChanged);
  accountTypeChanged();
  byId('accountForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = byId('addAccount'); button.disabled = true;
    const message = byId('accountMessage'); message.textContent = '';
    try {
      const domainId = Number(byId('domain').value);
      if (!domainId) throw new Error('Select a root domain first.');
      const login = byId('accountType').value === 'login_file';
      const file = byId('accountPath').value.trim();
      const email = byId('accountEmail').value.trim();
      const password = byId('accountPassword').value;
      if (login && Boolean(file) === Boolean(email && password))
        throw new Error('Enter email and password, or one owned login JSON path.');
      const result = await request('/api/hunt-credentials', {method: 'POST', body: JSON.stringify({
        domain_id: domainId, alias: byId('accountAlias').value.trim(),
        host: byId('accountHost').value.trim(), role: byId('accountRole').value.trim(),
        tenant: byId('accountTenant').value.trim(), credential_type: byId('accountType').value,
        credential_path: login ? file : '', email: login ? email : '',
        password: login ? password : '',
        secret: login || byId('accountType').value === 'manual_login' ? '' : byId('accountSecret').value,
        header_name: byId('accountHeader').value.trim(), authorized: byId('accountAuthorized').checked,
      })});
      byId('accountPath').value = ''; byId('accountEmail').value = '';
      byId('accountPassword').value = ''; byId('accountSecret').value = '';
      byId('accountAuthorized').checked = false;
      message.textContent = `Saved ${result.alias} for ${result.host}.`;
      message.style.color = 'var(--accent)';
      await loadAccounts();
      const matching = byId('accountChoices').querySelector(`input[value="${result.id}"]`);
      if (matching) matching.checked = true;
    } catch (error) {
      message.textContent = error.message; message.style.color = 'var(--red)';
    } finally {button.disabled = false;}
  });
  async function loadRuns() {
    const domain = byId('domain').value;
    const rows = await request('/api/agentic/runs' + (domain ? `?domain_id=${encodeURIComponent(domain)}` : ''));
    const list = byId('runList'); list.replaceChildren();
    if (!rows.length) list.append(el('p', 'empty', 'No runs for this domain.'));
    rows.forEach((row) => {
      const button = el('button', 'run-item' + (row.id === state.runId ? ' active' : ''));
      button.type = 'button';
      const top = el('span', 'run-item-top');
      top.append(el('strong', '', `#${row.id} · ${row.action.toUpperCase()}`));
      top.append(el('span', `status ${row.status}`, row.status));
      button.append(top, el('small', '', `${row.target_host || row.domain} · ${new Date(row.created_at).toLocaleString()}`));
      button.addEventListener('click', () => {state.runId = row.id; loadRun(); loadRuns();});
      list.append(button);
    });
    if (!state.runId && rows.length) {state.runId = rows[0].id; await loadRun();}
  }
  function stat(label, value) {
    const node = el('div', 'stat'); node.append(el('strong', '', value), el('span', '', label)); return node;
  }
  async function loadRun() {
    if (!state.runId) return;
    const run = await request(`/api/agentic/runs/${state.runId}`);
    state.run = run;
    byId('runEyebrow').textContent = `${run.action.toUpperCase()} · ${run.status.toUpperCase()}`;
    byId('runTitle').textContent = `${run.target_host || run.domain} · Run #${run.id}`;
    byId('pauseRun').hidden = run.status !== 'queued';
    const summary = run.summary || {}; const coverage = summary.coverage || {};
    byId('runStats').replaceChildren(
      stat('Scoped records', coverage.scoped_records ?? '—'),
      stat('Routed leads', coverage.routed_leads ?? run.leads.length),
      stat('Batches', run.action === 'recon' ? '—' : `${summary.passes_completed ?? 0}/${summary.passes_planned ?? run.max_passes ?? 1}`),
      stat('Target requests', run.action === 'hunt' ? `${summary.codex_request_count ?? 0}/${run.request_budget ?? '—'}` : (summary.active_request_count ?? '—')),
      stat('Confirmed', summary.confirmed_count ?? '—'));
    const model = summary.product_model || {};
    byId('productPages').textContent = `${summary.product_pages ?? 0} pages · ${summary.browser_request_count ?? 0} browser resources`;
    byId('researchSummary').textContent = model.summary || (run.status === 'running' ? 'Research in progress.' : 'No product model recorded.');
    byId('researchFeatures').replaceChildren(...(model.features || []).map((feature) => el('span', 'feature-label', feature)));
    const setup = summary.account_setup || {};
    byId('accountStatus').textContent = setup.status === 'waiting_login'
      ? 'Owned account login needs you in VNC. Complete each window, then mark it complete below.'
      : setup.status === 'mailbox_ready'
      ? `Mailbox ready. Owned signup still requires target permission and VNC interaction.${setup.signup_url ? ` Signup: ${setup.signup_url}` : ''}`
      : setup.status === 'mailbox_unavailable'
      ? 'Mailbox unavailable; account verification needs manual review.'
      : setup.status === 'blocked_scope' ? 'Account setup blocked: signup scope or endpoint needs review.'
      : run.account_count ? `${run.account_count} owned account(s) selected.` : '';
    const handoff = byId('loginHandoff'); handoff.replaceChildren();
    if (setup.status === 'waiting_login') {
      const link = el('a', 'quiet', 'Open VNC');
      link.href = 'http://127.0.0.1:6080/vnc.html?autoconnect=true&resize=scale';
      link.target = '_blank'; link.rel = 'noopener noreferrer'; handoff.append(link);
      (setup.accounts || []).forEach((account) => {
        const item = el('div', 'login-account');
        item.append(el('span', '', `${account.alias} · ${account.host} · ${account.status}`));
        if (account.status === 'manual_login_pending') {
          const done = el('button', 'quiet', 'Login complete'); done.type = 'button';
          done.addEventListener('click', async () => {
            done.disabled = true;
            try {
              await request(`/api/agentic/runs/${run.id}/login/${account.id}/complete`, {method: 'POST'});
              notice(`Checking ${account.alias} session.`); await loadRun();
            } catch (error) {notice(error.message, true);} finally {done.disabled = false;}
          });
          item.append(done);
        }
        handoff.append(item);
      });
    }
    const classes = Object.entries(summary.class_coverage || {});
    byId('classCoverage').replaceChildren(...classes.map(([name, value]) => {
      const item = el('span', `class-status ${value.status || ''}`);
      item.title = value.reason || '';
      item.append(el('strong', '', name.replaceAll('_', ' ')), el('small', '', value.status || 'unknown'));
      return item;
    }));
    byId('leadCount').textContent = `${run.leads.length} shown`;
    const rows = byId('leadRows'); rows.replaceChildren();
    if (run.error) {const row = el('tr'); const cell = el('td', 'error-note', run.error); cell.colSpan = 5; row.append(cell); rows.append(row);}
    if (summary.summary) {const row = el('tr'); const cell = el('td', 'muted', summary.summary); cell.colSpan = 5; row.append(cell); rows.append(row);}
    if (!run.leads.length) {const row = el('tr'); const cell = el('td', 'empty', run.status === 'running' ? 'Routing saved recon records…' : 'No routed leads in this run.'); cell.colSpan = 5; row.append(cell); rows.append(row);}
    run.leads.forEach((lead) => {
      const row = el('tr');
      const signal = el('td'); signal.append(el('strong', '', lead.title), el('span', 'lead-sub', lead.rationale));
      const asset = el('td', 'asset', lead.asset);
      const source = el('td', 'muted', `${lead.source_table} #${lead.source_id}`);
      const status = el('td'); status.append(el('span', `priority ${lead.priority}`, lead.priority),
        el('span', 'lead-sub', lead.status === 'lead' ? 'Recon signal' : lead.status));
      const action = el('td'); const details = el('button', 'quiet', 'Details');
      details.type = 'button'; details.title = 'View source, assessment and validation';
      details.addEventListener('click', () => openLead(lead.id));
      action.append(details); row.append(signal, asset, source, status, action); rows.append(row);
    });
  }
  function detailLine(label, value) {
    const line = el('div', 'lead-detail-line');
    line.append(el('dt', '', label), el('dd', '', value == null || value === '' ? 'Not recorded' : value));
    return line;
  }
  function leadMessage(message, error = false) {
    const node = byId('leadMessage'); node.textContent = message;
    node.style.color = error ? 'var(--red)' : 'var(--accent)';
  }
  async function openLead(id) {
    state.leadId = id;
    const dialog = byId('leadDialog');
    byId('leadScopeConfirmed').checked = false;
    byId('leadDetail').replaceChildren(el('p', 'muted', 'Loading lead details…'));
    byId('leadAccounts').replaceChildren();
    leadMessage('');
    dialog.showModal();
    try {
      const detail = await request(`/api/agentic/leads/${id}`);
      if (state.leadId !== id) return;
      const lead = detail.lead;
      byId('leadDialogHost').textContent = new URL(lead.asset).hostname.toLowerCase();
      byId('leadDialogTitle').textContent = lead.title;
      byId('leadDialogState').textContent = lead.status === 'lead' ? 'ROUTED RECON SIGNAL' : lead.status.toUpperCase();
      const content = byId('leadDetail'); content.replaceChildren();
      const summary = el('p', 'lead-context', lead.rationale || 'No rationale recorded.');
      const location = el('p', 'lead-location', lead.asset);
      content.append(summary, location);
      const metadata = el('dl', 'lead-detail-list');
      metadata.append(detailLine('Source record', `${lead.source_table} #${lead.source_id}`));
      metadata.append(detailLine('Classification', `${lead.signal} · ${lead.skill}`));
      metadata.append(detailLine('Priority / confidence', lead.status === 'lead'
        ? `${lead.priority} · unvalidated recon signal` : `${lead.priority} · ${lead.confidence}%`));
      Object.entries(detail.source || {}).forEach(([key, value]) => {
        if (value !== null && value !== '' && (!Array.isArray(value) || value.length)) {
          metadata.append(detailLine(key.replaceAll('_', ' '), Array.isArray(value) ? value.join(', ') : value));
        }
      });
      content.append(metadata);
      if (detail.assessments.length) {
        const heading = el('h3', '', 'Prior assessment'); content.append(heading);
        detail.assessments.forEach((item) => {
          const block = el('div', 'lead-assessment');
          block.append(el('strong', '', `${item.outcome.replaceAll('_', ' ')} · ${item.title}`));
          if (item.reason) block.append(el('p', '', item.reason));
          if (item.next_test) block.append(el('p', 'muted', `Next test: ${item.next_test}`));
          if (item.evidence_file) block.append(el('small', 'muted', `Evidence: ${item.evidence_file}`));
          content.append(block);
        });
      } else if (detail.run_summary) {
        content.append(el('h3', '', 'Run conclusion'), el('p', 'lead-context', detail.run_summary));
      }
      if (detail.validations.length) {
        content.append(el('h3', '', 'Validation runs'));
        detail.validations.forEach((item) => {
          const button = el('button', 'validation-run', `#${item.id} · ${item.status} · ${item.summary || item.error || 'No conclusion yet'}`);
          button.type = 'button';
          button.addEventListener('click', () => {dialog.close(); state.runId = item.id; loadRuns().then(loadRun).catch((error) => notice(error.message, true));});
          content.append(button);
        });
      }
      const host = new URL(lead.asset).hostname.toLowerCase();
      const choices = byId('leadAccounts');
      const accounts = (await request(`/api/hunt-credentials?domain_id=${encodeURIComponent(lead.domain_id)}`))
        .filter((account) => (account.host || '').toLowerCase().replace(/\.$/, '') === host);
      if (state.leadId !== id) return;
      choices.append(el('span', 'field-label', 'Owned accounts for this host'));
      if (!accounts.length) choices.append(el('span', 'muted', 'None saved. Validation will be anonymous unless you add an account.'));
      accounts.forEach((account) => {
        const label = el('label', 'account-choice'); const input = el('input');
        input.type = 'checkbox'; input.value = account.id;
        label.append(input, el('span', '', `${account.alias} · ${account.role || 'role unknown'}`)); choices.append(label);
      });
    } catch (error) {
      byId('leadDetail').replaceChildren(el('p', 'error-note', error.message));
      leadMessage(error.message, true);
    }
  }
  byId('closeLeadDialog').addEventListener('click', () => byId('leadDialog').close());
  byId('leadAddAccount').addEventListener('click', () => {
    const host = byId('leadDialogHost').textContent;
    byId('leadDialog').close();
    byId('accountHost').value = host;
    byId('accountManager').open = true;
    byId('accountManager').scrollIntoView({behavior: 'smooth', block: 'center'});
    byId('accountAlias').focus();
  });
  byId('leadDialog').addEventListener('close', () => {state.leadId = null;});
  byId('validateLead').addEventListener('click', async () => {
    if (!state.leadId || !state.run) return;
    if (!byId('leadScopeConfirmed').checked) {
      leadMessage('Confirm this exact host and validation action first.', true); return;
    }
    const button = byId('validateLead'); button.disabled = true;
    try {
      const result = await request('/api/agentic/runs', {method: 'POST', body: JSON.stringify({
        domain_id: state.run.domain_id, action: 'validate', lead_id: state.leadId,
        scope_confirmed: true, data_source: state.run.data_source,
        credential_ids: [...byId('leadAccounts').querySelectorAll('input:checked')].map((node) => Number(node.value))})});
      byId('leadDialog').close();
      state.runId = result.id;
      notice(`Validation #${result.id} queued.`);
      await loadRuns(); await loadRun();
    } catch (error) {leadMessage(error.message, true);}
    finally {button.disabled = false;}
  });
  document.querySelectorAll('[data-mode]').forEach((button) => button.addEventListener('click', () => setMode(button.dataset.mode)));
  byId('domain').addEventListener('change', () => {state.runId = null; loadRuns().catch((error) => notice(error.message, true)); loadAccounts().catch((error) => notice(error.message, true));});
  byId('targetHost').addEventListener('input', () => {
    const match = matchingRoot(exactHost());
    if (match && byId('domain').value !== match.value) {
      byId('domain').value = match.value;
      byId('domain').dispatchEvent(new Event('change'));
    }
  });
  byId('targetHost').addEventListener('change', () => {
    if (exactHost() && !matchingRoot(exactHost())) notice('This host has no matching recon root.', true);
    if (exactHost()) byId('accountHost').value = exactHost();
    loadAccounts().catch((error) => notice(error.message, true));
  });
  byId('refreshRuns').addEventListener('click', () => loadRuns().then(loadRun).catch((error) => notice(error.message, true)));
  byId('pauseRun').addEventListener('click', async () => {
    try {await request(`/api/agentic/runs/${state.runId}/pause`, {method: 'POST'}); notice('Queued run paused.'); await loadRuns(); await loadRun();}
    catch (error) {notice(error.message, true);}
  });
  byId('launchForm').addEventListener('submit', async (event) => {
    event.preventDefault(); const domainId = Number(byId('domain').value);
    if (!domainId || !byId('scopeConfirmed').checked) return;
    const button = byId('launchButton'); button.disabled = true;
    try {
      const result = state.mode === 'recon'
        ? await request('/api/agentic/recon', {method: 'POST', body: JSON.stringify({domain_id: domainId, scope_confirmed: true})})
        : await request('/api/agentic/runs', {method: 'POST', body: JSON.stringify({domain_id: domainId,
          action: 'hunt', data_source: byId('dataSource').value, focus: byId('focus').value,
          target_host: exactHost() || null,
          max_passes: Number(byId('maxPasses').value),
          request_budget: Number(byId('requestBudget').value),
          credential_ids: selectedAccounts(), scope_confirmed: true})});
      state.runId = state.mode === 'recon' ? result.run.id : result.id;
      notice(state.mode === 'recon' ? 'Recon queued in the existing scanner.' : `Hunt #${result.id} queued.`);
      await loadRuns(); await loadRun();
    } catch (error) {notice(error.message, true);} finally {button.disabled = false;}
  });
  if (config.domainId) byId('domain').value = String(config.domainId);
  setMode('hunt'); loadRuns().catch((error) => notice(error.message, true));
  loadAccounts().catch((error) => notice(error.message, true));
  setInterval(() => {if (!document.hidden) loadRuns().then(loadRun).catch(() => {});}, 15000);
})();
