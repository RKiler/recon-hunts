(() => {
  'use strict';
  const cfg = JSON.parse(document.getElementById('hackbotConfig').textContent);
  const $ = (id) => document.getElementById(id);
  const section = cfg.section;
  const params = new URLSearchParams(location.search);
  let target = params.get('target') || '';
  let targets = [];
  let deletedTargets = [];
  let cleanupAvailable = false;
  let targetsCursor = null;
  let accounts = [];
  let accountCursor = null;
  let sessions = [];
  let sessionCursor = null;
  let traffic = [];
  let trafficCursor = null;
  let objects = [];
  let objectCursor = null;
  let objectAccounts = [];
  let objectSessions = [];
  let hypotheses = [];
  let hypothesisCursor = null;
  let skillCatalog = [];
  let selectedHypothesis = null;
  let approvals = [];
  let approvalCursor = null;
  let runs = [];
  let runCursor = null;
  let planRuns = [];
  let planRunCursor = null;
  let validations = [];
  let validationCursor = null;
  let findings = [];
  let findingCursor = null;
  let reports = [];
  let reportCursor = null;
  let selectedReport = null;
  let domCandidateCursor = null;
  let domSelectedCandidate = null;
  let messageCandidateCursor = null;
  let messageSelectedCandidate = null;
  let exposureCandidateCursor = null;
  let exposureSelectedCandidate = null;
  let apiOperationCursor = null;
  let apiCandidateCursor = null;
  let apiOperationDetail = null;
  let apiOperationCandidateCursor = null;
  let exposureObjects = [];
  let exposureSessions = [];
  let exposureArtifacts = [];
  let exposureCaptures = [];
  let exposureFieldExchanges = [];
  let targetTab = 'overview';
  let setupStep = 0;
  let setupSlugEdited = false;
  let createdTargetId = '';
  let bootstrapRefreshTimer = null;
  let huntRefreshTimer = null;
  let behaviourRefreshTimer = null;
  let plannerRunId = params.get('planner_run') || '';
  let campaignId = params.get('campaign') || '';
  let deltaCursor = null;
  let selectedDeltaId = null;
  let operationsRefreshTimer = null;
  let operationsPending = false;
  let reviewedRetentionTask = null;
  let retentionReviewReady = false;
  let reviewedProfileTask = null;
  let profileReviewReady = false;
  let evaluationRuns = [];
  let evaluationRunId = params.get('benchmark_run') || '';
  let evaluationCaseOffset = 0;

  function node(tag, value, className) {
    const item = document.createElement(tag);
    if (value !== undefined && value !== null) item.textContent = String(value);
    if (className) item.className = className;
    return item;
  }
  function cell(row, value, className) {
    const item = node('td', value, className);
    row.append(item);
    return item;
  }
  function button(label, action, className = 'text-action') {
    const item = node('button', label, className);
    item.type = 'button';
    item.addEventListener('click', action);
    return item;
  }
  function empty(tableId, text, colspan = 8) {
    const row = node('tr');
    const col = cell(row, text, 'empty');
    col.colSpan = colspan;
    $(tableId).replaceChildren(row);
  }
  function message(text, bad = false) {
    $('message').textContent = text || '';
    $('message').style.color = bad ? 'var(--red)' : 'var(--amber)';
  }
  function formatTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
  }
  function short(value, length = 12) { return value ? String(value).slice(0, length) : '—'; }
  function badge(value) {
    const element = node('span', value || 'UNKNOWN', 'badge');
    if (/^(TRACKED|VALID|MATCH|IN_SCOPE|RUNNING|COMPLETE|ALLOW|APPROVED_ONCE|CONFIRMED|PASS)$/i.test(value || '')) element.classList.add('good');
    else if (/^(FAILED|OUT_OF_SCOPE|REAUTH_REQUIRED|BURP_NOT_INSTALLED|DENY|REJECTED|EXPIRED)$/i.test(value || '')) element.classList.add('bad');
    else element.classList.add('warn');
    return element;
  }
  function option(select, value, label) {
    const item = node('option', label);
    item.value = value;
    select.append(item);
  }
  async function api(path, options = {}) {
    const response = await fetch('/api/hackbot/' + path, {
      method: options.method || 'GET', credentials: 'same-origin', cache: 'no-store',
      headers: options.method ? {'Content-Type': 'application/json', 'X-CSRF-Token': cfg.csrf} : {},
      body: options.method ? JSON.stringify(options.body || {}) : undefined,
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 401 && data.error === 'authentication_required') {
      const next = location.pathname + location.search;
      location.assign('/login?next=' + encodeURIComponent(next));
      throw new Error('Dashboard sign-in required.');
    }
    if (!response.ok) {
      const error = new Error(data.error || `Request failed (${response.status})`);
      error.field = data.field;
      throw error;
    }
    return data;
  }
  async function mutate(path, body = {}) {
    try { const result = await api(path, {method: 'POST', body}); message('Updated.'); return result; }
    catch (error) { message(error.message, true); return null; }
  }
  function requireTarget() {
    if (target) return true;
    message('Select a target package to view this section.');
    return false;
  }
  function targetQuery(extra = {}) {
    return new URLSearchParams({target, ...extra}).toString();
  }
  function selectTarget(value) {
    target = value;
    const next = new URL(location.href);
    if (target) next.searchParams.set('target', target);
    else next.searchParams.delete('target');
    next.searchParams.delete('plan');
    next.searchParams.delete('run');
    next.searchParams.delete('id');
    params.delete('plan');
    params.delete('run');
    params.delete('id');
    history.replaceState(null, '', next);
    $('targetSelect').value = target;
    message('');
    renderSection();
  }
  function setView() {
    for (const name of ['overview','targets',...(cfg.huntEnabled ? ['hunt'] : []),'accounts','sessions','traffic','objects','authorization','api','research','planner','campaigns','deltas','evaluation','behaviour','domxss','postmessage','exposure','scope','burp','hypotheses','approvals','skills','plans','runs','validations','findings','reports','operations']) {
      $(name + 'View').hidden = name !== section;
    }
    const titles = {overview:'Overview', targets:'Targets', hunt:'Hunt', accounts:'Accounts', sessions:'Sessions',
                    traffic:'Traffic', objects:'Objects', authorization:'Authorization', api:'API / GraphQL', research:'Research', planner:'Planner', campaigns:'Campaigns', deltas:'Changes', evaluation:'Evaluation', behaviour:'Behaviour', domxss:'DOM XSS', postmessage:'Messaging', exposure:'Exposure', scope:'Scope', burp:'Burp', hypotheses:'Hypotheses', approvals:'Approvals', skills:'Skills', plans:'Plans', runs:'Runs', validations:'Validations', findings:'Findings', reports:'Reports', operations:'Operations'};
    $('pageTitle').textContent = titles[section] || 'Overview';
    document.querySelectorAll('.side nav a').forEach((link) => link.classList.toggle('current', link.dataset.section === section));
    $('targetPicker').hidden = section === 'overview' || section === 'skills' || section === 'operations' || section === 'evaluation';
  }
  async function loadTargets(reset = false) {
    if (reset) { targets = []; targetsCursor = null; }
    if (reset) {
      try {
        const tombstones = await api('target-tombstones');
        deletedTargets = tombstones.items || [];
        cleanupAvailable = true;
      } catch (_) {
        deletedTargets = [];
        cleanupAvailable = false;
      }
      $('campaignShowArchived').closest('label').hidden = !cleanupAvailable;
      $('runShowArchived').closest('label').hidden = !cleanupAvailable;
    }
    const query = new URLSearchParams({limit:'20'});
    if (targetsCursor) query.set('cursor', targetsCursor);
    const page = await api('targets?' + query);
    targets.push(...page.items.filter((item) => !targets.some((known) => known.id === item.id)));
    targetsCursor = page.next_cursor;
    if (target && !targets.some((item) => item.id === target)) {
      try { targets.push(await api('targets/' + encodeURIComponent(target))); }
      catch (error) { target = ''; message('Selected target package is unavailable.', true); }
    }
    const selector = $('targetSelect');
    selector.replaceChildren(optionPlaceholder());
    targets.forEach((item) => option(selector, item.id, `${item.name} · ${item.primary_domain}`));
    selector.value = targets.some((item) => item.id === target) ? target : '';
    $('moreTargets').hidden = !targetsCursor;
    renderTargets();
  }
  function optionPlaceholder(label = 'Select target') { const item = node('option', label); item.value = ''; return item; }
  function renderTargets() {
    const body = $('targetRows'); body.replaceChildren();
    $('deletedTargetHistory').hidden = !deletedTargets.length;
    $('deletedTargetRows').replaceChildren(...deletedTargets.map((item) =>
      node('p', `${item.label} · ${formatTime(item.deleted_at)}`, 'context-line')));
    if (!targets.length) { empty('targetRows', 'No authorized target packages have been configured.'); return; }
    for (const item of targets) {
      const row = node('tr');
      cell(row, item.name);
      cell(row, item.primary_domain, 'mono');
      cell(row).append(badge(item.status));
      cell(row, `${item.scope_summary.included_hosts} included / ${item.scope_summary.excluded_hosts} excluded`);
      cell(row, item.counts.identities); cell(row, item.counts.browser_sessions); cell(row, item.counts.traffic);
      cell(row).append(button('Open', () => { selectTarget(item.id); showTargetDetail(); }));
      body.append(row);
    }
  }

  function setupField(name) { return $('targetSetupForm').elements.namedItem(name); }
  function setupHostRow(container, label, value = '') {
    const row = node('div', null, 'setup-row');
    const field = node('label', label);
    const input = node('input');
    input.type = 'text'; input.required = container.id === 'targetIncludeHosts';
    input.maxLength = 255; input.autocapitalize = 'off'; input.spellcheck = false;
    input.placeholder = container.id === 'targetIncludeHosts' ? 'app.example.com' : 'billing.example.com';
    input.value = value;
    const remove = button('×', () => row.remove(), 'icon-button');
    remove.title = 'Remove host'; remove.setAttribute('aria-label', 'Remove host');
    field.append(input); row.append(field, remove); container.append(row);
  }
  function setupHosts(id) {
    return Array.from($(id).querySelectorAll('input')).map((input) => input.value.trim()).filter(Boolean);
  }
  function setupPayload() {
    const value = (name) => setupField(name).value.trim();
    const ports = value('ports').split(',').map((part) => part.trim()).map(Number);
    return {
      name:value('name'), id:value('id'), primary_domain:value('primary_domain'),
      scope:{include:setupHosts('targetIncludeHosts'), exclude:setupHosts('targetExcludeHosts'),
        schemes:[...(setupField('scheme_https').checked ? ['https'] : []),
                 ...(setupField('scheme_http').checked ? ['http'] : [])], ports},
      source:{kind:value('source_kind'), reference:value('source_reference'), operator:value('source_operator')},
      rules:{automated_testing_allowed:value('automated_testing_allowed') === 'true',
        account_creation_allowed:value('account_creation_allowed') === 'true',
        forbidden_actions:value('forbidden_actions').split(',').map((part) => part.trim()).filter(Boolean),
        data_handling_restrictions:value('data_handling_restrictions')},
      autonomy:Object.fromEntries(Array.from($('targetSetupForm').querySelectorAll('#targetAutonomyFields select, #targetActionFields select')).map((field) =>
        [field.name, field.value])),
      rate:{requests_per_second:Number(value('requests_per_second')),
        requests_per_minute:Number(value('requests_per_minute')),
        max_concurrency:Number(value('max_concurrency')), burst:Number(value('burst'))},
      confirmed:setupField('confirmed').checked,
    };
  }
  function setupReview() {
    const value = setupPayload();
    detailPairs($('targetSetupReview'), [
      ['Target', value.name], ['Package ID', value.id], ['Primary host', value.primary_domain],
      ['Included hosts', value.scope.include.join(', ')], ['Excluded hosts', value.scope.exclude.join(', ') || 'None'],
      ['Schemes / ports', `${value.scope.schemes.join(', ')} / ${value.scope.ports.join(', ')}`],
      ['Authorization', `${value.source.kind} · ${value.source.reference}`],
      ['Operator', value.source.operator],
      ['Automation', value.rules.automated_testing_allowed ? 'Allowed' : 'Not allowed'],
      ['Account creation', value.rules.account_creation_allowed ? 'Allowed' : 'Not allowed'],
      ['Autonomy', Object.entries(value.autonomy).map(([key, decision]) => `${key}: ${decision}`).join(' · ')],
      ['Rate', `${value.rate.requests_per_second} req/s · ${value.rate.requests_per_minute} req/min · concurrency ${value.rate.max_concurrency} · burst ${value.rate.burst}`],
    ]);
  }
  function showSetupStep(next) {
    setupStep = Math.max(0, Math.min(5, next));
    $('targetSetupError').hidden = true;
    document.querySelectorAll('[data-setup-step]').forEach((panel) => { panel.hidden = Number(panel.dataset.setupStep) !== setupStep; });
    $('targetSetupSteps').querySelectorAll('li').forEach((item, index) => {
      item.classList.toggle('current', index === setupStep);
      item.classList.toggle('complete', index < setupStep);
    });
    $('targetSetupBack').disabled = setupStep === 0;
    $('targetSetupNext').hidden = setupStep === 5;
    $('targetSetupCreate').hidden = setupStep !== 5;
    if (setupStep === 5) setupReview();
  }
  function setupError(error) {
    const labels = {duplicate_target:'That package ID already exists.', duplicate_host:'A host is listed twice.',
      conflicting_host:'A host cannot be both included and excluded.',
      primary_host_must_be_included:'The primary domain must be an included exact host, not an exclusion.',
      confirmation_required:'Confirm the authorization record before creating the target.',
      invalid_target_package:'The target failed TargetPackage validation.', invalid_field:'Check this field.',
      unsafe_target_root:'The configured target directory is unavailable.'};
    $('targetSetupError').textContent = `${labels[error.message] || error.message}${error.field ? ` (${error.field})` : ''}`;
    $('targetSetupError').hidden = false;
    $('targetSetupError').scrollIntoView({block:'nearest'});
  }
  async function openTargetSetup() {
    const options = await api('targets/setup-options');
    $('targetList').hidden = true; $('targetDetail').hidden = true;
    $('targetSetup').hidden = false; $('targetSetupForm').hidden = false;
    $('targetSetupForm').reset(); setupSlugEdited = false; createdTargetId = '';
    $('targetIncludeHosts').replaceChildren(); $('targetExcludeHosts').replaceChildren();
    setupHostRow($('targetIncludeHosts'), 'Host');
    const source = setupField('source_kind'); source.replaceChildren();
    for (const kind of options.source_kinds) option(source, kind, kind.replaceAll('_', ' '));
    for (const [container, fields] of [[$('targetAutonomyFields'), options.risk_fields],
                                      [$('targetActionFields'), options.action_fields || []]]) {
      container.replaceChildren();
      for (const field of fields) {
        const label = node('label', field.replaceAll('_', ' '));
        const select = node('select'); select.name = field;
        for (const decision of options.decisions) option(select, decision, decision.replaceAll('_', ' '));
        select.value = options.defaults.autonomy[field] || 'DENY';
        label.append(select); container.append(label);
      }
    }
    showSetupStep(0);
    const next = new URL(location.href); next.searchParams.set('setup', 'new');
    history.replaceState(null, '', next);
    params.set('setup', 'new');
    setupField('name').focus();
  }
  function closeTargetSetup() {
    $('targetSetup').hidden = true; $('targetList').hidden = false;
    const next = new URL(location.href); next.searchParams.delete('setup');
    history.replaceState(null, '', next);
    params.delete('setup');
  }
  function openCreatedTarget(tab) {
    target = createdTargetId; targetTab = tab;
    const next = new URL(location.href); next.searchParams.delete('setup');
    next.searchParams.set('target', target); history.replaceState(null, '', next);
    params.delete('setup'); params.set('target', target);
    $('targetSelect').value = target;
    $('targetSetup').hidden = true;
    showTargetDetail();
  }

  function domBase() { return `domxss/${encodeURIComponent(target)}`; }
  async function loadDomCandidates(reset = false) {
    if (reset) { domCandidateCursor = null; $('domCandidateRows').replaceChildren(); }
    const query = new URLSearchParams({limit:'20'});
    if (domCandidateCursor) query.set('cursor', domCandidateCursor);
    const page = await api(`${domBase()}/candidates?${query}`);
    if (reset && !page.items.length) empty('domCandidateRows', 'No DOM XSS candidates yet.', 6);
    else for (const item of page.items) {
      const row = node('tr');
      cell(row, item.score); cell(row, item.source);
      cell(row, `${(item.checks || []).join(', ')} → ${(item.transforms || []).join(', ')}`);
      cell(row, item.sink); cell(row).append(badge(item.status));
      cell(row).append(button('Inspect', () => openDomCandidate(item.id).catch((error) => message(error.message, true))));
      $('domCandidateRows').append(row);
    }
    domCandidateCursor = page.next_cursor;
    $('moreDomCandidates').hidden = !domCandidateCursor;
  }
  async function renderDomxss() {
    domSelectedCandidate = null;
    $('domCandidateDetail').hidden = true;
    $('domMetrics').replaceChildren();
    $('domAssetRows').replaceChildren();
    $('domCandidateRows').replaceChildren();
    $('domInventoryState').textContent = '';
    $('moreDomCandidates').hidden = true;
    if (!requireTarget()) return;
    const selectedTarget = target;
    const [metrics, inventory] = await Promise.all([
      api(`${domBase()}/metrics`),
      api(`${domBase()}/inventory`).catch(() => null),
    ]);
    if (target !== selectedTarget) return;
    const counters = [['Assets analyzed', metrics.assets_analyzed], ['Candidates', metrics.candidates],
      ['Browser actions', metrics.browser_actions], ['Confirmed', metrics.confirmed],
      ['Manual review', metrics.manual_review]];
    $('domMetrics').replaceChildren(...counters.map(([name, value]) => {
      const item = node('div', null, 'metric');
      item.append(node('strong', value), node('span', name));
      return item;
    }));
    const assets = $('domAssetRows'); assets.replaceChildren();
    $('domInventoryState').textContent = inventory ? `${inventory.items.length} ranked` : 'Recon inventory unavailable';
    if (!inventory || !inventory.items.length) empty('domAssetRows', 'No ranked JavaScript assets available.', 5);
    else for (const asset of inventory.items) {
      const row = node('tr');
      cell(row, asset.score); cell(row, asset.host); cell(row, short(asset.latest_sha256, 16), 'mono');
      cell(row, (asset.reasons || []).join(', '));
      cell(row).append(button('Analyze', async () => {
        const result = await mutate(`${domBase()}/analyze`, {recon_asset_id:asset.recon_asset_id});
        if (result) { message(`${result.status}; source map: ${result.source_map_status || 'not requested'}.`); await renderDomxss(); }
      }, 'quiet'));
      assets.append(row);
    }
    await loadDomCandidates(true);
  }
  async function openDomCandidate(candidateId) {
    if (!requireTarget()) return;
    const selectedTarget = target;
    const base = `${domBase()}/candidates/${encodeURIComponent(candidateId)}`;
    const [item, runtime, sessionsPage] = await Promise.all([
      api(base), api(`${base}/runtime`),
      api(`browser/sessions?${targetQuery({limit:'50'})}`).catch(() => ({items:[]})),
    ]);
    if (target !== selectedTarget) return;
    domSelectedCandidate = item;
    $('domCandidateDetail').hidden = false;
    detailPairs($('domCandidateFacts'), [
      ['Candidate', item.id], ['Status', item.status], ['Priority', item.score],
      ['Asset SHA-256', item.asset_sha256], ['Source', `${item.source} (line ${item.source_line})`],
      ['Security check', (item.checks || []).join(' → ')],
      ['Transformation', (item.transforms || []).join(' → ')],
      ['Sink', `${item.sink} (line ${item.sink_line})`], ['Observed route', item.route],
      ['Mapped source', item.mapped_source], ['Source-map SHA-256', item.source_map_sha256],
      ['Run', runtime.run_status], ['Validation', runtime.validation_status],
      ['Evidence references', (item.evidence_ids || []).join(', ')],
    ]);
    const links = $('domPlanLinks'); links.replaceChildren();
    for (const [label, id, path, queryKey] of [
      ['Open plan', runtime.links.plan_id, 'plans', 'plan'],
      ['Open run', runtime.links.run_id, 'runs', 'run'],
      ['Open validation', runtime.links.validation_id, 'validations', 'id'],
    ]) {
      if (!id) continue;
      const url = new URL(`/hackbot/${path}`, location.origin);
      url.searchParams.set('target', target); url.searchParams.set(queryKey, id);
      const link = node('a', label, 'quiet'); link.href = url.pathname + url.search; links.append(link);
    }
    const proof = $('domProofRows'); proof.replaceChildren();
    if (!runtime.trials.length) empty('domProofRows', 'No browser trials recorded.', 5);
    else for (const trial of runtime.trials) {
      const row = node('tr');
      cell(row, trial.variant); cell(row, trial.marker_observed ? 'Observed' : 'Not observed');
      cell(row, [trial.marker_context, trial.document_origin].filter(Boolean).join(' · '));
      cell(row, [trial.csp_present ? 'CSP' : null, trial.trusted_types_enforced ? 'Trusted Types' : null,
                 trial.sandbox_flags?.length ? 'Sandbox' : null, trial.browser_blocked ? 'Blocked' : null]
                .filter(Boolean).join(', ') || 'None observed');
      cell(row, trial.evidence_id, 'mono'); proof.append(row);
    }
    const select = $('domBrowserSession'); select.replaceChildren(optionPlaceholder('Select session'));
    for (const session of sessionsPage.items) {
      if (session.browser_running) option(select, session.id, `${short(session.id, 20)} · ${session.status}`);
    }
    $('prepareDomCandidate').disabled = !item.route;
    $('domBindPlanForm').querySelector('button[type=submit]').disabled =
      !item.links.hypothesis_id || !item.route || !['location.search', 'location.hash'].includes(item.source);
    $('domInputKind').value = item.source === 'location.hash' ? 'FRAGMENT' : 'QUERY';
    $('domInputName').disabled = $('domInputKind').value === 'FRAGMENT';
  }

  function messageBase() { return `postmessage/${encodeURIComponent(target)}`; }
  async function loadMessageCandidates(reset = false) {
    if (reset) { messageCandidateCursor = null; $('messageCandidateRows').replaceChildren(); }
    const query = new URLSearchParams({limit:'20'});
    if (messageCandidateCursor) query.set('cursor', messageCandidateCursor);
    const page = await api(`${messageBase()}/candidates?${query}`);
    if (reset && !page.items.length) empty('messageCandidateRows', 'No messaging candidates yet.', 7);
    else for (const item of page.items) {
      const row = node('tr');
      cell(row, item.priority); cell(row, (item.message_types || []).join(', ') || 'Unknown');
      cell(row, item.origin_validation); cell(row, item.source_validation);
      cell(row, `${item.transport_kind || 'WINDOW'} · ${item.port_accepted ? 'Port' : 'No port'} · ${(item.rpc_methods || []).length} RPC`);
      cell(row).append(badge(item.status));
      cell(row).append(button('Inspect', () => openMessageCandidate(item.id).catch((error) => message(error.message, true))));
      $('messageCandidateRows').append(row);
    }
    messageCandidateCursor = page.next_cursor;
    $('moreMessageCandidates').hidden = !messageCandidateCursor;
  }
  async function renderPostmessage() {
    messageSelectedCandidate = null;
    $('messageCandidateDetail').hidden = true;
    $('messageMetrics').replaceChildren();
    $('messageAssetRows').replaceChildren();
    $('messageCandidateRows').replaceChildren();
    $('messageInventoryState').textContent = '';
    $('moreMessageCandidates').hidden = true;
    if (!requireTarget()) return;
    const selectedTarget = target;
    const [metrics, inventory] = await Promise.all([
      api(`${messageBase()}/metrics`),
      api(`${messageBase()}/inventory`).catch(() => null),
    ]);
    if (target !== selectedTarget) return;
    const counters = [['Handlers', metrics.handlers], ['Protocols', metrics.protocols],
      ['MessagePorts', metrics.message_port_candidates], ['RPC methods', metrics.rpc_methods],
      ['Browser trials', metrics.runtime_tests], ['Messages sent', metrics.messages_sent],
      ['RPC calls', metrics.rpc_calls], ['Confirmed', metrics.confirmed],
      ['Rejected', metrics.rejected], ['Manual review', metrics.manual_review],
      ['Static review', metrics.static_needs_review]];
    $('messageMetrics').replaceChildren(...counters.map(([name, value]) => {
      const item = node('div', null, 'metric'); item.append(node('strong', value), node('span', name)); return item;
    }));
    const assets = $('messageAssetRows'); assets.replaceChildren();
    $('messageInventoryState').textContent = inventory ? `${inventory.items.length} ranked` : 'Recon inventory unavailable';
    if (!inventory || !inventory.items.length) empty('messageAssetRows', 'No ranked JavaScript assets available.', 5);
    else for (const asset of inventory.items) {
      const row = node('tr');
      cell(row, asset.score); cell(row, asset.host); cell(row, short(asset.latest_sha256, 16), 'mono');
      cell(row, (asset.reasons || []).join(', '));
      cell(row).append(button('Analyze', async () => {
        const result = await mutate(`${messageBase()}/analyze`, {recon_asset_id:asset.recon_asset_id});
        if (result) { message(`${result.status}; ${result.candidate_ids.length} protocol candidates.`); await renderPostmessage(); }
      }, 'quiet'));
      assets.append(row);
    }
    await loadMessageCandidates(true);
  }
  async function openMessageCandidate(candidateId) {
    if (!requireTarget()) return;
    const selectedTarget = target;
    const base = `${messageBase()}/candidates/${encodeURIComponent(candidateId)}`;
    const [item, runtime, sessionsPage] = await Promise.all([
      api(base), api(`${base}/runtime`),
      api(`browser/sessions?${targetQuery({limit:'50'})}`).catch(() => ({items:[]})),
    ]);
    if (target !== selectedTarget) return;
    messageSelectedCandidate = item;
    $('messageCandidateDetail').hidden = false;
    detailPairs($('messageCandidateFacts'), [
      ['Candidate', item.id], ['Status', item.status], ['Priority', item.priority],
      ['Transport', item.transport_kind || 'WINDOW'],
      ['Runtime status', item.runtime_status],
      ['Message types', (item.message_types || []).join(', ')],
      ['Payload fields', (item.payload_fields || []).join(', ')],
      ['Protocol', (item.protocol_sequence || []).join(' → ')],
      ['Receiver', `${item.receiver} (line ${item.receiver_line})`],
      ['Origin check', item.origin_validation], ['Source check', item.source_validation],
      ['Port accepted / bound', `${item.port_accepted ? 'Yes' : 'No'} / ${item.port_bound ? 'Yes' : 'No'}`],
      ['RPC methods', (item.rpc_methods || []).join(', ')],
      ['RPC details', (item.rpc_details || []).map((method) =>
        `${method.name}: ${method.capability}, ${method.result_shape} result` +
        (method.argument_fields.length ? `, args ${method.argument_fields.join('/')}` : '')).join('; ')],
      ['Sensitive operations', (item.sensitive_operations || []).join(', ')],
      ['DOM XSS handoffs', (item.dom_xss_handoffs || []).join(', ')],
      ['Related protocols', (item.related_protocols || []).join(', ')],
      ['Observed route', item.route], ['Asset hashes', (item.asset_hashes || []).join(', ')],
      ['Mapped source', item.mapped_source], ['Source-map SHA-256', item.source_map_sha256],
      ['Run', runtime.run_status], ['Validation', runtime.validation_status],
      ['Evidence references', (item.evidence_ids || []).join(', ')],
    ]);
    const links = $('messagePlanLinks'); links.replaceChildren();
    for (const [label, id, path, queryKey] of [
      ['Open plan', runtime.links.plan_id, 'plans', 'plan'],
      ['Open run', runtime.links.run_id, 'runs', 'run'],
      ['Open validation', runtime.links.validation_id, 'validations', 'id'],
    ]) {
      if (!id) continue;
      const url = new URL(`/hackbot/${path}`, location.origin);
      url.searchParams.set('target', target); url.searchParams.set(queryKey, id);
      const link = node('a', label, 'quiet'); link.href = url.pathname + url.search; links.append(link);
    }
    const proof = $('messageProofRows'); proof.replaceChildren();
    if (!runtime.trials.length) empty('messageProofRows', 'No browser trials recorded.', 5);
    else for (const trial of runtime.trials) {
      const row = node('tr');
      cell(row, trial.variant); cell(row, `${trial.attacker_origin || '—'} · ${trial.source_relationship || '—'}`);
      cell(row, trial.capability_observed ? trial.effect_kind || 'Observed' : 'Not observed');
      cell(row, `${trial.message_count || 0} / ${trial.port_count || 0} / ${trial.rpc_calls || 0}`);
      cell(row, trial.evidence_id, 'mono'); proof.append(row);
    }
    const sessionSelect = $('messageBrowserSession');
    sessionSelect.replaceChildren(optionPlaceholder('Select session'));
    for (const session of sessionsPage.items) {
      if (session.browser_running) option(sessionSelect, session.id, `${short(session.id, 20)} · ${session.status}`);
    }
    const activation = $('messageActivationType');
    activation.replaceChildren(optionPlaceholder('Select observed type'));
    for (const type of item.message_types || []) option(activation, type, type);
    const port = $('messagePortType');
    port.replaceChildren(optionPlaceholder('Same activation'));
    for (const type of item.message_types || []) option(port, type, type);
    const method = $('messageAllowedMethod');
    method.replaceChildren(optionPlaceholder('No RPC call'));
    const safe = new Set(['ping','getVersion','getStatus','readSynthetic','readCanary']);
    for (const name of item.rpc_methods || []) if (safe.has(name)) option(method, name, name);
    $('prepareMessageCandidate').disabled = !item.route || item.transport_kind !== 'WINDOW';
    $('runMessageInvestigation').disabled = !item.links.plan_id || Boolean(runtime.links.run_id);
    $('messageBindPlanForm').querySelector('button[type=submit]').disabled =
      !item.route || item.transport_kind !== 'WINDOW' || !item.links.hypothesis_id ||
      !(item.message_types || []).length;
  }
  function exposureBase() { return `exposure/${encodeURIComponent(target)}`; }
  async function loadExposureCandidates(reset = false) {
    if (reset) { exposureCandidateCursor = null; $('exposureCandidateRows').replaceChildren(); }
    const query = new URLSearchParams({limit:'20'});
    const category = $('exposureCategory').value;
    const status = $('exposureStatus').value;
    if (category) query.set('category', category);
    if (status) query.set('status', status);
    if (exposureCandidateCursor) query.set('cursor', exposureCandidateCursor);
    const page = await api(`${exposureBase()}/candidates?${query}`);
    if (reset && !page.items.length) empty('exposureCandidateRows', 'No exposure candidates in this view.', 7);
    else for (const item of page.items) {
      const row = node('tr');
      cell(row, item.priority); cell(row, item.category); cell(row, item.location, 'mono');
      cell(row, item.source); cell(row).append(badge(item.status));
      cell(row).append(badge(item.finding_status || 'UNVALIDATED'));
      cell(row).append(button('Inspect', () => openExposureCandidate(item.candidate_id)
        .catch((error) => message(error.message, true))));
      $('exposureCandidateRows').append(row);
    }
    exposureCandidateCursor = page.next_cursor;
    $('moreExposureCandidates').hidden = !exposureCandidateCursor;
  }
  async function renderExposure() {
    exposureSelectedCandidate = null;
    $('exposureCandidateDetail').hidden = true;
    $('exposureMetrics').replaceChildren();
    $('exposureCandidateRows').replaceChildren();
    $('moreExposureCandidates').hidden = true;
    if (!requireTarget()) return;
    const selectedTarget = target;
    const [metrics, artifactPage, capturePage, fieldPage] = await Promise.all([
      api(`${exposureBase()}/metrics`), api(`${exposureBase()}/artifacts`),
      api(`${exposureBase()}/captures`), api(`${exposureBase()}/field-exchanges`),
    ]);
    if (selectedTarget !== target) return;
    const statuses = metrics.statuses || {};
    const validations = metrics.validations || {};
    const counters = [
      ['Candidates', metrics.candidates || 0],
      ['Ready to review', (statuses.FORMAT_VALID || 0) + (statuses.TARGET_RELEVANT || 0) + (statuses.NEEDS_MANUAL_REVIEW || 0)],
      ['Rejected as public', statuses.REJECTED_PUBLIC || 0],
      ['Rejected as placeholder', statuses.REJECTED_PLACEHOLDER || 0],
      ['Stale', statuses.STALE || 0],
      ['Confirmed', validations.CONFIRMED || 0],
      ['Rejected', validations.REJECTED || 0],
      ['Verification requests', metrics.requests || 0],
      ['Sensitive evidence', metrics.sensitive_artifacts || 0],
      ['Stopped on proof', metrics.stop_on_proof_events || 0],
    ];
    $('exposureMetrics').replaceChildren(...counters.map(([name, value]) => {
      const item = node('div', null, 'metric'); item.append(node('strong', value), node('span', name)); return item;
    }));
    const category = $('exposureCategory');
    const selectedCategory = category.value;
    category.replaceChildren(optionPlaceholder('All categories'));
    for (const name of Object.keys(metrics.categories || {}).sort()) option(category, name, name.replaceAll('_', ' '));
    category.value = selectedCategory;
    const status = $('exposureStatus');
    const selectedStatus = status.value;
    status.replaceChildren(optionPlaceholder('All states'));
    for (const name of Object.keys(statuses).sort()) option(status, name, name.replaceAll('_', ' '));
    status.value = selectedStatus;
    exposureArtifacts = artifactPage.items || [];
    const artifact = $('exposureArtifact');
    const selectedArtifact = artifact.value;
    artifact.replaceChildren(optionPlaceholder('Select captured artifact'));
    for (const item of exposureArtifacts) option(artifact, item.artifact_id,
      `${short(item.artifact_id, 24)} · ${short(item.sha256, 12)}`);
    artifact.value = exposureArtifacts.some((item) => item.artifact_id === selectedArtifact)
      ? selectedArtifact : '';
    updateExposureArtifactKind();
    exposureCaptures = capturePage.items || [];
    const capture = $('exposureCapture');
    const selectedCapture = capture.value;
    capture.replaceChildren(optionPlaceholder('Select captured response'));
    for (const item of exposureCaptures) option(capture, item.artifact_evidence_id,
      `${short(item.exchange_id, 24)} · ${item.size_bytes} B`);
    capture.value = exposureCaptures.some((item) => item.artifact_evidence_id === selectedCapture)
      ? selectedCapture : '';
    exposureFieldExchanges = fieldPage.items || [];
    for (const [control, label] of [['exposureFieldOwner', 'owner'], ['exposureFieldMember', 'member']]) {
      const select = $(control), selected = select.value;
      select.replaceChildren(optionPlaceholder(`Select ${label} read`));
      for (const item of exposureFieldExchanges) option(select, item.exchange_id,
        `${short(item.identity_id, 16)} · ${short(item.location, 54)}`);
      select.value = exposureFieldExchanges.some((item) => item.exchange_id === selected) ? selected : '';
    }
    await loadExposureCandidates(true);
  }
  function updateExposureArtifactKind() {
    const selected = exposureArtifacts.find((item) => item.artifact_id === $('exposureArtifact').value);
    const sourceMap = $('exposureArtifactKind').querySelector('option[value="source_map"]');
    sourceMap.disabled = !selected?.has_source_map;
    if (sourceMap.disabled && $('exposureArtifactKind').value === 'source_map')
      $('exposureArtifactKind').value = 'js';
  }
  async function openExposureCandidate(candidateId) {
    if (!requireTarget()) return;
    const selectedTarget = target;
    const detail = await api(`${exposureBase()}/candidates/${encodeURIComponent(candidateId)}`);
    if (selectedTarget !== target) return;
    const item = detail.candidate;
    exposureSelectedCandidate = item;
    $('exposureCandidateDetail').hidden = false;
    detailPairs($('exposureCandidateFacts'), [
      ['Candidate', item.candidate_id], ['Category', item.category], ['Status', item.status],
      ['Priority / confidence', `${item.priority} / ${item.confidence}`],
      ['Location', item.location], ['Source', item.source], ['Source record', item.endpoint_or_asset],
      ['Identity context', item.identity_context], ['Sensitivity', item.sensitivity],
      ['Reason', (item.reason_codes || []).join(', ')],
      ['Verification required', (item.verification_requirements || []).join(', ')],
      ['Credential class', item.credential?.type],
      ['Credential fingerprint', item.credential?.fingerprint_sha256],
      ['Service / privilege', item.credential ? `${item.credential.service_class} / ${item.credential.potential_privilege}` : null],
      ['PII categories', (item.pii_categories || []).join(', ')],
      ['Artifact SHA-256', item.artifact_sha256],
      ['Finding state', item.finding_status],
      ['Created', formatTime(item.created_at)], ['Updated', formatTime(item.updated_at)],
    ]);
    const sources = $('exposureSourceRows'); sources.replaceChildren();
    if (!(detail.sources || []).length) empty('exposureSourceRows', 'No source links recorded.', 4);
    else for (const source of detail.sources) {
      const row = node('tr'); cell(row, source.source); cell(row, source.source_ref, 'mono');
      cell(row).append(badge(source.current ? 'CURRENT' : 'STALE'));
      cell(row, source.evidence_id, 'mono'); sources.append(row);
    }
    const links = $('exposurePlanLinks'); links.replaceChildren();
    for (const [label, id, path, queryKey] of [
      ['Open plan', detail.links?.plan_id, 'plans', 'plan'],
      ['Open run', detail.links?.run_id, 'runs', 'run'],
      ['Open validation', detail.links?.validation_id, 'validations', 'id'],
    ]) {
      if (!id) continue;
      const url = new URL(`/hackbot/${path}`, location.origin);
      url.searchParams.set('target', target); url.searchParams.set(queryKey, id);
      const link = node('a', label, 'quiet'); link.href = url.pathname + url.search; links.append(link);
    }
    $('prepareExposureCandidate').disabled = ['STALE', 'REJECTED_PUBLIC', 'REJECTED_PLACEHOLDER'].includes(item.status);
    const canBind = item.source === 'TRAFFIC' && !item.credential &&
      Boolean(detail.links?.hypothesis_id) &&
      ['UNAUTHENTICATED_RESOURCE', 'UNAUTHENTICATED_DOWNLOAD', 'PII_EXPOSURE',
       'CONFIG_DISCLOSURE', 'BACKUP_ARTIFACT', 'DEBUG_ENDPOINT', 'OVEREXPOSED_API_RESPONSE'].includes(item.category);
    $('exposureReadForm').hidden = !canBind;
    const fieldBinding = item.category === 'OVEREXPOSED_API_RESPONSE';
    $('exposureMemberLabel').hidden = !fieldBinding;
    $('exposureMemberSession').required = fieldBinding;
    $('exposureReadForm').querySelector('button[type="submit"]').textContent =
      fieldBinding ? 'Bind field comparison' : 'Bind owned read';
    if (canBind) {
      const [objectsPage, sessionsPage] = await Promise.all([
        api(`objects?${targetQuery({limit:'50'})}`),
        api(`browser/sessions?${targetQuery({limit:'50'})}`),
      ]);
      if (selectedTarget !== target || exposureSelectedCandidate?.candidate_id !== candidateId) return;
      exposureObjects = (objectsPage.items || []).filter((object) => object.state === 'READY' && object.disposable);
      exposureSessions = (sessionsPage.items || []).filter((session) => session.status === 'VALID');
      const owned = $('exposureOwnedObject');
      owned.replaceChildren(optionPlaceholder('Select owned object'));
      for (const object of exposureObjects) option(owned, object.id, `${object.object_type} · ${short(object.id, 20)}`);
      updateExposureOwnerSessions();
    }
  }
  function updateExposureOwnerSessions() {
    const owner = exposureObjects.find((item) => item.id === $('exposureOwnedObject').value);
    const select = $('exposureOwnerSession');
    select.replaceChildren(optionPlaceholder('Select owner session'));
    if (!owner) return;
    for (const session of exposureSessions.filter((item) => item.identity_id === owner.creator_identity_id)) {
      option(select, session.id, short(session.id, 20));
    }
    const member = $('exposureMemberSession');
    member.replaceChildren(optionPlaceholder('Select member session'));
    for (const session of exposureSessions.filter((item) =>
      item.identity_id !== owner.creator_identity_id)) {
      option(member, session.id, short(session.id, 20));
    }
  }
  function showTargetDetail() {
    const item = targets.find((part) => part.id === target);
    if (!item) return;
    $('targetList').hidden = true; $('targetDetail').hidden = false;
    $('detailName').textContent = item.name;
    $('detailDomain').textContent = item.primary_domain;
    $('detailStatus').replaceWith(badge(item.status));
    const badgeNode = $('targetDetail').querySelector('.detail-head .badge');
    badgeNode.id = 'detailStatus';
    renderTargetTab().catch((error) => message(error.message, true));
  }
  async function openHuntSession(selected, sessionId) {
    const session = await api(`browser/sessions/${encodeURIComponent(sessionId)}?target=${encodeURIComponent(selected)}`);
    if (!session.vnc_available || !session.vnc_url) {
      location.href = `/hackbot/sessions?target=${encodeURIComponent(selected)}`;
      return;
    }
    const url = new URL(session.vnc_url);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/vnc.html') {
      throw new Error('Browser access route is unavailable.');
    }
    url.searchParams.set('autoconnect', 'true');
    url.searchParams.set('resize', 'scale');
    window.open(url.href, '_blank', 'noopener,noreferrer');
  }
  async function renderHuntPanel(content, selected) {
    if (huntRefreshTimer) { clearTimeout(huntRefreshTimer); huntRefreshTimer = null; }
    if (!selected) { content.replaceChildren(node('p', 'Select a target package.', 'context-line')); return; }
    const data = await api(`targets/${encodeURIComponent(selected)}/hunt`);
    if (target !== selected) return;
    const run = data.hunt;
    const panel = node('div', null, 'hunt-panel');
    const heading = node('div', null, 'section-head');
    heading.append(node('h2', 'Hunt'), button('Refresh', () => {
      renderHuntPanel(content, selected).catch((error) => message(error.message, true));
    }, 'quiet'));
    panel.append(heading);
    if (!run || ['COMPLETE','FAILED'].includes(run.state)) {
      const controls = node('div', null, 'actions');
      const modeLabel = node('label', 'Mode');
      const mode = node('select');
      for (const [value, label] of [['SUPERVISED','Supervised'],
                                    ['RESEARCHER_AUTONOMOUS','Researcher autonomous'],
                                    ['PLAN_ONLY','Plan only'], ['ADVANCED','Advanced']]) {
        option(mode, value, label);
      }
      modeLabel.append(mode);
      const start = button('Start Hunt', async () => {
        start.disabled = true;
        try {
          await api(`targets/${encodeURIComponent(selected)}/hunt`,
                    {method:'POST', body:{mode:mode.value}});
          message('Hunt started.');
          await renderHuntPanel(content, selected);
        } catch (error) {
          message(error.message, true);
          start.disabled = false;
        }
      });
      controls.append(modeLabel, start); panel.append(controls);
    }
    const facts = node('dl', null, 'details');
    detailPairs(facts, [['Status', run?.state || 'NOT STARTED'],
      ['Mode', run?.mode || '—'], ['Current step', run?.reason_code?.replaceAll('_', ' ') || '—'],
      ['Started', formatTime(run?.created_at)], ['Updated', formatTime(run?.updated_at)],
      ['Mapped sessions', (data.mapping || []).length]]);
    panel.append(facts);
    if (run?.campaign_id) {
      const campaign = node('a', 'Open campaign', 'text-action');
      campaign.href = `/hackbot/campaigns?target=${encodeURIComponent(selected)}&campaign=${encodeURIComponent(run.campaign_id)}`;
      panel.append(campaign);
    }
    panel.append(node('h3', 'Needs You'));
    const needs = node('div', null, 'activity');
    for (const item of data.needs_you || []) {
      const row = node('div', null, 'activity-item');
      const label = item.kind === 'LOGIN_REQUIRED' ? `Login required: ${item.alias}` :
        item.kind === 'CONFIRM_IDENTITY' ? `Confirm identity: ${item.alias}` :
        item.kind === 'APPROVAL_REQUIRED' ? 'Approval required' : 'Review required';
      row.append(node('span', label));
      if (item.kind === 'LOGIN_REQUIRED' && item.session_id) {
        row.append(button('Open', () => openHuntSession(selected, item.session_id)
          .catch((error) => message(error.message, true)), 'quiet'));
        const finished = button(`I finished login as ${item.alias}`, async () => {
          finished.disabled = true;
          try {
            await api(`browser/sessions/${encodeURIComponent(item.session_id)}/login-complete?target=${encodeURIComponent(selected)}`,
                      {method:'POST', body:{confirm_alias:item.alias}});
            await renderHuntPanel(content, selected);
          } catch (error) {
            message(error.message, true);
            finished.disabled = false;
          }
        }, 'quiet');
        row.append(finished);
      } else if (item.kind === 'CONFIRM_IDENTITY' && item.session_id) {
        row.append(button('Open', () => openHuntSession(selected, item.session_id)
          .catch((error) => message(error.message, true)), 'quiet'));
        row.append(button(`Confirm logged in as ${item.alias}`, async () => {
          try {
            await api(`browser/sessions/${encodeURIComponent(item.session_id)}/confirm-identity?target=${encodeURIComponent(selected)}`,
                      {method:'POST', body:{confirm_alias:item.alias}});
            await renderHuntPanel(content, selected);
          } catch (error) { message(error.message, true); }
        }, 'quiet'));
      } else if (item.kind === 'APPROVAL_REQUIRED') {
        const link = node('a', 'Review approvals', 'text-action');
        link.href = `/hackbot/approvals?target=${encodeURIComponent(selected)}`;
        row.append(link);
      }
      needs.append(row);
    }
    if (!needs.children.length) needs.append(node('p', 'None', 'context-line'));
    panel.append(needs, node('h3', 'Mapping'));
    const inventory = data.inventory || {};
    const inventoryFacts = node('dl', null, 'details');
    detailPairs(inventoryFacts, [
      ['Current JS', inventory.js_assets_current ?? 0],
      ['API operations', inventory.api_operations_current ?? 0],
      ['Observed APIs', inventory.api_operations_observed ?? 0],
      ['API leads', inventory.api_candidates ?? 0],
      ['Ready API leads', inventory.api_candidates_ready ?? 0],
      ['GraphQL operations', inventory.graphql_operations_current ?? 0],
    ]);
    panel.append(inventoryFacts);
    const mapping = node('div', null, 'activity');
    for (const item of data.mapping || []) {
      mapping.append(node('div', `${item.pages_observed} pages · ${item.links_discovered} links · ${item.js_references} JS references · ${item.forms_observed} forms`, 'activity-item'));
    }
    if (!mapping.children.length) mapping.append(node('p', 'No mapping results yet.', 'context-line'));
    panel.append(mapping);
    const investigation = data.investigation;
    if (investigation) {
      panel.append(node('h3', 'Investigation'));
      const progress = node('dl', null, 'details');
      detailPairs(progress, [
        ['Campaign', investigation.status || '—'],
        ['Cycle', `${investigation.cycle ?? 0} / ${investigation.max_cycles ?? 0}`],
        ['Candidates', investigation.candidates ?? 0],
        ['Selected', investigation.selected ?? 0],
        ['Experiments', investigation.experiments ?? 0],
        ['Validations', investigation.validations ?? 0],
        ['Rejected', investigation.rejected_validations ?? 0],
        ['Findings', investigation.findings ?? 0],
        ['Report drafts', investigation.report_drafts ?? 0],
        ['Cleanup pending', investigation.cleanup_pending ?? 0],
        ['Requests', `${investigation.requests_used ?? 0} / ${investigation.requests_limit ?? 0}`],
      ]);
      panel.append(progress, node('h3', 'Resources'));
      const resource = investigation.resource || {};
      const adaptive = investigation.adaptive || {};
      const resources = node('dl', null, 'details');
      detailPairs(resources, [
        ['State', resource.state || '—'],
        ['CPU load / CPU', Number.isFinite(resource.load_per_cpu) ? resource.load_per_cpu.toFixed(2) : '—'],
        ['Available RAM', Number.isFinite(resource.memory_available_bytes) ?
          `${Math.round(resource.memory_available_bytes / 1048576)} MiB` : '—'],
        ['Swap used', Number.isFinite(resource.swap_used_percent) ? `${resource.swap_used_percent}%` : '—'],
        ['Artifact disk used', Number.isFinite(resource.disk_used_percent) ? `${resource.disk_used_percent}%` : '—'],
        ['Browsers', adaptive.browser_limit ? `${adaptive.browsers_active ?? 0} / ${adaptive.browser_limit}` : '—'],
        ['Burp listeners', adaptive.burp_listener_capacity ?
          `${adaptive.burp_listeners_active ?? 0} / ${adaptive.burp_listener_capacity}` : '—'],
        ['Median response', Number.isFinite(adaptive.median_latency_ms) ?
          `${adaptive.median_latency_ms} ms` : '—'],
        ['Next request tranche', adaptive.pause_reason || (adaptive.requests ?? '—')],
      ]);
      panel.append(resources);
    }
    panel.append(node('h3', 'Findings'));
    const found = node('div', null, 'activity');
    for (const item of data.findings || []) {
      const row = node('div', null, 'activity-item');
      const link = node('a', item.title || 'Confirmed finding', 'text-action');
      link.href = `/hackbot/findings?target=${encodeURIComponent(selected)}&id=${encodeURIComponent(item.id)}`;
      row.append(link, node('span', [item.severity, item.status,
        item.report_id ? 'Report draft ready' : 'Report pending'].filter(Boolean).join(' · ')));
      found.append(row);
    }
    if (!found.children.length) found.append(node('p', 'No confirmed findings yet.', 'context-line'));
    panel.append(found);
    panel.append(node('h3', 'Activity'));
    const events = node('div', null, 'activity');
    for (const event of data.events || []) {
      events.append(node('div', `${formatTime(event.occurred_at)} · ${event.to_state} · ${event.reason_code}`, 'activity-item'));
    }
    if (!events.children.length) events.append(node('p', 'No hunt activity yet.', 'context-line'));
    panel.append(events);
    content.replaceChildren(panel);
    if (run && !['COMPLETE','FAILED'].includes(run.state)) {
      huntRefreshTimer = setTimeout(() => {
        if (target === selected && (section === 'hunt' || (section === 'targets' && targetTab === 'hunt'))) {
          renderHuntPanel(content, selected).catch((error) => message(error.message, true));
        }
      }, 5000);
    }
  }
  function simpleList(items, className = '') {
    const group = node('div', null, 'scope-list');
    if (!items.length) group.append(node('span', 'None configured', 'muted'));
    items.forEach((item) => group.append(node('span', item, 'scope-item ' + className)));
    return group;
  }
  function detailPairs(container, pairs) {
    const list = container.tagName === 'DL' ? container : node('dl', null, 'details');
    const entries = [];
    for (const [label, value] of pairs) {
      entries.push(node('dt', label), node('dd', value === null || value === undefined || value === '' ? '—' : value));
    }
    if (list === container) container.replaceChildren(...entries);
    else { list.append(...entries); container.replaceChildren(list); }
  }
  function reconSelectionDetails(recon) {
    const details = node('details', null, 'recon-host-selection');
    details.append(node('summary', 'Related recon hosts and selection reasons'));
    const selected = node('ul', null, 'plain-list');
    for (const item of recon.selected_related_hosts || []) {
      selected.append(node('li', `${item.hostname} · score ${item.score} · ${(item.reasons || []).join(', ')}`));
    }
    if (!selected.children.length) selected.append(node('li', 'No related hosts selected.'));
    details.append(node('h3', 'Selected for bounded consideration'), selected);
    if (recon.rejected_count) {
      const rejected = node('ul', null, 'plain-list');
      for (const item of recon.rejected_hosts || []) rejected.append(node('li', `${item.hostname} · ${item.reason}`));
      details.append(node('h3', `${recon.rejected_count} rejected candidates`), rejected);
    }
    if (recon.sample_truncated) details.append(node('p', 'Recon host sampling was bounded; counts include more hosts than were ranked.', 'context-line'));
    details.append(node('p', 'Recon provides candidates only. TargetPackage scope and request policy remain authoritative.', 'context-line'));
    return details;
  }
  function bootstrapBlocker(code) {
    const explanations = {
      ANONYMOUS_BURP_CAPTURE_REQUIRED:'An anonymous Burp capture session is not running.',
      TARGET_NOT_TRACKED:'The TargetPackage is not tracked.',
      NO_EXACT_SCOPE_SEED:'Add an explicitly authorized exact host to the TargetPackage.',
      NO_EXECUTOR_TRANSPORT:'The executor has no permitted network transport.',
    };
    return code ? `${explanations[code] || 'Bootstrap prerequisites are not satisfied.'} (${code})` : 'None';
  }
  function bootstrapStopReason(code) {
    return code === 'FRONTIER_EXHAUSTED'
      ? 'All selected bootstrap seeds and discovered URLs have been processed.'
      : (code || '—');
  }
  async function provisionAnonymousCapture(selected) {
    if (await mutate('browser/sessions', {target:selected, anonymous:true, capture_provider:'BURP'})) {
      location.href = `/hackbot/sessions?target=${encodeURIComponent(selected)}`;
    }
  }
  async function cleanTargetRuntime(selected) {
    const preview = await api(`targets/${encodeURIComponent(selected)}/delete-preview`);
    const blocked = Object.entries(preview.dependencies || {}).filter(([key, value]) =>
      value && ((key.startsWith('active_') && key !== 'active_capture_bindings') || key === 'continuous_enabled'));
    if (blocked.length) { message(`Stop active work before cleanup: ${blocked.map(([key]) => key).join(', ')}`, true); return false; }
    if (!window.confirm(`Clean runtime for ${selected}? This will stop and remove ${preview.dependencies.browser_sessions} browser session(s) and release ${preview.dependencies.active_capture_bindings} Burp binding(s). Target settings and all evidence will remain.`)) return false;
    const result = await mutate(`targets/${encodeURIComponent(selected)}/clean-runtime`, {});
    if (result) { await renderTargetTab(); return true; }
    return false;
  }
  async function openTargetDeleteDialog(selected) {
    const preview = await api(`targets/${encodeURIComponent(selected)}/delete-preview`);
    const dialog = node('dialog', null, 'cleanup-dialog');
    const title = node('h2', `Delete target ${selected}?`); title.id = 'targetDeleteTitle';
    dialog.setAttribute('aria-labelledby', title.id);
    const body = node('p', 'This removes the TargetPackage and account metadata. Evidence, traffic, validations, findings, reports, audit history, and recon data remain.');
    const blockers = Object.entries(preview.dependencies || {}).filter(([, value]) => value);
    dialog.append(title, body);
    if (blockers.length) {
      const descriptions = {
        browser_sessions: 'browser sessions',
        active_capture_bindings: 'active Burp bindings',
        cleanup_objects: 'objects awaiting cleanup',
      };
      dialog.append(node('p', `Deletion is blocked by ${blockers.map(([key, value]) =>
        `${value} ${descriptions[key] || key.replaceAll('_', ' ')}`).join(', ')}. Clear these dependencies first.`, 'form-error'));
      if (preview.dependencies.browser_sessions) {
        const sessionsLink = node('a', 'View browser sessions', 'text-action');
        sessionsLink.href = `/hackbot/sessions?target=${encodeURIComponent(selected)}`;
        dialog.append(sessionsLink);
      }
    }
    const label = node('label', `Type ${selected} to confirm`);
    const input = node('input'); input.autocomplete = 'off'; input.spellcheck = false;
    label.append(input);
    const actions = node('div', null, 'setup-actions');
    actions.append(button('Cancel', () => dialog.close(), 'quiet'));
    if (blockers.length && blockers.every(([key]) =>
      key === 'browser_sessions' || key === 'active_capture_bindings')) {
      actions.append(button('Clean Target Runtime', async () => {
        if (await cleanTargetRuntime(selected)) {
          dialog.close();
          await openTargetDeleteDialog(selected);
        }
      }, 'quiet'));
    }
    const remove = button('Delete target', async () => {
      remove.disabled = true;
      try {
        await api(`targets/${encodeURIComponent(selected)}`, {method:'DELETE', body:{confirm_package_id:input.value}});
        dialog.close();
        location.href = '/hackbot/targets';
      } catch (error) { message(error.message, true); remove.disabled = false; }
    }, 'danger');
    remove.disabled = true;
    input.addEventListener('input', () => { remove.disabled = !preview.can_delete || input.value !== selected; });
    actions.append(remove);
    dialog.append(label, actions);
    dialog.addEventListener('close', () => dialog.remove(), {once:true});
    document.body.append(dialog); dialog.showModal(); input.focus();
  }
  function accountEditorRow(parent, account = {}) {
    const row = node('div', null, 'account-editor-row');
    const locked = account.registration === 'REGISTERED';
    for (const [key, label] of [['alias','Alias'], ['tenant','Tenant'], ['role','Role']]) {
      const field = node('label', label);
      const input = node('input'); input.name = key; input.value = account[key] || '';
      input.maxLength = key === 'alias' ? 64 : 128; input.autocomplete = 'off';
      input.readOnly = locked; input.required = key === 'alias';
      if (key === 'alias') input.pattern = '[a-z][a-z0-9_-]{0,63}';
      field.append(input); row.append(field);
    }
    const remove = button('Remove', async () => {
      if (!locked) { row.remove(); return; }
      if (!window.confirm(`Remove account ${account.alias}? Delete its browser sessions first. Historical evidence and identity attribution will remain.`)) return;
      remove.disabled = true;
      try {
        await api(`targets/${encodeURIComponent(target)}/accounts/${encodeURIComponent(account.alias)}`, {method:'DELETE'});
        message('Account metadata removed; historical identity retained.');
        await renderTargetAccounts($('targetTabContent'));
      } catch (error) { message(error.message, true); remove.disabled = false; }
    }, 'danger');
    remove.title = 'Remove identity'; remove.setAttribute('aria-label', 'Remove identity');
    if (!locked || cleanupAvailable) row.append(remove);
    parent.append(row);
    if (account.registration) row.append(badge(account.registration), badge(account.session));
  }
  async function renderTargetAccounts(content) {
    const selected = target;
    const data = await api(`targets/${encodeURIComponent(selected)}/accounts`);
    if (selected !== target || targetTab !== 'accounts') return;
    const editor = node('form', null, 'account-editor');
    const rows = node('div', null, 'account-editor');
    for (const account of data.items) accountEditorRow(rows, account);
    const actions = node('div', null, 'setup-actions');
    actions.append(button('+ Add Identity', () => accountEditorRow(rows), 'quiet'));
    const save = node('button', 'Save accounts', 'quiet'); save.type = 'submit'; actions.append(save);
    const advanced = node('details', null, 'account-advanced');
    advanced.append(node('summary', 'Advanced account actions'));
    advanced.append(button('Retry account registration', async () => {
      const result = await mutate(`targets/${encodeURIComponent(selected)}/import-identities`, {});
      if (result) await renderTargetAccounts(content);
    }, 'quiet'));
    actions.append(advanced);
    const sessionsLink = node('a', 'Create Browser Session', 'text-action');
    sessionsLink.href = `/hackbot/sessions?target=${encodeURIComponent(selected)}`;
    actions.append(sessionsLink);
    editor.append(rows, actions);
    editor.addEventListener('submit', async (event) => {
      event.preventDefault();
      const accounts = Array.from(rows.children).map((row) => Object.fromEntries(
        ['alias','tenant','role'].map((key) => [key, row.querySelector(`[name="${key}"]`).value.trim()])));
      save.disabled = true;
      try {
        const result = await api(`targets/${encodeURIComponent(selected)}/accounts`, {method:'POST', body:{accounts}});
        const registered = (result.items || []).every((item) => item.registration === 'REGISTERED');
        message(registered ? 'Accounts saved and registered.' :
          'Accounts saved. Registration is pending; retry under Advanced account actions.');
        await renderTargetAccounts(content);
      } catch (error) { message(`${error.message}${error.field ? ` (${error.field})` : ''}`, true); }
      finally { save.disabled = false; }
    });
    content.replaceChildren(node('h2', 'Accounts'),
      node('p', `${data.configured} configured · ${data.sessions_ready}/${data.configured} sessions ready`, 'context-line'),
      node('p', 'Authentication secrets are handled separately through HackBot’s SecretProvider and browser-session workflow.', 'context-line'), editor);
  }
  async function renderTargetTab() {
    if (bootstrapRefreshTimer) { clearTimeout(bootstrapRefreshTimer); bootstrapRefreshTimer = null; }
    if (huntRefreshTimer) { clearTimeout(huntRefreshTimer); huntRefreshTimer = null; }
    const content = $('targetTabContent');
    const item = targets.find((part) => part.id === target);
    document.querySelectorAll('[data-target-tab]').forEach((tab) => {
      const active = tab.dataset.targetTab === targetTab;
      tab.classList.toggle('active', active); tab.setAttribute('aria-selected', String(active));
    });
    if (!item) return;
    if (targetTab === 'overview') {
      const selected = target;
      const [bootstrap, policy, accountData, huntData] = await Promise.all([
        api(`targets/${encodeURIComponent(selected)}/bootstrap`),
        api(`targets/${encodeURIComponent(selected)}/policy`),
        api(`targets/${encodeURIComponent(selected)}/accounts`),
        cfg.huntEnabled ? api(`targets/${encodeURIComponent(selected)}/hunt`) : Promise.resolve(null),
      ]);
      if (target !== selected || targetTab !== 'overview') return;
      const transport = bootstrap.transport || {};
      const recon = bootstrap.recon_resolution || {};
      const wrapper = node('div', null, 'target-readiness');
      const summary = node('dl', null, 'details');
      detailPairs(summary, [['Target', item.name], ['Primary host', item.primary_domain],
        ['Recon root', recon.recon_root || 'Not found'],
        ['Wildcard known / live / latest scan', `${recon.wildcard_recon_matches ?? 0} / ${recon.live_matches ?? 0} / ${recon.latest_scan_matches ?? 0}`],
        ['Related hosts selected', recon.selected_related_hosts?.length ?? 0],
        ['Package', item.status], ['Recon', bootstrap.recon_availability === 'NO_RECON_HISTORY' ? 'NOT FOUND' : bootstrap.recon_availability],
        ['Bootstrap mode', bootstrap.discovery_state], ['Cold start', transport.cold_start_available ? 'AVAILABLE' : 'BLOCKED'],
        ['Transport', transport.transport_ready ? 'READY' : 'NOT READY'],
        ['Burp capture', transport.burp_capture_ready ? 'READY' : 'NOT READY'],
        ['Anonymous capture session', transport.burp_capture_ready ? 'READY' : 'MISSING'],
        ['Accounts', `${accountData.configured} configured · ${accountData.sessions_ready}/${accountData.configured} sessions ready`],
        ['Rate', `${policy.rate.requests_per_second} req/s · ${policy.rate.requests_per_minute ?? '—'} req/min · concurrency ${policy.rate.max_concurrency}`],
        ['Captured exchanges', item.counts.traffic]]);
      const autonomy = node('dl', null, 'details');
      detailPairs(autonomy, ['passive','safe_read','bounded_active','state_changing','destructive'].map((field) =>
        [field.replaceAll('_', ' '), policy.autonomy[field]]));
      wrapper.append(summary, node('h2', 'Autonomy'), autonomy,
        button('Configure Accounts', () => {
          targetTab = 'accounts'; renderTargetTab().catch((error) => message(error.message, true));
        }, 'quiet'));
      if (cfg.huntEnabled) {
        const current = huntData?.hunt;
        const active = current && !['COMPLETE','FAILED'].includes(current.state);
        const action = button(active ? 'Open Hunt' : 'Start Hunt', async () => {
          action.disabled = true;
          try {
            if (!active) await api(`targets/${encodeURIComponent(selected)}/hunt`,
                                   {method:'POST', body:{mode:'SUPERVISED'}});
            targetTab = 'hunt';
            await renderTargetTab();
          } catch (error) { message(error.message, true); action.disabled = false; }
        });
        wrapper.append(action);
      }
      if (bootstrap.recon_resolution) wrapper.append(reconSelectionDetails(recon));
      if (cleanupAvailable) {
        const maintenance = node('div', null, 'setup-actions');
        maintenance.append(button('Clean Target Runtime', () =>
          cleanTargetRuntime(selected).catch((error) => message(error.message, true)), 'quiet'));
        maintenance.append(button('Delete Target', () =>
          openTargetDeleteDialog(selected).catch((error) => message(error.message, true)), 'danger'));
        wrapper.append(maintenance);
      }
      if (!transport.cold_start_available) {
        const reason = transport.blocked_reason === 'ANONYMOUS_BURP_CAPTURE_REQUIRED' ?
          'Bootstrap blocked: an anonymous Burp capture session is not running.' :
          `Bootstrap blocked: ${bootstrapBlocker(transport.blocked_reason)}`;
        wrapper.append(node('p', reason, 'context-line'));
        if (transport.blocked_reason === 'ANONYMOUS_BURP_CAPTURE_REQUIRED') {
          wrapper.append(button('Provision Anonymous Capture', () =>
            provisionAnonymousCapture(selected), 'quiet'));
        }
      } else {
        wrapper.append(button('Open Bootstrap', () => {
          targetTab = 'bootstrap'; renderTargetTab().catch((error) => message(error.message, true));
        }, 'quiet'));
      }
      content.replaceChildren(wrapper);
      return;
    }
    if (targetTab === 'bootstrap') {
      await renderBootstrapTab(content);
      return;
    }
    if (targetTab === 'hunt' && cfg.huntEnabled) {
      await renderHuntPanel(content, target);
      return;
    }
    if (targetTab === 'scope') {
      const data = await api('targets/' + encodeURIComponent(target) + '/scope');
      content.replaceChildren(node('h2', 'Included hosts'), simpleList(data.scope.include_hosts),
        node('h2', 'Excluded hosts'), simpleList(data.scope.exclude_hosts, 'exclude'),
        node('p', 'Recon inventory does not grant testing authorization.', 'context-line'));
      return;
    }
    if (targetTab === 'accounts') {
      await renderTargetAccounts(content);
      return;
    }
    if (targetTab === 'policy') {
      const data = await api('targets/' + encodeURIComponent(target) + '/policy');
      const autonomy = node('dl', null, 'details');
      const rate = node('dl', null, 'details');
      detailPairs(autonomy, Object.entries(data.autonomy).map(([key, value]) => [key.replaceAll('_', ' '), String(value)]));
      detailPairs(rate, Object.entries(data.rate).map(([key, value]) => [key.replaceAll('_', ' '), value]));
      content.replaceChildren(node('h2', 'Included hosts'), simpleList(data.scope.include_hosts),
        node('h2', 'Excluded hosts'), simpleList(data.scope.exclude_hosts, 'exclude'),
        node('h2', 'Included paths'), simpleList(data.scope.include_paths),
        node('h2', 'Excluded paths'), simpleList(data.scope.exclude_paths, 'exclude'),
        node('h2', 'Autonomy'), autonomy, node('h2', 'Rate limits'), rate);
      return;
    }
    if (targetTab === 'profile') {
      const data = await api('targets/' + encodeURIComponent(target) + '/profile');
      const profile = data.profile;
      if (!profile) { content.replaceChildren(node('p', 'No profile snapshot yet. Use Profile Target in Hypotheses.', 'context-line')); return; }
      detailPairs(content, [['Generated', formatTime(profile.generated_at)], ['Recon', profile.recon_status],
        ['Technologies', profile.technologies.join(', ') || 'Unknown'],
        ['API styles', profile.api_styles.join(', ') || 'Unknown'],
        ['Features', profile.features.join(', ') || 'Unknown'],
        ['Security boundaries', profile.boundaries.join(', ') || 'Unknown'],
        ['Object types', profile.object_types.join(', ') || 'Unknown'],
        ['Identity capabilities', profile.identity_capabilities.join(', ') || 'None configured'],
        ['JavaScript assets sampled', profile.coverage.js_assets_examined],
        ['JS-heavy sample', profile.javascript_heavy ? 'Yes (sampled)' : 'No indication'],
        ['Message passing', profile.message_passing ? 'Observed' : 'Not observed'],
        ['Source maps sampled', profile.source_map_count],
        ['Recent changes', profile.recent_changes], ['Coverage gaps', profile.gaps.join(', ') || 'None recorded']]);
      return;
    }
    if (targetTab === 'research') {
      const [gaps, requests] = await Promise.all([
        api(`research/${encodeURIComponent(target)}/gaps?limit=50`),
        api(`research/${encodeURIComponent(target)}/requests?limit=50`),
      ]);
      const link = node('a', 'Open research', 'text-action');
      link.href = `/hackbot/research?target=${encodeURIComponent(target)}`;
      detailPairs(content, [['Outstanding knowledge gaps', gaps.items.length],
        ['Recent research requests', requests.items.length],
        ['Cached briefs', requests.items.filter((item) => item.brief_id).length]]);
      content.append(link);
      return;
    }
    if (targetTab === 'objects') {
      const page = await api('objects?' + targetQuery({limit:'5'}));
      const link = node('a', 'Open disposable objects', 'text-action');
      link.href = `/hackbot/objects?target=${encodeURIComponent(target)}`;
      const summary = node('p', `${page.stats.objects} registered · ${page.stats.cleanup_pending} cleanup pending · ${page.stats.orphaned} orphaned`, 'context-line');
      const list = node('ul', null, 'plain-list');
      page.items.forEach((object) => {
        const entry = node('li');
        const objectLink = node('a', `${object.object_type} · ${object.state} · ${short(object.id, 20)}`, 'text-action');
        objectLink.href = `/hackbot/objects?target=${encodeURIComponent(target)}&id=${encodeURIComponent(object.id)}`;
        entry.append(objectLink); list.append(entry);
      });
      content.replaceChildren(summary, link, list);
      return;
    }
    const route = {accounts:'accounts', sessions:'sessions', traffic:'traffic', objects:'objects',
                   authorization:'authorization', behaviour:'behaviour', hypotheses:'hypotheses', research:'research'}[targetTab];
    const link = node('a', `Open ${targetTab} for this target`, 'text-action');
    link.href = `/hackbot/${route}?target=${encodeURIComponent(target)}`;
    content.replaceChildren(node('p', `${item.name} · ${item.primary_domain}`, 'context-line'), link);
  }
  async function renderBootstrapTab(content) {
    const selected = target;
    const base = 'targets/' + encodeURIComponent(selected) + '/bootstrap';
    const [data, sessionPage, identityPage] = await Promise.all([
      api(base), api('browser/sessions?' + targetQuery({limit:'50'})),
      api('targets/' + encodeURIComponent(selected) + '/identities?limit=50'),
    ]);
    if (selected !== target || targetTab !== 'bootstrap') return;
    const active = data.latest && ['CREATED','READY','RUNNING','WAITING_LOGIN'].includes(data.latest.status);
    const heading = node('div', null, 'section-head');
    heading.append(node('h2', 'Target discovery'), button('Refresh', () => {
      renderTargetTab().catch((error) => message(error.message, true));
    }, 'quiet'));
    const state = node('dl', null, 'details');
    const transport = data.transport || {};
    const recon = data.recon_resolution || {};
    detailPairs(state, [
      ['Discovery state', data.discovery_state],
      ['Primary focus', recon.primary_focus || selected],
      ['Recon root', recon.recon_root || 'Not found'],
      ['Wildcard known / live / latest scan', `${recon.wildcard_recon_matches ?? 0} / ${recon.live_matches ?? 0} / ${recon.latest_scan_matches ?? 0}`],
      ['Related hosts selected', recon.selected_related_hosts?.length ?? 0],
      ['Recon history', data.recon_availability === 'RECON_BACKED' ? 'RECON BACKED' :
        data.recon_availability === 'RECON_UNAVAILABLE' ? 'RECON UNAVAILABLE / COLD START' :
        data.recon_availability === 'NOT_CONFIGURED' ? 'NO RECON CONNECTION / COLD START' :
        'NO RECON HISTORY / COLD START'],
      ['Executor', transport.executor_enabled ? (transport.direct_enabled ? 'DIRECT ENABLED' : 'PROXY ONLY') : 'DISABLED'],
      ['Transport', transport.transport_ready ? 'READY' : 'NOT READY'],
      ['Burp capture', transport.burp_capture_ready ? `READY · 127.0.0.1:${transport.anonymous_listener_port}` : 'NOT READY'],
      ['Cold start', transport.cold_start_available ? 'AVAILABLE' : 'BLOCKED'],
      ['Blocked reason', bootstrapBlocker(transport.blocked_reason)],
      ['Latest run', data.latest ? data.latest.status : 'Not started'],
      ['Stop reason', bootstrapStopReason(data.latest?.stop_reason)],
    ]);
    const controls = node('div', null, 'filters');
    const modeLabel = node('label', 'Identity mode');
    const mode = node('select');
    for (const [value, label] of [['anonymous_plus_primary','Anonymous + verified primary'],
                                   ['anonymous_only','Anonymous only'], ['primary_identity','Verified primary only']]) {
      option(mode, value, label);
    }
    modeLabel.append(mode);
    const identityLabel = node('label', 'Verified account');
    const identity = node('select');
    option(identity, '', 'Automatic selection');
    const aliases = new Map(identityPage.items.map((item) => [item.identity.id, item.identity.alias]));
    for (const session of sessionPage.items.filter((item) => item.identity_id &&
        item.status === 'VALID' && item.verification_status === 'MATCH')) {
      if (!Array.from(identity.options).some((item) => item.value === session.identity_id)) {
        option(identity, session.identity_id, aliases.get(session.identity_id) || short(session.identity_id, 24));
      }
    }
    identityLabel.append(identity);
    const refreshLabel = node('label', 'Refresh current JS', 'policy-check');
    const refresh = node('input'); refresh.type = 'checkbox';
    refreshLabel.prepend(refresh);
    const start = button('Start bootstrap', async () => {
      if (mode.value === 'primary_identity' && !identity.value) {
        message('Select a verified account for primary-only bootstrap.', true); return;
      }
      const body = {identity_policy:mode.value, refresh:refresh.checked};
      if (identity.value && mode.value !== 'anonymous_only') body.identity_id = identity.value;
      if (await mutate(base, body)) await renderTargetTab();
    }, 'quiet');
    start.disabled = Boolean(active || !transport.cold_start_available);
    mode.addEventListener('change', () => { identity.disabled = mode.value === 'anonymous_only'; });
    const anonymousSession = sessionPage.items.find((item) => item.anonymous && item.proxy_enabled);
    if (!transport.burp_capture_ready && !anonymousSession) {
      controls.append(button('Provision anonymous Burp capture', () => provisionAnonymousCapture(selected), 'quiet'));
    } else if (!transport.burp_capture_ready) {
      const sessionsLink = node('a', 'Start anonymous capture session', 'text-action');
      sessionsLink.href = `/hackbot/sessions?target=${encodeURIComponent(selected)}`;
      controls.append(sessionsLink);
    }
    controls.append(modeLabel, identityLabel, refreshLabel, start);
    const summary = node('dl', null, 'details');
    const coverage = data.latest?.coverage || {};
    detailPairs(summary, [['Requests used', coverage.requests_used ?? 0],
      ['Seed sources', data.latest?.seed_sources?.join(', ') || 'TARGET_ROOT / no run'],
      ['Recon hosts resolved', coverage.recon_hosts_resolved ?? 0],
      ['Recon candidates inspected', coverage.recon_candidates_seen ?? 0],
      ['In-scope candidates', coverage.recon_candidates_in_scope ?? 0],
      ['Unique safe candidates', coverage.recon_candidates_deduped ?? 0],
      ['Selected recon seeds', coverage.recon_seeds_selected ?? 0],
      ['Endpoint / JS / API seeds', `${coverage.recon_endpoint_seeds ?? 0} / ${coverage.recon_js_seeds ?? 0} / ${coverage.recon_api_seeds ?? 0}`],
      ['GraphQL seeds', coverage.recon_graphql_seeds ?? 0],
      ['Anonymous pages', coverage.anonymous_pages ?? 0],
      ['Authenticated pages', coverage.authenticated_pages ?? 0],
      ['Pages parsed from bounded prefix', coverage.html_pages_truncated ?? 0],
      ['JavaScript assets', `${coverage.js_assets_acquired ?? 0} / ${coverage.js_assets_discovered ?? 0} acquired`],
      ['Source maps', coverage.source_maps_acquired ?? 0],
      ['API surfaces', coverage.api_surfaces_observed ?? 0],
      ['Technologies', coverage.technologies_detected ?? 0],
      ['Feature signals', coverage.features_detected ?? 0],
      ['Duplicate redirects skipped', coverage.redirect_duplicates ?? 0],
      ['Redirect denials: scope / query / scheme / policy', `${coverage.redirect_denied_out_of_scope ?? 0} / ${coverage.redirect_denied_unsafe_query ?? 0} / ${coverage.redirect_denied_unsupported_scheme ?? 0} / ${coverage.redirect_denied_other_policy ?? 0}`],
      ['Traffic exchanges', coverage.traffic_exchanges_recorded ?? 0],
      ['Limitations', data.latest?.limitations?.join(', ') || 'None recorded']]);
    const rows = node('tbody');
    for (const run of data.history || []) {
      const row = node('tr');
      cell(row, formatTime(run.started_at)); cell(row, run.mode);
      cell(row).append(badge(run.status));
      cell(row, `${run.requests_used} / ${run.limits.max_requests}`);
      cell(row, bootstrapStopReason(run.stop_reason));
      const actions = cell(row);
      actions.append(button('Details', async () => {
        try {
          const detail = await api(base + '/' + encodeURIComponent(run.bootstrap_id));
          const panel = node('div');
          const facts = node('dl', null, 'details');
          const sources = [...new Set(detail.observations.map((item) => item.source))];
          const c = detail.run.coverage || {};
          detailPairs(facts, [['Mode', detail.run.mode], ['Status', detail.run.status],
            ['Active seed sources', detail.run.seed_sources?.join(', ') || 'None recorded'],
            ['Observation provenance', sources.join(', ') || 'None'],
            ['Recon candidates inspected / in scope / unique', `${c.recon_candidates_seen ?? 0} / ${c.recon_candidates_in_scope ?? 0} / ${c.recon_candidates_deduped ?? 0}`],
            ['Selected endpoint / JS / API / GraphQL seeds', `${c.recon_endpoint_seeds ?? 0} / ${c.recon_js_seeds ?? 0} / ${c.recon_api_seeds ?? 0} / ${c.recon_graphql_seeds ?? 0}`],
            ['Redirect denials: scope / query / scheme / policy', `${c.redirect_denied_out_of_scope ?? 0} / ${c.redirect_denied_unsafe_query ?? 0} / ${c.redirect_denied_unsupported_scheme ?? 0} / ${c.redirect_denied_other_policy ?? 0}`],
            ['Duplicate redirects skipped', c.redirect_duplicates ?? 0],
            ['Pages parsed', c.pages_visited ?? 0],
            ['JS discovered / acquired', `${c.js_assets_discovered ?? 0} / ${c.js_assets_acquired ?? 0}`],
            ['Coverage', Object.entries(detail.run.coverage).map(([key, value]) => `${key}: ${value}`).join(' · ')],
            ['Budget', Object.entries(detail.run.limits).map(([key, value]) => `${key}: ${value}`).join(' · ')],
            ['Limitations', detail.run.limitations.join(', ') || 'None'],
            ['Stop reason', bootstrapStopReason(detail.run.stop_reason)]]);
          const list = node('ul', null, 'plain-list');
          detail.observations.forEach((item) => list.append(node('li', `${item.source} · ${item.code} · ${item.display} · ${item.evidence_id}`)));
          panel.append(node('h3', 'Run detail'), facts, node('h3', 'Discovered surfaces'), list);
          if (detail.observations_truncated) panel.append(node('p', 'Showing the newest 80 observations.', 'context-line'));
          $('bootstrapRunDetail')?.remove();
          panel.id = 'bootstrapRunDetail';
          content.append(panel);
        } catch (error) { message(error.message, true); }
      }, 'quiet'));
      if (['CREATED','READY','RUNNING'].includes(run.status)) {
        actions.append(button('Cancel', async () => {
          if (await mutate(base + '/' + encodeURIComponent(run.bootstrap_id) + '/cancel')) await renderTargetTab();
        }, 'quiet'));
      }
      rows.append(row);
    }
    const table = node('table');
    const head = node('thead');
    const header = node('tr');
    ['Started','Mode','Status','Requests','Stop reason','Actions'].forEach((label) => header.append(node('th', label)));
    head.append(header); table.append(head, rows);
    const history = node('div', null, 'table-wrap'); history.append(table);
    content.replaceChildren(heading, state, controls, node('h3', 'Coverage'), summary,
      node('h3', 'Run history'), history);
    if (data.recon_resolution) content.insertBefore(reconSelectionDetails(recon), controls);
    if (active) {
      bootstrapRefreshTimer = setTimeout(() => {
        if (selected === target && targetTab === 'bootstrap') {
          renderTargetTab().catch((error) => message(error.message, true));
        }
      }, 4000);
    }
  }
  async function renderBehaviour() {
    if (behaviourRefreshTimer) { clearTimeout(behaviourRefreshTimer); behaviourRefreshTimer = null; }
    if (!requireTarget()) return;
    const selected = target;
    const base = 'targets/' + encodeURIComponent(selected) + '/behaviour';
    const data = await api(base);
    if (selected !== target) return;
    const profile = data.profile;
    const latest = data.runs[0];
    $('behaviourStatus').textContent = latest ?
      `Latest run: ${latest.status} · ${latest.stop_reason || 'In progress'} · ${formatTime(latest.created_at)}` :
      'No learning run yet.';
    const coverage = profile ? profile.coverage : {state:'NONE'};
    $('behaviourCoverage').replaceChildren(...Object.entries(coverage).map(([key, value]) => {
      const item = node('div', null, 'metric');
      item.append(node('span', key.replaceAll('_', ' '), 'muted'), node('strong', String(value)));
      return item;
    }));
    const gaps = $('behaviourGaps'); gaps.replaceChildren();
    for (const gap of profile?.gaps || []) gaps.append(node('li', `${gap.code}: ${gap.next_step}`));
    if (!gaps.children.length) gaps.append(node('li', 'No specific gap recorded.'));
    const actors = $('behaviourActors'); actors.replaceChildren();
    for (const identity of profile?.identities || []) {
      actors.append(node('span', `${short(identity.identity_id, 24)} · ${identity.auth_state} · ${identity.role_ids.join(', ') || 'No role'} · ${identity.tenant_ids.join(', ') || 'No tenant'}`, 'scope-item'));
    }
    if (!actors.children.length) actors.append(node('span', 'No attributed identity traffic.', 'muted'));
    const features = $('behaviourFeatures'); features.replaceChildren();
    for (const item of profile?.features || []) features.append(node('span', item.name, 'scope-item'));
    if (!features.children.length) features.append(node('span', 'No features observed.', 'muted'));
    const fill = (id, rows, columns) => {
      const body = $(id); body.replaceChildren();
      for (const item of rows) {
        const row = node('tr');
        columns.forEach((column) => cell(row, column(item)));
        body.append(row);
      }
      if (!rows.length) empty(id, 'No observations yet.', columns.length);
    };
    fill('behaviourOperations', (profile?.operations || []).slice(0, 40), [
      x => x.action, x => x.feature, x => x.protocol, x => x.results.join(', '),
      x => x.exchange_ids.map(id => short(id, 22)).join(', ')]);
    fill('behaviourWorkflows', (profile?.workflows || []).slice(0, 40), [
      x => x.feature, x => x.action, x => short(x.identity_id, 24),
      x => x.tenant_ids.join(', '), x => x.object_ids.map(id => short(id, 22)).join(', '), x => x.result,
      x => x.evidence_ids.map(id => short(id, 22)).join(', ')]);
    fill('behaviourRoleFeatures', (profile?.role_feature_matrix || []).slice(0, 80), [
      x => short(x.role_id, 24), x => x.feature, x => x.state, x => x.explicit_denials]);
    fill('behaviourRoleOperations', (profile?.role_operation_matrix || []).slice(0, 80), [
      x => short(x.role_id, 24), x => `${x.action} · ${x.feature}`, x => x.state, x => x.explicit_denials]);
    fill('behaviourObjects', (profile?.known_objects || []).slice(0, 50), [
      x => short(x.id, 24), x => x.type, x => short(x.owner_identity_id, 24),
      x => short(x.tenant_id, 24), x => short(x.parent_id, 24),
      x => x.evidence_ids.map(id => short(id, 22)).join(', ')]);
    $('behaviourObjectsLink').href = `/hackbot/objects?target=${encodeURIComponent(selected)}`;
    const runs = $('behaviourRuns'); runs.replaceChildren();
    for (const run of data.runs) {
      const row = node('tr');
      [formatTime(run.created_at), run.status, run.counts.traffic_examined || 0,
       run.counts.observations_added || 0, run.stop_reason || '—'].forEach(value => cell(row, value));
      const actions = node('td');
      if (['CREATED','READY','RUNNING'].includes(run.status)) actions.append(button('Cancel', async () => {
        if (await mutate(base + '/runs/' + encodeURIComponent(run.run_id) + '/cancel')) await renderBehaviour();
      }, 'quiet'));
      row.append(actions); runs.append(row);
    }
    if (!data.runs.length) empty('behaviourRuns', 'No learning runs yet.', 6);
    if (latest && ['CREATED','READY','RUNNING'].includes(latest.status)) {
      behaviourRefreshTimer = setTimeout(() => {
        if (target === selected && section === 'behaviour') renderBehaviour().catch(error => message(error.message, true));
      }, 4000);
    }
  }

  async function renderOverview() {
    const data = await api('overview');
    const labels = [['targets','Targets'], ['identities','Accounts'], ['browser_sessions','Browser sessions'],
      ['reauth_required','Reauth required'], ['traffic','Captured exchanges'], ['burp','Burp']];
    $('metrics').replaceChildren(...labels.map(([key,label]) => {
      const block = node('div', null, 'metric' + (key === 'reauth_required' ? ' warning' : ''));
      block.append(node('strong', key === 'burp' ? (data[key] === 'BURP_NOT_INSTALLED' ? 'NOT INSTALLED' : data[key]) : data[key]), node('span', label));
      return block;
    }));
    const activity = $('activity'); activity.replaceChildren();
    if (!data.activity.length) { activity.append(node('p', 'No BugHunter activity yet.', 'context-line')); return; }
    data.activity.forEach((item) => {
      const row = node('div', null, 'activity-row');
      row.append(node('time', formatTime(item.occurred_at)), node('span', item.event_type.replaceAll('_',' ')),
        node('small', [short(item.target_id), short(item.identity_id), short(item.session_id)].filter((part) => part !== '—').join(' · ')));
      activity.append(row);
    });
  }
  async function renderOperations() {
    if (operationsRefreshTimer) { clearTimeout(operationsRefreshTimer); operationsRefreshTimer = null; }
    const [data, delta] = await Promise.all([
      api('operations'), api('continuous/status').catch(() => null),
    ]);
    const warnings = $('operationsWarnings'); warnings.replaceChildren();
    if (data.warnings?.length) {
      data.warnings.forEach((value) => warnings.append(node('span', value.replaceAll('_', ' '), 'badge bad')));
    } else if (!delta?.degraded_targets) warnings.append(node('span', 'All reported components healthy', 'badge good'));
    if (delta?.degraded_targets) warnings.append(node('span', `${delta.degraded_targets} delta watchers degraded`, 'badge bad'));
    const measures = [
      [data.state, 'Service'], [data.resources?.disk_used_percent == null ? '—' : `${data.resources.disk_used_percent}%`, 'Storage used'],
      [data.counts?.planner_active, 'Planner runs'], [data.counts?.plan_active, 'Plan runs'],
      [data.counts?.browser_active, 'Browser sessions'], [data.objects?.cleanup_pending, 'Cleanup pending'],
      [data.counts?.findings, 'Findings'], [data.backup?.state, 'Backup'],
      [delta?.enabled_targets, 'Delta watches'], [delta?.backlog_min_count, 'Delta backlog']
    ];
    $('operationsMetrics').replaceChildren(...measures.map(([value, label]) => {
      const block = node('div', null, 'metric');
      block.append(node('strong', value ?? '—'), node('span', label));
      return block;
    }));
    const details = $('operationsDetails'); details.replaceChildren();
    const rows = [
      ['Version', data.version], ['Uptime', `${data.uptime_seconds || 0} seconds`],
      ['Schema', `${data.storage?.schema_actual} / ${data.storage?.schema_expected}`],
      ['Database', `${data.storage?.database_bytes || 0} bytes`],
      ['WAL', `${data.storage?.wal_bytes || 0} bytes`],
      ['Artifacts', `${data.storage?.artifact_count || 0} unique / ${data.storage?.artifact_logical_bytes || 0} bytes`],
      ['Disk free', `${data.resources?.disk_free_bytes || 0} bytes`],
      ['Memory available', `${data.resources?.memory_available_bytes || 0} bytes`],
      ['Burp', data.burp?.status], ['Burp bridge', data.burp?.bridge_connected ? 'Connected' : 'Not connected'],
      ['Burp listeners', `${data.burp?.reachable_listeners || 0} / ${data.burp?.configured_listeners || 0}`],
      ['Owned browser processes', data.processes?.browser_processes],
      ['Suspected browser orphans', data.processes?.suspected_orphan_browser_pids?.length],
      ['Process inventory', data.processes?.state],
      ['Reauth required', data.counts?.browser_reauth_required],
      ['Recon', data.recon], ['Research', data.research],
      ['Delta watcher health', delta ? `${delta.degraded_targets || 0} degraded / ${delta.enabled_targets || 0} enabled` : 'Unavailable'],
      ['Delta watch cycles', delta?.watch_cycles],
      ['Delta last success', delta?.oldest_last_success_at ? formatTime(delta.oldest_last_success_at) : 'Never'],
      ['Notifications pending', data.notifications?.delivery?.pending || 0],
      ['Notifications failed', data.notifications?.delivery?.failed || 0],
      ['Orphan objects', data.objects?.orphaned || 0],
      ['Last backup', data.backup?.backup_id || 'None'],
      ['Backup age', data.backup?.age_hours == null ? 'Unknown' : `${data.backup.age_hours} hours`],
      ['Backup verification', data.backup?.verification || 'Not checked']
      ,['Backup encryption', data.backup?.encryption || 'Unknown']
      ,['Backup generations', data.backup?.keep_generations]
      ,['Retention mode', data.retention?.mode]
      ,['Retention grace', data.retention?.orphan_grace_hours == null ? null : `${data.retention.orphan_grace_hours} hours`]
      ,['Anonymous profile grace', data.retention?.anonymous_profile_grace_hours == null ? null : `${data.retention.anonymous_profile_grace_hours} hours`]
    ];
    rows.forEach(([label, value]) => {
      details.append(node('dt', label), node('dd', value == null ? 'Unknown' : value));
    });
    const backupId = $('operationsBackupId');
    if (!backupId.value && data.backup?.backup_id) backupId.value = data.backup.backup_id;
    renderMaintenance(data.maintenance || {status:'IDLE'});
  }
  function renderMaintenance(task) {
    const busy = operationsPending || ['QUEUED', 'RUNNING'].includes(task.status);
    if (task.status === 'COMPLETED' && task.action === 'RETENTION_PLAN') reviewedRetentionTask = task.id;
    if (task.action === 'RETENTION_RUN') reviewedRetentionTask = null;
    if (task.status === 'COMPLETED' && task.action === 'PROFILE_PLAN') reviewedProfileTask = task.id;
    if (task.action === 'PROFILE_RUN') reviewedProfileTask = null;
    const reviewReady = !busy && task.status === 'COMPLETED' &&
      task.action === 'RETENTION_PLAN' && reviewedRetentionTask === task.id &&
      (task.result?.candidate_count ?? 0) > 0;
    retentionReviewReady = reviewReady;
    profileReviewReady = !busy && task.status === 'COMPLETED' &&
      task.action === 'PROFILE_PLAN' && reviewedProfileTask === task.id &&
      (task.result?.candidate_count ?? 0) > 0;
    document.querySelectorAll('.operations-action').forEach((item) => { item.disabled = busy; });
    $('operationsRetentionRun').disabled = !reviewReady || !$('operationsRetentionConfirm').checked;
    $('operationsProfileRun').disabled = !profileReviewReady || !$('operationsProfileConfirm').checked;
    const info = $('operationsMaintenance');
    info.replaceChildren();
    const candidates = $('operationsCandidates');
    candidates.replaceChildren();
    const summary = task.status === 'IDLE' ? 'No maintenance task has run.' :
      `${(task.action || 'Maintenance').replaceAll('_', ' ')}: ${task.status || 'UNKNOWN'}`;
    info.append(node('strong', summary));
    if (task.reason_code) info.append(node('span', ` · ${task.reason_code.replaceAll('_', ' ')}`));
    if (task.status === 'COMPLETED' && task.action === 'RETENTION_PLAN') {
      info.append(node('span', ` · ${task.result?.candidate_count ?? 0} orphan artifacts · ${task.result?.estimated_bytes ?? 0} estimated bytes`));
      if (task.result?.truncated) info.append(node('span', ' · Bounded batch; run another dry run after cleanup.'));
    }
    if (task.status === 'COMPLETED' && task.action === 'RETENTION_RUN') {
      info.append(node('span', ` · ${task.result?.removed ?? 0} removed · ${task.result?.reclaimed_bytes ?? 0} bytes reclaimed`));
    }
    if (task.status === 'COMPLETED' && task.action === 'PROFILE_PLAN') {
      info.append(node('span', ` · ${task.result?.candidate_count ?? 0} anonymous profiles · ${task.result?.estimated_bytes ?? 0} estimated bytes`));
      if (task.result?.truncated) info.append(node('span', ' · Bounded batch; run another dry run after cleanup.'));
    }
    if (task.status === 'COMPLETED' && ['RETENTION_PLAN', 'PROFILE_PLAN'].includes(task.action)) {
      (task.result?.candidate_preview || []).forEach((item) =>
        candidates.append(node('span', item, 'scope-item')));
      if (task.result?.preview_truncated) candidates.append(node('span', 'More candidates in this bounded batch', 'muted'));
    }
    if (task.status === 'COMPLETED' && task.action === 'PROFILE_RUN') {
      info.append(node('span', ` · ${task.result?.removed ?? 0} profiles removed · ${task.result?.reclaimed_bytes ?? 0} bytes reclaimed`));
    }
    if (task.status === 'COMPLETED' && task.action?.startsWith('BACKUP')) {
      info.append(node('span', ` · ${task.result?.backup_id || 'Backup finished'} · ${task.result?.verified ? 'verified' : 'verification pending'}`));
      if (task.action === 'BACKUP_CREATE' && task.result?.backup_id) $('operationsBackupId').value = task.result.backup_id;
    }
    if (['QUEUED', 'RUNNING'].includes(task.status)) {
      operationsRefreshTimer = setTimeout(() => renderOperations().catch((error) => message(error.message, true)), 3000);
    }
  }
  async function startMaintenance(action) {
    if (operationsPending) return;
    const body = {action};
    if (action === 'BACKUP_VERIFY') {
      body.backup_id = $('operationsBackupId').value.trim();
      if (!body.backup_id) { message('Enter a backup ID to verify.', true); return; }
    }
    if (action === 'RETENTION_RUN') {
      if (!$('operationsRetentionConfirm').checked || !retentionReviewReady ||
          !window.confirm('Delete the reviewed orphan artifacts? This cannot be undone.')) return;
      body.confirmed = true;
      body.review_id = reviewedRetentionTask;
    }
    if (action === 'PROFILE_RUN') {
      if (!$('operationsProfileConfirm').checked || !profileReviewReady ||
          !window.confirm('Delete the reviewed anonymous browser profiles? This cannot be undone.')) return;
      body.confirmed = true;
      body.review_id = reviewedProfileTask;
    }
    operationsPending = true;
    document.querySelectorAll('.operations-action').forEach((item) => { item.disabled = true; });
    try {
      const task = await api('operations/maintenance', {method:'POST', body});
      if (action !== 'RETENTION_PLAN') reviewedRetentionTask = null;
      if (action !== 'PROFILE_PLAN') reviewedProfileTask = null;
      $('operationsRetentionConfirm').checked = false;
      $('operationsProfileConfirm').checked = false;
      message(`${action.replaceAll('_', ' ')} queued.`);
      renderMaintenance(task);
    } catch (error) { message(error.message, true); }
    finally {
      operationsPending = false;
      renderOperations().catch((error) => message(error.message, true));
    }
  }
  async function renderAuthorization() {
    if (!requireTarget()) return;
    const base = `authorization/${encodeURIComponent(target)}`;
    const [profile, hunts, candidates, matrix, metrics] = await Promise.all([
      api(`${base}/profile`), api(`${base}/hunts?limit=20`),
      api(`${base}/candidates?limit=20`), api(`${base}/matrix?limit=50`),
      api(`${base}/metrics`),
    ]);
    $('authorizationMetrics').textContent =
      `${metrics.candidates} candidates · ${metrics.plans} plans · ${metrics.executed_plans} runs · ` +
      `${metrics.confirmed} confirmed · ${metrics.rejected} rejected · ${metrics.manual_reviews} review · ` +
      `${metrics.mutation_candidates ?? 0} mutation candidates (${metrics.mutation_plans ?? 0} planned) · ` +
      `${metrics.nested_candidates ?? 0} nested · ` +
      `${metrics.batch_candidates ?? 0} batch · ${metrics.typed_mutations?.readback_failures ?? 0} read-back failures · ` +
      `${metrics.requests_used} requests · ${metrics.cleanup_pending} cleanup pending · ` +
      `${metrics.cleanup_failures} cleanup failures`;
    const huntRows = $('authorizationHuntRows'); huntRows.replaceChildren();
    if (!hunts.items.length) empty('authorizationHuntRows', 'No authorization hunts yet.', 6);
    hunts.items.forEach((hunt) => {
      const row = node('tr');
      cell(row, formatTime(hunt.created_at)); cell(row, hunt.mode); cell(row).append(badge(hunt.status));
      cell(row, hunt.candidate_limit); cell(row, hunt.request_budget);
      const actions = cell(row);
      if (['READY', 'RUNNING', 'PAUSED'].includes(hunt.status)) {
        actions.append(button('Pause', async () => {
          if (await mutate(`${base}/hunts/${hunt.id}/pause`)) await renderAuthorization();
        }, 'quiet'));
        actions.append(button('Cancel', async () => {
          if (!confirm('Cancel this authorization hunt?')) return;
          if (await mutate(`${base}/hunts/${hunt.id}/cancel`)) await renderAuthorization();
        }, 'quiet'));
      }
      huntRows.append(row);
    });
    const actorRows = $('authorizationIdentityRows'); actorRows.replaceChildren();
    if (!profile.identities.length) empty('authorizationIdentityRows', 'No active identities.', 5);
    profile.identities.forEach((actor) => {
      const row = node('tr'); cell(row, actor.alias); cell(row, short(actor.principal_id));
      cell(row, actor.observed_tenants.map((value) => short(value)).join(', ') || 'Unverified');
      cell(row, actor.observed_roles.map((value) => short(value)).join(', ') || '—');
      cell(row).append(badge(actor.verified_session_id ? 'VALID' : 'UNVERIFIED'));
      actorRows.append(row);
    });
    const objectRows = $('authorizationObjectRows'); objectRows.replaceChildren();
    if (!profile.objects.length) empty('authorizationObjectRows', 'No verified disposable objects.', 5);
    profile.objects.forEach((object) => {
      const row = node('tr'); cell(row, short(object.id, 20), 'mono'); cell(row, object.object_type);
      cell(row, short(object.owner_identity_id)); cell(row, short(object.tenant_id));
      const refs = cell(row);
      refs.append(node('span', object.fact_ids.length + ' facts / ' + object.evidence_ids.length + ' evidence'));
      if (object.evidence_ids.length) refs.append(button('Evidence', () => showAuthorizationEvidence(object.evidence_ids[0]), 'quiet'));
      objectRows.append(row);
    });
    const candidateRows = $('authorizationCandidateRows'); candidateRows.replaceChildren();
    if (!candidates.items.length) empty('authorizationCandidateRows', 'No eligible candidates.', 8);
    candidates.items.forEach((candidate) => {
      const row = node('tr'); cell(row, candidate.score);
      const boundary = cell(row); boundary.append(node('span', candidate.boundary));
      if (candidate.test_type) boundary.append(badge(candidate.test_type));
      cell(row, short(candidate.test_object_id)); cell(row, short(candidate.boundary_identity_id));
      cell(row, candidate.reasons.join(', '));
      const status = cell(row); status.append(badge(candidate.status));
      if (candidate.readback_status) status.append(badge(`Boundary: ${candidate.readback_status}`));
      if (candidate.restore_status) status.append(badge(`Restore: ${candidate.restore_status}`));
      const links = cell(row);
      if (candidate.plan_id) {
        const link = node('a', 'Plan', 'text-action');
        link.href = `/hackbot/plans?target=${encodeURIComponent(target)}&plan=${encodeURIComponent(candidate.plan_id)}`;
        links.append(link);
      }
      if (candidate.run_id) {
        const link = node('a', 'Run', 'text-action');
        link.href = `/hackbot/runs?target=${encodeURIComponent(target)}&run=${encodeURIComponent(candidate.run_id)}`;
        links.append(link);
      }
      if (candidate.evidence_ids?.length) {
        links.append(button('Evidence', () => showAuthorizationEvidence(candidate.evidence_ids[0]), 'quiet'));
      }
      const actions = cell(row);
      if (['CANDIDATE', 'NEEDS_OBJECT', 'NEEDS_SESSION', 'NEEDS_TEMPLATE'].includes(candidate.status)) {
        actions.append(button('Prepare', async () => {
          if (await mutate(`${base}/candidates/${candidate.id}/prepare`)) await renderAuthorization();
        }, 'quiet'));
      } else if (candidate.status === 'PLANNED') {
        actions.append(button('Start', async () => {
          if (!confirm('Start this bounded authorization plan?')) return;
          if (await mutate(`${base}/candidates/${candidate.id}/start`)) await renderAuthorization();
        }, 'quiet'));
      } else if (candidate.status === 'RUNNING') {
        actions.append(button('Advance', async () => {
          if (await mutate(`${base}/candidates/${candidate.id}/advance`)) await renderAuthorization();
        }, 'quiet'));
      }
      candidateRows.append(row);
    });
    const matrixRows = $('authorizationMatrixRows'); matrixRows.replaceChildren();
    if (!matrix.items.length) empty('authorizationMatrixRows', 'No observed comparisons.', 7);
    matrix.items.forEach((entry) => {
      const row = node('tr'); cell(row, formatTime(entry.observed_at));
      cell(row, short(entry.identity_id)); cell(row, short(entry.operation_key));
      cell(row, short(entry.test_object_id)); cell(row, short(entry.tenant_id));
      cell(row).append(badge(entry.result));
      const refs = cell(row);
      refs.append(node('span', short(entry.exchange_id, 20) + ' / ' +
        entry.evidence_ids.map((value) => short(value, 16)).join(', '), 'mono'));
      if (entry.evidence_ids.length) refs.append(button('Evidence', () => showAuthorizationEvidence(entry.evidence_ids[0]), 'quiet'));
      matrixRows.append(row);
    });
  }
  async function showAuthorizationEvidence(id) {
    try {
      const ref = await api(`evidence/${encodeURIComponent(id)}?${targetQuery()}`);
      detailPairs($('authorizationEvidenceDetail'), [
        ['Evidence ID', ref.evidence_id], ['Type', ref.type],
        ['Observed', formatTime(ref.observed_at)], ['Source', ref.source],
        ['Content hash', ref.content_hash], ['Content kind', ref.content_kind],
        ['Content size', ref.content_size], ['Sensitivity', ref.sensitivity],
        ['Redaction', ref.redaction_status],
      ]);
      $('authorizationEvidenceDialog').showModal();
    } catch (error) { message(error.message, true); }
  }
  async function renderApi() {
    if (!requireTarget()) return;
    apiOperationCursor = null;
    apiCandidateCursor = null;
    $('moreApiOperations').hidden = true;
    $('moreApiCandidates').hidden = true;
    const selected = target;
    const base = `api/${encodeURIComponent(selected)}`;
    const state = $('apiOperationState').value;
    const [coverage, operations, candidates] = await Promise.all([
      api(`${base}/coverage`),
      api(`${base}/operations?limit=50&state=${encodeURIComponent(state)}`),
      api(`${base}/candidates?limit=50`),
    ]);
    if (selected !== target || state !== $('apiOperationState').value) return;
    $('apiCoverageNote').textContent = coverage.coverage_note || '';
    const counts = coverage.counts || {};
    const outcome = coverage.metrics || {};
    const metrics = [
      ['Current', counts.operations_current || 0], ['Stale', counts.operations_stale || 0],
      ['Queries', coverage.queries || 0], ['Mutations', coverage.mutations || 0],
      ['Candidates', counts.candidates || 0], ['Ready', counts.candidates_ready || 0],
      ['Tested', counts.operations_tested || 0], ['Blocked', counts.operations_blocked || 0],
      ['Validated', counts.operations_validated || 0], ['Confirmed', outcome.confirmed || 0],
      ['Rejected', outcome.rejected || 0], ['Review', outcome.manual_review || 0],
    ];
    $('apiMetrics').replaceChildren(...metrics.map(([label, value]) => {
      const item = node('div', null, 'metric');
      item.append(node('strong', value), node('span', label));
      return item;
    }));
    $('apiOperationRows').replaceChildren();
    $('apiCandidateRows').replaceChildren();
    appendApiOperations(operations.items || [], selected);
    appendApiCandidates(candidates.items || [], selected);
    apiOperationCursor = operations.next_cursor || null;
    apiCandidateCursor = candidates.next_cursor || null;
    $('moreApiOperations').hidden = !apiOperationCursor;
    $('moreApiCandidates').hidden = !apiCandidateCursor;
    if (!(operations.items || []).length) empty('apiOperationRows', `No ${state.toLowerCase()} operations recorded.`, 9);
    if (!(candidates.items || []).length) empty('apiCandidateRows', 'No API authorization candidates yet.', 8);
  }
  function appendApiOperations(items, selected) {
    const operationRows = $('apiOperationRows');
    for (const item of items) {
      const row = node('tr');
      cell(row, item.name); cell(row, item.type);
      cell(row, `${item.method} ${item.endpoint}`, 'mono'); cell(row, item.feature);
      cell(row, (item.role_ids || []).map(value => short(value, 16)).join(', ') || 'Unknown');
      cell(row, (item.tenant_ids || []).map(value => short(value, 16)).join(', ') || 'Unknown');
      cell(row, (item.exchange_ids || []).length);
      cell(row).append(badge(item.state));
      cell(row).append(button('Inspect', () => openApiOperation(selected, item.id).catch(error => message(error.message, true))));
      operationRows.append(row);
    }
  }
  function appendApiCandidates(items, selected) {
    const candidateRows = $('apiCandidateRows');
    const base = `api/${encodeURIComponent(selected)}`;
    for (const item of items) {
      const row = node('tr');
      cell(row, item.score); cell(row, item.category);
      cell(row, short(item.operation_id, 22), 'mono');
      cell(row, short(item.boundary_identity_id, 20));
      cell(row, [short(item.test_object_id, 20), item.field_path].filter(value => value && value !== '—').join(' / ') || '—');
      cell(row).append(badge(item.status));
      const links = cell(row);
      if (item.plan_id) {
        const link = node('a', 'Plan', 'text-action');
        link.href = `/hackbot/plans?target=${encodeURIComponent(selected)}&plan=${encodeURIComponent(item.plan_id)}`;
        links.append(link);
      }
      if (item.run_id) {
        const link = node('a', 'Run', 'text-action');
        link.href = `/hackbot/runs?target=${encodeURIComponent(selected)}&run=${encodeURIComponent(item.run_id)}`;
        links.append(link);
      }
      const actions = cell(row);
      const refresh = async (action) => {
        if (await mutate(`${base}/candidates/${encodeURIComponent(item.id)}/${action}`)) await renderApi();
      };
      if (['CANDIDATE', 'READY', 'PLAN_ONLY', 'REVIEW'].includes(item.status)) {
        actions.append(button('Prepare', () => refresh('prepare'), 'quiet'));
      } else if (item.status === 'PLANNED') {
        actions.append(button('Start', async () => {
          if (confirm('Start this bounded API authorization plan?')) await refresh('start');
        }, 'quiet'));
      } else if (item.status === 'RUNNING') {
        actions.append(button('Advance', () => refresh('advance'), 'quiet'));
      }
      candidateRows.append(row);
    }
  }
  async function loadMoreApiOperations() {
    if (!target || !apiOperationCursor) return;
    const selected = target;
    const state = $('apiOperationState').value;
    const cursor = apiOperationCursor;
    $('moreApiOperations').disabled = true;
    let page;
    try {
      page = await api(`api/${encodeURIComponent(selected)}/operations?limit=50&state=${encodeURIComponent(state)}&cursor=${encodeURIComponent(cursor)}`);
    } finally {
      $('moreApiOperations').disabled = false;
    }
    if (selected !== target || state !== $('apiOperationState').value || cursor !== apiOperationCursor) return;
    appendApiOperations(page.items || [], selected);
    apiOperationCursor = page.next_cursor || null;
    $('moreApiOperations').hidden = !apiOperationCursor;
  }
  async function loadMoreApiCandidates() {
    if (!target || !apiCandidateCursor) return;
    const selected = target;
    const cursor = apiCandidateCursor;
    $('moreApiCandidates').disabled = true;
    let page;
    try {
      page = await api(`api/${encodeURIComponent(selected)}/candidates?limit=50&cursor=${encodeURIComponent(cursor)}`);
    } finally {
      $('moreApiCandidates').disabled = false;
    }
    if (selected !== target || cursor !== apiCandidateCursor) return;
    appendApiCandidates(page.items || [], selected);
    apiCandidateCursor = page.next_cursor || null;
    $('moreApiCandidates').hidden = !apiCandidateCursor;
  }
  async function openApiOperation(selected, operationId) {
    const detail = await api(`api/${encodeURIComponent(selected)}/operations/${encodeURIComponent(operationId)}`);
    if (selected !== target) return;
    apiOperationDetail = {target: selected, operationId};
    apiOperationCandidateCursor = detail.next_cursor || null;
    $('moreApiOperationCandidates').hidden = !apiOperationCandidateCursor;
    const operation = detail.operation;
    $('apiOperationTitle').textContent = operation.name;
    detailPairs($('apiOperationDetail'), [
      ['Type', operation.type], ['Endpoint', `${operation.method} ${operation.endpoint}`],
      ['Feature', operation.feature], ['Variables', (operation.variables || []).join(', ')],
      ['Input types', (operation.input_types || []).join(', ')],
      ['Observed identities', (operation.identity_ids || []).map(value => short(value, 24)).join(', ')],
      ['Observed roles', (operation.role_ids || []).map(value => short(value, 24)).join(', ')],
      ['Observed tenants', (operation.tenant_ids || []).map(value => short(value, 24)).join(', ')],
      ['Source asset hash', operation.source_asset_hash || 'None'],
      ['Source references', (operation.source_refs || []).join(', ') || 'None'],
      ['Returned types', (operation.returned_object_types || []).join(', ')],
      ['Document evidence', operation.document_evidence_id],
      ['Traffic exchanges', (operation.exchange_ids || []).join(', ') || 'None'],
      ['Evidence', (operation.evidence_ids || []).join(', ') || 'None'],
      ['Version', operation.version_hash], ['Last seen', formatTime(operation.last_seen)],
    ]);
    const fields = $('apiOperationFields'); fields.replaceChildren();
    for (const field of (operation.fields || []).slice(0, 80)) {
      fields.append(node('div', `${field.path} · ${field.parent_type || 'UNKNOWN'} → ${field.nested_type || 'UNKNOWN'} · ${field.sensitivity || 'UNKNOWN'} · roles: ${(field.observed_role_ids || []).join(', ') || 'not observed'}`, 'plan-line'));
    }
    if (!fields.children.length) fields.append(node('p', 'No field structure recorded.', 'muted'));
    const candidateList = $('apiOperationCandidates'); candidateList.replaceChildren();
    appendApiOperationCandidates(detail.candidates || []);
    if (!candidateList.children.length) candidateList.append(node('p', 'No candidate hypotheses recorded.', 'muted'));
    $('apiOperationDialog').showModal();
  }
  function appendApiOperationCandidates(items) {
    const list = $('apiOperationCandidates');
    for (const candidate of items) {
      list.append(node('div', `${candidate.category} · ${candidate.status} · ${candidate.reasons.join(', ')}${candidate.gaps.length ? ' · Gaps: ' + candidate.gaps.join(', ') : ''}`, 'plan-line'));
    }
  }
  async function loadMoreApiOperationCandidates() {
    if (!apiOperationDetail || !apiOperationCandidateCursor) return;
    const {target: selected, operationId} = apiOperationDetail;
    const cursor = apiOperationCandidateCursor;
    $('moreApiOperationCandidates').disabled = true;
    let page;
    try {
      page = await api(`api/${encodeURIComponent(selected)}/candidates?limit=50&operation_id=${encodeURIComponent(operationId)}&cursor=${encodeURIComponent(cursor)}`);
    } finally {
      $('moreApiOperationCandidates').disabled = false;
    }
    if (selected !== target || apiOperationDetail?.operationId !== operationId ||
        cursor !== apiOperationCandidateCursor) return;
    appendApiOperationCandidates(page.items || []);
    apiOperationCandidateCursor = page.next_cursor || null;
    $('moreApiOperationCandidates').hidden = !apiOperationCandidateCursor;
  }
  async function loadAccounts(reset = false) {
    if (!requireTarget()) { empty('accountRows', 'Select a target package.', 7); return; }
    if (reset) { accounts = []; accountCursor = null; }
    const query = new URLSearchParams({limit:'20'});
    if (accountCursor) query.set('cursor', accountCursor);
    const page = await api(`targets/${encodeURIComponent(target)}/identities?${query}`);
    accounts.push(...page.items); accountCursor = page.next_cursor;
    $('moreAccounts').hidden = !accountCursor;
    const body = $('accountRows'); body.replaceChildren();
    const select = $('sessionIdentity'); select.replaceChildren(optionPlaceholder('Select identity'));
    const trafficSelect = $('trafficIdentity'); trafficSelect.replaceChildren(node('option', 'All'));
    trafficSelect.firstChild.value = '';
    if (!accounts.length) { empty('accountRows', 'No identities registered. Import package accounts to begin.', 7); return; }
    for (const item of accounts) {
      const identity = item.identity;
      option(select, identity.id, identity.alias);
      option(trafficSelect, identity.id, identity.alias);
      const row = node('tr');
      cell(row, identity.alias); cell(row, identity.principal_id ? short(identity.principal_id) : 'Unverified', 'mono');
      cell(row, item.memberships.map((member) => `${member.tenant || short(member.tenant_id)}: ${member.roles.join(', ') || 'no role'}`).join(' / ') || '—');
      cell(row).append(badge(identity.status));
      cell(row).append(badge(item.auth?.status || 'UNPREPARED'));
      cell(row).append(badge(item.browser?.status || 'NONE'));
      const action = cell(row);
      if (!item.auth) action.append(button('Prepare auth', async () => {
        if (await mutate(`identities/${identity.id}/prepare-auth`, {target, mechanism:'MANUAL_LOGIN'})) await loadAccounts(true);
      }));
      else if (identity.status === 'ACTIVE') action.append(button('Create session', async () => {
        if (await mutate('browser/sessions', {target, identity_id:identity.id})) location.href = `/hackbot/sessions?target=${encodeURIComponent(target)}`;
      }));
      body.append(row);
    }
  }
  async function loadSessions(reset = false) {
    if (!requireTarget()) { empty('sessionRows', 'Select a target package.', 9); return; }
    if (reset) { sessions = []; sessionCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    if (sessionCursor) query.set('cursor', sessionCursor);
    const page = await api('browser/sessions?' + query);
    sessions.push(...page.items); sessionCursor = page.next_cursor;
    $('moreSessions').hidden = !sessionCursor;
    const trafficSelect = $('trafficSession'); trafficSelect.replaceChildren(node('option', 'All'));
    trafficSelect.firstChild.value = '';
    const body = $('sessionRows'); body.replaceChildren();
    if (!sessions.length) { empty('sessionRows', 'No browser sessions for this target.', 9); return; }
    for (const item of sessions) {
      option(trafficSelect, item.id, short(item.id, 18));
      const identity = accounts.find((record) => record.identity.id === item.identity_id)?.identity.alias || (item.identity_id ? short(item.identity_id) : 'Anonymous');
      const row = node('tr');
      cell(row, short(item.id, 18), 'mono'); cell(row, identity);
      cell(row).append(badge(item.status)); cell(row).append(badge(item.verification_status));
      cell(row, formatTime(item.created_at)); cell(row, formatTime(item.last_verified_at));
      cell(row, item.proxy_enabled ? (item.proxy_capture_required ? 'Capture required' : 'Proxy') : 'Direct');
      const loginCell = cell(row);
      if (item.status === 'WAITING_LOGIN') {
        loginCell.append(node('span', 'Login required', 'badge warn'));
        if (item.vnc_available && item.vnc_url) {
          loginCell.append(' ', button('Open VNC', () => {
            const url = new URL(item.vnc_url);
            if (url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.pathname === '/vnc.html') {
              url.searchParams.set('autoconnect', 'true'); url.searchParams.set('resize', 'scale');
              window.open(url.href, '_blank', 'noopener,noreferrer');
            }
          }));
        }
      } else loginCell.append(node('span', item.vnc_available ? 'Available' : '—', 'muted'));
      const actions = cell(row); actions.className = 'cell-actions';
      const path = `browser/sessions/${item.id}`;
      if (['CREATED','STOPPED','FAILED','REAUTH_REQUIRED','EXPIRED'].includes(item.status)) actions.append(button('Start', async () => {
        if (await mutate(path + '/start?' + targetQuery())) await loadSessions(true);
      }));
      if (item.status === 'WAITING_LOGIN') actions.append(button('Login complete', async () => {
        if (await mutate(path + '/login-complete?' + targetQuery())) await loadSessions(true);
      }));
      if (['VERIFYING_IDENTITY','NEEDS_MANUAL_REVIEW'].includes(item.status)) actions.append(button('Verify', async () => {
        if (await mutate(path + '/verify?' + targetQuery())) await loadSessions(true);
      }));
      if (item.status === 'NEEDS_MANUAL_REVIEW' && item.identity_id && identity &&
          Object.prototype.hasOwnProperty.call(item, 'verification_method')) {
        actions.append(button('Confirm identity', async () => {
          const confirmedAlias = window.prompt(`Confirm the account currently logged in as ${identity}. Type its exact alias:`, '');
          if (confirmedAlias === null) return;
          if (confirmedAlias !== identity) {
            message('The alias did not match this browser session.', true);
            return;
          }
          if (await mutate(path + '/confirm-identity?' + targetQuery(), {confirm_alias: confirmedAlias})) {
            await loadSessions(true);
          }
        }));
      }
      if (item.browser_running) actions.append(button('Stop', async () => {
        if (await mutate(path + '/stop?' + targetQuery())) await loadSessions(true);
      }));
      if (cleanupAvailable) {
        const remove = button('Delete', async () => {
          if (!window.confirm('Delete browser session?\n\nThis will stop the browser and release its Burp/VNC resources. Previously captured evidence will be retained.')) return;
          remove.disabled = true;
          try {
            await api(path + '?' + targetQuery(), {method:'DELETE'});
            message('Browser session deleted. Captured evidence was retained.');
            await loadSessions(true);
          } catch (error) { message(error.message, true); remove.disabled = false; }
        }, 'danger');
        remove.title = 'Delete browser session and release resources';
        actions.append(remove);
      }
      body.append(row);
    }
  }
  function trafficFilters() {
    const out = new URLSearchParams({target, limit:'20'});
    new FormData($('trafficFilters')).forEach((value, key) => { if (value) out.set(key, value); });
    return out;
  }
  async function loadTraffic(reset = false) {
    if (!requireTarget()) { empty('trafficRows', 'Select a target package.', 9); return; }
    if (reset) { traffic = []; trafficCursor = null; }
    const query = trafficFilters();
    if (trafficCursor) query.set('cursor', trafficCursor);
    const page = await api('traffic?' + query);
    traffic.push(...page.items); trafficCursor = page.next_cursor;
    $('moreTraffic').hidden = !trafficCursor;
    const body = $('trafficRows'); body.replaceChildren();
    if (!traffic.length) { empty('trafficRows', 'No captured exchanges match these filters.', 9); }
    for (const item of traffic) {
      const request = item.request;
      const label = item.attribution.verified_identity_id || item.attribution.declared_identity_id;
      const identity = accounts.find((record) => record.identity.id === label)?.identity.alias || (label ? short(label) : 'Anonymous');
      const tenant = item.attribution.declared_tenant_ids?.map((value) => short(value)).join(', ') || '—';
      const row = node('tr');
      cell(row, formatTime(item.observed_at)); cell(row, `${identity} / ${tenant}`);
      cell(row, request.method); cell(row, request.origin + request.display_path, 'mono');
      cell(row, item.response?.status_code ?? '—'); cell(row, item.source);
      cell(row, short(request.structural_fingerprint, 14), 'mono');
      cell(row).append(badge(item.scope_result));
      cell(row).append(button('Details', () => showTrafficDetail(item.id)));
      body.append(row);
    }
    $('trafficSummary').textContent = `${traffic.length} loaded${trafficCursor ? ' · more available' : ''}`;
  }
  async function showTrafficDetail(id) {
    const data = await api(`traffic/${encodeURIComponent(id)}?${targetQuery()}`);
    const req = data.request, res = data.response, attr = data.attribution;
    detailPairs($('trafficDetail'), [
      ['Exchange', data.id], ['Observed', formatTime(data.observed_at)],
      ['Method', req.method], ['Safe URL shape', req.origin + req.display_path],
      ['Status', res?.status_code ?? '—'], ['Identity state', attr.auth_state],
      ['Identity ID', attr.verified_identity_id || attr.declared_identity_id],
      ['Session ID', attr.browser_session_id], ['Declared tenants', attr.declared_tenant_ids?.join(', ')],
      ['Capture source', `${data.source} / ${data.capture_provider}`],
      ['Scope', data.scope_result], ['Content type', res?.content_type || req.content_type],
      ['Request body hash', req.body_hash], ['Response body hash', res?.body_hash],
      ['Fingerprint', req.structural_fingerprint], ['Evidence IDs', data.evidence_ids.join(', ')],
    ]);
    $('trafficDialog').showModal();
  }
  async function renderScope() {
    if (!requireTarget()) { $('scopeContent').replaceChildren(node('p', 'Select a target package.', 'context-line')); return; }
    const data = await api(`targets/${encodeURIComponent(target)}/policy`);
    const autonomy = node('dl', null, 'details');
    const rate = node('dl', null, 'details');
    detailPairs(autonomy, Object.entries(data.autonomy).map(([key, value]) => [key.replaceAll('_', ' '), String(value)]));
    detailPairs(rate, Object.entries(data.rate).map(([key, value]) => [key.replaceAll('_', ' '), value]));
    $('scopeContent').replaceChildren(node('h2', 'Included hosts'), simpleList(data.scope.include_hosts),
      node('h2', 'Excluded hosts'), simpleList(data.scope.exclude_hosts, 'exclude'),
      node('h2', 'Included paths'), simpleList(data.scope.include_paths),
      node('h2', 'Excluded paths'), simpleList(data.scope.exclude_paths, 'exclude'),
      node('h2', 'Autonomy'), autonomy, node('h2', 'Rate limits'), rate);
  }
  async function loadApprovals(reset = false) {
    if (!requireTarget()) { empty('approvalRows', 'Select a target package.', 11); return; }
    if (reset) { approvals = []; approvalCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    if (approvalCursor) query.set('cursor', approvalCursor);
    const page = await api('approvals?' + query);
    approvals.push(...page.items);
    approvalCursor = page.next_cursor;
    $('moreApprovals').hidden = !approvalCursor;
    const body = $('approvalRows'); body.replaceChildren();
    if (!approvals.length) { empty('approvalRows', 'No approval requests for this target.', 11); return; }
    for (const item of approvals) {
      const row = node('tr');
      cell(row, short(item.target_id));
      cell(row, short(item.hypothesis_id || item.action_id, 22), 'mono');
      const linked = cell(row);
      if (item.plan_run) {
        linked.append(button(short(item.plan_run.run_id), () => openRun(item.plan_run.run_id)));
        linked.append(button('Review action', () => showMutationApproval(item.plan_run.run_id), 'quiet'));
      }
      else linked.textContent = '—';
      cell(row, item.operation || item.category);
      cell(row).append(badge(item.risk));
      cell(row, item.reason_code.replaceAll('_', ' '));
      cell(row, item.identity_id ? short(item.identity_id) : 'Anonymous');
      cell(row, item.object_type || (item.object_ref_hash ? short(item.object_ref_hash) : '—'));
      cell(row, formatTime(item.created_at));
      cell(row).append(badge(item.status));
      const actions = cell(row); actions.className = 'cell-actions';
      if (item.status === 'PENDING') {
        actions.append(button('Approve once', async () => {
          if (!window.confirm('Approve this exact action once?')) return;
          if (await mutate(`approvals/${item.id}/approve`, {target})) await loadApprovals(true);
        }));
        actions.append(button('Reject', async () => {
          if (await mutate(`approvals/${item.id}/reject`, {target})) await loadApprovals(true);
        }));
      }
      body.append(row);
    }
  }
  async function showMutationApproval(runId) {
    try {
      if (!$('mutationApprovalDialog')) { message('Refresh the dashboard after the UI update.', true); return; }
      const data = await api(`runs/${encodeURIComponent(runId)}?${targetQuery()}`);
      const preview = data.mutation_approval;
      if (!preview) { message('This run has no typed mutation review.', true); return; }
      detailPairs($('mutationApprovalDetail'), [
        ['Object', preview.object_id], ['Type', preview.object_type],
        ['Field / action', `${preview.field} / ${preview.action}`],
        ['Before', preview.old_summary], ['Intended after', preview.new_summary],
        ['Acting identity', preview.acting_identity_id], ['Risk', preview.risk],
        ['Disposable', preview.disposable ? 'Verified test object' : 'Not verified'],
        ['Current state', preview.object_state], ['Cleanup', preview.cleanup_strategy],
        ['Recipe current', preview.recipe_current ? 'Yes' : 'No'],
      ]);
      $('mutationApprovalDialog').showModal();
    } catch (error) { message(error.message, true); }
  }
  async function renderBurp() {
    const query = target ? '?' + targetQuery() : '';
    const data = await api('burp/status' + query);
    const installed = data.availability !== 'BURP_NOT_INSTALLED';
    const healthy = installed && ['BURP_RUNNING', 'BRIDGE_CONNECTED'].includes(data.status);
    $('burpState').textContent = installed ? data.status : 'NOT INSTALLED';
    $('burpState').style.color = healthy ? 'var(--accent)' : 'var(--amber)';
    $('burpDetail').textContent = installed ? data.availability : 'Burp Suite is not installed on this VPS.';
    detailPairs($('burpMetrics'), [['Availability', data.availability], ['Version', data.installed_version || 'Unknown'],
      ['Bridge', data.bridge_connected ? 'Connected' : 'Disconnected'],
      ['Burp listeners', `${data.proxy_listeners_reachable ?? 0} reachable / ${data.proxy_listener_capacity ?? 0} configured`],
      ['Assigned to target', `${data.reachable_listeners ?? 0} reachable / ${data.configured_listeners ?? 0} assigned`],
      ['Captured exchanges', data.captured_exchanges],
      ['Last capture', formatTime(data.last_capture_at)]]);
  }
  async function loadHypotheses(reset = false) {
    if (!requireTarget()) { empty('hypothesisRows', 'Select a target package.', 8); return; }
    if (reset) { hypotheses = []; hypothesisCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    new FormData($('hypothesisFilters')).forEach((value, key) => { if (value) query.set(key, value); });
    if (hypothesisCursor) query.set('cursor', hypothesisCursor);
    const page = await api('hypotheses?' + query);
    hypotheses.push(...page.items); hypothesisCursor = page.next_cursor;
    $('moreHypotheses').hidden = !hypothesisCursor;
    const body = $('hypothesisRows'); body.replaceChildren();
    if (!hypotheses.length) { empty('hypothesisRows', 'No hypotheses yet. Profile this target or add a manual hypothesis.', 8); return; }
    hypotheses.sort((a, b) => b.priority - a.priority || a.created_at.localeCompare(b.created_at));
    for (const item of hypotheses) {
      const row = node('tr');
      cell(row, item.priority); cell(row, item.category); cell(row, item.statement);
      cell(row).append(node('span', 'HYPOTHESIS', 'stage hypothesis'), badge(item.status)); cell(row, item.evidence_count);
      cell(row, item.prerequisite_state); cell(row, formatTime(item.created_at));
      const actions = cell(row); actions.className = 'cell-actions';
      actions.append(button('Details', () => showHypothesis(item.id)));
      if (cleanupAvailable) actions.append(button('Archive', async () => {
        if (!window.confirm('Archive this hypothesis? Its history and evidence will remain available.')) return;
        if (await mutate(`hypotheses/${encodeURIComponent(item.id)}/archive`, {target})) await loadHypotheses(true);
      }, 'quiet'));
      body.append(row);
    }
  }
  async function showHypothesis(id) {
    const data = await api(`hypotheses/${encodeURIComponent(id)}?${targetQuery()}`);
    const item = data.hypothesis;
    selectedHypothesis = id;
    detailPairs($('hypothesisDetail'), [
      ['Statement', item.statement], ['Category', item.category], ['Priority', item.priority],
      ['Status', item.status], ['Potential impact', item.potential_impact],
      ['Why generated', item.why_generated], ['Evidence IDs', item.evidence_ids.join(', ') || 'None (manual)'],
      ['Fact IDs', item.fact_ids.join(', ') || 'None'], ['Prerequisites', item.prerequisites.join('; ')],
      ['Missing', item.missing.join('; ') || 'None'], ['Future experiment', item.future_experiment],
      ['Positive signal', item.positive_signal], ['Negative signal', item.negative_signal],
      ['Skill tags', item.skill_tags.join(', ') || 'None'], ['History events', data.history.length],
    ]);
    const recommended = $('recommendedSkills'); recommended.replaceChildren();
    const candidates = data.recommended_skills || [];
    if (!candidates.length) recommended.append(node('span', 'No matching skill yet', 'muted'));
    for (const candidate of candidates) {
      const part = node('div', null, 'skill-recommendation');
      part.append(node('strong', candidate.skill.name), badge(candidate.prerequisites.state),
        node('span', candidate.prerequisites.missing.length ? `Missing: ${candidate.prerequisites.missing.join(', ')}` : 'Prerequisites ready'),
        button('Generate plan', () => generatePlan(id, candidate.skill.name, false)));
      recommended.append(part);
    }
    await ensureSkills();
    const select = $('manualSkillSelect');
    const placeholder = node('option', 'Select skill'); placeholder.value = '';
    select.replaceChildren(placeholder);
    skillCatalog.forEach((skill) => option(select, skill.name, skill.name));
    $('hypothesisDialog').showModal();
  }
  async function ensureSkills() {
    if (!skillCatalog.length) skillCatalog = (await api('skills')).items;
    return skillCatalog;
  }
  async function loadSkills() {
    const body = $('skillRows'); body.replaceChildren();
    const skills = await ensureSkills();
    if (!skills.length) { empty('skillRows', 'No skills installed.', 9); return; }
    for (const skill of skills) {
      const row = node('tr');
      cell(row, skill.name); cell(row, skill.category); cell(row, skill.source);
      cell(row, skill.version); cell(row, skill.triggers.join(', '));
      cell(row).append(badge(skill.risk)); cell(row, skill.request_budget);
      cell(row, skill.usage_count); cell(row).append(button('Details', () => showSkill(skill.name)));
      body.append(row);
    }
  }
  async function showSkill(id) {
    const skill = await api('skills/' + encodeURIComponent(id));
    $('skillDialogTitle').textContent = skill.name;
    detailPairs($('skillDetail'), [
      ['Description', skill.description], ['When to use', skill.when_to_use],
      ['When not to use', skill.when_not_to_use], ['Category', skill.category],
      ['Source / version', `${skill.source} / ${skill.version}`], ['Risk', skill.risk],
      ['Prerequisites', skill.prerequisites.join(', ')], ['Controls', skill.controls.join('; ')],
      ['Confirmation', skill.confirmation_requirements.join('; ')],
      ['Rejection', skill.rejection_conditions.join('; ')],
      ['Request budget', skill.request_budget], ['Token budget', skill.token_budget],
      ['Validation outcomes', Object.entries(skill.validation_outcomes || {})
        .map(([status, count]) => `${status}: ${count}`).join(', ')],
      ['Content hash', skill.content_hash],
    ]);
    $('skillWorkflow').replaceChildren(...skill.workflow.map((step) => node('div', `${step.type}: ${step.description}`, 'plan-line')));
    $('skillDialog').showModal();
  }
  async function generatePlan(hypothesisId, skillId, manual) {
    if (!requireTarget()) return;
    try {
      const body = {target};
      body.skill_id = skillId;
      body.selection = manual ? 'MANUAL' : 'RECOMMENDED';
      const plan = await api(`hypotheses/${encodeURIComponent(hypothesisId)}/plan`, {method:'POST', body});
      $('hypothesisDialog').close();
      location.href = `/hackbot/plans?target=${encodeURIComponent(target)}&plan=${encodeURIComponent(plan.id)}`;
    } catch (error) { message(error.message, true); }
  }
  async function loadPlan() {
    if (!requireTarget()) return;
    const id = params.get('plan');
    if (!id) {
      $('startPlan').hidden = true;
      detailPairs($('planSummary'), [['Plan', 'Open a hypothesis and generate a plan.']]);
      empty('planRunRows', 'Select a plan.', 7);
      return;
    }
    const plan = await api(`plans/${encodeURIComponent(id)}?${targetQuery()}`);
    $('startPlan').hidden = !['READY_FOR_MANUAL_REVIEW', 'REQUIRE_APPROVAL'].includes(plan.status);
    detailPairs($('planSummary'), [
      ['Plan ID', plan.id], ['Hypothesis ID', plan.hypothesis_id],
      ['Skill', `${plan.skill_id} ${plan.skill_version}`], ['Skill hash', plan.skill_hash],
      ['Status', plan.status], ['Prerequisite state', plan.prerequisites.state],
      ['Missing', plan.prerequisites.missing.join(', ') || 'None'],
      ['Risk', plan.risk], ['Request budget', plan.request_budget],
      ['Expected requests', plan.expected_request_count], ['Token budget', plan.token_budget],
      ['Manual selection', plan.manual_selection ? 'Yes' : 'No'],
      ['Later manual choice', (plan.selection_history || []).some((item) => item.manual) ? 'Recorded' : 'No'],
      ['Positive signal', plan.positive_signals.join('; ')],
      ['Negative signal', plan.negative_signals.join('; ')],
      ['Evidence required', plan.evidence_requirements.join('; ')],
      ['Confirmation required', plan.confirmation_requirements.join('; ')],
      ['Rejection conditions', plan.rejection_conditions.join('; ')],
    ]);
    $('planSteps').replaceChildren(...plan.controls.map((control) => node('div', `Control: ${control}`, 'plan-line')),
      ...plan.steps.map((step) => node('div', `${step.type}: ${step.description}`, 'plan-line')));
    $('planActions').replaceChildren(...(plan.proposed_actions.length ? plan.proposed_actions.map((action) =>
      node('div', `${action.category} / ${action.method}: ${action.policy.result} (${action.policy.reason_code})`, 'plan-line')) :
      [node('p', 'No policy-simulated action is available. Missing evidence or a safe request template may be required.', 'context-line')]));
    await loadPlanRuns(true);
  }
  async function loadPlanRuns(reset = false) {
    const planId = params.get('plan');
    if (!target || !planId) return;
    if (reset) { planRuns = []; planRunCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    if (planRunCursor) query.set('cursor', planRunCursor);
    const page = await api(`plans/${encodeURIComponent(planId)}/runs?${query}`);
    planRuns.push(...page.items);
    planRunCursor = page.next_cursor;
    const active = planRuns.find((run) => !['COMPLETED','BLOCKED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED'].includes(run.status));
    $('startPlan').textContent = active ? 'Open run' : planRuns.length ? 'Rerun Investigation' : 'Start Investigation';
    $('startPlan').dataset.activeRun = active?.id || '';
    $('startPlan').dataset.rerun = String(!active && planRuns.length > 0);
    $('morePlanRuns').hidden = !planRunCursor;
    const body = $('planRunRows'); body.replaceChildren();
    if (!planRuns.length) { empty('planRunRows', 'No runs for this plan.', 7); return; }
    for (const run of planRuns) {
      const row = node('tr');
      cell(row, formatTime(run.created_at));
      cell(row, short(run.id), 'mono');
      cell(row).append(badge(run.status));
      cell(row, run.current_step);
      cell(row, `${run.requests_consumed} / ${run.request_budget}`);
      cell(row, run.approval_id ? short(run.approval_id) : '—', 'mono');
      cell(row).append(button('Open', () => openRun(run.id)));
      body.append(row);
    }
  }
  function openRun(id) {
    location.href = `/hackbot/runs?target=${encodeURIComponent(target)}&run=${encodeURIComponent(id)}`;
  }
  async function loadRuns(reset = false) {
    if (!requireTarget()) { empty('runRows', 'Select a target package.', 8); return; }
    const id = params.get('run');
    $('runList').hidden = Boolean(id);
    $('runDetail').hidden = !id;
    if (id) { await showRun(id); return; }
    if (reset) { runs = []; runCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    if (cleanupAvailable) query.set('archived', $('runShowArchived').checked ? '1' : '0');
    if (runCursor) query.set('cursor', runCursor);
    const page = await api(`runs?${query}`);
    runs.push(...page.items);
    runCursor = page.next_cursor;
    $('moreRuns').hidden = !runCursor;
    const body = $('runRows'); body.replaceChildren();
    if (!runs.length) { empty('runRows', 'No investigation runs for this target.', 8); return; }
    for (const run of runs) {
      const row = node('tr');
      cell(row, formatTime(run.created_at));
      cell(row, short(run.id), 'mono');
      cell(row, short(run.hypothesis_id), 'mono');
      cell(row, run.skill_id);
      cell(row).append(badge(run.status));
      cell(row, `${run.requests_consumed} / ${run.request_budget}`);
      cell(row, run.approval_id ? short(run.approval_id) : '—', 'mono');
      const actions = cell(row); actions.className = 'cell-actions';
      actions.append(button('Open', () => openRun(run.id)));
      if (cleanupAvailable && ['COMPLETED','BLOCKED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED'].includes(run.status)) {
        actions.append(button('Archive', async () => {
          if (!window.confirm('Archive this run? Its audit and evidence remain available.')) return;
          if (await mutate(`runs/${encodeURIComponent(run.id)}/archive`, {target})) await loadRuns(true);
        }, 'quiet'));
      }
      body.append(row);
    }
  }
  async function runAction(id, command) {
    if (command === 'advance' && !window.confirm('Run the next permitted step? This may send target requests.')) return;
    if (command === 'cancel' && !window.confirm('Cancel this run? Completed requests remain recorded.')) return;
    const result = await mutate(`runs/${encodeURIComponent(id)}/${command}`, {target});
    if (result) await showRun(id);
  }
  async function showRun(id) {
    const data = await api(`runs/${encodeURIComponent(id)}?${targetQuery()}`);
    const run = data.run;
    detailPairs($('runSummary'), [
      ['Run ID', run.id], ['Plan ID', run.plan_id], ['Hypothesis', run.hypothesis_id],
      ['Skill / version', `${run.skill_id} ${run.skill_version}`], ['Skill hash', run.skill_hash],
      ['Plan snapshot hash', run.snapshot_hash], ['Status', run.status],
      ['Finding status', run.finding_status], ['Current step', run.current_step],
      ['Requests', `${run.requests_consumed} / ${run.request_budget}`],
      ['Token budget metadata', run.token_budget], ['Approval', run.approval_id],
      ['Stop reason', run.stop_reason], ['Started', formatTime(run.started_at)],
      ['Updated', formatTime(run.updated_at)], ['Finished', formatTime(run.finished_at)],
    ]);
    const mutationSection = $('runMutationSection');
    if (mutationSection) mutationSection.hidden = !data.mutation_approval && !(data.mutation_results || []).length;
    if (mutationSection && !mutationSection.hidden) {
      const preview = data.mutation_approval || {};
      detailPairs($('runMutationSummary'), [
        ['Object', preview.object_id], ['Field / action', [preview.field, preview.action].filter(Boolean).join(' / ')],
        ['Before', preview.old_summary], ['Intended after', preview.new_summary],
        ['Acting identity', preview.acting_identity_id], ['Risk', preview.risk],
        ['Disposable state', preview.object_state], ['Recipe current', preview.recipe_current ? 'Yes' : 'No'],
        ['Cleanup', data.mutation_cleanup_status],
      ]);
      const history = $('runMutationHistory'); history.replaceChildren();
      (data.mutation_results || []).forEach((entry) => {
        history.append(node('p', `${entry.phase}: ${entry.status} · read-back ${short(entry.readback_exchange_id)}`,
                            'context-line'));
      });
    }
    const controls = $('runControls'); controls.replaceChildren();
    if (['CREATED','READY'].includes(run.status)) controls.append(button('Next step', () => runAction(id, 'advance'), 'quiet'));
    if (['CREATED','READY','RUNNING','WAITING_APPROVAL'].includes(run.status)) controls.append(button('Pause', () => runAction(id, 'pause'), 'quiet'));
    if (['PAUSED','WAITING_APPROVAL'].includes(run.status)) controls.append(button('Resume', () => runAction(id, 'resume'), 'quiet'));
    if (!['COMPLETED','BLOCKED','REJECTED','FAILED','BUDGET_EXHAUSTED','CANCELLED'].includes(run.status))
      controls.append(button('Cancel', () => runAction(id, 'cancel'), 'quiet'));
    if (run.status === 'COMPLETED') controls.append(button('Validate evidence', async () => {
      const result = await mutate(`runs/${encodeURIComponent(id)}/validate`, {target});
      if (result) {
        message(result.validation.status === 'CONFIRMED' ? 'Confirmed finding recorded.' :
                `Validation: ${result.validation.status.replaceAll('_', ' ').toLowerCase()}.`);
        await showRun(id);
      }
    }, 'quiet'));
    if (data.validation) controls.append(button('View validation', () => {
      location.href = `/hackbot/validations?target=${encodeURIComponent(target)}&id=${encodeURIComponent(data.validation.id)}`;
    }));
    const review = $('manualReviewForm');
    review.hidden = run.status !== 'WAITING_HUMAN';
    if (!review.hidden) review.dataset.stepId = data.steps[run.current_step]?.id || '';
    const body = $('runStepRows'); body.replaceChildren();
    for (const step of data.steps) {
      const row = node('tr');
      cell(row, step.ordinal);
      cell(row, `${step.type} / ${step.role}`);
      cell(row).append(badge(step.status));
      cell(row, step.control_step_id ? short(step.control_step_id) : '—', 'mono');
      cell(row, [step.decision_id, step.approval_id].filter(Boolean).map((x) => short(x)).join(' / ') || '—', 'mono');
      cell(row, [step.permit_id, step.execution_id].filter(Boolean).map((x) => short(x)).join(' / ') || '—', 'mono');
      const result = step.result;
      const refs = [...(result?.traffic_exchange_ids || []), ...(result?.evidence_ids || []),
                    ...(step.manual_review?.traffic_exchange_ids || []), ...(step.manual_review?.evidence_ids || [])];
      cell(row, refs.map((x) => short(x)).join(', ') || '—', 'mono');
      cell(row, result ? `${result.status_code || '—'} ${result.error_class || ''} ${step.safe_reason || ''}` : (step.safe_reason || '—'));
      body.append(row);
    }
    const timeline = $('runTimeline'); timeline.replaceChildren();
    for (const event of data.timeline) {
      const item = node('div', null, 'activity-row');
      item.append(node('time', formatTime(event.occurred_at)),
                  node('span', `${event.event_type} / ${event.reason_code}`),
                  node('small', event.step_id ? short(event.step_id) : 'Run'));
      timeline.append(item);
    }
  }
  function openValidation(id) {
    location.href = `/hackbot/validations?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
  }
  function openFinding(id) {
    location.href = `/hackbot/findings?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
  }
  async function loadValidations(reset = false) {
    if (!requireTarget()) { empty('validationRows', 'Select a target package.', 7); return; }
    const id = params.get('id');
    $('validationList').hidden = Boolean(id); $('validationDetail').hidden = !id;
    if (id) { await showValidation(id); return; }
    if (reset) { validations = []; validationCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    new FormData($('validationFilters')).forEach((value, key) => { if (value) query.set(key, value); });
    if (validationCursor) query.set('cursor', validationCursor);
    const page = await api('validations?' + query);
    validations.push(...page.items); validationCursor = page.next_cursor;
    $('moreValidations').hidden = !validationCursor;
    const body = $('validationRows'); body.replaceChildren();
    if (!validations.length) { empty('validationRows', 'No validation decisions for this target.', 7); return; }
    for (const item of validations) {
      const row = node('tr');
      cell(row, formatTime(item.created_at));
      cell(row).append(node('span', 'TESTED', 'stage tested'), badge(item.status));
      cell(row, `${item.skill_id} / ${item.validator_id}`);
      cell(row).append(button(short(item.run_id), () => openRun(item.run_id)));
      cell(row, item.controls_evaluated.join(', ') || '—');
      cell(row, item.supporting_evidence_ids.length + item.contradicting_evidence_ids.length);
      cell(row).append(button('Open', () => openValidation(item.id)));
      body.append(row);
    }
  }
  async function showValidation(id) {
    const data = await api(`validations/${encodeURIComponent(id)}?${targetQuery()}`);
    const item = data.validation;
    detailPairs($('validationSummary'), [
      ['Status', item.status], ['Source', item.source], ['Hypothesis', item.hypothesis_id],
      ['Plan / run', `${item.plan_id} / ${item.run_id}`],
      ['Skill / version', `${item.skill_id} ${item.skill_version}`],
      ['Validator / version', `${item.validator_id} ${item.validator_version}`],
      ['Reproductions', item.reproduction_count], ['Demonstrated impact', item.impact.demonstrated],
      ['Potential impact', item.impact.potential], ['Reason codes', item.reason_codes.join(', ')],
      ['Limitations', item.limitations.join('; ')],
      ['Supporting evidence IDs', item.supporting_evidence_ids.join(', ')],
      ['Contradicting evidence IDs', item.contradicting_evidence_ids.join(', ')],
      ['Duplicate of finding', item.duplicate_of_finding_id],
      ['Supersedes', item.supersedes_id], ['Evidence snapshot', item.evidence_snapshot_hash],
      ['Created', formatTime(item.created_at)]]);
    const criteria = $('validationCriteria'); criteria.replaceChildren();
    for (const [label, values] of [['Controls', item.controls_evaluated],
                                    ['Confirmation', item.confirmation_criteria],
                                    ['Rejection', item.rejection_criteria]]) {
      const line = node('div', null, 'plan-line');
      line.append(node('strong', label + ': '), node('span', values.join('; ') || 'None recorded'));
      criteria.append(line);
    }
    const rows = $('validationCheckRows'); rows.replaceChildren();
    if (!item.checks.length) empty('validationCheckRows', 'No deterministic checks were available.', 3);
    for (const check of item.checks) {
      const row = node('tr'); cell(row, check.code.replaceAll('_', ' '));
      cell(row).append(badge(check.outcome)); cell(row, check.evidence_ids.join(', ') || '—', 'mono');
      rows.append(row);
    }
    if (data.finding) {
      const line = node('div', null, 'plan-line');
      line.append(button('Open confirmed finding', () => openFinding(data.finding.id)));
      criteria.prepend(line);
    }
  }
  async function loadFindings(reset = false) {
    if (!requireTarget()) { empty('findingRows', 'Select a target package.', 8); return; }
    const id = params.get('id');
    $('findingList').hidden = Boolean(id); $('findingDetail').hidden = !id;
    if (id) { await showFinding(id); return; }
    if (reset) { findings = []; findingCursor = null; }
    const query = new URLSearchParams({target, limit:'20'});
    new FormData($('findingFilters')).forEach((value, key) => { if (value) query.set(key, value); });
    if (findingCursor) query.set('cursor', findingCursor);
    const page = await api('findings?' + query);
    findings.push(...page.items); findingCursor = page.next_cursor;
    $('moreFindings').hidden = !findingCursor;
    const body = $('findingRows'); body.replaceChildren();
    if (!findings.length) { empty('findingRows', 'No confirmed findings for this target.', 8); return; }
    for (const item of findings) {
      const row = node('tr');
      cell(row, formatTime(item.created_at));
      cell(row).append(node('span', 'CONFIRMED FINDING', 'stage confirmed'), node('span', item.title));
      cell(row, item.category); cell(row).append(badge(item.status));
      cell(row, item.evidence_count); cell(row, item.report_readiness.replaceAll('_', ' '));
      cell(row, item.notification_status || 'NOT_CONFIGURED');
      cell(row).append(button('Open', () => openFinding(item.id)));
      body.append(row);
    }
  }
  async function showFinding(id) {
    const data = await api(`findings/${encodeURIComponent(id)}?${targetQuery()}`);
    const item = data.finding;
    detailPairs($('findingSummary'), [
      ['Title', item.title], ['Status', item.status], ['Category', item.category],
      ['Target', item.target_id], ['Summary', item.safe_summary],
      ['Demonstrated impact', item.impact.demonstrated],
      ['Potential impact', item.impact.potential], ['Object type', item.object_type],
      ['Root-cause fingerprint', item.root_cause_fingerprint],
      ['Reproductions', data.validation?.reproduction_count],
      ['Limitations', data.validation?.limitations.join('; ')],
      ['Report readiness', data.report_attempt?.readiness || 'NOT_GENERATED'],
      ['Report quality', data.report_attempt?.quality_codes?.join(', ') || '—'],
      ['Latest report', data.latest_draft?.id || 'Not generated'],
      ['Submission', data.workflow.submission?.external_report_id || 'Not submitted'],
      ['Skill', [data.workflow.lineage?.skill_id, data.workflow.lineage?.skill_version].filter(Boolean).join(' / ')],
      ['Planner candidate', (data.workflow.lineage?.planner_links || []).map((item) => item.candidate_id).join(', ')],
      ['Research brief', (data.workflow.lineage?.planner_links || []).map((item) => item.research_brief_id).filter(Boolean).join(', ')],
      ['Created', formatTime(item.created_at)]]);
    const actions = $('findingActions'); actions.replaceChildren();
    const draftLabel = data.latest_draft ? 'Regenerate draft' : 'Generate draft';
    actions.append(button(draftLabel, async () => {
      const outcome = await mutate(`findings/${encodeURIComponent(id)}/report`, {target});
      if (!outcome) return;
      if (outcome.draft) {
        message(`Draft ${outcome.draft.readiness.replaceAll('_', ' ').toLowerCase()}.`);
        await showFinding(id);
      } else message(`Draft needs evidence: ${outcome.quality_codes.join(', ')}`, true);
    }, 'quiet'));
    if (data.latest_draft) actions.append(button('Open report', () => openReport(data.latest_draft.id), 'quiet'));
    const transitionLabels = {READY_FOR_REPORT:'Mark Ready', SUBMITTED:'Mark Submitted',
      TRIAGED:'Mark Triaged', DUPLICATE:'Mark Duplicate', INFORMATIVE:'Mark Informative',
      RESOLVED:'Mark Resolved', REWARDED:'Mark Rewarded'};
    for (const state of data.workflow.allowed_transitions || []) {
      if (!transitionLabels[state]) continue;
      const control = button(transitionLabels[state], async () => {
        if (state === 'READY_FOR_REPORT' && (data.report_attempt?.readiness !== 'READY' ||
            data.report_attempt?.report_id !== data.latest_draft?.id)) {
          message('A ready report draft is required.', true); return;
        }
        const entered = Object.fromEntries(new FormData($('findingWorkflowForm')));
        const fields = {target, status:state, expected_version:data.workflow.workflow_version};
        for (const [key, value] of Object.entries(entered)) if (value) fields[key] = value;
        if (state === 'SUBMITTED' && (!fields.platform || !fields.external_report_id)) {
          message('Platform and report ID are required to mark submitted.', true); return;
        }
        if (state === 'REWARDED' && (!fields.reward_amount || !fields.reward_currency)) {
          message('Reward amount and currency are required.', true); return;
        }
        if (!window.confirm(`${transitionLabels[state]} for this finding?`)) return;
        const changed = await mutate(`findings/${encodeURIComponent(id)}/workflow`, fields);
        if (changed) await showFinding(id);
      }, 'quiet');
      actions.append(control);
    }
    const history = $('findingWorkflowHistory'); history.replaceChildren();
    for (const entry of data.workflow.history || []) {
      const line = node('div', null, 'activity-row');
      line.append(node('time', formatTime(entry.occurred_at)),
        node('span', `${entry.status} / ${entry.reason_code}`),
        node('small', entry.actor_alias || 'System'));
      history.append(line);
    }
    const evidence = $('findingEvidence'); evidence.replaceChildren();
    for (const [label, values] of [['Evidence IDs', item.evidence_ids],
                                    ['Affected surfaces', item.locations],
                                    ['Duplicate validations', item.duplicate_validation_ids]]) {
      const line = node('div', null, 'plan-line');
      line.append(node('strong', label + ': '));
      if (label === 'Evidence IDs') {
        for (const ref of values) line.append(button(ref, () => showAuthorizationEvidence(ref)));
        if (!values.length) line.append(node('span', 'None'));
      } else line.append(node('span', values.join(', ') || 'None'));
      evidence.append(line);
    }
    for (const event of data.notifications || []) {
      const line = node('div', null, 'plan-line');
      const delivery = (event.deliveries || []).map((item) => `${item.provider}: ${item.status}`).join(', ');
      line.append(node('strong', event.event_type + ': '), node('span', delivery || 'Queued'));
      evidence.append(line);
    }
    const related = node('div', null, 'plan-line');
    related.append(button('View validation', () => openValidation(item.validation_id)),
                   node('span', ' · '),
                   button('View run', () => openRun(data.validation.run_id)));
    evidence.append(related);
  }
  function openReport(id) {
    location.href = `/hackbot/reports?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
  }
  async function loadReports(reset = false) {
    if (!requireTarget()) { empty('reportRows', 'Select a target package.', 8); return; }
    const id = params.get('id');
    $('reportList').hidden = Boolean(id); $('reportDetail').hidden = !id;
    if (id) await showReport(id);
    else {
      if (reset) { reports = []; reportCursor = null; }
      const query = new URLSearchParams({target, limit:'20'});
      if (reportCursor) query.set('cursor', reportCursor);
      const page = await api('reports?' + query);
      reports.push(...page.items); reportCursor = page.next_cursor;
      $('moreReports').hidden = !reportCursor;
      const body = $('reportRows'); body.replaceChildren();
      if (!reports.length) empty('reportRows', 'No report drafts for this target.', 8);
      for (const item of reports) {
        const row = node('tr');
        cell(row, formatTime(item.created_at)); cell(row, item.finding_title || item.finding_id);
        cell(row, target); cell(row, item.category || '—'); cell(row, item.version);
        cell(row).append(badge(item.workflow_state)); cell(row).append(badge(item.readiness));
        cell(row).append(button('Open', () => openReport(item.id)));
        body.append(row);
      }
    }
    const [settings, events] = await Promise.all([
      api('notifications/status?' + targetQuery()), api('notifications?' + targetQuery({limit:'20'}))]);
    $('notificationStatus').textContent = `Discord: ${settings.discord_configured ? 'configured' : 'off'} / SMTP: ${settings.smtp_configured ? 'configured' : 'off'} / Providers: ${(settings.configured_providers || []).join(', ') || 'none'}. Sent: ${settings.delivery?.sent || 0}; failed: ${settings.delivery?.failed || 0}.`;
    const history = $('notificationHistory'); history.replaceChildren();
    for (const event of events.items || []) {
      const line = node('div', null, 'activity-row');
      line.append(node('time', formatTime(event.created_at)),
        node('span', `${event.event_type} / ${event.finding_id || 'Operational event'}`),
        node('small', (event.deliveries || []).map((item) => `${item.provider}: ${item.status}`).join(', ') || 'Queued'));
      history.append(line);
    }
  }
  async function showReport(id) {
    const data = await api(`reports/${encodeURIComponent(id)}?${targetQuery()}`);
    const item = data.report; selectedReport = item;
    detailPairs($('reportSummary'), [['Report ID', item.id], ['Finding', item.finding_id],
      ['Version', item.version], ['Readiness', item.readiness], ['Provenance', item.provenance],
      ['Severity assessment', item.severity_status], ['Quality checks', item.quality_codes.join(', ') || 'Passed'],
      ['Generated', formatTime(item.created_at)]]);
    $('reportMarkdown').textContent = data.markdown;
    $('reportEditText').value = data.markdown;
    $('reportReviewed').checked = false;
    const actions = $('reportActions'); actions.replaceChildren();
    actions.append(button('Open finding', () => openFinding(item.finding_id), 'quiet'));
    const download = node('a', 'Download Markdown', 'quiet');
    download.href = `/api/hackbot/reports/${encodeURIComponent(item.id)}/download?${targetQuery()}`;
    download.setAttribute('download', `${item.id}.md`); actions.append(download);
    if (item.previous_report_id) actions.append(button('Previous version', () => openReport(item.previous_report_id), 'quiet'));
  }
  function objectFilterQuery() {
    const query = new URLSearchParams({target, limit:'20'});
    new FormData($('objectFilters')).forEach((value, key) => { if (value) query.set(key, value); });
    if (objectCursor) query.set('cursor', objectCursor);
    return query;
  }
  async function loadObjects(reset = false) {
    if (!requireTarget()) { empty('objectRows', 'Select a target package.', 9); return; }
    if (reset) { objects = []; objectCursor = null; }
    const page = await api('objects?' + objectFilterQuery());
    objects.push(...page.items.filter((item) => !objects.some((known) => known.id === item.id)));
    objectCursor = page.next_cursor;
    $('moreObjects').hidden = !objectCursor;
    $('objectSummary').textContent = `${page.stats.objects} total · ${page.stats.cleanup_pending} cleanup pending · ${page.stats.orphaned} orphaned`;
    const rows = $('objectRows'); rows.replaceChildren();
    if (!objects.length) empty('objectRows', 'No disposable objects match these filters.', 9);
    for (const item of objects) {
      const row = node('tr');
      if (item.state === 'ORPHANED' || item.state === 'UNKNOWN') row.classList.add('object-alert');
      cell(row, short(item.id, 20), 'mono'); cell(row, target);
      cell(row, item.object_type); cell(row, short(item.tenant_id, 18), 'mono');
      cell(row, short(item.creator_identity_id, 18), 'mono'); cell(row).append(badge(item.state));
      cell(row, item.cleanup_strategy.replaceAll('_', ' ')); cell(row, formatTime(item.created_at));
      cell(row).append(button('View', () => openObject(item.id)));
      rows.append(row);
    }
    if (reset) await loadObjectOptions();
  }
  async function loadObjectOptions() {
    if (!target) return;
    const selected = {recipe: $('objectRecipe').value, identity: $('objectIdentity').value,
      tenant: $('objectTenant').value, session: $('objectSession').value};
    const [recipes, accountsPage, sessionsPage] = await Promise.all([
      api('objects/recipes?' + targetQuery()),
      api(`targets/${encodeURIComponent(target)}/identities?limit=50`),
      api('browser/sessions?' + targetQuery({limit:'50'})),
    ]);
    objectAccounts = accountsPage.items;
    objectSessions = sessionsPage.items;
    const recipeSelect = $('objectRecipe'); recipeSelect.replaceChildren(optionPlaceholder('Select recipe'));
    recipes.items.forEach((item) => option(recipeSelect, item.id, `${item.object_type} · ${item.id}`));
    recipeSelect.value = selected.recipe;
    const identitySelect = $('objectIdentity'); identitySelect.replaceChildren(optionPlaceholder('Select identity'));
    objectAccounts.filter((item) => item.identity.status === 'ACTIVE').forEach((item) =>
      option(identitySelect, item.identity.id, item.identity.alias));
    identitySelect.value = selected.identity;
    updateObjectIdentityOptions(selected.tenant, selected.session);
  }
  function updateObjectIdentityOptions(tenantValue = '', sessionValue = '') {
    const identityId = $('objectIdentity').value;
    const account = objectAccounts.find((item) => item.identity.id === identityId);
    const tenantSelect = $('objectTenant'); tenantSelect.replaceChildren(optionPlaceholder('Select tenant'));
    (account?.memberships || []).filter((item) => item.status === 'ACTIVE').forEach((item) =>
      option(tenantSelect, item.tenant_id, item.tenant || short(item.tenant_id, 18)));
    tenantSelect.value = tenantValue;
    const sessionSelect = $('objectSession'); sessionSelect.replaceChildren(optionPlaceholder('Select session'));
    objectSessions.filter((item) => item.identity_id === identityId && item.status === 'VALID').forEach((item) =>
      option(sessionSelect, item.id, short(item.id, 20)));
    sessionSelect.value = sessionValue;
  }
  async function openObject(objectId) {
    const data = await api(`objects/${encodeURIComponent(objectId)}?${targetQuery()}`);
    const item = data.object;
    $('objectList').hidden = true; $('objectDetail').hidden = false;
    detailPairs($('objectDetails'), [['Object ID', item.id], ['Type', item.object_type],
      ['External ID fingerprint', item.external_id_fingerprint], ['State', item.state],
      ['Creator identity', item.creator_identity_id], ['Tenant', item.tenant_id],
      ['Parent', item.parent_id], ['Creation run', item.run_id], ['Plan', item.plan_id],
      ['Recipe', item.recipe_id], ['Cleanup strategy', item.cleanup_strategy],
      ['Cleanup required', item.cleanup_required ? 'Yes' : 'No'],
      ['Mutation state', data.mutation_state],
      ['Latest read-back', data.latest_readback?.readback_exchange_id],
      ['Active reservation', data.active_reservation_run], ['Created', formatTime(item.created_at)],
      ['Verified', formatTime(item.verified_at)], ['Cleaned', formatTime(item.cleaned_at)],
      ['Evidence', item.evidence_ids.join(', ')]]);
    const mutationHistory = $('objectMutationHistory');
    if (mutationHistory) {
      mutationHistory.replaceChildren();
      if (!(data.mutation_history || []).length) mutationHistory.append(node('p', 'No typed mutations recorded.', 'context-line'));
      (data.mutation_history || []).forEach((entry) => mutationHistory.append(
        node('p', `${entry.phase}: ${entry.status} · read-back ${short(entry.readback_exchange_id)} · ${formatTime(entry.updated_at)}`,
             'context-line')));
    }
    const rows = $('objectEvents'); rows.replaceChildren();
    for (const event of data.events) {
      const row = node('tr'); cell(row, formatTime(event.occurred_at));
      cell(row, event.event_type); cell(row, event.reason_code);
      cell(row, event.source); cell(row, short(event.exchange_id, 20), 'mono');
      cell(row, (event.evidence_ids || []).map((value) => short(value, 18)).join(', '), 'mono');
      rows.append(row);
    }
    if (!data.events.length) empty('objectEvents', 'No lifecycle events.', 6);
    const actions = $('objectActions'); actions.replaceChildren();
    const sessionSelect = node('select');
    sessionSelect.setAttribute('aria-label', 'Verified creator session');
    sessionSelect.append(optionPlaceholder('Select session'));
    objectSessions.filter((entry) => entry.identity_id === item.creator_identity_id && entry.status === 'VALID')
      .forEach((entry) => option(sessionSelect, entry.id, short(entry.id, 20)));
    sessionSelect.value = $('objectSession').value;
    if (item.state === 'PLANNED' || (['READY', 'CLEANUP_PENDING'].includes(item.state) &&
        item.cleanup_strategy === 'AUTO_CLEANUP')) actions.append(sessionSelect);
    const session = () => objectSessions.find((entry) => entry.id === sessionSelect.value &&
      entry.identity_id === item.creator_identity_id && entry.status === 'VALID');
    if (item.state === 'PLANNED') actions.append(button('Resume creation', async () => {
      if (!session()) { message('Select a verified creator session.', true); return; }
      const result = await mutate(`objects/${item.id}/create`, {target, session_id: session().id});
      if (result) { message(result.outcome); await loadObjects(true); await openObject(item.id); }
    }, 'quiet'));
    if (['READY', 'CLEANUP_PENDING'].includes(item.state) && item.cleanup_strategy === 'AUTO_CLEANUP')
      actions.append(button('Clean up', async () => {
        if (!session()) { message('Select a verified creator session.', true); return; }
        if (!confirm('Clean up this registered disposable object?')) return;
        const result = await mutate(`objects/${item.id}/cleanup`, {target, session_id: session().id});
        if (result) { message(result.outcome); await loadObjects(true); await openObject(item.id); }
      }, 'quiet'));
    if (['ORPHANED', 'UNKNOWN', 'FAILED', 'CLEANUP_PENDING'].includes(item.state))
      actions.append(button('Mark cleaned', async () => {
        if (!confirm('Mark this object cleaned externally? This records a manual assertion, not a verified delete.')) return;
        const result = await mutate(`objects/${item.id}/mark-cleaned`, {target, reason:'MANUAL_CONFIRMATION'});
        if (result) { await loadObjects(true); await openObject(item.id); }
      }, 'quiet'));
  }
  async function showResearchBrief(briefId) {
    const item = await api(`research/${encodeURIComponent(target)}/briefs/${encodeURIComponent(briefId)}`);
    $('researchDetail').hidden = false;
    detailPairs($('researchBriefFacts'), [
      ['Topic', item.topic], ['Summary', item.summary], ['Version', item.version],
      ['Freshness', item.freshness], ['Quality', item.source_quality],
      ['Patterns', (item.patterns || []).join('\n') || 'No compact pattern extracted'],
      ['False positives', (item.false_positives || []).join('\n')],
      ['Runtime controls', (item.runtime_controls || []).join('\n')],
      ['Documented relationships', (item.ontology_relationships || []).join('\n')],
      ['Recommended skills', (item.recommended_skills || []).join(', ')],
      ['Conflicts', (item.conflicts || []).join('\n')],
      ['Limitations', (item.limitations || []).join('\n')],
      ['Related hypothesis', item.hypothesis_id || 'See research request'],
      ['Content hash', short(item.content_hash, 20)],
    ]);
    const sources = $('researchSourceList'); sources.replaceChildren();
    for (const source of item.sources || []) {
      const line = node('p', `${source.source_type} · ${source.publisher} · quality ${source.quality} · ${source.title}`, 'context-line');
      if (source.canonical_url && source.canonical_url.startsWith('https://')) {
        const link = node('a', 'Open source', 'text-action');
        link.href = source.canonical_url; link.target = '_blank'; link.rel = 'noopener noreferrer';
        line.append(' ', link);
      }
      sources.append(line);
    }
    const actions = $('researchBriefActions'); actions.replaceChildren();
    if (['STALE', 'EXPIRED'].includes(item.freshness)) actions.append(button('Refresh stale brief', async () => {
      const result = await mutate(`research/${encodeURIComponent(target)}/briefs/${encodeURIComponent(briefId)}/refresh`,
        {external:$('researchExternal').checked});
      if (result) await renderResearch();
    }, 'quiet'));
  }
  async function renderResearch() {
    if (!requireTarget()) return;
    const root = `research/${encodeURIComponent(target)}`;
    const [gaps, requests, metrics] = await Promise.all([
      api(`${root}/gaps?limit=50`), api(`${root}/requests?limit=50`), api(`${root}/metrics`)]);
    $('researchMetrics').replaceChildren(...[
      ['Requests', metrics.requests], ['Briefs', metrics.briefs],
      ['Hypothesis links', metrics.hypothesis_recommendations],
      ['Later confirmed links', metrics.later_confirmed_links],
    ].map(([label, value]) => { const box = node('div', null, 'metric');
      box.append(node('span', label), node('strong', value)); return box; }));
    const gapRows = $('researchGapRows'); gapRows.replaceChildren();
    for (const gap of gaps.items) {
      const row = node('tr');
      cell(row, gap.priority); cell(row, gap.topic); cell(row, gap.gap_type); cell(row, gap.specialist);
      const action = cell(row, '');
      action.append(button('Research gap', async () => {
        const result = await mutate(`${root}/requests`, {gap_ref:gap.gap_ref,
          external:$('researchExternal').checked});
        if (result) await renderResearch();
      }, 'quiet'));
      gapRows.append(row);
    }
    if (!gaps.items.length) empty('researchGapRows', 'No structured research gaps for this target.', 5);
    const requestRows = $('researchRequestRows'); requestRows.replaceChildren();
    for (const item of requests.items) {
      const row = node('tr');
      cell(row, formatTime(item.created_at)); cell(row, item.topic); cell(row, item.status);
      cell(row, item.freshness || '—'); cell(row, item.quality ?? '—');
      cell(row, (item.recommended_skills || []).join(', ') || '—');
      const action = cell(row, '');
      if (item.brief_id) action.append(button('View brief', () => showResearchBrief(item.brief_id).catch(error => message(error.message, true))));
      if (['PENDING','RESEARCHING'].includes(item.status)) action.append(button('Cancel', async () => {
        const result = await mutate(`${root}/requests/${encodeURIComponent(item.request_id)}/cancel`, {});
        if (result) await renderResearch();
      }));
      requestRows.append(row);
    }
    if (!requests.items.length) empty('researchRequestRows', 'No research briefs yet.', 7);
  }
  function campaignMetric(label, value) {
    const item = node('div', undefined, 'metric');
    item.append(node('span', label), node('strong', value));
    return item;
  }
  async function loadDeltas(reset = false) {
    if (reset) { deltaCursor = null; $('deltaRows').replaceChildren(); }
    if (!requireTarget()) { empty('deltaRows', 'Select a target package.', 9); return; }
    const selected = target;
    const query = new URLSearchParams({target, limit:'20'});
    if ($('deltaStatusFilter').value) query.set('status', $('deltaStatusFilter').value);
    if (deltaCursor) query.set('cursor', deltaCursor);
    const page = await api(`deltas?${query}`);
    if (selected !== target) return;
    if (reset && !page.items.length) empty('deltaRows', 'No recorded changes for this target.', 9);
    for (const item of page.items) {
      const row = node('tr');
      cell(row, formatTime(item.observed_at));
      cell(row, item.delta_type.replaceAll('_', ' '));
      cell(row, item.display_location, 'mono');
      cell(row, item.relevance);
      cell(row, (item.specialist_hints || []).join(', ') || '—');
      cell(row).append(badge(item.status));
      cell(row, item.campaign_status || '—');
      cell(row, item.finding_count || 0);
      cell(row).append(button('Inspect', () => openDelta(item.delta_id).catch((error) => message(error.message, true))));
      $('deltaRows').append(row);
    }
    deltaCursor = page.next_cursor;
    $('moreDeltas').hidden = !deltaCursor;
  }
  async function openDelta(deltaId) {
    if (!requireTarget()) return;
    const selected = target;
    const item = await api(`deltas/${encodeURIComponent(deltaId)}?${targetQuery()}`);
    if (selected !== target) return;
    selectedDeltaId = item.delta_id;
    $('deltaDetail').hidden = false;
    detailPairs($('deltaFacts'), [
      ['Type', item.delta_type], ['Status', item.status], ['Observed', formatTime(item.observed_at)],
      ['Location', item.display_location], ['Source', `${item.source_kind} · ${item.source_ref}`],
      ['Old fingerprint', item.old_fingerprint], ['New fingerprint', item.new_fingerprint],
      ['Semantic fingerprint', item.semantic_hash], ['Signals', (item.signal_tags || []).join(', ')],
      ['Specialists', (item.specialist_hints || []).join(', ')], ['Relevance', item.relevance],
      ['Reason', item.reason_code], ['Evidence', item.evidence_id],
      ['Findings', item.finding_count || 0],
    ]);
    const links = $('deltaLinks'); links.replaceChildren();
    if (item.campaign_id) {
      const link = node('a', `Campaign ${short(item.campaign_id, 20)} · ${item.campaign_status || 'unknown'}`, 'plan-line text-action');
      link.href = `/hackbot/campaigns?target=${encodeURIComponent(target)}&campaign=${encodeURIComponent(item.campaign_id)}`;
      links.append(link);
    }
    for (const id of item.hypothesis_ids || []) {
      const link = node('a', `Hypothesis ${short(id, 20)}`, 'plan-line text-action');
      link.href = `/hackbot/hypotheses?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
      links.append(link);
    }
    $('deltaCreateCampaign').disabled = !['CLASSIFIED', 'CAMPAIGN_READY'].includes(item.status) ||
      !(item.specialist_hints || []).length;
    $('deltaDetail').scrollIntoView({block:'nearest'});
  }
  async function renderDeltas() {
    selectedDeltaId = null;
    $('deltaDetail').hidden = true;
    const stats = await api('continuous/status');
    const measures = [
      [stats.enabled_targets, 'Enabled targets'], [stats.degraded_targets, 'Degraded watches'],
      [stats.deltas_today, 'Deltas today'], [stats.focused_campaigns, 'Focused campaigns'],
      [stats.findings_from_deltas, 'Confirmed findings'], [stats.backlog_min_count, 'Backlog (minimum)'],
    ];
    $('deltaMetrics').replaceChildren(...measures.map(([value, label]) => {
      const block = node('div', null, 'metric');
      block.append(node('strong', value ?? '—'), node('span', label));
      return block;
    }));
    if (!target) {
      $('deltaWatchState').textContent = 'Select a target package.';
      $('deltaSettingsForm').hidden = true;
      $('deltaCheckNow').disabled = true;
      $('deltaPause').disabled = true;
      $('deltaResume').disabled = true;
      await loadDeltas(true);
      return;
    }
    $('deltaSettingsForm').hidden = false;
    const state = await api(`continuous/targets/${encodeURIComponent(target)}`);
    const settings = state.settings;
    const form = $('deltaSettingsForm');
    form.elements.namedItem('enabled').checked = Boolean(state.enabled);
    form.elements.namedItem('cadence').value = settings.cadence;
    form.elements.namedItem('minimum_relevance').value = settings.minimum_relevance;
    form.elements.namedItem('daily_campaign_cap').value = settings.daily_campaign_cap;
    form.elements.namedItem('request_cap').value = settings.request_cap;
    form.elements.namedItem('cooldown_hours').value = settings.cooldown_seconds / 3600;
    form.querySelectorAll('input[name="specialist"]').forEach((input) => {
      input.checked = settings.allowed_specialists.includes(input.value);
    });
    $('deltaWatchState').textContent = `${state.enabled ? 'Enabled' : 'Disabled'} · ${state.status} · Last checked ${formatTime(state.last_checked_at)} · Next ${formatTime(state.next_check_at)} · Last delta ${formatTime(state.last_delta_at)} · Last campaign ${formatTime(state.last_campaign_at)} · Backlog ${state.backlog_min_count || 0}${state.error_code ? ` · ${state.error_code}` : ''}`;
    $('deltaCheckNow').disabled = state.status === 'RUNNING' || state.status === 'PAUSED';
    $('deltaPause').disabled = !state.enabled || ['RUNNING', 'PAUSED'].includes(state.status);
    $('deltaResume').disabled = state.status !== 'PAUSED';
    await loadDeltas(true);
  }
  function campaignElapsed(item) {
    if (!item.started_at) return 'Not started';
    const start = Date.parse(item.started_at);
    const end = item.finished_at ? Date.parse(item.finished_at) : Date.now();
    if (!Number.isFinite(start) || !Number.isFinite(end)) return '—';
    const seconds = Math.max(0, Math.floor((end - start) / 1000));
    return seconds < 3600 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` :
      `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
  }
  async function renderCampaigns() {
    $('campaignMetrics').replaceChildren();
    for (const id of ['campaignCycles','campaignWork','campaignTasks','campaignLinks','campaignObjects','campaignTimeline']) $(id).replaceChildren();
    $('campaignSummary').textContent = '';
    $('campaignCoverage').textContent = '';
    $('campaignOutcome').textContent = '';
    $('campaignRows').replaceChildren();
    if (!requireTarget()) { empty('campaignRows', 'Select a target package.', 9); return; }
    const selected = target;
    const campaignFilters = {limit:'50'};
    if (cleanupAvailable) campaignFilters.archived = $('campaignShowArchived').checked ? '1' : '0';
    const page = await api(`campaigns?${targetQuery(campaignFilters)}`);
    if (selected !== target) return;
    const entries = page.items || [];
    if (!entries.some((item) => item.id === campaignId)) campaignId = entries[0]?.id || '';
    const picker = $('campaignSelect');
    picker.replaceChildren(optionPlaceholder('Select campaign'));
    entries.forEach((item) => option(picker, item.id, `${formatTime(item.started_at || item.created_at)} · ${item.mode} · ${item.status}`));
    picker.value = campaignId;
    for (const item of entries) {
      const row = node('tr');
      const usage = item.usage || {}, limits = item.limits || {};
      cell(row, item.package_id);
      cell(row).append(badge(item.status));
      cell(row, item.mode.replaceAll('_', ' '));
      cell(row, formatTime(item.started_at));
      cell(row, campaignElapsed(item));
      cell(row, `${usage.requests || 0} / ${limits.requests || 0}`);
      cell(row, item.finding_count || 0);
      cell(row, item.readiness_code || '—');
      const actions = cell(row);
      actions.append(button('View', () => {
        campaignId = item.id;
        const url = new URL(location.href);
        url.searchParams.set('campaign', campaignId);
        history.replaceState(null, '', url);
        renderCampaigns().catch((error) => message(error.message, true));
      }));
      if (cleanupAvailable && ['COMPLETED','CANCELLED','BLOCKED','FAILED','BUDGET_EXHAUSTED','TIME_EXHAUSTED'].includes(item.status)) {
        actions.append(button('Archive', async () => {
          if (!window.confirm('Archive this campaign? Its history, findings, and evidence will be retained.')) return;
          if (await mutate(`campaigns/${encodeURIComponent(item.id)}/archive?${targetQuery()}`)) await renderCampaigns();
        }, 'quiet'));
      }
      $('campaignRows').append(row);
    }
    if (!entries.length) empty('campaignRows', 'No campaigns for this target.', 9);
    for (const id of ['campaignPause','campaignResume','campaignCancel']) $(id).disabled = !campaignId;
    if (!campaignId) {
      $('campaignSummary').textContent = 'No campaign has been started for this target.';
      empty('campaignCycles', 'No cycles yet.', 5);
      empty('campaignWork', 'No work yet.', 5);
      empty('campaignTasks', 'No active tasks.', 5);
      return;
    }
    const detail = await api(`campaigns/${encodeURIComponent(campaignId)}`);
    if (selected !== target || picker.value !== campaignId) return;
    const item = detail.campaign;
    const usage = item.usage || {}, limits = item.limits || {};
    const works = detail.work || [];
    const latestPlanner = [...works].reverse().find((work) => work.planner)?.planner;
    const readiness = detail.readiness?.readiness || latestPlanner?.readiness || {};
    const coverage = detail.readiness?.coverage || {};
    const summary = detail.coverage_summary || {}, progress = detail.progress || {};
    $('campaignSummary').textContent = `${item.status} · ${item.mode} · ${item.stop_reason || item.readiness_code || 'In progress'} · Identity ${readiness.identity_coverage || 'not assessed'} · Recon ${coverage.recon || 'not assessed'} · Resources ${detail.resource?.state || 'unknown'}`;
    $('campaignPause').disabled = !['CREATED','ASSESSING_READINESS','RUNNING'].includes(item.status);
    $('campaignResume').disabled = !['PAUSED','WAITING_LOGIN','WAITING_APPROVAL','WAITING_RESEARCH','WAITING_HUMAN'].includes(item.status);
    $('campaignCancel').disabled = ['COMPLETED','CANCELLED','BLOCKED','FAILED','BUDGET_EXHAUSTED','TIME_EXHAUSTED','CLEANUP_REQUIRED'].includes(item.status);
    const pendingObjects = (detail.objects || []).filter((object) => object.cleanup_status !== 'CLEANED');
    $('campaignMetrics').replaceChildren(
      campaignMetric('Cycles', `${item.current_cycle} / ${limits.max_cycles}`),
      campaignMetric('Requests reserved', `${usage.requests || 0} / ${limits.requests}`),
      campaignMetric('Cleanup requests', `${usage.cleanup_requests || 0} / ${limits.cleanup_reserve}`),
      campaignMetric('Browser actions reserved', `${usage.browser_actions || 0} / ${limits.browser_actions}`),
      campaignMetric('Research calls reserved', `${usage.research_requests || 0} / ${limits.research_requests}`),
      campaignMetric('Tokens reserved', `${usage.tokens || 0} / ${limits.tokens}`),
      campaignMetric('Plans / executed', `${detail.metrics?.plans_created || 0} / ${detail.metrics?.plans_executed || 0}`),
      campaignMetric('Validations / manual', `${detail.metrics?.validations || 0} / ${detail.metrics?.manual_reviews || 0}`),
      campaignMetric('Findings', (detail.findings || []).length),
      campaignMetric('Cleanup pending', pendingObjects.length),
      campaignMetric('Identities / roles', `${summary.verified_identities || 0} / ${summary.roles || 0}`),
      campaignMetric('Tenants / features', `${summary.tenants || 0} / ${summary.features || 0}`),
      campaignMetric('High-priority processed', progress.high_priority_candidates_processed || 0),
      campaignMetric('Completed tasks / blockers', `${progress.completed_tasks || 0} / ${progress.remaining_blockers || 0}`));
    const classes = Object.entries(summary.candidate_classes || {}).map(([name, count]) => `${name}: ${count}`).join(', ');
    $('campaignCoverage').textContent = `Specialists exercised: ${(summary.specialists_exercised || []).join(', ') || 'none'} · Candidate classes: ${classes || 'none'} · Knowledge changes: ${progress.knowledge_changes || 0}`;
    const metrics = detail.metrics || {};
    $('campaignOutcome').textContent = `Research ${metrics.research_work || 0} · Rejected validations ${metrics.rejected_validations || 0} · Objects cleaned ${metrics.objects_cleaned || 0} / ${metrics.objects_created || 0} · Report drafts ${metrics.report_drafts || 0} · Notification events ${metrics.notification_events || 0} · Active tasks ${progress.active_tasks || 0}${detail.active_tasks_truncated ? ' (first 24 shown)' : ''}`;
    for (const cycle of detail.cycles || []) {
      const row = node('tr');
      cell(row, cycle.cycle_number);
      cell(row).append(badge(cycle.status));
      cell(row, `v${cycle.package_version}`);
      const plannerCell = cell(row);
      if (cycle.planner_run_id) {
        const link = node('a', short(cycle.planner_run_id));
        link.href = `/hackbot/planner?target=${encodeURIComponent(target)}&planner_run=${encodeURIComponent(cycle.planner_run_id)}`;
        plannerCell.append(link);
      } else plannerCell.textContent = '—';
      cell(row, formatTime(cycle.created_at));
      $('campaignCycles').append(row);
    }
    if (!detail.cycles?.length) empty('campaignCycles', 'No cycles yet.', 5);
    for (const work of works) {
      const row = node('tr');
      cell(row, work.kind); cell(row).append(badge(work.status)); cell(row, short(work.child_id));
      cell(row, `${work.requests} req · ${work.browser_actions} browser · ${work.tokens} tokens`);
      cell(row, formatTime(work.updated_at)); $('campaignWork').append(row);
    }
    if (!works.length) empty('campaignWork', 'No child work yet.', 5);
    for (const task of detail.active_tasks || []) {
      const row = node('tr');
      cell(row, task.task_type); cell(row, task.specialist || '—');
      cell(row).append(badge(task.status)); cell(row, task.reason_code || '—');
      cell(row, short(task.planner_run_id)); $('campaignTasks').append(row);
    }
    if (!detail.active_tasks?.length) empty('campaignTasks', 'No active tasks.', 5);
    for (const finding of detail.findings || []) {
      const entry = node('p');
      const link = node('a', `Finding ${short(finding.finding_id)}`);
      link.href = `/hackbot/findings?target=${encodeURIComponent(target)}`;
      entry.append(link);
      if (finding.report_id) {
        entry.append(node('span', ' · '));
        const report = node('a', `Report ${short(finding.report_id)}`);
        report.href = `/hackbot/reports?target=${encodeURIComponent(target)}`;
        entry.append(report);
      }
      $('campaignLinks').append(entry);
    }
    if (!detail.findings?.length) $('campaignLinks').append(node('p', 'No confirmed findings linked.'));
    if (item.status === 'WAITING_LOGIN') {
      const link = node('a', 'Open accounts and sessions'); link.href = `/hackbot/sessions?target=${encodeURIComponent(target)}`;
      $('campaignLinks').append(link);
    }
    if (item.status === 'WAITING_APPROVAL') {
      const link = node('a', 'Review approvals'); link.href = `/hackbot/approvals?target=${encodeURIComponent(target)}`;
      $('campaignLinks').append(link);
    }
    for (const object of detail.objects || []) $('campaignObjects').append(node('p', `${short(object.object_id)} · ${object.cleanup_status}`));
    if (!detail.objects?.length) $('campaignObjects').append(node('p', 'No campaign-created objects.'));
    for (const event of detail.timeline || []) $('campaignTimeline').append(node('p', `${formatTime(event.occurred_at)} · ${event.event_type} · ${event.reason_code}`));
  }

  function plannerBase() { return `planner/${encodeURIComponent(target)}/runs`; }
  function plannerRunPath() { return `${plannerBase()}/${encodeURIComponent(plannerRunId)}`; }
  function plannerMetric(label, value) {
    const box = node('div', null, 'metric');
    box.append(node('strong', value), node('span', label));
    return box;
  }
  async function renderPlanner() {
    if (!requireTarget()) return;
    const selected = target;
    const runs = await api(plannerBase() + '?limit=50');
    if (selected !== target) return;
    const entries = runs.items || [];
    if (!entries.some((run) => run.id === plannerRunId)) plannerRunId = entries[0]?.id || '';
    const picker = $('plannerRunSelect');
    picker.replaceChildren(optionPlaceholder('Select run'));
    entries.forEach((run) => option(picker, run.id, `${formatTime(run.created_at)} · ${run.mode} · ${run.status}`));
    picker.value = plannerRunId;
    $('plannerCandidateRows').replaceChildren();
    $('plannerTaskRows').replaceChildren();
    $('plannerLinks').replaceChildren();
    $('plannerEvents').replaceChildren();
    $('plannerMetrics').replaceChildren();
    $('plannerSummary').textContent = '';
    if (!plannerRunId) {
      empty('plannerCandidateRows', 'No planner runs for this target.', 9);
      empty('plannerTaskRows', 'Start an analysis or planning run.', 6);
      return;
    }
    const detail = await api(plannerRunPath());
    if (selected !== target || picker.value !== plannerRunId) return;
    const run = detail.run;
    const metrics = detail.metrics || {};
    const readiness = run.readiness || {};
    const nextSteps = (readiness.recommendations || []).slice(0, 3)
      .map(code => code.toLowerCase().replaceAll('_', ' ')).join(', ');
    $('plannerSummary').textContent = `${run.status} · ${run.mode} · ${run.stop_reason || 'No stop reason'} · Scope ${readiness.scope_ready ? 'ready' : 'not ready'} · Identity ${readiness.identity_coverage || 'none'} · Behaviour ${readiness.behaviour_coverage || 'none'}${nextSteps ? ' · Next: ' + nextSteps : ''}`;
    const requestLeft = Math.max(0, run.limits.requests - run.usage.requests);
    const browserLeft = Math.max(0, run.limits.browser_actions - run.usage.browser_actions);
    const tokenLeft = Math.max(0, run.limits.tokens - run.usage.tokens);
    $('plannerMetrics').replaceChildren(
      plannerMetric('Considered / selected', `${metrics.considered || 0} / ${metrics.selected || 0}`),
      plannerMetric('Deferred / blocked', `${metrics.deferred || 0} / ${metrics.blocked || 0}`),
      plannerMetric('Child request slots / reserved / left', `${metrics.child_request_slots_consumed || 0} / ${run.usage.requests} / ${requestLeft}`),
      plannerMetric('Browser trials / reserved / left', `${metrics.browser_navigation_attempts_accounted || 0} / ${run.usage.browser_actions} / ${browserLeft}`),
      plannerMetric('Fresh repro / reloads', `${metrics.fresh_context_reproductions_accounted || 0} / ${metrics.browser_reload_attempts_accounted || 0}`),
      plannerMetric('Research token estimate / reserved / left', `${metrics.research_tokens_estimated || 0} / ${run.usage.tokens} / ${tokenLeft}`),
      plannerMetric('Validated / confirmed', `${metrics.validations || 0} / ${metrics.confirmed_root_causes || 0}`),
      plannerMetric('Research / manual', `${metrics.research_requests || 0} / ${metrics.manual_reviews || 0}`),
      plannerMetric('Elapsed / limit', `${metrics.duration_seconds || 0}s / ${run.limits.seconds}s`));
    const active = ['READY', 'RUNNING', 'RESOLVING_GAPS'].includes(run.status);
    $('plannerPause').disabled = !active;
    $('plannerResume').disabled = !['PAUSED','WAITING_LOGIN','WAITING_RESEARCH','WAITING_APPROVAL','WAITING_HUMAN'].includes(run.status);
    $('plannerCancel').disabled = ['COMPLETED','CANCELLED','BLOCKED','FAILED','BUDGET_EXHAUSTED'].includes(run.status);
    for (const item of detail.candidates || []) {
      const row = node('tr');
      cell(row, item.priority); cell(row, item.category); cell(row, item.specialist);
      cell(row, item.gaps?.length ? item.gaps.join(', ') : item.freshness);
      cell(row, item.risk); cell(row, item.estimated_requests);
      cell(row, item.reason_codes?.join(', ') || '—'); cell(row).append(badge(item.status));
      const actions = cell(row);
      if (['SELECTED','NEEDS_REFRESH','DEFERRED'].includes(item.status) && ['READY','PAUSED'].includes(run.status)) {
        actions.append(button('Pin', async () => {
          const result = await mutate(`${plannerRunPath()}/candidates/${encodeURIComponent(item.id)}/override`, {choice:'PIN'});
          if (result) renderPlanner().catch(error => message(error.message, true));
        }));
        actions.append(button('Lower', async () => {
          const result = await mutate(`${plannerRunPath()}/candidates/${encodeURIComponent(item.id)}/override`, {choice:'DEPRIORITIZE'});
          if (result) renderPlanner().catch(error => message(error.message, true));
        }));
        actions.append(button('Exclude', async () => {
          const result = await mutate(`${plannerRunPath()}/candidates/${encodeURIComponent(item.id)}/override`, {choice:'EXCLUDE'});
          if (result) renderPlanner().catch(error => message(error.message, true));
        }));
        if (item.source_kind === 'HYPOTHESIS') {
          const specialist = node('select');
          specialist.setAttribute('aria-label', 'Specialist override');
          for (const name of ['AUTHORIZATION','API_GRAPHQL','DOM_XSS','POSTMESSAGE','EXPOSURE']) {
            option(specialist, name, name.replaceAll('_', ' '));
          }
          specialist.value = item.specialist;
          const skill = node('select');
          skill.setAttribute('aria-label', 'Skill override');
          option(skill, '', 'Auto skill');
          (item.skill_ids || []).forEach((name) => option(skill, name, name));
          actions.append(specialist, skill, button('Route', async () => {
            const result = await mutate(`${plannerRunPath()}/candidates/${encodeURIComponent(item.id)}/override`,
              {choice:'PIN', specialist:specialist.value, ...(skill.value ? {skill_id:skill.value} : {})});
            if (result) renderPlanner().catch(error => message(error.message, true));
          }));
        }
      }
      $('plannerCandidateRows').append(row);
    }
    if (!detail.candidates?.length) empty('plannerCandidateRows', 'No candidate signals in this run.', 9);
    const loginAccounts = new Map((detail.login_requirements || []).map((item) =>
      [item.task_id, item.account_alias]));
    for (const item of detail.tasks || []) {
      const row = node('tr');
      cell(row, item.priority); cell(row, item.task_type); cell(row, short(item.candidate_id));
      cell(row, item.dependencies?.map(id => short(id)).join(', ') || '—');
      cell(row).append(badge(item.status));
      const account = loginAccounts.get(item.id);
      cell(row, account ? `LOGIN_REQUIRED · ${account}` : item.reason_code || item.result_ref || '—');
      $('plannerTaskRows').append(row);
    }
    if (!detail.tasks?.length) empty('plannerTaskRows', 'No tasks for this run.', 6);
    for (const id of detail.findings || []) {
      const link = node('a', `Confirmed finding ${short(id)}`, 'text-action');
      link.href = `/hackbot/findings?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
      $('plannerLinks').append(link);
    }
    for (const id of detail.research_briefs || []) {
      const link = node('a', `Research brief ${short(id)}`, 'text-action');
      link.href = `/hackbot/research?target=${encodeURIComponent(target)}&id=${encodeURIComponent(id)}`;
      $('plannerLinks').append(link);
    }
    if (!(detail.findings?.length || detail.research_briefs?.length)) $('plannerLinks').append(node('p', 'No linked findings or research briefs.'));
    for (const event of detail.events || []) {
      const entry = node('div', null, 'activity-row');
      entry.append(node('time', formatTime(event.occurred_at)), node('span', `${event.event_type} · ${event.reason_code || ''}`), node('small', short(event.candidate_id)));
      $('plannerEvents').append(entry);
    }
  }
  function evaluationPercent(value) {
    return value === null || value === undefined ? 'Not measured' : `${(value * 100).toFixed(1)}%`;
  }
  function populateEvaluationRuns() {
    const suite = $('evaluationSuite').value;
    const available = evaluationRuns.filter((run) => !suite || run.suite === suite);
    const selector = $('evaluationRun');
    selector.replaceChildren(optionPlaceholder('Select run'));
    available.forEach((run) => option(selector, run.run_id,
      `${run.suite} · ${formatTime(run.started_at)} · ${run.status}`));
    selector.value = available.some((run) => run.run_id === evaluationRunId) ? evaluationRunId : '';
    const baseline = $('evaluationBaseline');
    baseline.replaceChildren(optionPlaceholder('Select baseline'));
    available.filter((run) => run.run_id !== evaluationRunId).forEach((run) =>
      option(baseline, run.run_id, `${formatTime(run.started_at)} · ${run.status}`));
  }
  async function loadEvaluationCases(reset = false) {
    if (!evaluationRunId) return;
    if (reset) { evaluationCaseOffset = 0; $('evaluationCaseRows').replaceChildren(); }
    const page = await api(`evaluation/runs/${evaluationRunId}/cases?limit=20&offset=${evaluationCaseOffset}`);
    for (const item of page.items || []) {
      const row = node('tr');
      const result = item.evaluation || {};
      cell(row, item.case_id, 'mono'); cell(row, item.trial);
      cell(row).append(badge(item.status));
      cell(row, result.detected_vulnerabilities ?? '—');
      cell(row, result.false_confirmed_findings ?? '—');
      cell(row, result.failure_stage || '—');
      cell(row, result.usage?.requests ?? '—');
      $('evaluationCaseRows').append(row);
    }
    if (reset && !page.items?.length) empty('evaluationCaseRows', 'No case outcomes yet.', 7);
    evaluationCaseOffset = page.next_offset ?? 0;
    $('moreEvaluationCases').hidden = page.next_offset === null;
  }
  async function showEvaluationRun(runId) {
    evaluationRunId = runId;
    const next = new URL(location.href);
    if (runId) next.searchParams.set('benchmark_run', runId);
    else next.searchParams.delete('benchmark_run');
    history.replaceState(null, '', next);
    $('evaluationMetrics').replaceChildren();
    $('evaluationFacts').replaceChildren();
    $('evaluationSpecialistRows').replaceChildren();
    $('evaluationModelRows').replaceChildren();
    $('evaluationModelComparisonFacts').replaceChildren();
    $('evaluationModelComparisonRows').replaceChildren();
    $('evaluationFailureFacts').replaceChildren();
    $('evaluationGateRows').replaceChildren();
    $('evaluationCaseRows').replaceChildren();
    $('evaluationComparison').replaceChildren();
    $('moreEvaluationCases').hidden = true;
    populateEvaluationRuns();
    if (!runId) { $('evaluationState').textContent = 'No benchmark run selected.'; return; }
    const [run, readiness] = await Promise.all([
      api(`evaluation/runs/${runId}`), api(`evaluation/readiness?run_id=${runId}`),
    ]);
    const metrics = run.metrics || {};
    const measures = [
      [evaluationPercent(metrics.precision), 'Precision'],
      [evaluationPercent(metrics.recall), 'Recall'],
      [evaluationPercent(metrics.top_k_recall?.['10']), 'Top-10 recall'],
      [metrics.false_confirmed_findings ?? '—', 'False confirmed'],
      [metrics.safety_violations ?? '—', 'Safety violations'],
      [metrics.requests ?? '—', 'Requests'],
      [metrics.manual_reviews ?? '—', 'Manual reviews'],
      [run.cost_estimate?.total_usd == null ? '—' : `$${Number(run.cost_estimate.total_usd).toFixed(3)}`, 'Est. cost'],
    ];
    $('evaluationMetrics').replaceChildren(...measures.map(([value, label]) => {
      const block = node('div', null, 'metric');
      block.append(node('strong', value), node('span', label));
      return block;
    }));
    $('evaluationState').textContent = `${run.label || 'SYNTHETIC / EVALUATION'} · ${run.suite} · ${run.status}`;
    detailPairs($('evaluationFacts'), [
      ['Run', run.run_id], ['Benchmark version', run.benchmark_version],
      ['BugHunter version', run.bughunter_version],
      ['Started', formatTime(run.started_at)], ['Finished', formatTime(run.finished_at)],
      ['Cases evaluated', `${run.evaluated_cases} / ${run.total_case_runs}`],
      ['Model mode', run.model_mode || 'Unknown'],
      ['Readiness', readiness.readiness?.conclusion || 'Not measured'],
      ['Limitations', (run.limitations || []).join(', ') || 'None recorded'],
    ]);
    for (const item of run.specialist_breakdown || []) {
      const row = node('tr');
      cell(row, item.specialist); cell(row).append(badge(item.status));
      cell(row, item.expected_vulnerabilities); cell(row, item.detected_vulnerabilities);
      cell(row, evaluationPercent(item.recall));
      cell(row, evaluationPercent(item.routing_accuracy)); cell(row, item.requests);
      $('evaluationSpecialistRows').append(row);
    }
    if (!run.specialist_breakdown?.length) empty('evaluationSpecialistRows', 'No specialist results recorded.', 7);
    for (const item of run.model_usage || []) {
      const row = node('tr');
      cell(row, item.lane); cell(row, item.role);
      cell(row, `${item.provider} / ${item.model}`);
      cell(row, item.calls); cell(row, (item.input_tokens || 0) + (item.output_tokens || 0));
      cell(row, `${item.latency_ms} ms`); cell(row).append(badge(item.quality));
      $('evaluationModelRows').append(row);
    }
    if (!run.model_usage?.length) empty('evaluationModelRows', 'No model calls recorded.', 7);
    const advice = run.model_comparison || {};
    detailPairs($('evaluationModelComparisonFacts'), [
      ['Status', advice.status || 'NOT_MEASURED'],
      ['Packets', advice.comparison_packets ?? 0],
      ['Disagreement positions', advice.disagreement_positions ?? 0],
      ['Candidate provenance', Object.entries(advice.candidate_provenance || {})
        .map(([name, count]) => `${name}: ${count}`).join(', ') || 'None recorded'],
      ['Quality', advice.quality || 'NOT_MEASURED'],
    ]);
    const laneRow = node('tr');
    for (const lane of ['PRIMARY', 'CHALLENGER', 'CRITIC']) {
      const counts = advice.lane_statuses?.[lane] || {};
      cell(laneRow, Object.entries(counts).map(([status, count]) =>
        `${status}: ${count}`).join(', ') || 'Not measured');
    }
    $('evaluationModelComparisonRows').append(laneRow);
    const failures = run.failure_analysis || {};
    detailPairs($('evaluationFailureFacts'), [
      ['Missed cases', failures.missed_cases ?? 'Not measured'],
      ['Missed vulnerabilities', failures.missed_vulnerabilities ?? 'Not measured'],
      ['Stages', Object.entries(failures.stages || {}).map(([name, count]) => `${name}: ${count}`).join(', ') || 'None recorded'],
    ]);
    for (const gate of readiness.readiness?.gates || []) {
      const row = node('tr');
      cell(row, gate.category); cell(row).append(badge(gate.outcome));
      cell(row, gate.reason_code); cell(row, gate.measured_cases);
      $('evaluationGateRows').append(row);
    }
    if (!readiness.readiness?.gates?.length) empty('evaluationGateRows', 'No readiness gates available.', 4);
    await loadEvaluationCases(true);
  }
  async function renderEvaluation() {
    const [catalog, runs] = await Promise.all([
      api('evaluation/suites'), api('evaluation/runs?limit=50'),
    ]);
    evaluationRuns = runs.items || [];
    const suite = $('evaluationSuite');
    const selected = suite.value;
    suite.replaceChildren(optionPlaceholder('All suites'));
    (catalog.items || []).forEach((item) => option(suite, item.name,
      `${item.name} (${item.case_count})`));
    suite.value = selected;
    if (!evaluationRunId && evaluationRuns.length) evaluationRunId = evaluationRuns[0].run_id;
    if (evaluationRunId && !evaluationRuns.some((run) => run.run_id === evaluationRunId)) {
      evaluationRunId = evaluationRuns[0]?.run_id || '';
    }
    await showEvaluationRun(evaluationRunId);
  }
  async function compareEvaluationRuns() {
    const baselineId = $('evaluationBaseline').value;
    if (!baselineId || !evaluationRunId) { message('Select a baseline and current run.', true); return; }
    const result = await api(`evaluation/compare?baseline_id=${baselineId}&current_id=${evaluationRunId}`);
    detailPairs($('evaluationComparison'), [
      ['Outcome', result.outcome], ['Reason', result.reason_code],
      ['Baseline precision', evaluationPercent(result.baseline?.precision)],
      ['Current precision', evaluationPercent(result.current?.precision)],
      ['Baseline recall', evaluationPercent(result.baseline?.recall)],
      ['Current recall', evaluationPercent(result.current?.recall)],
      ['Checks', Object.entries(result.checks || {}).map(([key, value]) => `${key}: ${value}`).join(', ') || 'Not comparable'],
    ]);
  }
  async function renderSection() {
    try {
      if (section === 'overview') await renderOverview();
      else if (section === 'operations') await renderOperations();
      else if (section === 'targets') {
        if (params.get('setup') === 'new') await openTargetSetup();
        else if (target) showTargetDetail();
        else { $('targetList').hidden = false; $('targetDetail').hidden = true; renderTargets(); }
      } else if (section === 'hunt' && cfg.huntEnabled) await renderHuntPanel($('huntContent'), target);
      else if (section === 'accounts') await loadAccounts(true);
      else if (section === 'sessions') { await loadAccounts(true); await loadSessions(true); }
      else if (section === 'traffic') { await loadAccounts(true); await loadSessions(true); await loadTraffic(true); }
      else if (section === 'objects') {
        await loadObjects(true);
        if (params.get('id')) await openObject(params.get('id'));
      }
      else if (section === 'authorization') await renderAuthorization();
      else if (section === 'api') await renderApi();
      else if (section === 'research') await renderResearch();
      else if (section === 'planner') await renderPlanner();
      else if (section === 'campaigns') await renderCampaigns();
      else if (section === 'deltas') await renderDeltas();
      else if (section === 'evaluation') await renderEvaluation();
      else if (section === 'behaviour') await renderBehaviour();
      else if (section === 'domxss') await renderDomxss();
      else if (section === 'postmessage') await renderPostmessage();
      else if (section === 'exposure') await renderExposure();
      else if (section === 'scope') await renderScope();
      else if (section === 'burp') await renderBurp();
      else if (section === 'hypotheses') await loadHypotheses(true);
      else if (section === 'skills') await loadSkills();
      else if (section === 'plans') await loadPlan();
      else if (section === 'runs') await loadRuns(true);
      else if (section === 'validations') await loadValidations(true);
      else if (section === 'findings') await loadFindings(true);
      else if (section === 'reports') await loadReports(true);
      else if (section === 'approvals') await loadApprovals(true);
    } catch (error) { message(error.message, true); }
  }
  $('targetSelect').addEventListener('change', (event) => selectTarget(event.target.value));
  $('refreshEvaluation').addEventListener('click', () => renderEvaluation().catch((error) => message(error.message, true)));
  $('evaluationSuite').addEventListener('change', () => {
    const selected = evaluationRuns.find((run) =>
      !$('evaluationSuite').value || run.suite === $('evaluationSuite').value);
    showEvaluationRun(selected?.run_id || '').catch((error) => message(error.message, true));
  });
  $('evaluationRun').addEventListener('change', (event) =>
    showEvaluationRun(event.target.value).catch((error) => message(error.message, true)));
  $('moreEvaluationCases').addEventListener('click', () =>
    loadEvaluationCases().catch((error) => message(error.message, true)));
  $('compareEvaluation').addEventListener('click', () =>
    compareEvaluationRuns().catch((error) => message(error.message, true)));
  $('refreshOperations').addEventListener('click', () => renderOperations().catch((error) => message(error.message, true)));
  $('refreshDeltas').addEventListener('click', () => renderDeltas().catch((error) => message(error.message, true)));
  $('moreDeltas').addEventListener('click', () => loadDeltas().catch((error) => message(error.message, true)));
  $('deltaStatusFilter').addEventListener('change', () => loadDeltas(true).catch((error) => message(error.message, true)));
  $('closeDeltaDetail').addEventListener('click', () => { selectedDeltaId = null; $('deltaDetail').hidden = true; });
  $('deltaSettingsForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const form = event.currentTarget;
    const allowed_specialists = [...form.querySelectorAll('input[name="specialist"]:checked')].map((item) => item.value);
    if (!allowed_specialists.length) { message('Select at least one specialist.', true); return; }
    const body = {
      enabled: form.elements.namedItem('enabled').checked,
      cadence: form.elements.namedItem('cadence').value,
      minimum_relevance: Number(form.elements.namedItem('minimum_relevance').value),
      daily_campaign_cap: Number(form.elements.namedItem('daily_campaign_cap').value),
      request_cap: Number(form.elements.namedItem('request_cap').value),
      cooldown_seconds: Number(form.elements.namedItem('cooldown_hours').value) * 3600,
      allowed_specialists,
    };
    const result = await mutate(`continuous/targets/${encodeURIComponent(target)}/settings`, body);
    if (result) await renderDeltas();
  });
  for (const [id, action] of [['deltaCheckNow', 'check'], ['deltaPause', 'pause'], ['deltaResume', 'resume']]) {
    $(id).addEventListener('click', async () => {
      if (!requireTarget()) return;
      $(id).disabled = true;
      try {
        const result = await api(`continuous/targets/${encodeURIComponent(target)}/${action}`,
                                 {method:'POST', body:{}});
        message(action === 'check' ? `Watch ${result.watch?.status || 'finished'} · ${result.watch?.candidates_created || 0} new candidates · ${result.campaign?.status || 'no campaign'}` : `Watch ${result.status}.`);
        await renderDeltas();
      } catch (error) { message(error.message, true); $(id).disabled = false; }
    });
  }
  $('deltaCreateCampaign').addEventListener('click', async () => {
    if (!requireTarget() || !selectedDeltaId) return;
    const deltaId = selectedDeltaId;
    const mode = $('deltaCampaignMode').value;
    if (mode === 'BOUNDED_AUTONOMOUS' && !window.confirm('Start a bounded active campaign for this delta?')) return;
    $('deltaCreateCampaign').disabled = true;
    try {
      const result = await api(`deltas/${encodeURIComponent(deltaId)}/campaigns`,
                               {method:'POST', body:{target, mode}});
      message(result.campaign_id ? `Focused campaign ${short(result.campaign_id)}: ${result.status}` :
              `${result.status}: ${result.reason_code || 'not started'}`, !result.campaign_id);
      await renderDeltas();
      await openDelta(deltaId);
    } catch (error) { message(error.message, true); $('deltaCreateCampaign').disabled = false; }
  });
  $('operationsBackupCreate').addEventListener('click', () => startMaintenance('BACKUP_CREATE'));
  $('operationsBackupVerify').addEventListener('click', () => startMaintenance('BACKUP_VERIFY'));
  $('operationsRetentionPlan').addEventListener('click', () => startMaintenance('RETENTION_PLAN'));
  $('operationsRetentionRun').addEventListener('click', () => startMaintenance('RETENTION_RUN'));
  $('operationsProfilePlan').addEventListener('click', () => startMaintenance('PROFILE_PLAN'));
  $('operationsProfileRun').addEventListener('click', () => startMaintenance('PROFILE_RUN'));
  $('operationsRetentionConfirm').addEventListener('change', () => {
    $('operationsRetentionRun').disabled = !retentionReviewReady || !$('operationsRetentionConfirm').checked;
  });
  $('operationsProfileConfirm').addEventListener('change', () => {
    $('operationsProfileRun').disabled = !profileReviewReady || !$('operationsProfileConfirm').checked;
  });
  $('moreTargets').addEventListener('click', () => loadTargets().catch((error) => message(error.message, true)));
  $('moreAccounts').addEventListener('click', () => loadAccounts().catch((error) => message(error.message, true)));
  $('moreSessions').addEventListener('click', () => loadSessions().catch((error) => message(error.message, true)));
  $('moreTraffic').addEventListener('click', () => loadTraffic().catch((error) => message(error.message, true)));
  $('moreObjects').addEventListener('click', () => loadObjects().catch((error) => message(error.message, true)));
  $('refreshObjects').addEventListener('click', () => loadObjects(true).catch((error) => message(error.message, true)));
  $('refreshAuthorization').addEventListener('click', () => renderAuthorization().catch((error) => message(error.message, true)));
  $('refreshApi').addEventListener('click', () => renderApi().catch((error) => message(error.message, true)));
  $('refreshResearch').addEventListener('click', () => renderResearch().catch((error) => message(error.message, true)));
  $('refreshPlanner').addEventListener('click', () => renderPlanner().catch((error) => message(error.message, true)));
  $('plannerRunSelect').addEventListener('change', (event) => {
    plannerRunId = event.target.value;
    const url = new URL(location.href);
    if (plannerRunId) url.searchParams.set('planner_run', plannerRunId);
    else url.searchParams.delete('planner_run');
    history.replaceState(null, '', url);
    renderPlanner().catch(error => message(error.message, true));
  });
  $('plannerStartForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const limits = Object.fromEntries(['requests','browser_actions','tokens','seconds'].map(key => [key, Number(values[key])]));
    const result = await mutate(plannerBase(), {mode: values.mode, limits});
    if (result) { plannerRunId = result.id; await renderPlanner(); }
  });
  for (const [name, action] of [['plannerPause','pause'],['plannerResume','resume'],['plannerCancel','cancel']]) {
    $(name).addEventListener('click', async () => {
      if (!plannerRunId) return;
      const result = await mutate(`${plannerRunPath()}/${action}`);
      if (result) renderPlanner().catch(error => message(error.message, true));
    });
  }
  $('refreshCampaigns').addEventListener('click', () => renderCampaigns().catch((error) => message(error.message, true)));
  $('campaignPreset').addEventListener('change', () => {
    $('campaignCustomLimits').hidden = $('campaignPreset').value !== 'CUSTOM';
  });
  $('campaignSelect').addEventListener('change', (event) => {
    campaignId = event.target.value;
    const url = new URL(location.href);
    if (campaignId) url.searchParams.set('campaign', campaignId);
    else url.searchParams.delete('campaign');
    history.replaceState(null, '', url);
    renderCampaigns().catch((error) => message(error.message, true));
  });
  $('campaignShowArchived').addEventListener('change', () =>
    renderCampaigns().catch((error) => message(error.message, true)));
  $('campaignStartForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const payload = {target, mode: values.mode, preset: values.preset};
    if (values.preset === 'CUSTOM') {
      const names = ['max_cycles','seconds','requests','browser_actions','research_requests','tokens','setup_objects','cleanup_reserve'];
      payload.limits = Object.fromEntries(names.map((name) => [name, Number(values[name])]));
    }
    const result = await mutate('campaigns', payload);
    if (result) { campaignId = result.id; await renderCampaigns(); }
  });
  for (const [name, action] of [['campaignPause','pause'],['campaignResume','resume'],['campaignCancel','cancel']]) {
    $(name).addEventListener('click', async () => {
      if (!campaignId) return;
      if (action === 'cancel' && !window.confirm('Cancel this campaign and retain cleanup obligations?')) return;
      const result = await mutate(`campaigns/${encodeURIComponent(campaignId)}/${action}`);
      if (result) renderCampaigns().catch((error) => message(error.message, true));
    });
  }
  $('closeResearchDetail').addEventListener('click', () => { $('researchDetail').hidden = true; });
  $('apiOperationState').addEventListener('change', () => renderApi().catch((error) => message(error.message, true)));
  $('moreApiOperations').addEventListener('click', () => loadMoreApiOperations().catch((error) => message(error.message, true)));
  $('moreApiCandidates').addEventListener('click', () => loadMoreApiCandidates().catch((error) => message(error.message, true)));
  $('moreApiOperationCandidates').addEventListener('click', () => loadMoreApiOperationCandidates().catch((error) => message(error.message, true)));
  $('closeApiOperation').addEventListener('click', () => $('apiOperationDialog').close());
  $('analyzeApi').addEventListener('click', async () => {
    if (!requireTarget()) return;
    if (await mutate(`api/${encodeURIComponent(target)}/analyze`, {mode: 'PLAN_ONLY'})) await renderApi();
  });
  $('refreshDomxss').addEventListener('click', () => renderDomxss().catch((error) => message(error.message, true)));
  $('refreshPostmessage').addEventListener('click', () => renderPostmessage().catch((error) => message(error.message, true)));
  $('refreshExposure').addEventListener('click', () => renderExposure().catch((error) => message(error.message, true)));
  $('exposureCategory').addEventListener('change', () => loadExposureCandidates(true).catch((error) => message(error.message, true)));
  $('exposureStatus').addEventListener('change', () => loadExposureCandidates(true).catch((error) => message(error.message, true)));
  $('exposureArtifact').addEventListener('change', updateExposureArtifactKind);
  $('exposureArtifactForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const artifact_id = $('exposureArtifact').value;
    const kind = $('exposureArtifactKind').value;
    const selected = exposureArtifacts.find((item) => item.artifact_id === artifact_id);
    if (!selected || (kind === 'source_map' && !selected.has_source_map)) return;
    const result = await mutate(`${exposureBase()}/analyze`, {artifact_id, kind});
    if (result) { message(`${result.signals} signals reviewed; no requests sent.`); await renderExposure(); }
  });
  $('exposureCaptureForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const item = exposureCaptures.find((capture) =>
      capture.artifact_evidence_id === $('exposureCapture').value);
    if (!item) return;
    const result = await mutate(`${exposureBase()}/analyze-response`, {
      exchange_id: item.exchange_id, artifact_evidence_id: item.artifact_evidence_id,
    });
    if (result) { message(`${result.signals} response signals reviewed; no requests sent.`); await renderExposure(); }
  });
  $('exposureFieldForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const owner_exchange_id = $('exposureFieldOwner').value;
    const member_exchange_id = $('exposureFieldMember').value;
    if (!owner_exchange_id || !member_exchange_id || owner_exchange_id === member_exchange_id) return;
    const result = await mutate(`${exposureBase()}/analyze-field`, {
      owner_exchange_id, member_exchange_id,
    });
    if (result) { message(`${result.signals} field-boundary leads reviewed; no requests sent.`); await renderExposure(); }
  });
  $('moreExposureCandidates').addEventListener('click', () => loadExposureCandidates().catch((error) => message(error.message, true)));
  $('closeExposureCandidate').addEventListener('click', () => {
    exposureSelectedCandidate = null; $('exposureCandidateDetail').hidden = true;
  });
  for (const [control, source] of [['discoverExposureRecon', 'recon'], ['discoverExposureTraffic', 'traffic']]) {
    $(control).addEventListener('click', async () => {
      if (!requireTarget()) return;
      const result = await mutate(`${exposureBase()}/discover`, {source});
      if (result) { message(`${result.signals} observed signals; no requests sent.`); await renderExposure(); }
    });
  }
  $('prepareExposureCandidate').addEventListener('click', async () => {
    if (!requireTarget() || !exposureSelectedCandidate) return;
    const id = exposureSelectedCandidate.candidate_id;
    const result = await mutate(`${exposureBase()}/candidates/${encodeURIComponent(id)}/prepare`, {});
    if (result) await openExposureCandidate(id);
  });
  $('exposureOwnedObject').addEventListener('change', updateExposureOwnerSessions);
  $('exposureReadForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget() || !exposureSelectedCandidate) return;
    const id = exposureSelectedCandidate.candidate_id;
    const body = Object.fromEntries(new FormData(event.currentTarget));
    if (!body.test_object_id || !body.owner_session_id) return;
    const fieldBinding = exposureSelectedCandidate.category === 'OVEREXPOSED_API_RESPONSE';
    if (fieldBinding && !body.member_session_id) return;
    if (!fieldBinding) delete body.member_session_id;
    const route = fieldBinding ? 'bind-field' : 'bind-read';
    const result = await mutate(`${exposureBase()}/candidates/${encodeURIComponent(id)}/${route}`, body);
    if (result) await openExposureCandidate(id);
  });
  $('moreMessageCandidates').addEventListener('click', () => loadMessageCandidates().catch((error) => message(error.message, true)));
  $('closeMessageCandidate').addEventListener('click', () => {
    messageSelectedCandidate = null; $('messageCandidateDetail').hidden = true;
  });
  $('messageRouteForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget() || !messageSelectedCandidate) return;
    const id = messageSelectedCandidate.id;
    const exchange_id = String(new FormData(event.currentTarget).get('exchange_id') || '').trim();
    if (!exchange_id) return;
    const result = await mutate(`${messageBase()}/candidates/${encodeURIComponent(id)}/route`, {exchange_id});
    if (result) { await loadMessageCandidates(true); await openMessageCandidate(id); }
  });
  $('prepareMessageCandidate').addEventListener('click', async () => {
    if (!requireTarget() || !messageSelectedCandidate?.route) return;
    const id = messageSelectedCandidate.id;
    const result = await mutate(`${messageBase()}/candidates/${encodeURIComponent(id)}/prepare`, {});
    if (result) await openMessageCandidate(id);
  });
  $('messageBindPlanForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget() || !messageSelectedCandidate?.links?.hypothesis_id) return;
    const id = messageSelectedCandidate.id;
    const form = new FormData(event.currentTarget);
    const browser_session_id = form.get('browser_session_id');
    const activation_type = form.get('activation_type');
    if (!browser_session_id || !activation_type) {
      message('Select a running session and observed activation type.', true); return;
    }
    const result = await mutate(`${messageBase()}/candidates/${encodeURIComponent(id)}/bind-plan`, {
      browser_session_id, activation_type, port_type:form.get('port_type') || null,
      allowed_method:form.get('allowed_method') || null,
    });
    if (result) await openMessageCandidate(id);
  });
  $('runMessageInvestigation').addEventListener('click', async () => {
    if (!requireTarget() || !messageSelectedCandidate?.links?.plan_id) return;
    if (!window.confirm('Start the bounded messaging investigation? Browser steps execute only when advanced.')) return;
    const result = await mutate(`plans/${encodeURIComponent(messageSelectedCandidate.links.plan_id)}/runs`,
                                {target, rerun:false});
    if (result?.run?.id) {
      const url = new URL('/hackbot/runs', location.origin);
      url.searchParams.set('target', target); url.searchParams.set('run', result.run.id);
      location.href = url.pathname + url.search;
    }
  });
  $('moreDomCandidates').addEventListener('click', () => loadDomCandidates().catch((error) => message(error.message, true)));
  $('closeDomCandidate').addEventListener('click', () => {
    domSelectedCandidate = null; $('domCandidateDetail').hidden = true;
  });
  $('domInputKind').addEventListener('change', () => {
    $('domInputName').disabled = $('domInputKind').value === 'FRAGMENT';
  });
  $('domRouteForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget() || !domSelectedCandidate) return;
    const id = domSelectedCandidate.id;
    const exchange_id = new FormData(event.currentTarget).get('exchange_id').trim();
    if (!exchange_id) return;
    const result = await mutate(`${domBase()}/candidates/${encodeURIComponent(id)}/route`, {exchange_id});
    if (result) { await loadDomCandidates(true); await openDomCandidate(id); }
  });
  $('prepareDomCandidate').addEventListener('click', async () => {
    if (!requireTarget() || !domSelectedCandidate?.route) return;
    const id = domSelectedCandidate.id;
    const result = await mutate(`${domBase()}/candidates/${encodeURIComponent(id)}/prepare`, {});
    if (result) await openDomCandidate(id);
  });
  $('domBindPlanForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget() || !domSelectedCandidate?.links?.hypothesis_id) return;
    const id = domSelectedCandidate.id;
    const form = new FormData(event.currentTarget);
    const input_kind = form.get('input_kind');
    const input_name = input_kind === 'FRAGMENT' ? null : String(form.get('input_name') || '').trim();
    if (!form.get('browser_session_id') || (input_kind === 'QUERY' && !input_name)) {
      message('Select a running session and input parameter.', true); return;
    }
    const result = await mutate(`${domBase()}/candidates/${encodeURIComponent(id)}/bind-plan`, {
      browser_session_id:form.get('browser_session_id'), input_kind, input_name,
    });
    if (result) await openDomCandidate(id);
  });
  $('authorizationHuntForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const data = new FormData(event.currentTarget);
    const mode = data.get('mode');
    if (mode === 'BOUNDED_AUTONOMOUS' && !confirm('Allow bounded automatic authorization checks on owned disposable objects?')) return;
    const result = await mutate(`authorization/${encodeURIComponent(target)}/hunts`, {
      mode, candidate_limit: Number(data.get('candidate_limit')),
      request_budget: Number(data.get('request_budget')),
    });
    if (result) await renderAuthorization();
  });
  $('objectFilters').addEventListener('submit', (event) => { event.preventDefault(); loadObjects(true).catch((error) => message(error.message, true)); });
  $('objectIdentity').addEventListener('change', () => updateObjectIdentityOptions());
  $('backObjects').addEventListener('click', () => { $('objectDetail').hidden = true; $('objectList').hidden = false; });
  $('createObjectForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const form = new FormData(event.currentTarget);
    const payload = {target, recipe_id: form.get('recipe_id'), identity_id: form.get('identity_id'),
      tenant_id: form.get('tenant_id'), session_id: form.get('session_id'), purpose:'Dashboard disposable fixture'};
    if (form.get('parent_id')) payload.parent_id = form.get('parent_id');
    const result = await mutate('objects', payload);
    if (result) { message(result.outcome); await loadObjects(true); if (result.object) await openObject(result.object.id); }
  });
  $('refreshOverview').addEventListener('click', () => renderOverview().catch((error) => message(error.message, true)));
  $('refreshTargets').addEventListener('click', () => loadTargets(true).catch((error) => message(error.message, true)));
  $('addTarget').addEventListener('click', () => openTargetSetup().catch((error) => message(error.message, true)));
  $('cancelTargetSetup').addEventListener('click', closeTargetSetup);
  $('addTargetHost').addEventListener('click', () => setupHostRow($('targetIncludeHosts'), 'Host'));
  $('addTargetExclusion').addEventListener('click', () => setupHostRow($('targetExcludeHosts'), 'Excluded host'));
  setupField('name').addEventListener('input', (event) => {
    if (!setupSlugEdited) setupField('id').value = event.currentTarget.value.toLowerCase()
      .normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 64);
  });
  setupField('id').addEventListener('input', () => { setupSlugEdited = true; });
  $('targetSetupBack').addEventListener('click', () => showSetupStep(setupStep - 1));
  $('targetSetupNext').addEventListener('click', () => {
    const active = document.querySelector(`[data-setup-step="${setupStep}"]`);
    const invalid = Array.from(active.querySelectorAll('input,select,textarea')).find((field) =>
      !field.checkValidity());
    if (invalid) { invalid.reportValidity(); invalid.focus(); return; }
    if (setupStep === 1 && setupHosts('targetIncludeHosts').length === 0) {
      setupError(new Error('At least one authorized host is required.')); return;
    }
    showSetupStep(setupStep + 1);
  });
  $('targetSetupForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!setupField('confirmed').checked) { setupField('confirmed').reportValidity(); return; }
    const create = $('targetSetupCreate'); create.disabled = true; create.textContent = 'Creating…';
    try {
      const result = await api('targets', {method:'POST', body:setupPayload()});
      createdTargetId = result.target.id;
      await loadTargets(true);
      openCreatedTarget('overview');
      message('TargetPackage created. No target traffic was sent.');
    } catch (error) { setupError(error); }
    finally { create.disabled = false; create.textContent = 'Create TargetPackage'; }
  });
  $('backTargets').addEventListener('click', () => { $('targetList').hidden = false; $('targetDetail').hidden = true; });
  document.querySelectorAll('[data-target-tab]').forEach((tab) => tab.addEventListener('click', () => {
    targetTab = tab.dataset.targetTab; renderTargetTab().catch((error) => message(error.message, true));
  }));
  $('importAccounts').addEventListener('click', async () => {
    if (!requireTarget()) return;
    if (await mutate(`targets/${encodeURIComponent(target)}/import-identities`, {})) await loadAccounts(true);
  });
  $('createSession').addEventListener('click', async () => {
    if (!requireTarget()) return;
    const identity_id = $('sessionIdentity').value;
    if (!identity_id) { message('Select an owned identity first.', true); return; }
    if (await mutate('browser/sessions', {target, identity_id})) await loadSessions(true);
  });
  $('trafficFilters').addEventListener('submit', (event) => { event.preventDefault(); loadTraffic(true).catch((error) => message(error.message, true)); });
  $('closeTraffic').addEventListener('click', () => $('trafficDialog').close());
  $('closeAuthorizationEvidence').addEventListener('click', () => $('authorizationEvidenceDialog').close());
  if ($('closeMutationApproval')) $('closeMutationApproval').addEventListener('click', () => $('mutationApprovalDialog').close());
  $('moreHypotheses').addEventListener('click', () => loadHypotheses().catch((error) => message(error.message, true)));
  $('moreApprovals').addEventListener('click', () => loadApprovals().catch((error) => message(error.message, true)));
  $('refreshApprovals').addEventListener('click', () => loadApprovals(true).catch((error) => message(error.message, true)));
  $('morePlanRuns').addEventListener('click', () => loadPlanRuns().catch((error) => message(error.message, true)));
  $('startPlan').addEventListener('click', async () => {
    const id = params.get('plan');
    if (!target || !id) return;
    if ($('startPlan').dataset.activeRun) { openRun($('startPlan').dataset.activeRun); return; }
    if (!window.confirm('Start this investigation run? Steps execute only when advanced.')) return;
    const result = await mutate(`plans/${encodeURIComponent(id)}/runs`,
                                {target, rerun:$('startPlan').dataset.rerun === 'true'});
    if (result) openRun(result.run.id);
  });
  $('refreshRuns').addEventListener('click', () => loadRuns(true).catch((error) => message(error.message, true)));
  $('runShowArchived').addEventListener('change', () => loadRuns(true).catch((error) => message(error.message, true)));
  $('moreRuns').addEventListener('click', () => loadRuns().catch((error) => message(error.message, true)));
  $('backRuns').addEventListener('click', () => {
    location.href = `/hackbot/runs?target=${encodeURIComponent(target)}`;
  });
  $('refreshValidations').addEventListener('click', () => loadValidations(true).catch((error) => message(error.message, true)));
  $('moreValidations').addEventListener('click', () => loadValidations().catch((error) => message(error.message, true)));
  $('validationFilters').addEventListener('submit', (event) => { event.preventDefault(); loadValidations(true).catch((error) => message(error.message, true)); });
  $('backValidations').addEventListener('click', () => { location.href = `/hackbot/validations?target=${encodeURIComponent(target)}`; });
  $('refreshFindings').addEventListener('click', () => loadFindings(true).catch((error) => message(error.message, true)));
  $('moreFindings').addEventListener('click', () => loadFindings().catch((error) => message(error.message, true)));
  $('findingFilters').addEventListener('submit', (event) => { event.preventDefault(); loadFindings(true).catch((error) => message(error.message, true)); });
  $('backFindings').addEventListener('click', () => { location.href = `/hackbot/findings?target=${encodeURIComponent(target)}`; });
  $('refreshReports').addEventListener('click', () => loadReports(true).catch((error) => message(error.message, true)));
  $('moreReports').addEventListener('click', () => loadReports().catch((error) => message(error.message, true)));
  $('backReports').addEventListener('click', () => { location.href = `/hackbot/reports?target=${encodeURIComponent(target)}`; });
  $('reportEditForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!selectedReport) return;
    if (!window.confirm('Save this as a new report version? The previous version will remain available.')) return;
    const result = await mutate(`reports/${encodeURIComponent(selectedReport.id)}/edit`,
      {target, content:$('reportEditText').value, expected_version:selectedReport.version,
       researcher_reviewed:$('reportReviewed').checked});
    if (result?.report) openReport(result.report.id);
  });
  $('testNotification').addEventListener('click', async () => {
    if (!requireTarget() || !window.confirm('Send one clearly labelled TEST notification to configured providers?')) return;
    const result = await mutate('notifications/test', {target});
    if (result) await loadReports(true);
  });
  $('manualReviewForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const runId = params.get('run');
    const stepId = event.currentTarget.dataset.stepId;
    const values = Object.fromEntries(new FormData(event.currentTarget));
    if (!runId || !stepId || (!values.evidence_id && !values.exchange_id)) {
      message('Provide a target-owned evidence or exchange reference.', true); return;
    }
    if (!window.confirm('Link this manual review and complete the waiting step?')) return;
    const result = await mutate(`runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}/complete`,
                                {target, evidence_ids:values.evidence_id ? [values.evidence_id] : [],
                                 exchange_id:values.exchange_id || null});
    if (result) { event.currentTarget.reset(); await showRun(runId); }
  });
  $('policyCheckForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!requireTarget()) return;
    const form = Object.fromEntries(new FormData(event.currentTarget));
    const body = {target, category:form.category, actor:form.actor, url:form.url, method:form.method};
    if (form.operation) body.operation = form.operation;
    if (form.object_type) body.object_type = form.object_type;
    if (form.disposable_intent) body.disposable_intent = true;
    if (form.actor === 'AUTHENTICATED') {
      if (form.identity_id) body.identity_id = form.identity_id;
      if (form.session_id) body.session_id = form.session_id;
    }
    try {
      const data = await api('policy/evaluate', {method:'POST', body});
      const decision = data.decision;
      detailPairs($('policyCheckResult'), [
        ['Decision', decision.result], ['Reason', decision.reason_code],
        ['Scope', decision.scope_result], ['Matched rule', decision.matched_scope_rule],
        ['Risk', decision.risk], ['Side effect', decision.side_effect],
        ['Decision ID', decision.id], ['Approval ID', decision.approval_id],
      ]);
      message('Policy check recorded. No request was sent.');
    } catch (error) { message(error.message, true); }
  });
  $('hypothesisFilters').addEventListener('submit', (event) => { event.preventDefault(); loadHypotheses(true).catch((error) => message(error.message, true)); });
  $('profileTarget').addEventListener('click', async () => {
    if (!requireTarget()) return;
    $('profileTarget').disabled = true;
    try {
      const result = await api(`targets/${encodeURIComponent(target)}/profile`, {method:'POST', body:{}});
      message(`Profiled ${result.profile.signals.length} signals; ${result.hypotheses_generated} hypotheses considered.`);
      await loadHypotheses(true);
    } catch (error) { message(error.message, true); }
    finally { $('profileTarget').disabled = false; }
  });
  $('addHypothesis').addEventListener('click', () => { if (requireTarget()) $('manualHypothesisDialog').showModal(); });
  $('closeHypothesis').addEventListener('click', () => $('hypothesisDialog').close());
  $('closeSkill').addEventListener('click', () => $('skillDialog').close());
  $('manualPlan').addEventListener('click', () => {
    if (!selectedHypothesis || !$('manualSkillSelect').value) { message('Select a skill first.', true); return; }
    generatePlan(selectedHypothesis, $('manualSkillSelect').value, true);
  });
  $('closeManualHypothesis').addEventListener('click', () => $('manualHypothesisDialog').close());
  $('manualHypothesisForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(event.currentTarget));
    const result = await mutate('hypotheses/manual', {target, ...values});
    if (result) { $('manualHypothesisDialog').close(); event.currentTarget.reset(); await loadHypotheses(true); }
  });

  $('refreshBehaviourView').addEventListener('click', () => renderBehaviour().catch(error => message(error.message, true)));
  $('startBehaviour').addEventListener('click', async () => {
    if (!requireTarget()) return;
    const result = await mutate(`targets/${encodeURIComponent(target)}/behaviour`, {});
    if (result) await renderBehaviour();
  });
  $('refreshBehaviour').addEventListener('click', async () => {
    if (!requireTarget()) return;
    const result = await mutate(`targets/${encodeURIComponent(target)}/behaviour/refresh`, {});
    if (result) await renderBehaviour();
  });

  (async () => {
    setView();
    try {
      const health = await api('health');
      $('serviceState').textContent = health.status === 'ok' ? 'Service online' : 'Service degraded';
      await loadTargets(true);
      await renderSection();
    } catch (error) {
      $('serviceState').textContent = 'Service unavailable';
      message(error.message, true);
    }
  })();
})();
