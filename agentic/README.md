# Recon Agentic

Focused, sanitized source bundle for the authenticated Agentic interface at
`https://recon.base64.live/agentic`.

The public request path redirects to the dashboard login. This directory
contains the application source only; it does not include a production session,
credentials, target scope, collected evidence, or database contents.

## Contents

- `agentic_hunter.py` implements Agentic run and lead persistence operations.
- `agentic_hunter_worker.py` prepares bounded work packets and executes queued
  Agentic passes.
- `hunt_signal_classifier.py` supplies route-signal classification used by the
  worker.
- `independent_hunt_worker.py`, `independent_hunt.py`, `hunt_coordinator.py`,
  `hunt_research.py`, and `bug_job_taxonomy.py` provide the shared result
  normalization, request-budget, scope, and research controls used by Agentic.
- `dashboard.py` is the full integration snapshot containing `/agentic` and the
  `/api/agentic/*` routes. Shared modules imported by it remain at repository
  root.
- `templates/agentic_panel.html` is the page template.
- `static/agentic_panel.js` and `static/agentic_panel.css` implement the browser
  interface.
- `database_schema.sql` includes the Agentic run, pass, lead, and credential
  tables used by this snapshot.
- `scripts/` contains the scoped browser, mailbox, CAPTCHA, and confirmed-bug
  notification helpers used by the worker.
- `tests/` contains focused backend and browser-smoke coverage.

## Local checks

From this directory:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest tests.test_agentic_hunter tests.test_agentic_mail_bridge
node --check static/agentic_panel.js
node --check tests/agentic_panel_smoke.cjs
```

The browser smoke test itself requires the deployed dashboard, Chromium, and
the pinned `playwright-core` runtime. The backend unit tests do not send target
traffic.

## External runtime boundaries

The production worker additionally expects deployment-owned resources that are
deliberately excluded from Git:

- `/app/AGENTS.md` and `/app/scope.md`
- `/opt/agentic-bug-hunter`
- `/run/agentic-mail/mail.sock`
- isolated credential/session files
- the PostgreSQL database and `/root/codex_artifacts` volumes

Keep those resources outside source control. Preserve scope confirmation,
request budgets, credential isolation, reconciliation, and report-readiness
gates before enabling target-facing actions.
