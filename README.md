# Recon Hunts

Sanitized source snapshot for the authenticated Hunts interface deployed at
`https://recon.base64.live/hunts`.

This repository contains the application code, browser UI, database schema,
supporting workers, and tests. It intentionally does **not** contain production
credentials, cookies, target data, evidence, logs, local configuration, or the
PostgreSQL data volume.

## Hunt implementation

- `dashboard.py` exposes `/hunts` and the `/api/hunts/*` routes.
- `independent_hunt.py` contains the run coordinator and operator actions.
- `independent_hunt_worker.py` executes queued hunt passes.
- `hunt_coordinator.py` enforces scope and prepares bounded hunt inputs.
- `hunt_research.py` classifies research context and evidence.
- `hunt_credentials.py` handles references to separately stored credentials.
- `hunt_signal_classifier.py` classifies route and feature signals.
- `templates/hunt_panel.html` is the Hunts page template.
- `static/hunt_panel.js` and `static/hunt_panel.css` implement the browser UI.
- `database_schema.sql` defines the framework and Hunt data model.

The surrounding framework modules are included because the Hunts dashboard and
workers import shared recon, taxonomy, monitoring, and gateway code.

## Local setup

Requirements:

- Python 3.11+
- PostgreSQL 16+
- Redis 7+
- Node.js and Chromium for the optional browser helpers

Create local configuration from the examples:

```bash
cp .env.example .env
cp config.example.yaml config.yaml
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Initialize a disposable PostgreSQL database with `database_schema.sql`, then
run focused tests such as:

```bash
python -m unittest tests.test_hunt_research
python -m unittest tests.test_hunt_signal_classifier
python -m unittest tests.test_independent_hunt
```

The production deployment uses private, host-specific mounts and service
configuration that are intentionally excluded. Treat this repository as the
source snapshot, not as a backup of the live deployment or its data.

## Security notes

- Keep `.env`, `config.yaml`, credential files, cookies, session state, and
  collected evidence outside Git.
- Do not add production database dumps or artifact directories.
- Preserve the deterministic scope and authorization gates before enabling any
  target-facing worker actions.
