"""Database contract for the separate Agentic Bug Hunter workbench."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")


def normalize_exact_host(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    host = str(value).strip().lower().rstrip(".")
    labels = host.split(".")
    if (len(host) > 253 or len(labels) < 2 or
            any(len(label) > 63 or not HOST_LABEL.fullmatch(label) for label in labels)):
        raise ValueError("Enter one hostname, without a scheme, path, port, or wildcard")
    return host


def host_belongs_to_root(host: str, root: str, include_subdomains: bool) -> bool:
    root = root.lower().rstrip(".")
    return host == root or (include_subdomains and host.endswith("." + root))


def _iso(value):
    return value.isoformat() + "Z" if isinstance(value, datetime) else value


def _json_object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


class AgenticHunter:
    def __init__(self, pool):
        self.pool = pool

    async def ensure_schema(self):
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(45123, 31901)")
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS agentic_runs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    action TEXT NOT NULL CHECK (action IN ('hunt', 'recon', 'validate')),
                    status TEXT NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'waiting_login', 'done', 'failed', 'paused')),
                    data_source TEXT NOT NULL DEFAULT 'recent_delta'
                        CHECK (data_source IN ('recent_delta', 'all')),
                    target_host TEXT,
                    focus TEXT NOT NULL DEFAULT '',
                    max_passes SMALLINT NOT NULL DEFAULT 4 CHECK (max_passes BETWEEN 1 AND 12),
                    request_budget INTEGER NOT NULL DEFAULT 300 CHECK (request_budget BETWEEN 10 AND 1200),
                    credential_ids BIGINT[] NOT NULL DEFAULT '{}'::bigint[],
                    parent_lead_id BIGINT,
                    scope_confirmed_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    artifact_dir TEXT,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT
                )
                """)
                await conn.execute("ALTER TABLE agentic_runs ADD COLUMN IF NOT EXISTS credential_ids BIGINT[] NOT NULL DEFAULT '{}'::bigint[]")
                await conn.execute("ALTER TABLE agentic_runs ADD COLUMN IF NOT EXISTS max_passes SMALLINT NOT NULL DEFAULT 4")
                await conn.execute("ALTER TABLE agentic_runs ADD COLUMN IF NOT EXISTS request_budget INTEGER NOT NULL DEFAULT 300")
                await conn.execute("ALTER TABLE agentic_runs ADD COLUMN IF NOT EXISTS target_host TEXT")
                await conn.execute("""
                DO $$ BEGIN
                  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                                 WHERE conrelid='agentic_runs'::regclass
                                   AND conname='agentic_runs_status_check'
                                   AND pg_get_constraintdef(oid) LIKE '%waiting_login%') THEN
                    ALTER TABLE agentic_runs DROP CONSTRAINT IF EXISTS agentic_runs_status_check;
                    ALTER TABLE agentic_runs ADD CONSTRAINT agentic_runs_status_check
                      CHECK (status IN ('queued', 'running', 'waiting_login', 'done', 'failed', 'paused'));
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                                 WHERE conrelid='agentic_runs'::regclass
                                   AND conname='agentic_runs_max_passes_check') THEN
                    ALTER TABLE agentic_runs ADD CONSTRAINT agentic_runs_max_passes_check
                      CHECK (max_passes BETWEEN 1 AND 12);
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_constraint
                                 WHERE conrelid='agentic_runs'::regclass
                                   AND conname='agentic_runs_request_budget_check') THEN
                    ALTER TABLE agentic_runs ADD CONSTRAINT agentic_runs_request_budget_check
                      CHECK (request_budget BETWEEN 10 AND 1200);
                  END IF;
                END $$
                """)
                await conn.execute("""
                CREATE TABLE IF NOT EXISTS agentic_leads (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES agentic_runs(id) ON DELETE CASCADE,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    lead_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    skill TEXT NOT NULL,
                    signal TEXT NOT NULL,
                    source_table TEXT NOT NULL,
                    source_id BIGINT NOT NULL,
                    asset TEXT NOT NULL,
                    priority TEXT NOT NULL DEFAULT 'med',
                    status TEXT NOT NULL DEFAULT 'lead',
                    confidence INTEGER NOT NULL DEFAULT 0,
                    rationale TEXT NOT NULL DEFAULT '',
                    evidence_path TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(run_id, lead_key)
                )
                """)
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_agentic_runs_domain ON agentic_runs(domain_id, id DESC)")
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_agentic_runs_queue ON agentic_runs(status, id) WHERE status='queued'")
                await conn.execute("CREATE INDEX IF NOT EXISTS idx_agentic_leads_run ON agentic_leads(run_id, id DESC)")

    async def create_run(self, domain_id: int, action: str, data_source: str = "recent_delta",
                         focus: str = "", parent_lead_id: int | None = None,
                         credential_ids: list[int] | None = None, max_passes: int = 4,
                         target_host: str | None = None, request_budget: int = 300):
        if action not in {"hunt", "recon", "validate"}:
            raise ValueError("Unknown action")
        if data_source not in {"recent_delta", "all"}:
            raise ValueError("Unknown data source")
        if len(focus) > 12000:
            raise ValueError("Focus must be at most 12000 characters")
        if type(max_passes) is not int or not 1 <= max_passes <= 12:
            raise ValueError("Investigation batches must be between 1 and 12")
        if type(request_budget) is not int or not 50 <= request_budget <= 1200:
            raise ValueError("Hunt request budget must be between 50 and 1200")
        if action != "hunt":
            max_passes = 1
            request_budget = 10
        target_host = normalize_exact_host(target_host)
        credential_ids = credential_ids or []
        if (not isinstance(credential_ids, list) or len(credential_ids) > 3
                or any(type(value) is not int or value < 1 for value in credential_ids)
                or len(set(credential_ids)) != len(credential_ids)):
            raise ValueError("Select up to three unique owned accounts")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                domain = await conn.fetchrow(
                    "SELECT id, domain, active, include_subdomains FROM domains WHERE id=$1", domain_id)
                if not domain or not domain["active"]:
                    raise ValueError("Select an active recon root domain")
                if action == "validate":
                    lead = await conn.fetchrow(
                        "SELECT l.id, l.domain_id, l.asset FROM agentic_leads l WHERE l.id=$1", parent_lead_id)
                    if not lead or lead["domain_id"] != domain_id:
                        raise ValueError("Select a lead from this domain")
                    lead_host = urlsplit(lead["asset"]).hostname
                    if not lead_host or not host_belongs_to_root(
                            lead_host, domain["domain"], domain["include_subdomains"]):
                        raise ValueError("Lead host is outside this recon root")
                    if target_host and target_host != lead_host:
                        raise ValueError("Validation must use the lead's exact host")
                    target_host = lead_host
                elif parent_lead_id is not None:
                    raise ValueError("Lead ID is only valid for validation")
                if action == "recon" and target_host:
                    raise ValueError("Recon scans are root-domain based; use Hunt for one host")
                if target_host:
                    if not host_belongs_to_root(target_host, domain["domain"], domain["include_subdomains"]):
                        raise ValueError("Exact host is outside the selected recon root")
                    if action == "hunt":
                        has_host_data = await conn.fetchval("""
                            SELECT EXISTS(
                              SELECT 1 FROM subdomains s JOIN live_hosts h ON h.subdomain_id=s.id
                              WHERE s.domain_id=$1 AND s.subdomain=$2
                            )
                        """, domain_id, target_host)
                        if not has_host_data:
                            raise ValueError("No saved live-host data for this hostname; run recon first")
                if credential_ids:
                    count = await conn.fetchval("""
                        SELECT COUNT(*) FROM hunt_credentials
                        WHERE domain_id=$1 AND id=ANY($2::bigint[])
                    """, domain_id, credential_ids)
                    if count != len(credential_ids):
                        raise ValueError("An account does not belong to this root domain")
                    if target_host:
                        exact_count = await conn.fetchval("""
                            SELECT COUNT(*) FROM hunt_credentials
                            WHERE domain_id=$1 AND id=ANY($2::bigint[]) AND lower(host)=$3
                        """, domain_id, credential_ids, target_host)
                        if exact_count != len(credential_ids):
                            raise ValueError("Selected accounts must be recorded for the exact host")
                if action == "hunt" and data_source == "recent_delta":
                    has_delta = await conn.fetchval("""
                        SELECT EXISTS(SELECT 1 FROM scan_snapshots
                          WHERE domain_id=$1 AND first_run=FALSE AND scan_finished_at IS NOT NULL)
                    """, domain_id)
                    if not has_delta:
                        raise ValueError("No completed delta scan; select all saved data")
                row = await conn.fetchrow("""
                    INSERT INTO agentic_runs
                      (domain_id, action, data_source, focus, parent_lead_id, credential_ids,
                       max_passes, target_host, request_budget, scope_confirmed_at)
                    VALUES ($1,$2,$3,$4,$5,$6::bigint[],$7,$8,$9,NOW()) RETURNING id, status, created_at
                """, domain_id, action, data_source, focus.strip(), parent_lead_id, credential_ids, max_passes, target_host, request_budget)
        return {"id": row["id"], "status": row["status"], "created_at": _iso(row["created_at"]),
                "domain": domain["domain"], "target_host": target_host, "action": action,
                "request_budget": request_budget}

    async def list_runs(self, domain_id: int | None = None, limit: int = 40):
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT r.id, r.domain_id, d.domain, r.target_host, r.action, r.status, r.data_source,
                       r.parent_lead_id, r.max_passes, r.request_budget, cardinality(r.credential_ids) AS account_count,
                       r.created_at, r.started_at, r.finished_at,
                       r.summary, r.error,
                       (SELECT COUNT(*) FROM agentic_leads l WHERE l.run_id=r.id) AS lead_count
                FROM agentic_runs r JOIN domains d ON d.id=r.domain_id
                WHERE ($1::integer IS NULL OR r.domain_id=$1)
                ORDER BY r.id DESC LIMIT $2
            """, domain_id, max(1, min(limit, 100)))
        return [{**dict(row), "summary": _json_object(row["summary"]),
                 "created_at": _iso(row["created_at"]),
                 "started_at": _iso(row["started_at"]), "finished_at": _iso(row["finished_at"])}
                for row in rows]

    async def get_run(self, run_id: int):
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT r.id, r.domain_id, d.domain, r.target_host, r.action, r.status, r.data_source,
                       r.parent_lead_id, r.max_passes, r.request_budget, cardinality(r.credential_ids) AS account_count,
                       r.created_at, r.started_at, r.finished_at,
                       r.summary, r.error, r.artifact_dir
                FROM agentic_runs r JOIN domains d ON d.id=r.domain_id WHERE r.id=$1
            """, run_id)
            if not row:
                raise ValueError("Run not found")
            leads = await conn.fetch("""
                SELECT id, title, skill, signal, source_table, source_id, asset,
                       priority, status, confidence, rationale, evidence_path, created_at
                FROM agentic_leads WHERE run_id=$1 ORDER BY
                  CASE priority WHEN 'high' THEN 0 WHEN 'med' THEN 1 ELSE 2 END,
                  confidence DESC, id DESC LIMIT 150
            """, run_id)
        data = dict(row)
        data["summary"] = _json_object(data["summary"])
        for key in ("created_at", "started_at", "finished_at"):
            data[key] = _iso(data[key])
        data["leads"] = [{**dict(lead), "created_at": _iso(lead["created_at"])} for lead in leads]
        return data

    async def get_lead_detail(self, lead_id: int):
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT l.id, l.run_id, l.domain_id, l.title, l.skill, l.signal,
                       l.source_table, l.source_id, l.asset, l.priority, l.status,
                       l.confidence, l.rationale, l.created_at,
                       r.action AS run_action, r.status AS run_status, r.artifact_dir,
                       r.summary, d.domain
                FROM agentic_leads l JOIN agentic_runs r ON r.id=l.run_id
                JOIN domains d ON d.id=l.domain_id WHERE l.id=$1
            """, lead_id)
            if not row:
                raise ValueError("Lead not found")
            lead = dict(row)
            source = None
            if lead["source_table"] == "endpoints":
                source = await conn.fetchrow("""
                    SELECT e.method, e.status_code, e.source, e.risk_tags,
                           e.first_seen, e.last_seen, h.url AS live_host,
                           ARRAY(SELECT DISTINCT p.param_name FROM url_parameters p
                                 WHERE p.endpoint_id=e.id ORDER BY p.param_name LIMIT 25) AS parameter_names
                    FROM endpoints e JOIN live_hosts h ON h.id=e.live_host_id
                    JOIN subdomains s ON s.id=h.subdomain_id
                    WHERE e.id=$1 AND s.domain_id=$2
                """, lead["source_id"], lead["domain_id"])
            elif lead["source_table"] == "js_assets":
                source = await conn.fetchrow("""
                    SELECT j.http_status AS status_code, j.source, j.sha256,
                           j.size_bytes, j.first_seen, j.last_seen, h.url AS live_host
                    FROM js_assets j JOIN live_hosts h ON h.id=j.live_host_id
                    JOIN subdomains s ON s.id=h.subdomain_id
                    WHERE j.id=$1 AND s.domain_id=$2
                """, lead["source_id"], lead["domain_id"])
            elif lead["source_table"] == "live_hosts":
                source = await conn.fetchrow("""
                    SELECT h.status_code, h.webserver, h.first_seen, h.last_seen,
                           h.url AS live_host FROM live_hosts h
                    JOIN subdomains s ON s.id=h.subdomain_id
                    WHERE h.id=$1 AND s.domain_id=$2
                """, lead["source_id"], lead["domain_id"])
            elif lead["source_table"] == "asset_events":
                source = await conn.fetchrow("""
                    SELECT event_type, entity_type, severity, first_seen, last_seen
                    FROM asset_events WHERE id=$1 AND domain_id=$2
                """, lead["source_id"], lead["domain_id"])
            validations = await conn.fetch("""
                SELECT id, status, created_at, finished_at, summary, error
                FROM agentic_runs WHERE action='validate' AND parent_lead_id=$1
                ORDER BY id DESC LIMIT 10
            """, lead_id)
        summary = _json_object(lead.pop("summary"))
        artifact_dir = lead.pop("artifact_dir")
        assessments = []
        base = Path("/root/codex_artifacts/agentic_hunts").resolve()
        if artifact_dir:
            run_dir = Path(artifact_dir).resolve()
            if run_dir.is_relative_to(base):
                for result_path in list(run_dir.glob("pass_*/result.json"))[:12]:
                    if not result_path.resolve().is_relative_to(run_dir) or result_path.stat().st_size > 2_000_000:
                        continue
                    try:
                        result = _json_object(result_path.read_text(encoding="utf-8"))
                    except OSError:
                        continue
                    for category in ("confirmed_findings", "leads", "killed"):
                        for item in (result.get(category) or [])[:100]:
                            if not isinstance(item, dict) or (item.get("source_table"), item.get("source_id")) != (lead["source_table"], lead["source_id"]):
                                continue
                            assessments.append({
                                "outcome": category, "title": str(item.get("title") or "")[:200],
                                "reason": str(item.get("reason") or item.get("observation") or item.get("proof_gap") or "")[:700],
                                "next_test": str(item.get("decisive_next_test") or "")[:350],
                                "evidence_file": Path(str(item.get("evidence_path") or "")).name[:100],
                            })
        for key in ("created_at",):
            lead[key] = _iso(lead[key])
        detail = {"lead": lead, "source": {key: _iso(value) for key, value in dict(source).items()} if source else None,
                  "assessments": assessments[:20],
                  "run_summary": str(summary.get("summary") or "")[:700],
                  "validations": [{"id": item["id"], "status": item["status"],
                                   "created_at": _iso(item["created_at"]),
                                   "finished_at": _iso(item["finished_at"]),
                                   "summary": str(_json_object(item["summary"]).get("summary") or "")[:500],
                                   "error": str(item["error"] or "")[:300]} for item in validations]}
        return detail

    async def pause_run(self, run_id: int):
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                UPDATE agentic_runs SET status='paused'
                WHERE id=$1 AND status='queued' RETURNING id, status
            """, run_id)
        if not row:
            raise ValueError("Only a queued run can be paused")
        return dict(row)
