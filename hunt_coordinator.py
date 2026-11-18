"""Domain-scoped hunt runs over the existing, evidence-backed bug-job queue."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import asyncpg
import yaml
from bug_job_taxonomy import ALIASES, canonical_job_type, job_category


LOG = logging.getLogger(__name__)

FAMILIES = (
    ("A01", "Broken access control", ("idor_bac_test", "graphql_authz_test", "mobile_api_parity_review", "ssrf_candidate_test")),
    ("A02", "Security misconfiguration", ("new_admin_route_review", "cors_misconfig_test", "cloud_storage_review", "cache_desync_review")),
    ("A03", "Software supply chain", ("component_supply_chain_review", "source_map_review")),
    ("A04", "Cryptographic failures", ("crypto_token_review",)),
    ("A05", "Injection", ("injection_review", "xss_reflection_test", "js_dom_xss_review", "upload_attack_surface")),
    ("A06", "Insecure design", ("business_logic_review", "ai_llm_workflow_review")),
    ("A07", "Authentication failures", ("auth_session_review", "email_parser_idn_review")),
    ("A08", "Software or data integrity", ("integrity_review",)),
    ("A09", "Security logging and alerting", ("logging_audit_review",)),
    ("A10", "Exceptional conditions", ("exceptional_condition_review",)),
    ("EX1", "Client messaging and WebSockets", ("websocket_review",)),
    ("EX2", "Secrets and exposed assets", ("js_secret_review", "js_endpoint_extraction", "delta_intelligence_review")),
)
JOB_FAMILY = {job_type: code for code, _, job_types in FAMILIES for job_type in job_types}
ACTIVE_STATUSES = {"active", "paused"}


def normalize_application_context(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Application context must be text")
    if "\0" in value:
        raise ValueError("Application context contains an invalid character")
    return value.strip()


def iso(value):
    return value.isoformat() + "Z" if isinstance(value, datetime) else value


def safe_asset_display(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        query = urlencode([(name, "[redacted]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))[:350]
    except ValueError:
        return "[invalid URL]"


def safe_hypothesis_display(value: str) -> str:
    return re.sub(
        r"(?i)\b(token|secret|key|code|session|auth|password|email)=([^&\s]+)",
        r"\1=[redacted]",
        str(value or "")[:500],
    )[:300]


def root_host_allowed(url: str, domain: str, include_subdomains: bool) -> bool:
    try:
        parsed = urlsplit(url if "://" in url else "https://" + url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    domain = domain.lower().rstrip(".")
    return host == domain or (include_subdomains and host.endswith("." + domain))


def rule_matches(pattern: str, value: str) -> bool:
    pattern = pattern.strip()
    if not pattern:
        return False
    if pattern.startswith("regex:"):
        try:
            return re.search(pattern[6:], value, re.IGNORECASE) is not None
        except re.error:
            return False
    if any(char in pattern for char in "*?[]"):
        return fnmatch.fnmatch(value.lower(), pattern.lower())
    return pattern.lower() in value.lower()


def excluded(value: str, patterns: list[str]) -> bool:
    try:
        hostname = urlsplit(value if "://" in value else "https://" + value).hostname or ""
    except ValueError:
        hostname = ""
    return any(rule_matches(pattern, value) or (hostname and rule_matches(pattern, hostname))
               for pattern in patterns)


def candidate_allowed(row, domain: str, include_subdomains: bool, exclusions: list[str]) -> bool:
    asset = str(row["asset_value"] or "")
    source_url = str(row["source_url"] or "")
    # A URL in a job is not proof of scope. For path-only jobs, verify the
    # owning endpoint or JavaScript host through its source relationship.
    if asset.startswith("recon-delta://"):
        return (row["source_table"] == "scan_snapshots"
                and root_host_allowed(asset, domain, False) and not excluded(asset, exclusions))
    if source_url and not root_host_allowed(source_url, domain, include_subdomains):
        return False
    if not source_url and row["source_table"] in {"endpoints", "js_assets", "live_hosts"}:
        return False
    if not source_url and "://" not in asset:
        return False
    if "://" in asset and not root_host_allowed(asset, domain, include_subdomains):
        return False
    return not excluded(source_url or asset, exclusions) and not excluded(asset, exclusions)


def select_candidates(rows, domain: str, include_subdomains: bool, exclusions: list[str], limit: int):
    """Round-robin across families while avoiding multiple labels per source."""
    buckets = defaultdict(list)
    for row in rows:
        family = JOB_FAMILY.get(canonical_job_type(row["job_type"]))
        if family and candidate_allowed(row, domain, include_subdomains, exclusions):
            buckets[family].append(row)
    for family_rows in buckets.values():
        family_rows.sort(
            key=lambda row: (
                row["status"] in {"running", "queued", "curation_pending"},
                row["priority"],
                row["source_observed_at"] or datetime.min,
            ),
            reverse=True,
        )
    chosen = []
    seen_sources = set()
    seen_types = set()
    while len(chosen) < limit and any(buckets.values()):
        advanced = False
        for code, _, _ in FAMILIES:
            bucket = buckets[code]
            bucket.sort(
                key=lambda row: (
                    row["job_type"] not in seen_types,
                    row["status"] in {"running", "queued", "curation_pending"},
                    row["priority"],
                    row["source_observed_at"] or datetime.min,
                ),
                reverse=True,
            )
            while bucket:
                row = bucket.pop(0)
                source_key = (row["source_table"], row["source_id"])
                if source_key[0] and source_key[1] and source_key in seen_sources:
                    continue
                if source_key[0] and source_key[1]:
                    seen_sources.add(source_key)
                chosen.append((code, row))
                seen_types.add(row["job_type"])
                advanced = True
                break
            if len(chosen) >= limit:
                break
        if not advanced:
            break
    return chosen


def classify_endpoint(path: str, method: str, parameters: list[str], status: int | None,
                      auth_profiles: int) -> list[tuple[str, int, str]]:
    """Require a concrete input or sensitive route; one hypothesis per surface."""
    try:
        route = urlsplit(path).path.lower()
    except ValueError:
        return []
    params = {name.lower().replace("-", "_") for name in parameters}
    useful = {0, 200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405}
    if status not in useful:
        return []
    authz = {"id", "user_id", "account_id", "org_id", "organization_id", "tenant_id",
             "workspace_id", "project_id", "member_id", "file_id", "report_id", "export_id"}
    url_inputs = {"url", "uri", "target_url", "callback_url", "webhook_url", "import_url",
                  "redirect_uri", "return_url", "next", "redirect"}
    text_inputs = {"q", "query", "search", "comment", "message", "description", "markdown", "html", "title"}
    query_inputs = {"filter", "sort", "where", "expression", "template", "query"}
    file_inputs = {"file", "filename", "filepath", "path", "folder", "template", "document", "resource"}
    if params & authz and auth_profiles >= 2 and re.search(r"/(api|graphql|users|orgs|projects|files|reports|exports)(/|$)", route):
        return [("idor_bac_test", 97, "Compare this object identifier across two owned actor profiles and an invalid control.")]
    if params & url_inputs:
        return [("ssrf_candidate_test", 96, "Determine whether this concrete URL input crosses a server-fetch or redirect trust boundary.")]
    if params & file_inputs and (method in {"POST", "PUT", "PATCH"} or re.search(r"/(upload|import|download|preview|export|files?)(/|$)", route)):
        return [("upload_attack_surface", 96, "Validate file/path handling on this observed endpoint using only owned or public fixtures.")]
    if params & text_inputs and method == "GET":
        return [("xss_reflection_test", 95, "Trace this observed text input to its response context and test a bounded harmless reflection proof.")]
    if params & query_inputs and re.search(r"/(api|search|query|report|filter)(/|$)", route):
        return [("injection_review", 94, "Check whether this observed query input reaches an unsafe interpreter with bounded controls.")]
    if re.search(r"/(admin|internal|debug|actuator|swagger|openapi)(/|$)", route) and status in {200, 301, 302, 307, 308, 401}:
        return [("new_admin_route_review", 94, "Verify the current sensitive route is real and identify its access boundary.")]
    return []


class HuntCoordinator:
    def __init__(self, pool: asyncpg.Pool, config: dict):
        self.pool = pool
        self.config = config

    async def ensure_schema(self) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_runs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    mode VARCHAR(20) NOT NULL CHECK (mode IN ('one_time', 'continuous')),
                    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
                    scope_confirmed_at TIMESTAMP NOT NULL,
                    source_window_days INTEGER NOT NULL DEFAULT 30 CHECK (source_window_days BETWEEN 1 AND 30),
                    max_jobs_per_cycle INTEGER NOT NULL DEFAULT 24 CHECK (max_jobs_per_cycle BETWEEN 1 AND 60),
                    application_context TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_refresh_at TIMESTAMP,
                    last_snapshot_id INTEGER,
                    signal_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
                    last_error TEXT
                )
            """)
            await conn.execute("ALTER TABLE hunt_runs ADD COLUMN IF NOT EXISTS signal_summary JSONB NOT NULL DEFAULT '[]'::jsonb")
            await conn.execute("ALTER TABLE hunt_runs ADD COLUMN IF NOT EXISTS application_context TEXT NOT NULL DEFAULT ''")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_credentials (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    alias VARCHAR(80) NOT NULL,
                    role VARCHAR(100) NOT NULL DEFAULT '',
                    tenant VARCHAR(100) NOT NULL DEFAULT '',
                    host VARCHAR(255) NOT NULL,
                    credential_type VARCHAR(12) NOT NULL CHECK (credential_type IN ('cookie', 'bearer', 'header', 'login_file', 'manual_login')),
                    header_name VARCHAR(80) NOT NULL,
                    secret_file VARCHAR(40) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, alias)
                )
            """)
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(45123, 31881)")
                definition = await conn.fetchval("""
                    SELECT pg_get_constraintdef(oid) FROM pg_constraint
                    WHERE conrelid = 'hunt_credentials'::regclass
                      AND conname = 'hunt_credentials_credential_type_check'
                """)
                if not definition or "manual_login" not in definition:
                    await conn.execute("ALTER TABLE hunt_credentials DROP CONSTRAINT IF EXISTS hunt_credentials_credential_type_check")
                    await conn.execute("""
                        ALTER TABLE hunt_credentials ADD CONSTRAINT hunt_credentials_credential_type_check
                        CHECK (credential_type IN ('cookie', 'bearer', 'header', 'login_file', 'manual_login'))
                    """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_run_credentials (
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    credential_id BIGINT NOT NULL REFERENCES hunt_credentials(id) ON DELETE CASCADE,
                    PRIMARY KEY (run_id, credential_id)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_run_jobs (
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    job_id BIGINT NOT NULL REFERENCES bug_jobs(id) ON DELETE CASCADE,
                    family VARCHAR(8) NOT NULL,
                    linked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (run_id, job_id)
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_runs_active ON hunt_runs(status, mode, last_refresh_at) WHERE status = 'active'")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_runs_domain ON hunt_runs(domain_id, created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_run_jobs_family ON hunt_run_jobs(run_id, family)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_run_jobs_job ON hunt_run_jobs(job_id)")

    async def validate_credentials(self, conn, domain_id: int, ids: list[int]) -> None:
        if (not isinstance(ids, list) or len(ids) > 8
                or any(type(value) is not int or value < 1 for value in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError("Select up to eight unique owned account IDs")
        if ids:
            found = await conn.fetchval("SELECT COUNT(*) FROM hunt_credentials WHERE domain_id = $1 AND id = ANY($2::bigint[])", domain_id, ids)
            if found != len(ids):
                raise ValueError("A selected account does not belong to this root domain")

    async def sync_pending_job_context(self, conn, run_id: int) -> None:
        run = await conn.fetchrow("SELECT domain_id, application_context FROM hunt_runs WHERE id = $1", run_id)
        if not run:
            return
        rows = await conn.fetch("""
            SELECT hc.alias, hc.role, hc.tenant, hc.host, hc.credential_type,
                   hc.header_name, hc.secret_file
            FROM hunt_run_credentials hrc JOIN hunt_credentials hc ON hc.id = hrc.credential_id
            WHERE hrc.run_id = $1 AND hc.domain_id = $2 ORDER BY hc.alias
        """, run_id, run["domain_id"])
        accounts = [{"alias": row["alias"], "role": row["role"], "tenant": row["tenant"],
                     "exact_host": row["host"], "type": row["credential_type"],
                     "header": row["header_name"],
                     "secret_file": f"/root/codex_artifacts/hunt_credentials/{row['secret_file']}"}
                    for row in rows]
        context = {"run_id": run_id, "application_context": run["application_context"],
                   "owned_accounts": accounts,
                   "account_rule": "Use only these owned accounts on their exact host; never print or persist secret values; verify identity before testing."}
        await conn.execute("""
            UPDATE bug_jobs bj
            SET required_context = COALESCE(bj.required_context, '{}'::jsonb)
                || jsonb_build_object('_hunt_context_fallback', $2::jsonb)
            FROM hunt_run_jobs hrj
            WHERE hrj.run_id = $1 AND bj.id = hrj.job_id AND bj.domain_id = $3
              AND bj.status IN ('queued', 'curation_pending')
              AND bj.required_context->'_hunt_context_fallback' IS DISTINCT FROM $2::jsonb
        """, run_id, json.dumps(context), run["domain_id"])

    async def list_credentials(self, domain_id: int) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, alias, role, tenant, host, credential_type, header_name, created_at
                FROM hunt_credentials WHERE domain_id = $1 ORDER BY alias
            """, domain_id)
        return [{key: iso(value) for key, value in dict(row).items()} for row in rows]

    async def add_credential(self, domain_id: int, fields: dict, secret_file: str) -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO hunt_credentials (domain_id, alias, role, tenant, host, credential_type, header_name, secret_file)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                RETURNING id, alias, role, tenant, host, credential_type, header_name, created_at
            """, domain_id, fields["alias"], fields["role"], fields["tenant"], fields["host"],
                fields["credential_type"], fields["header_name"], secret_file)
        return {key: iso(value) for key, value in dict(row).items()}

    async def delete_credential(self, credential_id: int) -> str:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run_ids = await conn.fetch("SELECT run_id FROM hunt_run_credentials WHERE credential_id = $1", credential_id)
                row = await conn.fetchrow("DELETE FROM hunt_credentials WHERE id = $1 RETURNING secret_file", credential_id)
                for item in run_ids:
                    await self.sync_pending_job_context(conn, item["run_id"])
        if not row:
            raise ValueError("Account not found")
        return row["secret_file"]

    async def start_run(self, domain_id: int, mode: str, max_jobs: int,
                        application_context: str = "", credential_ids: list[int] | None = None) -> dict:
        if mode not in {"one_time", "continuous"}:
            raise ValueError("mode must be one_time or continuous")
        if not 1 <= max_jobs <= 60:
            raise ValueError("max_jobs_per_cycle must be between 1 and 60")
        application_context = normalize_application_context(application_context)
        credential_ids = credential_ids or []
        existing = None
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                domain = await conn.fetchrow("SELECT id, domain, active FROM domains WHERE id = $1", domain_id)
                if not domain or not domain["active"]:
                    raise ValueError("select an active root domain from the recon database")
                await self.validate_credentials(conn, domain_id, credential_ids)
                if mode == "continuous":
                    existing = await conn.fetchval("""
                        SELECT id FROM hunt_runs WHERE domain_id = $1 AND mode = 'continuous'
                          AND status = 'active' ORDER BY created_at DESC LIMIT 1
                    """, domain_id)
                if not existing:
                    run_id = await conn.fetchval("""
                        INSERT INTO hunt_runs (domain_id, mode, scope_confirmed_at, max_jobs_per_cycle, application_context)
                        VALUES ($1, $2, NOW(), $3, $4) RETURNING id
                    """, domain_id, mode, max_jobs, application_context)
                    for credential_id in credential_ids:
                        await conn.execute("INSERT INTO hunt_run_credentials (run_id, credential_id) VALUES ($1, $2)", run_id, credential_id)
        if existing:
            await self.update_context(existing, application_context, credential_ids)
            return await self.get_run(existing)
        try:
            await self.refresh_run(run_id)
        except Exception as exc:
            LOG.exception("Initial hunt run %s refresh failed", run_id)
            async with self.pool.acquire() as conn:
                await conn.execute("UPDATE hunt_runs SET last_error = $2 WHERE id = $1", run_id, str(exc)[:500])
        return await self.get_run(run_id)

    async def refresh_run(self, run_id: int) -> dict:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchval("SELECT pg_try_advisory_xact_lock(817265, $1::int)", run_id)
                if not locked:
                    return {"run_id": run_id, "busy": True, "linked": 0}
                run = await conn.fetchrow("""
                    SELECT h.*, d.domain, d.active AS domain_active, d.include_subdomains
                    FROM hunt_runs h JOIN domains d ON d.id = h.domain_id WHERE h.id = $1
                """, run_id)
                if not run:
                    raise ValueError("hunt run not found")
                if run["status"] != "active" or not run["domain_active"]:
                    return {"run_id": run_id, "linked": 0, "paused": True}
                latest_snapshot = await conn.fetchval("""
                    SELECT id FROM scan_snapshots WHERE domain_id = $1
                    ORDER BY scan_finished_at DESC LIMIT 1
                """, run["domain_id"])
                rules = await conn.fetch("""
                    SELECT pattern FROM scope_rules WHERE enabled = TRUE
                      AND (domain_id = $1 OR domain_id IS NULL)
                      AND rule_type IN ('exclude', 'deny', 'out_of_scope')
                """, run["domain_id"])
                exclusions = [str(row["pattern"]) for row in rules]
                exclusions += list(self.config.get("scan", {}).get("out_of_scope_patterns", []) or [])
                rows = await conn.fetch("""
                    SELECT bj.id, bj.job_type, bj.status, bj.priority, bj.asset_value,
                           bj.source_table, bj.source_id, bj.source_observed_at,
                           COALESCE(eh.url, jh.url, lh.url, '') AS source_url
                    FROM unnest($4::text[]) AS jt(job_type)
                    CROSS JOIN LATERAL (
                      SELECT bj.id, bj.job_type, bj.status, bj.priority,
                             bj.asset_value, bj.source_table, bj.source_id,
                             bj.source_observed_at
                      FROM bug_jobs bj
                      WHERE bj.domain_id = $1 AND bj.job_type = jt.job_type
                        AND bj.scope_ok = TRUE AND bj.priority >= 90
                        AND bj.status IN ('queued', 'curation_pending', 'running', 'done')
                        AND (bj.status <> 'done' OR bj.outcome_class IN (
                          'CONFIRMED_UNIQUE', 'STRONG_CANDIDATE', 'NEEDS_MANUAL_REVIEW'
                        ))
                        AND bj.source_observed_at >= NOW() - make_interval(days => $2::int)
                        AND NOT EXISTS (
                          SELECT 1 FROM hunt_run_jobs hrj
                          WHERE hrj.run_id = $3 AND hrj.job_id = bj.id
                        )
                      ORDER BY bj.source_observed_at DESC, bj.priority DESC
                      LIMIT 80
                    ) bj
                    LEFT JOIN endpoints e ON bj.source_table = 'endpoints' AND bj.source_id = e.id
                    LEFT JOIN live_hosts eh ON eh.id = e.live_host_id
                    LEFT JOIN js_assets j ON bj.source_table = 'js_assets' AND bj.source_id = j.id
                    LEFT JOIN live_hosts jh ON jh.id = j.live_host_id
                    LEFT JOIN live_hosts lh ON bj.source_table = 'live_hosts' AND bj.source_id = lh.id
                    ORDER BY bj.source_observed_at DESC, bj.priority DESC
                    LIMIT 3000
                """, run["domain_id"], run["source_window_days"], run_id,
                    list(JOB_FAMILY) + [alias for alias, canonical in ALIASES.items() if canonical in JOB_FAMILY])
                chosen = select_candidates(
                    rows, run["domain"], run["include_subdomains"], exclusions,
                    run["max_jobs_per_cycle"],
                )
                for family, row in chosen:
                    await conn.execute("""
                        INSERT INTO hunt_run_jobs (run_id, job_id, family)
                        VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
                    """, run_id, row["id"], family)
                credential_hosts = await conn.fetchval("""
                    SELECT COALESCE(array_agg(hc.host), '{}'::text[])
                    FROM hunt_run_credentials hrc JOIN hunt_credentials hc ON hc.id = hrc.credential_id
                    WHERE hrc.run_id = $1 AND hc.domain_id = $2
                """, run_id, run["domain_id"])
                endpoint_rows = await conn.fetch("""
                    SELECT e.id, e.path, e.method, e.status_code, e.last_seen,
                           e.parameters, lh.url AS host_url,
                           (SELECT array_agg(up.param_name) FROM url_parameters up
                            WHERE up.endpoint_id = e.id) AS param_names
                    FROM endpoints e
                    JOIN live_hosts lh ON lh.id = e.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    WHERE s.domain_id = $1
                      AND e.last_seen >= NOW() - make_interval(days => $2::int)
                    ORDER BY e.last_seen DESC
                    LIMIT 250
                """, run["domain_id"], run["source_window_days"])
                linked_sources = set(await conn.fetchval("""
                    SELECT COALESCE(array_agg(DISTINCT bj.source_id), '{}'::int[])
                    FROM hunt_run_jobs hrj JOIN bug_jobs bj ON bj.id = hrj.job_id
                    WHERE hrj.run_id = $1 AND bj.source_table = 'endpoints'
                """, run_id) or [])
                signals = []
                family_signal_counts = Counter()
                source_seen = {}
                for endpoint in endpoint_rows:
                    if endpoint["id"] in linked_sources:
                        continue
                    host_url = str(endpoint["host_url"] or "")
                    if not root_host_allowed(host_url, run["domain"], run["include_subdomains"]):
                        continue
                    path = str(endpoint["path"] or "")
                    if path.startswith("//") or ("://" in path and not root_host_allowed(path, run["domain"], run["include_subdomains"])):
                        continue
                    try:
                        parsed = urlsplit(path)
                        asset = (urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
                                 if parsed.scheme else urljoin(host_url.rstrip("/") + "/", parsed.path.lstrip("/")))
                    except ValueError:
                        continue
                    if excluded(asset, exclusions):
                        continue
                    parameters = list(endpoint["param_names"] or [])
                    parameters += [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
                    if isinstance(endpoint["parameters"], dict):
                        parameters += list(endpoint["parameters"].keys())
                    parameters = [str(name) for name in parameters
                                  if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", str(name))]
                    source_seen[endpoint["id"]] = endpoint["last_seen"]
                    endpoint_host = (urlsplit(host_url).hostname or "").lower()
                    auth_profiles = sum(host == endpoint_host for host in credential_hosts or [])
                    hypotheses = classify_endpoint(path, str(endpoint["method"] or "GET").upper(), parameters,
                                                   endpoint["status_code"], max(int(auth_profiles or 0), 2))
                    for job_type, priority, hypothesis in hypotheses:
                        family = JOB_FAMILY[job_type]
                        if family_signal_counts[family] >= 3 or len(signals) >= 20:
                            continue
                        blocker = "two owned actor profiles required" if job_type == "idor_bac_test" and auth_profiles < 2 else "no linked high-signal job"
                        signals.append({"family": family, "job_type": job_type,
                                        "asset": asset, "source_id": endpoint["id"],
                                        "priority": priority, "hypothesis": hypothesis,
                                        "parameters": sorted(set(parameters))[:24],
                                        "method": str(endpoint["method"] or "GET").upper(),
                                        "http_status": endpoint["status_code"],
                                        "blocker": blocker, "observed_at": iso(endpoint["last_seen"])})
                        family_signal_counts[family] += 1
                slots = min(6, max(0, run["max_jobs_per_cycle"] - len(chosen)))
                generated = 0
                if slots:
                    # Match the watcher's canonical key so repeated runs do not
                    # relabel the same endpoint as a fresh security job.
                    from continuous_recon import ContinuousReconFramework
                    for signal in signals:
                        if generated >= slots:
                            break
                        if signal["blocker"] != "no linked high-signal job":
                            continue
                        canonical = ContinuousReconFramework.canonical_bug_job_asset_key("endpoint", signal["asset"])
                        job_key = hashlib.sha256(
                            f"{run['domain_id']}|endpoint|None|endpoint|{canonical}|{signal['job_type']}".encode()
                        ).hexdigest()
                        context = {
                            "hunt_run_id": run_id,
                            "bug_job_high_signal_reasons": ["campaign-concrete-endpoint-input"],
                            "location": signal["asset"],
                            "payload": {
                                "url": signal["asset"], "method": signal["method"],
                                "status_code": signal["http_status"],
                                "parameters": signal["parameters"],
                                "source": "hunt_coordinator",
                            },
                        }
                        job_id = await conn.fetchval("""
                            INSERT INTO bug_jobs (
                                domain_id, target, asset_type, asset_value, job_type,
                                job_category, priority, status, scope_ok, source_table,
                                source_id, source_observed_at, job_key, hypothesis,
                                safety_notes, required_context
                            ) VALUES (
                                $1, $2, 'endpoint', $3, $4, $5, $6, $7, TRUE,
                                'endpoints', $8, $9, $10, $11, $12, $13::jsonb
                            ) ON CONFLICT (job_key) DO NOTHING RETURNING id
                        """, run["domain_id"], run["domain"], signal["asset"], signal["job_type"],
                            job_category(signal["job_type"]), signal["priority"],
                            "curation_pending" if self.config.get("scan", {}).get("bug_job_curator_enabled", True) else "queued",
                            signal["source_id"], source_seen[signal["source_id"]], job_key,
                            signal["hypothesis"], ["Use only authorized assets and owned test data", "Avoid non-disposable mutations"],
                            json.dumps(context))
                        if job_id:
                            await conn.execute("""
                                INSERT INTO hunt_run_jobs (run_id, job_id, family)
                                VALUES ($1, $2, $3) ON CONFLICT DO NOTHING
                            """, run_id, job_id, signal["family"])
                            signal["blocker"] = "queued for curation"
                            generated += 1
                        else:
                            signal["blocker"] = "existing deduplicated job"
                signals = [signal for signal in signals if signal["blocker"] != "queued for curation"]
                await self.sync_pending_job_context(conn, run_id)
                await conn.execute("""
                    UPDATE hunt_runs SET last_refresh_at = NOW(), last_snapshot_id = $2,
                        signal_summary = $3::jsonb, last_error = NULL WHERE id = $1
                """, run_id, latest_snapshot, json.dumps(signals))
                return {"run_id": run_id, "linked": len(chosen) + generated,
                        "generated": generated, "signals": len(signals), "snapshot_id": latest_snapshot}

    async def set_status(self, run_id: int, status: str) -> dict:
        if status not in ACTIVE_STATUSES:
            raise ValueError("status must be active or paused")
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                UPDATE hunt_runs SET status = $2 WHERE id = $1 RETURNING id
            """, run_id, status)
        if not row:
            raise ValueError("hunt run not found")
        if status == "active":
            try:
                await self.refresh_run(run_id)
            except Exception as exc:
                LOG.exception("Resumed hunt run %s refresh failed", run_id)
                async with self.pool.acquire() as conn:
                    await conn.execute("UPDATE hunt_runs SET last_error = $2 WHERE id = $1", run_id, str(exc)[:500])
        return await self.get_run(run_id)

    async def update_context(self, run_id: int, application_context: str, credential_ids: list[int]) -> dict:
        application_context = normalize_application_context(application_context)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                domain_id = await conn.fetchval("SELECT domain_id FROM hunt_runs WHERE id = $1 FOR UPDATE", run_id)
                if not domain_id:
                    raise ValueError("hunt run not found")
                await self.validate_credentials(conn, domain_id, credential_ids)
                await conn.execute("UPDATE hunt_runs SET application_context = $2 WHERE id = $1", run_id, application_context)
                await conn.execute("DELETE FROM hunt_run_credentials WHERE run_id = $1", run_id)
                for credential_id in credential_ids:
                    await conn.execute("INSERT INTO hunt_run_credentials (run_id, credential_id) VALUES ($1, $2)", run_id, credential_id)
                await self.sync_pending_job_context(conn, run_id)
        return await self.get_run(run_id)

    async def list_runs(self, domain_id: int | None = None, limit: int = 40) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT h.id, h.domain_id, d.domain, h.mode, h.status, h.created_at,
                       h.last_refresh_at, h.last_snapshot_id, h.max_jobs_per_cycle,
                       COUNT(hrj.job_id)::int AS job_count,
                       COUNT(hrj.job_id) FILTER (WHERE bj.status = 'done')::int AS done_count,
                       COUNT(hrj.job_id) FILTER (WHERE bj.outcome_class = 'CONFIRMED_UNIQUE')::int AS confirmed_count,
                       COUNT(hrj.job_id) FILTER (WHERE bj.outcome_class IN ('STRONG_CANDIDATE', 'NEEDS_MANUAL_REVIEW'))::int AS lead_count
                FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                LEFT JOIN hunt_run_jobs hrj ON hrj.run_id = h.id
                LEFT JOIN bug_jobs bj ON bj.id = hrj.job_id
                WHERE ($1::int IS NULL OR h.domain_id = $1)
                GROUP BY h.id, d.domain
                ORDER BY h.created_at DESC LIMIT $2
            """, domain_id, limit)
            return [{key: iso(value) for key, value in dict(row).items()} for row in rows]

    async def get_run(self, run_id: int) -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT h.*, d.domain FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                WHERE h.id = $1
            """, run_id)
            if not row:
                raise ValueError("hunt run not found")
            group_rows = await conn.fetch("""
                SELECT hrj.family, bj.status, COALESCE(bj.outcome_class, '') AS outcome,
                       COUNT(*)::int AS count
                FROM hunt_run_jobs hrj JOIN bug_jobs bj ON bj.id = hrj.job_id
                WHERE hrj.run_id = $1
                GROUP BY hrj.family, bj.status, bj.outcome_class
            """, run_id)
            jobs = await conn.fetch("""
                SELECT hrj.family, bj.id, bj.job_type, bj.status, bj.priority,
                       bj.asset_value, bj.hypothesis, bj.source_table, bj.source_id,
                       bj.finding_status, bj.outcome_class, bj.confidence,
                       bj.manual_review_priority,
                       bj.created_at, bj.updated_at
                FROM hunt_run_jobs hrj JOIN bug_jobs bj ON bj.id = hrj.job_id
                WHERE hrj.run_id = $1
                ORDER BY CASE WHEN bj.outcome_class = 'CONFIRMED_UNIQUE' THEN 0
                              WHEN bj.outcome_class IN ('STRONG_CANDIDATE', 'NEEDS_MANUAL_REVIEW') THEN 1
                              WHEN bj.status = 'running' THEN 2 ELSE 3 END,
                         bj.priority DESC, bj.updated_at DESC
                LIMIT 300
            """, run_id)
            credentials = await conn.fetch("""
                SELECT hc.id, hc.alias, hc.role, hc.tenant, hc.host, hc.credential_type
                FROM hunt_run_credentials hrc JOIN hunt_credentials hc ON hc.id = hrc.credential_id
                WHERE hrc.run_id = $1 ORDER BY hc.alias
            """, run_id)
        serialized_jobs = []
        counts = Counter()
        outcomes = Counter()
        statuses = Counter()
        for group in group_rows:
            counts[group["family"]] += group["count"]
            outcomes[(group["family"], group["outcome"])] += group["count"]
            statuses[(group["family"], group["status"])] += group["count"]
        for job in jobs:
            item = {key: iso(value) for key, value in dict(job).items()}
            item["asset_value"] = safe_asset_display(item["asset_value"])
            item["hypothesis"] = safe_hypothesis_display(item.get("hypothesis"))
            serialized_jobs.append(item)
        coverage = []
        signals = row["signal_summary"] if isinstance(row["signal_summary"], list) else []
        for code, label, job_types in FAMILIES:
            family_signals = [signal for signal in signals if signal["family"] == code]
            if outcomes[(code, "CONFIRMED_UNIQUE")]:
                state = "confirmed"
            elif outcomes[(code, "STRONG_CANDIDATE")] or outcomes[(code, "NEEDS_MANUAL_REVIEW")]:
                state = "lead"
            elif statuses[(code, "running")]:
                state = "running"
            elif statuses[(code, "queued")] or statuses[(code, "curation_pending")]:
                state = "queued"
            elif counts[code] and statuses[(code, "done")] == counts[code]:
                state = "reviewed_sample"
            elif counts[code]:
                state = "blocked"
            elif family_signals and all(signal["blocker"] == "two owned actor profiles required" for signal in family_signals):
                state = "needs_accounts"
            elif family_signals:
                state = "unverified_signal"
            else:
                state = "no_recon_signal"
            coverage.append({"code": code, "label": label, "state": state,
                             "jobs": counts[code], "signals": len(family_signals), "job_types": list(job_types)})
        return {
            "run": {key: iso(value) for key, value in dict(row).items()},
            "credentials": [dict(item) for item in credentials],
            "coverage": coverage,
            "jobs": serialized_jobs,
            "signals": signals,
            "summary": {
                "jobs": sum(counts.values()),
                "displayed_jobs": len(serialized_jobs),
                "confirmed": sum(count for (family, outcome), count in outcomes.items() if outcome == "CONFIRMED_UNIQUE"),
                "leads": sum(count for (family, outcome), count in outcomes.items() if outcome in {"STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}),
                "running": sum(count for (family, status), count in statuses.items() if status == "running"),
                "unassessed_families": sum(item["state"] in {"no_recon_signal", "unverified_signal", "needs_accounts"} for item in coverage),
            },
        }


async def run_service() -> None:
    with open("/app/config.yaml", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    database = config["database"]
    database["password"] = os.getenv("RECON_DB_PASSWORD", database["password"])
    pool = await asyncpg.create_pool(
        host=database["host"], port=database["port"], database=database["name"],
        user=database["user"], password=database["password"], min_size=1, max_size=2,
        command_timeout=30,
    )
    coordinator = HuntCoordinator(pool, config)
    await coordinator.ensure_schema()
    try:
        while True:
            try:
                async with pool.acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT id FROM hunt_runs WHERE status = 'active' AND mode = 'continuous'
                          AND (last_refresh_at IS NULL OR last_refresh_at < NOW() - INTERVAL '12 hours')
                        ORDER BY last_refresh_at NULLS FIRST LIMIT 20
                    """)
                for row in rows:
                    try:
                        await coordinator.refresh_run(row["id"])
                    except Exception as exc:
                        LOG.exception("Hunt run %s refresh failed", row["id"])
                        async with pool.acquire() as conn:
                            await conn.execute("UPDATE hunt_runs SET last_error = $2 WHERE id = $1", row["id"], str(exc)[:500])
            except Exception:
                LOG.exception("Hunt coordinator cycle failed")
            await asyncio.sleep(300)
    finally:
        await pool.close()


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    asyncio.run(run_service())
