#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import re
import signal
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import asyncpg

from continuous_recon import load_config


LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "bug_job_curator.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("bug-job-curator")


CURATOR_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "job_id": {"type": "integer"},
                    "action": {"type": "string", "enum": ["keep", "defer"]},
                    "score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "reason": {"type": "string", "maxLength": 500},
                },
                "required": ["job_id", "action", "score", "reason"],
            },
        }
    },
    "required": ["decisions"],
}


@dataclass(frozen=True)
class Decision:
    action: str
    score: int
    reason: str
    decided_by: str = "rules"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def int_value(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def source_age_days(value: Any, now: datetime) -> float | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0.0, (now - value.astimezone(timezone.utc)).total_seconds() / 86400)


def canonical_host(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value.lower()
    if not parsed.hostname:
        return value.lower()
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and not ((parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    return host


def path_weight(value: str) -> int:
    path = urlsplit(value).path.lower()
    weights = {
        "/actuator/env": 20,
        "/actuator/configprops": 19,
        "/actuator/logfile": 18,
        "/actuator/mappings": 17,
        "/debug": 16,
        "/config": 15,
        "/backup": 15,
        "/openapi": 14,
        "/api-docs": 14,
        "/swagger": 14,
        "/admin": 13,
        "/internal": 12,
        "/actuator/health": 3,
        "/actuator/info": 2,
    }
    return max((score for token, score in weights.items() if token in path), default=0)


def parameter_names(context: dict[str, Any]) -> set[str]:
    payload = as_dict(context.get("payload"))
    names: set[str] = set()
    for item in as_list(payload.get("parameters")):
        if isinstance(item, dict) and item.get("name"):
            names.add(str(item["name"]).lower())
        elif isinstance(item, str):
            names.add(item.lower())
    try:
        query = urlsplit(str(payload.get("url") or context.get("location") or "")).query
    except ValueError:
        query = ""
    for pair in query.split("&"):
        if pair:
            names.add(pair.split("=", 1)[0].lower())
    return names


def deterministic_decision(job: dict[str, Any], now: datetime, max_source_age_days: int) -> Decision:
    context = as_dict(job.get("required_context"))
    payload = as_dict(context.get("payload"))
    reasons = {str(item) for item in as_list(context.get("bug_job_high_signal_reasons"))}
    risk = as_dict(job.get("js_risk"))
    job_type = str(job.get("job_type") or "")
    source_table = str(job.get("source_table") or "")
    asset_value = str(job.get("asset_value") or "")
    priority = int_value(job.get("priority"))
    age = source_age_days(job.get("source_observed_at"), now)

    if not bool(job.get("scope_ok", True)):
        return Decision("defer", 0, "scope is not confirmed")
    if priority < 90:
        return Decision("defer", priority, "priority is below the autonomous worker threshold")
    if age is None and job_type != "delta_intelligence_review":
        return Decision("defer", 20, "source freshness is unknown")
    if age is not None and age > max_source_age_days:
        return Decision("defer", 10, f"source is older than {max_source_age_days} days")
    if job_type == "delta_intelligence_review":
        concrete_ids = context.get("high_signal_source_ids")
        if isinstance(concrete_ids, list) and concrete_ids:
            return Decision("keep", max(priority, 96), "delta window contains concrete prefiltered high-signal source IDs")
        return Decision("defer", 40, "aggregate delta summary has no concrete prefiltered security signal")

    status = int_value(payload.get("status_code") or payload.get("http_status") or job.get("source_http_status"))
    params = parameter_names(context)
    path = urlsplit(asset_value).path.lower()
    is_js = source_table == "js_assets" or str(job.get("asset_type") or "") in {"js_asset", "js_file"}

    if job_type == "js_dom_xss_review":
        if status and status != 200:
            return Decision("defer", 15, "JavaScript body is not a current HTTP 200 response")
        mandatory_delta_review = bool(
            context.get("mandatory_delta_js_dom_review") is True
            and context.get("is_delta_scan") is True
            and str(context.get("scan_lane") or "").lower() in {"fast_delta", "deep_scan"}
            and (payload.get("is_new") is True or payload.get("is_changed") is True)
            and re.fullmatch(r"[0-9a-f]{64}", str(context.get("javascript_sha256") or ""))
        )
        if mandatory_delta_review:
            return Decision("keep", max(priority, 97), "new or changed delta-scan JavaScript body requires focused DOM/postMessage review")
        sinks = int_value(risk.get("dom_sink_count"))
        messages = int_value(risk.get("postmessage_count"))
        dom_flow = int_value(risk.get("dom_source_sink_proximity_count"))
        message_flow = int_value(risk.get("postmessage_data_flow_count"))
        message_effect = int_value(risk.get("postmessage_sensitive_effect_count"))
        if dom_flow:
            return Decision("keep", 99, "JavaScript has a bounded location-source to executable-DOM-sink relationship")
        if message_flow and message_effect:
            return Decision("keep", 98, "message receiver has bounded event-data and security-sensitive-effect relationships")
        if sinks or messages:
            return Decision("defer", 45, "file-wide DOM/postMessage keywords exist without a bounded data-flow relationship")
        return Decision("defer", 35, "new or changed JavaScript has no extracted DOM sink or postMessage signal")

    if job_type == "graphql_authz_test":
        operations = int_value(risk.get("graphql_operation_count"))
        persisted = int_value(risk.get("graphql_persisted_query_count"))
        client_endpoints = int_value(job.get("graphql_client_endpoint_count"))
        if bool(job.get("graphql_protocol_confirmed")):
            return Decision("keep", 99, "current endpoint produced a confirmed or probable GraphQL protocol response")
        if is_js and client_endpoints and (operations or persisted):
            return Decision("keep", 96, "JavaScript ties a concrete GraphQL endpoint to an operation or persisted query")
        return Decision("defer", 30, "GraphQL evidence is lexical or incomplete; protocol response or endpoint plus operation is absent")

    if job_type == "source_map_review":
        linked_secrets = int_value(job.get("linked_secret_like_count"))
        if status in {0, 200} and linked_secrets:
            return Decision("keep", 97, "current source map is tied to a redacted secret-like static-analysis candidate")
        if status in {0, 200} and (path.endswith(".map") or "source-map-signal" in reasons):
            return Decision("defer", 45, "source map is reachable but deterministic analysis found no sensitive candidate")
        return Decision("defer", 30, "source-map availability is not established")

    parameter_driven = {
        "ssrf_candidate_test": {"url", "uri", "redirect", "redirect_uri", "next", "return_to", "callback", "callback_url", "webhook", "import_url"},
        "xss_reflection_test": {"comment", "message", "description", "markdown", "html", "note", "title", "name", "q", "query", "search", "callback", "return"},
        "injection_review": {"query", "search", "filter", "sort", "order", "where", "select", "json", "template", "expression", "cmd", "command", "exec", "xpath", "ldap"},
        "idor_bac_test": {"id", "user_id", "userid", "account_id", "org_id", "organization_id", "tenant_id", "team_id", "workspace_id", "project_id", "member_id", "role_id", "file_id", "report_id", "export_id"},
    }
    if job_type in parameter_driven:
        matched = params & parameter_driven[job_type]
        if matched:
            if job_type == "idor_bac_test" and int_value(job.get("auth_profile_count")) < 2:
                return Decision("defer", 50, "object identifier exists but two owned actor profiles are not configured")
            return Decision("keep", max(priority, 96), f"concrete security-relevant parameter: {', '.join(sorted(matched)[:4])}")
        if source_table == "endpoints" and job_type == "idor_bac_test" and re.search(r"/(?:users|accounts|orgs|projects|files|reports|exports)/[^/]+", path):
            if int_value(job.get("auth_profile_count")) < 2:
                return Decision("defer", 50, "object-bearing path exists but two owned actor profiles are not configured")
            return Decision("keep", 95, "object-bearing endpoint path supports focused authorization testing")
        return Decision("review", 72, "bug-class signal exists but the controlling parameter or object boundary is not explicit")

    if job_type == "upload_attack_surface":
        path_params = params & {"filename", "file", "filepath", "path", "dir", "folder", "template", "document", "resource", "asset", "log"}
        if path_params:
            return Decision("keep", 99, f"file/path parameter is explicit: {', '.join(sorted(path_params)[:4])}")
        if source_table == "endpoints" and any(token in path for token in ("/upload", "/import", "/export", "/download", "/preview")):
            return Decision("review", 72, "route name suggests a file workflow but no controlling parameter or request schema is known")
        return Decision("defer", 40, "file workflow signal lacks endpoint-level input evidence")

    if job_type == "new_admin_route_review":
        if source_table not in {"endpoints", "live_hosts"}:
            return Decision("review", 65, "admin or staging signal is inferred rather than a current route observation")
        if status in {200, 204, 301, 302, 307, 308, 401}:
            return Decision("review", min(99, 82 + path_weight(asset_value)), "current sensitive route needs fallback and authorization validation")
        return Decision("defer", 35, "route has no useful current response status")

    if job_type in {"auth_session_review", "logging_audit_review"}:
        required_profiles = 2
        if (
            source_table == "endpoints"
            and status in {0, 200, 204, 301, 302, 307, 308, 400, 401, 403, 405}
            and int_value(job.get("auth_profile_count")) >= required_profiles
        ):
            return Decision("keep", max(priority, 95), "current sensitive endpoint has two configured owned actor profiles")
        return Decision("defer", 45, "owned actor profiles required for a meaningful differential are absent")

    if job_type in {"crypto_token_review", "integrity_review"}:
        if (
            source_table == "endpoints"
            and status in {0, 200, 204, 301, 302, 307, 308, 400, 401, 403, 405}
            and int_value(job.get("auth_profile_count")) >= 1
        ):
            return Decision("keep", max(priority, 94), "current sensitive endpoint has an owned profile for bounded lifecycle testing")
        return Decision("defer", 45, "owned account context required for lifecycle or integrity testing is absent")

    if job_type == "component_supply_chain_review":
        secret_count = int_value(job.get("secret_like_count"))
        if is_js and (secret_count or "source-map-signal" in reasons):
            return Decision("keep", 95, "artifact contains a secret-like or source-map signal")
        return Decision("review", 62, "component keyword alone does not establish reachable supply-chain impact")

    if job_type == "exceptional_condition_review":
        if source_table == "endpoints" and status >= 500:
            return Decision("review", 70, "current server error may expose a fail-open or sensitive error path")
        return Decision("defer", 30, "exception signal is not tied to a current endpoint response")

    if reasons:
        return Decision("review", min(90, max(60, priority - 10)), "high-signal reason exists but requires bounded expert triage")
    return Decision("defer", 20, "no concrete security-relevant signal")


def apply_group_limits(jobs: list[dict[str, Any]], decisions: dict[int, Decision]) -> None:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for job in jobs:
        decision = decisions[int(job["id"])]
        if decision.action not in {"keep", "review"}:
            continue
        job_type = str(job.get("job_type") or "")
        asset = str(job.get("asset_value") or "")
        if str(job.get("source_table") or "") == "js_assets":
            key = (job.get("domain_id"), job_type, asset.lower())
            limit = 1
        elif str(job.get("source_table") or "") in {"endpoints", "live_hosts"}:
            key = (job.get("domain_id"), job_type, canonical_host(asset))
            limit = 2 if job_type == "new_admin_route_review" else 4
        else:
            continue
        job["_group_limit"] = limit
        groups[key].append(job)

    for members in groups.values():
        limit = int(members[0]["_group_limit"])
        ranked = sorted(
            members,
            key=lambda item: (
                decisions[int(item["id"])].score,
                path_weight(str(item.get("asset_value") or "")),
                item.get("source_observed_at") or datetime.min,
                int(item["id"]),
            ),
            reverse=True,
        )
        for duplicate in ranked[limit:]:
            decisions[int(duplicate["id"])] = Decision(
                "defer",
                decisions[int(duplicate["id"])].score,
                f"superseded by a stronger representative from the same asset family (limit {limit})",
            )


def compact_candidate(job: dict[str, Any], decision: Decision) -> dict[str, Any]:
    context = as_dict(job.get("required_context"))
    payload = as_dict(context.get("payload"))
    risk = as_dict(job.get("js_risk"))
    return {
        "job_id": int(job["id"]),
        "domain": str(job.get("target") or ""),
        "job_type": str(job.get("job_type") or ""),
        "asset_type": str(job.get("asset_type") or ""),
        "asset": str(job.get("asset_value") or "")[:1000],
        "priority": int_value(job.get("priority")),
        "source": f"{job.get('source_table')}:{job.get('source_id')}",
        "source_observed_at": str(job.get("source_observed_at") or ""),
        "status_code": payload.get("status_code") or payload.get("http_status"),
        "parameters": sorted(parameter_names(context))[:20],
        "high_signal_reasons": as_list(context.get("bug_job_high_signal_reasons"))[:20],
        "js_risk": {key: int_value(value) for key, value in risk.items() if str(key).endswith("_count")},
        "hypothesis": str(job.get("hypothesis") or "")[:600],
        "rule_score": decision.score,
        "rule_reason": decision.reason,
    }


class BugJobCurator:
    def __init__(self, *, dry_run: bool = False) -> None:
        self.config = load_config()
        scan = self.config.scan
        self.enabled = bool(scan.get("bug_job_curator_enabled", True))
        self.dry_run = dry_run
        self.interval_seconds = max(3600, int(scan.get("bug_job_curator_interval_seconds", 86400) or 86400))
        self.max_source_age_days = max(1, int(scan.get("bug_job_curator_max_source_age_days", 30) or 30))
        self.max_candidates = max(100, int(scan.get("bug_job_curator_max_candidates_per_run", 50000) or 50000))
        self.ai_enabled = bool(scan.get("bug_job_curator_codex_enabled", True))
        self.ai_batch_size = max(1, min(200, int(scan.get("bug_job_curator_codex_batch_size", 80) or 80)))
        self.ai_timeout = max(60, int(scan.get("bug_job_curator_codex_timeout_seconds", 900) or 900))
        self.codex_bin = str(scan.get("codex_bin") or "codex")
        self.model = str(scan.get("bug_job_curator_model") or scan.get("codex_worker_model") or "gpt-5.6-sol")
        self.reasoning_effort = str(scan.get("bug_job_curator_reasoning_effort") or "medium")
        self.output_root = Path(str(scan.get("bug_job_curator_output_dir") or "/root/codex_artifacts/bug-jobs/curator"))
        self.state_path = self.output_root / ".worker_state.json"
        self.pool: asyncpg.Pool | None = None
        self.lock_conn: asyncpg.Connection | None = None

    async def init(self) -> None:
        db = self.config.database
        self.pool = await asyncpg.create_pool(
            host=db["host"], port=db["port"], database=db["name"], user=db["user"], password=db["password"],
            min_size=1, max_size=2,
        )
        self.output_root.mkdir(parents=True, exist_ok=True)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_job_curation_runs (
                    id BIGSERIAL PRIMARY KEY,
                    status VARCHAR(30) NOT NULL DEFAULT 'running',
                    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
                    candidates_considered INTEGER NOT NULL DEFAULT 0,
                    jobs_approved INTEGER NOT NULL DEFAULT 0,
                    jobs_deferred INTEGER NOT NULL DEFAULT 0,
                    jobs_pending_ai INTEGER NOT NULL DEFAULT 0,
                    ai_candidates_reviewed INTEGER NOT NULL DEFAULT 0,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_job_curation_decisions (
                    bug_job_id BIGINT PRIMARY KEY REFERENCES bug_jobs(id) ON DELETE CASCADE,
                    run_id BIGINT REFERENCES bug_job_curation_runs(id) ON DELETE SET NULL,
                    decision VARCHAR(30) NOT NULL,
                    score INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    decided_by VARCHAR(30) NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    decided_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_bug_job_curation_decision ON bug_job_curation_decisions(decision, score DESC, decided_at DESC)"
            )
        self.lock_conn = await self.pool.acquire()
        acquired = await self.lock_conn.fetchval("SELECT pg_try_advisory_lock(hashtext('recon_bug_job_curator_v1'))")
        if not acquired:
            await self.pool.release(self.lock_conn)
            self.lock_conn = None
            raise RuntimeError("another bug job curator holds the singleton lock")

    async def close(self) -> None:
        if self.lock_conn is not None and self.pool is not None:
            await self.lock_conn.execute("SELECT pg_advisory_unlock(hashtext('recon_bug_job_curator_v1'))")
            await self.pool.release(self.lock_conn)
            self.lock_conn = None
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    def write_state(self, **values: Any) -> None:
        state = {
            "worker": "bug-job-curator",
            "updated_at": utcnow().isoformat(),
            "interval_seconds": self.interval_seconds,
            **values,
        }
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(state, indent=2, sort_keys=True, default=str), encoding="utf-8")
        with contextlib.suppress(OSError):
            temp.chmod(0o600)
        temp.replace(self.state_path)

    async def collect(self) -> list[dict[str, Any]]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT bj.*,
                       COALESCE(jar.risk_summary, '{}'::jsonb) AS js_risk,
                       CASE WHEN jar.extraction IS NULL THEN 0 ELSE jsonb_array_length(COALESCE(jar.extraction->'graphql_client_endpoints', '[]'::jsonb)) END AS graphql_client_endpoint_count,
                       CASE WHEN jar.extraction IS NULL THEN 0 ELSE jsonb_array_length(COALESCE(jar.extraction->'tokens_or_secret_like_strings', '[]'::jsonb)) END AS secret_like_count,
                       ja.http_status AS source_http_status
                FROM bug_jobs bj
                LEFT JOIN js_assets ja ON bj.source_table = 'js_assets' AND ja.id = bj.source_id
                LEFT JOIN js_analysis_results jar ON jar.js_asset_id = ja.id
                WHERE bj.status IN ('queued', 'curation_pending')
                  AND bj.attempt_count < bj.max_attempts
                ORDER BY bj.priority DESC, bj.source_observed_at DESC NULLS LAST, bj.id DESC
                LIMIT $1
                """,
                self.max_candidates,
            )
            source_map_endpoint_ids = [
                int(row["source_id"])
                for row in rows
                if row["source_table"] == "endpoints"
                and row["source_id"] is not None
                and row["job_type"] == "source_map_review"
            ]
            linked_secret_rows = []
            if source_map_endpoint_ids:
                linked_secret_rows = await conn.fetch(
                    """SELECT r.endpoint_id,
                              MAX(jsonb_array_length(COALESCE(jar.extraction->'tokens_or_secret_like_strings', '[]'::jsonb)))::int AS secret_count
                       FROM endpoint_js_references r
                       JOIN js_analysis_results jar ON jar.js_asset_id = r.js_asset_id
                       WHERE r.endpoint_id = ANY($1::int[])
                       GROUP BY r.endpoint_id""",
                    source_map_endpoint_ids,
                )
            auth_profile_rows = await conn.fetch(
                """SELECT domain_id, COUNT(*)::int AS profile_count
                   FROM auth_profiles WHERE enabled = TRUE GROUP BY domain_id"""
            )
            surfaces = await conn.fetch(
                """SELECT id, domain_id, location, metadata->>'endpoint_id' AS endpoint_id
                   FROM api_surfaces
                   WHERE surface_type = 'graphql'
                     AND lower(COALESCE(metadata->>'confidence', '')) IN ('confirmed', 'probable')"""
            )
        locations = {(int(row["domain_id"]), str(row["location"] or "")) for row in surfaces}
        surface_ids = {int(row["id"]) for row in surfaces}
        endpoint_ids = {
            (int(row["domain_id"]), str(row["endpoint_id"]))
            for row in surfaces
            if row["endpoint_id"] is not None
        }
        result = [dict(row) for row in rows]
        linked_secret_counts = {
            int(row["endpoint_id"]): int(row["secret_count"] or 0)
            for row in linked_secret_rows
        }
        auth_profile_counts = {
            int(row["domain_id"]): int(row["profile_count"] or 0)
            for row in auth_profile_rows
        }
        for item in result:
            domain_id = int(item["domain_id"]) if item.get("domain_id") is not None else -1
            item["auth_profile_count"] = auth_profile_counts.get(domain_id, 0)
            item["graphql_protocol_confirmed"] = bool(
                (domain_id, str(item.get("asset_value") or "")) in locations
                or (item.get("source_table") == "api_surfaces" and item.get("source_id") in surface_ids)
                or (
                    item.get("source_table") == "endpoints"
                    and (domain_id, str(item.get("source_id"))) in endpoint_ids
                )
            )
            item["linked_secret_like_count"] = linked_secret_counts.get(
                int(item["source_id"]) if item.get("source_id") is not None else -1,
                0,
            )
        return result

    async def ai_review(self, run_dir: Path, candidates: list[dict[str, Any]]) -> dict[int, Decision]:
        if not self.ai_enabled or self.dry_run or not candidates:
            return {}
        batch = candidates[: self.ai_batch_size]
        allowed_ids = {int(job["id"]) for job in batch}
        # A failed persistence transaction must not spend another Codex call on
        # the identical batch. Reuse only a complete, schema-valid prior batch.
        for prior in sorted(self.output_root.glob("run_*/codex_decisions.json"), reverse=True):
            if prior.parent == run_dir:
                continue
            reused = self.parse_ai_output(prior, allowed_ids)
            if set(reused) == allowed_ids:
                logger.info("reusing completed Codex curation batch from %s", prior)
                (run_dir / "codex_decisions.json").write_text(
                    prior.read_text(encoding="utf-8"), encoding="utf-8"
                )
                return reused
        input_rows = [compact_candidate(job, Decision("review", int(job["_score"]), str(job["_reason"]))) for job in batch]
        prompt = f"""You are the offline queue curator for an authorized bug bounty recon system.

Decide whether each candidate is worth one expensive, focused Codex worker run. You are not finding or confirming a vulnerability. Use only supplied database evidence and do not make network requests or call tools.

KEEP only when the row contains a concrete, current, testable trust-boundary signal: an explicit security-relevant parameter/object/operation, a current sensitive endpoint, a source-to-sink or postMessage-sensitive-flow combination, a real GraphQL operation/endpoint, a retrievable source map, or similarly specific evidence. DEFER route names, keyword-only matches, lexical GraphQL hints, generic new JavaScript, public client configuration, ordinary login pages, WAF/fallback-like observations, speculative CVEs, and duplicate family members.

Optimize for reportable impact and worker efficiency. A high scanner priority is not evidence. When uncertain, defer; future recon can enqueue a stronger changed asset.

Return one decision for every supplied job ID as JSON matching the schema.

<candidates>
{json.dumps(input_rows, sort_keys=True, default=str)}
</candidates>
"""
        schema_path = run_dir / "response_schema.json"
        prompt_path = run_dir / "prompt.txt"
        output_path = run_dir / "codex_decisions.json"
        stdout_path = run_dir / "codex.stdout.log"
        stderr_path = run_dir / "codex.stderr.log"
        schema_path.write_text(json.dumps(CURATOR_SCHEMA, indent=2), encoding="utf-8")
        prompt_path.write_text(prompt, encoding="utf-8")
        for path in (schema_path, prompt_path):
            path.chmod(0o600)
        command = [
            self.codex_bin, "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config",
            # Bubblewrap namespaces are unavailable in this Docker runtime. The
            # container and narrow mounts are the boundary for this offline job.
            "--sandbox", "danger-full-access", "--cd", str(run_dir), "--output-schema", str(schema_path),
            "--output-last-message", str(output_path), "--model", self.model,
            "--config", f'model_reasoning_effort="{self.reasoning_effort}"', "-",
        ]
        child_env = {
            "HOME": "/root", "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "TERM": "dumb",
        }
        with prompt_path.open("rb") as stdin_handle, stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = await asyncio.create_subprocess_exec(
                *command, cwd=str(run_dir), env=child_env, stdin=stdin_handle,
                stdout=stdout_handle, stderr=stderr_handle, start_new_session=True,
            )
            try:
                await asyncio.wait_for(process.wait(), timeout=self.ai_timeout)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                logger.warning("curator Codex batch timed out; candidates remain pending")
                return {}
        if process.returncode != 0 or not output_path.exists():
            logger.warning("curator Codex batch failed with status %s; candidates remain pending", process.returncode)
            return {}
        decisions = self.parse_ai_output(output_path, allowed_ids)
        if not decisions:
            logger.warning("curator Codex returned invalid JSON; candidates remain pending")
        return decisions

    @staticmethod
    def parse_ai_output(output_path: Path, allowed_ids: set[int]) -> dict[int, Decision]:
        try:
            result = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        decisions: dict[int, Decision] = {}
        for item in as_list(result.get("decisions")):
            if not isinstance(item, dict):
                continue
            job_id = int_value(item.get("job_id"))
            action = str(item.get("action") or "")
            if job_id not in allowed_ids or action not in {"keep", "defer"}:
                continue
            decisions[job_id] = Decision(
                action,
                max(0, min(100, int_value(item.get("score")))),
                str(item.get("reason") or "Codex queue triage")[:500],
                "codex",
            )
        return decisions

    async def persist(self, run_id: int, jobs: list[dict[str, Any]], decisions: dict[int, Decision]) -> Counter[str]:
        counts: Counter[str] = Counter()
        update_rows: list[tuple[Any, ...]] = []
        decision_rows: list[tuple[Any, ...]] = []
        for job in jobs:
            decision = decisions[int(job["id"])]
            counts[decision.action] += 1
            status = "queued" if decision.action == "keep" else "deferred_curator" if decision.action == "defer" else "curation_pending"
            update_rows.append((int(job["id"]), status, decision.reason))
            decision_rows.append(
                (int(job["id"]), decision.action, decision.score, decision.reason, decision.decided_by, run_id)
            )
        if self.dry_run:
            return counts
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(
                    """
                    UPDATE bug_jobs
                    SET status = $2::varchar,
                        result_summary = CASE WHEN $2::text = 'queued' THEN NULL ELSE 'Queue curator: ' || $3::text END,
                        error = NULL,
                        updated_at = NOW()
                    WHERE id = $1
                      AND status IN ('queued', 'curation_pending')
                      AND attempt_count < max_attempts
                    """,
                    update_rows,
                )
                await conn.executemany(
                    """
                    INSERT INTO bug_job_curation_decisions (
                        bug_job_id, decision, score, reason, decided_by, run_id, details
                    ) VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)
                    ON CONFLICT (bug_job_id) DO UPDATE SET
                        decision = EXCLUDED.decision,
                        score = EXCLUDED.score,
                        reason = EXCLUDED.reason,
                        decided_by = EXCLUDED.decided_by,
                        run_id = EXCLUDED.run_id,
                        decided_at = NOW()
                    """,
                    decision_rows,
                )
        return counts

    async def run_once(self) -> dict[str, Any]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            run_id = await conn.fetchval(
                "INSERT INTO bug_job_curation_runs (dry_run) VALUES ($1) RETURNING id",
                self.dry_run,
            )
        run_dir = self.output_root / f"run_{run_id}_{utcnow().strftime('%Y%m%dT%H%M%SZ')}"
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            jobs = await self.collect()
            now = utcnow()
            decisions = {
                int(job["id"]): deterministic_decision(job, now, self.max_source_age_days)
                for job in jobs
            }
            apply_group_limits(jobs, decisions)
            review_jobs: list[dict[str, Any]] = []
            for job in jobs:
                decision = decisions[int(job["id"])]
                if decision.action == "review":
                    job["_score"] = decision.score
                    job["_reason"] = decision.reason
                    review_jobs.append(job)
            review_jobs.sort(key=lambda item: (int(item["_score"]), int_value(item.get("priority"))), reverse=True)
            ai_decisions = await self.ai_review(run_dir, review_jobs)
            decisions.update(ai_decisions)
            if not self.ai_enabled:
                for job in review_jobs:
                    job_id = int(job["id"])
                    current = decisions[job_id]
                    if current.action == "review":
                        decisions[job_id] = Decision(
                            "defer",
                            current.score,
                            f"{current.reason}; deterministic proof gate not met",
                            "deterministic",
                        )
            counts = await self.persist(run_id, jobs, decisions)
            summary = {
                "run_id": run_id,
                "dry_run": self.dry_run,
                "candidates": len(jobs),
                "approved": counts["keep"],
                "deferred": counts["defer"],
                "pending_ai": counts["review"],
                "ai_reviewed": len(ai_decisions),
                "by_job_type": dict(Counter(str(job.get("job_type")) for job in jobs)),
                "decision_reasons": dict(Counter(decisions[int(job["id"])].reason for job in jobs).most_common(20)),
            }
            (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE bug_job_curation_runs
                    SET status='done', candidates_considered=$2, jobs_approved=$3,
                        jobs_deferred=$4, jobs_pending_ai=$5, ai_candidates_reviewed=$6,
                        summary=$7::jsonb, finished_at=NOW()
                    WHERE id=$1
                    """,
                    run_id, len(jobs), counts["keep"], counts["defer"], counts["review"],
                    len(ai_decisions), json.dumps(summary, default=str),
                )
            self.write_state(status="idle", last_run=summary, next_run_at=utcnow() + timedelta(seconds=self.interval_seconds))
            return summary
        except Exception as exc:
            async with self.pool.acquire() as conn:
                await conn.execute(
                    "UPDATE bug_job_curation_runs SET status='failed', error=$2, finished_at=NOW() WHERE id=$1",
                    run_id, repr(exc)[:4000],
                )
            self.write_state(status="failed", error=repr(exc))
            raise

    async def run_forever(self) -> None:
        if not self.enabled:
            self.write_state(status="disabled")
            while True:
                await asyncio.sleep(3600)
        while True:
            self.write_state(status="running")
            try:
                summary = await self.run_once()
                logger.info("queue curation complete: %s", summary)
            except Exception:
                logger.exception("queue curation failed")
            deadline = utcnow() + timedelta(seconds=self.interval_seconds)
            while utcnow() < deadline:
                self.write_state(status="sleeping", next_run_at=deadline)
                await asyncio.sleep(min(60, max(1, int((deadline - utcnow()).total_seconds()))))


async def healthcheck() -> int:
    config = load_config()
    scan = config.scan
    path = Path(str(scan.get("bug_job_curator_output_dir") or "/root/codex_artifacts/bug-jobs/curator")) / ".worker_state.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        updated = datetime.fromisoformat(str(state["updated_at"]).replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return 1
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    return 0 if utcnow() - updated <= timedelta(seconds=180) else 1


async def main() -> int:
    parser = argparse.ArgumentParser(description="Curate recon bug jobs before Codex execution")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        return await healthcheck()
    curator = BugJobCurator(dry_run=args.dry_run)
    await curator.init()
    try:
        if args.once:
            print(json.dumps(await curator.run_once(), indent=2, default=str))
        else:
            await curator.run_forever()
    finally:
        await curator.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
