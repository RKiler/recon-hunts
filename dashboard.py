#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import csv
import fcntl
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg
import yaml
from flask import Flask, Response, abort, jsonify, redirect, render_template, render_template_string, request, send_from_directory, session, stream_with_context, url_for
from bug_job_taxonomy import normalized_allocations
from independent_hunt import IndependentHuntCoordinator as HuntCoordinator
from agentic_hunter import AgenticHunter
from hunt_credentials import validate_credential, write_secret, remove_secret
from domain_management import (
    DOMAIN_OPTION_KEYS,
    DomainValidationError,
    domain_options_from_payload,
    parse_domain_values,
)
from monitor_core import run_browser_monitor
from search_intelligence import SearchIntelligence, provider_from_config


SCREENSHOT_ROOT = Path("/app/screenshots")
HUNT_LOGIN_SIGNAL_DIR = Path("/app/hunt_login_signals")
WORDLIST_ROOT = Path("/app/wordlists")
TABLE_LIMIT = 50
SEARCH_LIMIT = 250
SCAN_TABLES = {"subdomains", "live_hosts", "urls", "js", "parameters", "findings", "screenshots"}
SCAN_PARAMETER_SCOPE_SQL = """
    WITH scan_parameters AS MATERIALIZED (
      SELECT up.*, ss.domain_id
      FROM scan_snapshots ss
      JOIN url_parameters up
        ON up.first_seen >= ss.scan_started_at
       AND up.first_seen <= ss.scan_finished_at
      WHERE ss.id = $1
    )
"""
FILTER_PRESETS = {
    "200 OK": {"status_code": "200"},
    "With Parameters": {"has_parameters": "true"},
    "Admin": {"contains": "admin"},
    "GraphQL": {"tech": "GraphQL"},
    "Large Responses": {"response_size_gt": "100000"},
}
REPORT_SECTIONS = {"risk", "playbooks", "validation", "evidence", "events", "cloud", "api"}
CODEX_RESULT_FIELDS = {
    "job_id", "target", "asset", "job_type", "finding_status", "outcome_class",
    "vulnerability_class", "owasp_category", "title", "impact", "affected_endpoint",
    "roles_tested", "safe_reproduction_steps", "evidence_files", "confidence",
    "recommended_next_step", "recommended_followup_job", "manual_review_priority",
    "manual_review_reason", "alert_signals", "observed_anomaly", "tests_performed", "data_sources_used",
    "skills_used", "instruction_files_read", "active_request_count", "variant_count",
    "db_records_reviewed", "scope_anchor", "item_scope_respected", "blocked_by",
    "prompt_family", "transport_block", "vpn_retry",
}
AI_ASSISTANT_SECTIONS = {
    "overview", "leads", "workers", "validation", "evidence", "endpoints", "javascript", "ffuf",
    "urls", "live_hosts", "infrastructure", "subdomains", "js", "credential_leaks", "parameters",
    "findings", "screenshots", "risk", "bookmarks", "events", "monitors", "ffuf_workbench", "cloud",
    "api_surfaces", "active_hunt", "codex_worker", "bug_jobs", "playbooks", "triage", "search_intel",
    "search",
}
AI_ASSISTANT_MODES = {"global_search", "tab_assistant"}
DASHBOARD_SCHEMA_VERSION = 2
AI_SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|private[_-]?key|client[_-]?secret|session)",
    re.IGNORECASE,
)

RISK_NOISE_FINDING_TYPES = {
    "api_surface_discovered",
    "host_fingerprint_changed",
    "interesting_bruteforce_hit",
    "interesting_exposed_path",
    "interesting_open_port",
    "js_asset_changed",
    "js_dom_xss_candidate",
    "js_dom_xss_sinks",
    "js_secret_like_strings",
    "js_sensitive_admin_surface",
    "risky_url_parameter",
}
FINDING_REVIEW_TYPES = {
    "interesting_exposed_path",
    "interesting_open_port",
    "js_dom_xss_candidate",
    "js_secret_like_strings",
}
FINDING_GROUP_FAMILIES = {
    "js_dom_xss_candidate": "js_dom_xss_review",
    "js_dom_xss_sinks": "js_dom_xss_review",
}
FINDING_VIEWS = {"actionable", "leads", "raw"}
RISK_PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
RISK_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
RISK_LONG_HEX_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{20,64}(?![0-9a-f])")
RISK_BUNDLED_FILE_RE = re.compile(
    r"(?i)^(?P<prefix>.+?)[-._](?P<token>[a-z0-9_-]{8,64})(?P<suffix>\.(?:js|mjs|cjs|css|map))$"
)


def canonical_risk_location(value: Any) -> str:
    """Normalize volatile build identifiers without merging distinct routes."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if any(marker in raw for marker in ("${", "`;", "};", "<script", "javascript:")):
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        parsed = None
    try:
        hostname = parsed.hostname if parsed else None
        port = parsed.port if parsed else None
    except ValueError:
        return ""
    if parsed and parsed.scheme in {"http", "https"} and hostname:
        hostname = hostname.lower().rstrip(".")
        default_port = (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
        netloc = hostname if not port or default_port else f"{hostname}:{port}"
        path = parsed.path or "/"
        segments = []
        for segment in path.split("/"):
            segment = RISK_UUID_RE.sub("{id}", segment)
            segment = RISK_LONG_HEX_RE.sub("{hash}", segment)
            match = RISK_BUNDLED_FILE_RE.match(segment)
            if match:
                token = match.group("token")
                if any(char.isdigit() for char in token) or re.fullmatch(r"(?i)[0-9a-f]+", token):
                    segment = f"{match.group('prefix')}-{{hash}}{match.group('suffix').lower()}"
            segments.append(segment)
        return urlunsplit((parsed.scheme.lower(), netloc, "/".join(segments), "", ""))
    normalized = RISK_UUID_RE.sub("{id}", raw)
    return RISK_LONG_HEX_RE.sub("{hash}", normalized).split("?", 1)[0].split("#", 1)[0]


def risk_priority(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def normalize_finding_view(value: Any) -> str:
    view = str(value or "").strip().lower()
    return view if view in FINDING_VIEWS else "leads"


def load_config() -> dict:
    config_path = Path("/app/config.yaml")
    with config_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    data["database"]["password"] = os.getenv("RECON_DB_PASSWORD", data["database"]["password"])
    dashboard_cfg = data.setdefault("dashboard", {})
    auth_cfg = dashboard_cfg.setdefault("auth", {})
    if os.getenv("RECON_DASHBOARD_AUTH_ENABLED"):
        auth_cfg["enabled"] = os.getenv("RECON_DASHBOARD_AUTH_ENABLED", "").lower() in {"1", "true", "yes", "on"}
    if os.getenv("RECON_DASHBOARD_USERNAME"):
        auth_cfg["username"] = os.getenv("RECON_DASHBOARD_USERNAME")
    if os.getenv("RECON_DASHBOARD_PASSWORD"):
        auth_cfg["password"] = os.getenv("RECON_DASHBOARD_PASSWORD")
    search_intelligence = data.setdefault("search_intelligence", {})
    for env_name, config_name in (
        ("GOOGLE_CSE_API_KEY", "google_api_key"),
        ("GOOGLE_CSE_ENGINE_ID", "google_engine_id"),
        ("SERPER_API_KEY", "serper_api_key"),
        ("SERPAPI_API_KEY", "serpapi_api_key"),
    ):
        if os.getenv(env_name):
            search_intelligence[config_name] = os.getenv(env_name)
    return data


def normalize_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def csv_value(value: Any) -> str:
    value = normalize_json(value)
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    return str(value)


def redact_ai_url(value: str) -> str:
    """Keep useful URL structure while removing query values and credentials."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value[:2000]
    if not parsed.scheme or not parsed.netloc:
        return value[:2000]
    hostname = parsed.hostname or ""
    netloc = hostname
    try:
        if parsed.port:
            netloc = f"{hostname}:{parsed.port}"
    except ValueError:
        pass
    query = urlencode([(name, "[redacted]") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))[:2000]


def sanitize_ai_context(value: Any, depth: int = 0) -> Any:
    """Bound and redact browser-provided context before queue persistence."""
    if depth > 4:
        return "[truncated]"
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in list(value.items())[:40]:
            clean_key = str(key)[:100]
            if AI_SENSITIVE_KEY_RE.search(clean_key):
                output[clean_key] = "[redacted]"
            else:
                output[clean_key] = sanitize_ai_context(item, depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [sanitize_ai_context(item, depth + 1) for item in list(value)[:30]]
    if isinstance(value, str):
        text = value[:4000]
        if text.startswith(("http://", "https://")):
            return redact_ai_url(text)
        text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}", "Bearer [redacted]", text)
        text = re.sub(r"(?i)(cookie|authorization|password|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+", r"\1=[redacted]", text)
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def codex_artifact_root(config: dict) -> Path:
    configured = config.get("scan", {}).get("codex_worker_output_dir")
    return Path(str(configured or "/root/codex_artifacts/bug-jobs/results")).resolve()


def ai_assistant_artifact_root(config: dict) -> Path:
    configured = config.get("scan", {}).get("ai_assistant_output_dir")
    return Path(str(configured or "/root/codex_artifacts/ai-assistant")).resolve()


def load_codex_result(config: dict, output_path: Any, summary: Any) -> tuple[dict[str, Any], str | None]:
    """Load a worker result only from its configured artifact tree."""
    root = codex_artifact_root(config)
    path_error: str | None = None
    decoded: Any = None
    raw_path = str(output_path or "").strip()
    if raw_path:
        try:
            candidate = Path(raw_path)
            if not candidate.is_absolute():
                candidate = root / candidate
            candidate = candidate.resolve()
            candidate.relative_to(root)
            if candidate.is_file():
                if candidate.stat().st_size > 2 * 1024 * 1024:
                    path_error = "result artifact exceeds the 2 MB dashboard limit"
                else:
                    decoded = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
            else:
                path_error = "result artifact is not mounted or no longer exists"
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            path_error = f"unable to load result artifact: {type(exc).__name__}"
    if not isinstance(decoded, dict):
        try:
            fallback = json.loads(str(summary or ""))
            decoded = fallback if isinstance(fallback, dict) else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded = {}
    return {key: decoded[key] for key in CODEX_RESULT_FIELDS if key in decoded}, path_error


def load_codex_summary(summary: Any) -> dict[str, Any]:
    """Decode DB-resident list metadata without touching block-storage artifacts."""
    try:
        decoded = json.loads(str(summary or ""))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(decoded, dict):
        return {}
    return {
        key: decoded[key]
        for key in ("title", "finding_status", "outcome_class")
        if key in decoded
    }


def recent_codex_job_ids(config: dict, limit: int = 500) -> list[int]:
    root = codex_artifact_root(config)
    candidates: list[tuple[float, int]] = []
    try:
        for entry in root.iterdir():
            match = re.match(r"job_(\d+)_", entry.name)
            if not match or not entry.is_dir():
                continue
            try:
                candidates.append((entry.stat().st_mtime, int(match.group(1))))
            except (OSError, ValueError):
                continue
    except OSError:
        return []
    candidates.sort(reverse=True)
    return [job_id for _, job_id in candidates[: max(1, min(limit, 2000))]]


def read_codex_worker_state(config: dict) -> dict[str, Any]:
    state_path = codex_artifact_root(config) / ".worker_state.json"
    try:
        if not state_path.is_file() or state_path.stat().st_size > 256 * 1024:
            return {"status": "unknown", "error": "worker state is unavailable"}
        parsed = json.loads(state_path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(parsed, dict):
            return {"status": "unknown", "error": "worker state is invalid"}
        return {key: parsed.get(key) for key in (
            "worker", "status", "current_job_id", "updated_at", "pause_until",
            "pause_reason", "daily_date", "daily_started_count", "parallelism",
            "active_count", "current_job_ids", "active_jobs", "vpn_failover",
            "daily_category_counts", "category_allocations", "category_roi",
        )}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"status": "unknown", "error": "worker state is unavailable"}


def degraded_codex_worker_overview(config: dict) -> dict[str, Any]:
    """Serve live worker state when PostgreSQL analytics are temporarily busy."""
    return {
        "worker": read_codex_worker_state(config),
        "summary": {},
        "recent_days": 0,
        "rows": [],
        "roi_by_category": [],
        "roi_by_job_type": [],
        "focus_domains": [],
        "degraded": True,
        "degraded_reason": "analytics refresh is waiting for database capacity",
    }


def canonical_bug_job_display_key(asset_type: str, asset_value: str) -> str:
    value = str(asset_value or "").split("#", 1)[0]
    parsed = urlsplit(value)

    def normalize_path(path: str) -> str:
        path = re.sub(r"/+", "/", path or "/").rstrip("/") or "/"
        uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
        parts: list[str] = []
        for part in path.split("/"):
            if uuid_re.match(part):
                parts.append("{uuid}")
            elif re.fullmatch(r"\d{4,}", part):
                parts.append("{int}")
            elif re.fullmatch(r"[A-Za-z0-9_-]{20,}", part):
                parts.append("{opaque}")
            else:
                normalized = re.sub(r"[0-9a-f]{20,}", "{hex}", part, flags=re.IGNORECASE)
                normalized = re.sub(r"([._-])[A-Za-z0-9_-]{8,}(?=\.(?:js|mjs|cjs|css|map|json)$)", r"\1{hash}", normalized, flags=re.IGNORECASE)
                normalized = re.sub(r"[A-Za-z0-9_-]{32,}", "{opaque}", normalized)
                parts.append(normalized)
        return "/".join(parts) or "/"

    def normalize_query(query: str) -> str:
        if not query:
            return ""
        names = sorted({name for name, _ in parse_qsl(query, keep_blank_values=True) if name})
        return urlencode([(name, "{value}") for name in names])

    if parsed.scheme and parsed.netloc:
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower().rstrip(".")
        netloc = hostname
        if parsed.port and not ((scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)):
            netloc = f"{hostname}:{parsed.port}"
        path = normalize_path(parsed.path or "/")
        query = normalize_query(parsed.query) if asset_type in {"endpoint", "url", "finding", "playbook"} else parsed.query
        return urlunsplit((scheme, netloc, path, query, ""))
    return normalize_path(value) if asset_type in {"endpoint", "path"} else value


class Dashboard:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.pool: asyncpg.Pool | None = None
        self.hunts: HuntCoordinator | None = None
        self.agentic: AgenticHunter | None = None

    async def init(self) -> None:
        self.pool = await asyncpg.create_pool(
            host=self.config["database"]["host"],
            port=self.config["database"]["port"],
            database=self.config["database"]["name"],
            user=self.config["database"]["user"],
            password=self.config["database"]["password"],
            min_size=1,
            max_size=10,
            command_timeout=20,
            server_settings={
                "application_name": "recon_dashboard",
                "idle_in_transaction_session_timeout": "15000",
            },
        )
        await self.ensure_dashboard_schema()
        await self.ensure_search_intelligence_schema()
        self.hunts = HuntCoordinator(self.pool, self.config)
        await self.hunts.ensure_schema()
        self.agentic = AgenticHunter(self.pool)
        await self.agentic.ensure_schema()

    async def ensure_search_intelligence_schema(self) -> None:
        """Run shared search-intelligence DDL once across Gunicorn workers."""
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            current_version = await conn.fetchval(
                "SELECT schema_version FROM dashboard_schema_state WHERE schema_key = 'search_intelligence'"
            )
            if int(current_version or 0) >= 1:
                return
            schema_ready = await conn.fetchval(
                """
                SELECT
                  to_regclass('public.search_intel_jobs') IS NOT NULL
                  AND to_regclass('public.search_intel_runs') IS NOT NULL
                  AND to_regclass('public.search_intel_results') IS NOT NULL
                  AND to_regclass('public.search_intel_run_results') IS NOT NULL
                  AND EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'domains'
                      AND column_name = 'enable_search_intelligence'
                  )
                """
            )
            if schema_ready:
                await conn.execute(
                    """
                    INSERT INTO dashboard_schema_state(schema_key, schema_version, updated_at)
                    VALUES ('search_intelligence', 1, NOW())
                    ON CONFLICT (schema_key) DO UPDATE
                    SET schema_version = EXCLUDED.schema_version, updated_at = NOW()
                    """
                )
                return
            acquired = await conn.fetchval("SELECT pg_try_advisory_lock(817263546)")
            if not acquired:
                return
            try:
                current_version = await conn.fetchval(
                    "SELECT schema_version FROM dashboard_schema_state WHERE schema_key = 'search_intelligence'"
                )
                if int(current_version or 0) >= 1:
                    return
                await SearchIntelligence(
                    self.pool,
                    self.config.get("search_intelligence", {}),
                ).ensure_schema()
                await conn.execute(
                    """
                    INSERT INTO dashboard_schema_state(schema_key, schema_version, updated_at)
                    VALUES ('search_intelligence', 1, NOW())
                    ON CONFLICT (schema_key) DO UPDATE
                    SET schema_version = EXCLUDED.schema_version, updated_at = NOW()
                    """
                )
            finally:
                await conn.execute("SELECT pg_advisory_unlock(817263546)")

    async def ensure_dashboard_schema(self) -> None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dashboard_schema_state (
                    schema_key TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            current_version = await conn.fetchval(
                "SELECT schema_version FROM dashboard_schema_state WHERE schema_key = 'dashboard'"
            )
            if int(current_version or 0) >= DASHBOARD_SCHEMA_VERSION:
                return
            acquired = await conn.fetchval("SELECT pg_try_advisory_lock(817263545)")
            if not acquired:
                # Another Gunicorn worker owns the one-time migration. The
                # existing schema remains usable while that worker finishes.
                return
            current_version = await conn.fetchval(
                "SELECT schema_version FROM dashboard_schema_state WHERE schema_key = 'dashboard'"
            )
            if int(current_version or 0) >= DASHBOARD_SCHEMA_VERSION:
                await conn.execute("SELECT pg_advisory_unlock(817263545)")
                return
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS active_hunt_results (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    run_id VARCHAR(120) NOT NULL,
                    scope TEXT NOT NULL,
                    check_type VARCHAR(80) NOT NULL,
                    target_url TEXT NOT NULL,
                    source_url TEXT,
                    parameter_name TEXT,
                    http_status INTEGER,
                    finding VARCHAR(120),
                    confidence VARCHAR(30) NOT NULL DEFAULT 'info',
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    request JSONB NOT NULL DEFAULT '{}'::jsonb,
                    response JSONB NOT NULL DEFAULT '{}'::jsonb,
                    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, run_id, check_type, target_url)
                )
                """
            )
            for ddl in (
                "ALTER TABLE active_hunt_results ALTER COLUMN parameter_name TYPE TEXT",
                "CREATE INDEX IF NOT EXISTS idx_active_hunt_domain_created ON active_hunt_results(domain_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_active_hunt_finding ON active_hunt_results(finding, confidence, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_active_hunt_check_type ON active_hunt_results(check_type, created_at DESC)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_leaks (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    live_host_id INTEGER REFERENCES live_hosts(id) ON DELETE SET NULL,
                    js_asset_id INTEGER REFERENCES js_assets(id) ON DELETE SET NULL,
                    detector_name TEXT NOT NULL,
                    detector_type TEXT,
                    decoder_name TEXT,
                    source_type TEXT NOT NULL DEFAULT 'js_asset',
                    source_url TEXT NOT NULL,
                    source_file TEXT,
                    line_number INTEGER,
                    verified BOOLEAN NOT NULL DEFAULT FALSE,
                    redacted_secret TEXT,
                    fingerprint VARCHAR(64) NOT NULL,
                    raw_sha256 VARCHAR(64),
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    is_new BOOLEAN NOT NULL DEFAULT TRUE,
                    is_resolved BOOLEAN NOT NULL DEFAULT FALSE,
                    UNIQUE(domain_id, source_url, detector_name, fingerprint)
                )
                """
            )
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_domain_seen ON credential_leaks(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_detector_seen ON credential_leaks(detector_name, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_verified_seen ON credential_leaks(verified, last_seen DESC)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_playbooks (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    source_table VARCHAR(60) NOT NULL,
                    source_id INTEGER,
                    playbook_key VARCHAR(128) NOT NULL UNIQUE,
                    target_url TEXT NOT NULL,
                    owasp_category VARCHAR(100) NOT NULL,
                    check_type VARCHAR(80) NOT NULL,
                    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
                    confidence VARCHAR(30) NOT NULL DEFAULT 'candidate',
                    reasons TEXT[] NOT NULL DEFAULT '{}',
                    validation_steps TEXT[] NOT NULL DEFAULT '{}',
                    stop_conditions TEXT[] NOT NULL DEFAULT '{}',
                    safety_notes TEXT[] NOT NULL DEFAULT '{}',
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    status VARCHAR(40) NOT NULL DEFAULT 'queued',
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source_table, source_id, check_type, target_url)
                )
                """
            )
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_attack_playbooks_domain_priority ON attack_playbooks(domain_id, status, priority, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_attack_playbooks_check_type ON attack_playbooks(check_type, updated_at DESC)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bug_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    asset_type VARCHAR(60) NOT NULL,
                    asset_value TEXT NOT NULL,
                    job_type VARCHAR(80) NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 50,
                    status VARCHAR(30) NOT NULL DEFAULT 'queued',
                    scope_ok BOOLEAN NOT NULL DEFAULT TRUE,
                    source_table VARCHAR(60),
                    source_id INTEGER,
                    source_observed_at TIMESTAMP,
                    job_key VARCHAR(128) NOT NULL UNIQUE,
                    hypothesis TEXT,
                    safety_notes TEXT[] NOT NULL DEFAULT '{}',
                    required_context JSONB NOT NULL DEFAULT '{}'::jsonb,
                    prompt_path TEXT,
                    codex_output_path TEXT,
                    result_summary TEXT,
                    finding_status VARCHAR(30),
                    confidence INTEGER,
                    codex_alerted_at TIMESTAMP,
                    vpn_failover_attempted BOOLEAN NOT NULL DEFAULT FALSE,
                    vpn_failover_succeeded BOOLEAN NOT NULL DEFAULT FALSE,
                    vpn_failover_reason TEXT,
                    vpn_egress_before VARCHAR(64),
                    vpn_egress_after VARCHAR(64),
                    vpn_retry_output_path TEXT,
                    vpn_failover_at TIMESTAMP,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2,
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS authz_observations (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    bug_job_id BIGINT REFERENCES bug_jobs(id) ON DELETE SET NULL,
                    endpoint TEXT NOT NULL,
                    method VARCHAR(12) NOT NULL DEFAULT 'GET',
                    actor TEXT NOT NULL,
                    object_owner TEXT,
                    status_code INTEGER,
                    response_hash VARCHAR(64),
                    content_length INTEGER,
                    sensitive_keywords TEXT[] NOT NULL DEFAULT '{}',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_claim ON bug_jobs(status, scope_ok, priority DESC, created_at ASC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_domain_status ON bug_jobs(domain_id, status, priority DESC, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_bug_jobs_type_status ON bug_jobs(job_type, status, priority DESC, updated_at DESC)",
                """CREATE INDEX IF NOT EXISTS idx_bug_jobs_dashboard_domain_order_v3
                   ON bug_jobs(domain_id, scope_ok DESC, priority DESC, updated_at DESC)
                   WHERE status IN ('queued', 'running', 'prepared', 'done', 'failed')""",
                "CREATE INDEX IF NOT EXISTS idx_authz_observations_domain_endpoint ON authz_observations(domain_id, endpoint, method, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_authz_observations_job ON authz_observations(bug_job_id, created_at DESC)",
            ):
                await conn.execute(ddl)
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_url_parameters_last_seen_desc ON url_parameters(last_seen DESC NULLS LAST)",
                "CREATE INDEX IF NOT EXISTS idx_findings_domain_severity_seen ON findings(domain_id, severity, last_seen DESC NULLS LAST)",
                """CREATE INDEX IF NOT EXISTS idx_findings_precise_risk
                   ON findings(domain_id, severity, last_seen DESC)
                   WHERE severity IN ('critical','high','medium')
                     AND finding_type NOT IN (
                       'js_sensitive_admin_surface','js_dom_xss_sinks','js_dom_xss_candidate',
                       'risky_url_parameter','interesting_exposed_path','interesting_open_port',
                       'interesting_bruteforce_hit','api_surface_discovered','js_asset_changed',
                       'host_fingerprint_changed','js_secret_like_strings'
                     )""",
                """CREATE INDEX IF NOT EXISTS idx_findings_review_leads
                   ON findings(domain_id, last_seen DESC)
                   WHERE is_resolved = FALSE
                     AND finding_type IN (
                       'interesting_exposed_path','interesting_open_port',
                       'js_dom_xss_candidate','js_secret_like_strings'
                     )""",
                "CREATE INDEX IF NOT EXISTS idx_evidence_packs_source_lookup ON evidence_packs(domain_id, source_table, source_id, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_validation_queue_source_lookup ON validation_queue(domain_id, source_table, source_id, updated_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_validation_queue_finding_lookup ON validation_queue(finding_id, updated_at DESC) WHERE finding_id IS NOT NULL",
                """CREATE INDEX IF NOT EXISTS idx_validation_queue_promoted_finding
                   ON validation_queue(finding_id, updated_at DESC)
                   WHERE status IN ('confirmed', 'validated') AND finding_id IS NOT NULL""",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_targets (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    name VARCHAR(160) NOT NULL,
                    start_url TEXT NOT NULL,
                    auth_type VARCHAR(30) NOT NULL DEFAULT 'none',
                    cookie_secret_ref TEXT,
                    login_url TEXT,
                    login_email TEXT,
                    password_secret_ref TEXT,
                    username_selector TEXT,
                    password_selector TEXT,
                    submit_selector TEXT,
                    auth_check_url TEXT,
                    auth_check_selector TEXT,
                    auth_check_text TEXT,
                    auth_failure_text TEXT,
                    auth_status VARCHAR(30),
                    auth_last_checked_at TIMESTAMP,
                    auth_last_error TEXT,
                    extra_routes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    interval_hours INTEGER NOT NULL DEFAULT 24,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    alert_min_risk VARCHAR(20) NOT NULL DEFAULT 'medium',
                    last_run_at TIMESTAMP,
                    last_error TEXT,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, start_url)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_runs (
                    id SERIAL PRIMARY KEY,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    status VARCHAR(30) NOT NULL DEFAULT 'running',
                    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP,
                    duration_seconds DOUBLE PRECISION,
                    auth_status VARCHAR(30),
                    new_items_count INTEGER NOT NULL DEFAULT 0,
                    new_events_count INTEGER NOT NULL DEFAULT 0,
                    scripts_count INTEGER NOT NULL DEFAULT 0,
                    requests_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_intel_items (
                    id SERIAL PRIMARY KEY,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    item_type VARCHAR(80) NOT NULL,
                    item_key VARCHAR(128) NOT NULL,
                    value TEXT NOT NULL,
                    risk VARCHAR(20) NOT NULL DEFAULT 'info',
                    source_url TEXT,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(monitor_id, item_type, item_key)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id SERIAL PRIMARY KEY,
                    run_id INTEGER REFERENCES monitor_runs(id) ON DELETE SET NULL,
                    monitor_id INTEGER NOT NULL REFERENCES monitor_targets(id) ON DELETE CASCADE,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
                    event_type VARCHAR(80) NOT NULL,
                    item_type VARCHAR(80) NOT NULL,
                    item_key VARCHAR(128) NOT NULL,
                    value TEXT NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'info',
                    summary TEXT,
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    alerted_at TIMESTAMP,
                    UNIQUE(monitor_id, event_type, item_key)
                )
                """
            )
            for ddl in (
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_url TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_selector TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_check_text TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_failure_text TEXT",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_status VARCHAR(30)",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_last_checked_at TIMESTAMP",
                "ALTER TABLE monitor_targets ADD COLUMN IF NOT EXISTS auth_last_error TEXT",
                "ALTER TABLE monitor_events ADD COLUMN IF NOT EXISTS run_id INTEGER REFERENCES monitor_runs(id) ON DELETE SET NULL",
                "ALTER TABLE analyst_annotations ADD COLUMN IF NOT EXISTS location TEXT",
                "CREATE INDEX IF NOT EXISTS idx_monitor_targets_due ON monitor_targets(enabled, last_run_at, interval_hours)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_targets_domain ON monitor_targets(domain_id, enabled)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_runs_monitor_started ON monitor_runs(monitor_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_runs_domain_started ON monitor_runs(domain_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_intel_domain_type ON monitor_intel_items(domain_id, item_type, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_domain_seen ON monitor_events(domain_id, severity, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_run_seen ON monitor_events(run_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor_seen ON monitor_events(monitor_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_api_surfaces_confidence ON api_surfaces((metadata->>'confidence'), last_seen DESC)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                UPDATE api_surfaces
                SET metadata = metadata || jsonb_build_object(
                      'confidence', CASE WHEN status_code = 404 THEN 'rejected' ELSE 'candidate' END,
                      'verified', FALSE
                    ),
                    risk_flags = CASE
                      WHEN status_code = 404 THEN ARRAY['graphql_candidate', 'rejected']::text[]
                      ELSE ARRAY['graphql_candidate', 'candidate']::text[]
                    END
                WHERE surface_type = 'graphql'
                  AND NOT (metadata ? 'confidence')
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ffuf_run_hits (
                    id SERIAL PRIMARY KEY,
                    ffuf_run_id INTEGER NOT NULL REFERENCES ffuf_runs(id) ON DELETE CASCADE,
                    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
                    url TEXT NOT NULL,
                    path TEXT,
                    status_code INTEGER,
                    content_length INTEGER,
                    words INTEGER,
                    lines INTEGER,
                    redirect_location TEXT,
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ffuf_run_id, url)
                )
                """
            )
            for ddl in (
                "ALTER TABLE ffuf_runs ADD COLUMN IF NOT EXISTS options JSONB NOT NULL DEFAULT '{}'::jsonb",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_runs_lane_started ON ffuf_runs(scan_lane, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run ON ffuf_run_hits(ffuf_run_id)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_endpoint ON ffuf_run_hits(endpoint_id)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_status ON ffuf_run_hits(status_code)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_status ON ffuf_run_hits(ffuf_run_id, status_code)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_size ON ffuf_run_hits(ffuf_run_id, content_length)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_run_hits_run_words ON ffuf_run_hits(ffuf_run_id, words)",
            ):
                await conn.execute(ddl)
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_domains_active_domain ON domains(active, domain)",
                "CREATE INDEX IF NOT EXISTS idx_subdomains_domain_seen ON subdomains(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_live_hosts_subdomain_seen ON live_hosts(subdomain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_live_hosts_status_seen ON live_hosts(status_code, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen_desc_nulls_last ON endpoints(last_seen DESC NULLS LAST)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_live_host_seen ON endpoints(live_host_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_status_seen ON endpoints(status_code, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_source_seen ON endpoints(source, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_method_seen ON endpoints(method, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_endpoints_risk_tags_gin ON endpoints USING GIN(risk_tags)",
                "CREATE INDEX IF NOT EXISTS idx_url_parameters_endpoint_seen ON url_parameters(endpoint_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_url_parameters_first_seen_endpoint ON url_parameters(first_seen, endpoint_id)",
                "CREATE INDEX IF NOT EXISTS idx_url_parameters_name_seen ON url_parameters(param_name, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_url_parameters_risk_tags_gin ON url_parameters USING GIN(risk_tags)",
                "CREATE INDEX IF NOT EXISTS idx_js_assets_live_host_seen ON js_assets(live_host_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_js_assets_status_seen ON js_assets(http_status, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_findings_domain_seen ON findings(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_findings_severity_seen ON findings(severity, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_domain_seen ON credential_leaks(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_detector_seen ON credential_leaks(detector_name, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_credential_leaks_verified_seen ON credential_leaks(verified, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_screenshots_live_host_seen ON screenshots(live_host_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_scan_snapshots_domain_finished ON scan_snapshots(domain_id, scan_finished_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_domain_last_seen ON monitor_events(domain_id, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitor_events_severity_last_seen ON monitor_events(severity, last_seen DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_runs_domain_started ON ffuf_runs(domain_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_ffuf_runs_live_host_started ON ffuf_runs(live_host_id, started_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_technologies_live_host_technology ON technologies(live_host_id, technology)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_assistant_queries (
                    id BIGSERIAL PRIMARY KEY,
                    thread_id UUID NOT NULL,
                    domain_id INTEGER REFERENCES domains(id) ON DELETE SET NULL,
                    mode VARCHAR(30) NOT NULL DEFAULT 'tab_assistant',
                    section VARCHAR(40) NOT NULL DEFAULT 'overview',
                    question TEXT NOT NULL,
                    selected_context JSONB NOT NULL DEFAULT '{}'::jsonb,
                    status VARCHAR(30) NOT NULL DEFAULT 'queued',
                    answer JSONB NOT NULL DEFAULT '{}'::jsonb,
                    model VARCHAR(120),
                    prompt_path TEXT,
                    output_path TEXT,
                    error TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 2,
                    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            for ddl in (
                "CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_claim ON ai_assistant_queries(status, available_at, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_thread ON ai_assistant_queries(thread_id, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_ai_assistant_queries_domain ON ai_assistant_queries(domain_id, created_at DESC)",
            ):
                await conn.execute(ddl)
            await conn.execute(
                """
                INSERT INTO dashboard_schema_state(schema_key, schema_version, updated_at)
                VALUES ('dashboard', $1, NOW())
                ON CONFLICT (schema_key) DO UPDATE
                SET schema_version = EXCLUDED.schema_version,
                    updated_at = EXCLUDED.updated_at
                """,
                DASHBOARD_SCHEMA_VERSION,
            )
            await conn.execute("SELECT pg_advisory_unlock(817263545)")

    @staticmethod
    def file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def endpoint_path(full_url: str) -> str:
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @staticmethod
    def endpoint_parameters(full_url: str) -> list[dict[str, Any]]:
        parsed = urlsplit(full_url)
        params = []
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            risk_tags = []
            lowered = name.lower()
            if lowered in {"url", "redirect", "redirect_uri", "callback", "next", "return_to"}:
                risk_tags.append("redirect")
            if any(token in lowered for token in ("id", "user", "account", "org", "tenant", "workspace")):
                risk_tags.append("idor")
            params.append({"name": name, "example_value": value, "risk_tags": risk_tags})
        return params

    def list_ffuf_wordlists(self) -> list[dict[str, Any]]:
        if not WORDLIST_ROOT.exists():
            return []
        rows = []
        for path in sorted(WORDLIST_ROOT.rglob("*")):
            if not self.is_ffuf_wordlist_file(path):
                continue
            try:
                stat = path.stat()
                rel = path.relative_to(WORDLIST_ROOT)
            except OSError:
                continue
            rows.append(
                {
                    "name": str(rel),
                    "path": str(path),
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
                }
            )
        return rows

    @staticmethod
    def is_ffuf_wordlist_file(path: Path) -> bool:
        if not path.is_file() or path.name.startswith("."):
            return False
        if path.name.lower() in {"license", "copying", "contributing", "code_of_conduct", "funding.json"}:
            return False
        return path.suffix.lower() not in {
            ".md",
            ".markdown",
            ".rst",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".pdf",
            ".gz",
            ".zip",
            ".7z",
            ".tar",
            ".bz2",
            ".xz",
            ".sh",
            ".py",
            ".rb",
            ".pl",
            ".go",
        }

    def validate_wordlist_path(self, wordlist_path: str) -> Path:
        path = Path(wordlist_path)
        if not path.is_absolute():
            path = WORDLIST_ROOT / path
        resolved = path.resolve()
        root = WORDLIST_ROOT.resolve()
        if root not in resolved.parents and resolved != root:
            raise ValueError("wordlist must be under /app/wordlists")
        if not resolved.is_file():
            raise ValueError("wordlist not found")
        return resolved

    def browse_ffuf_wordlists(self, relative_path: str = "") -> dict[str, Any]:
        root = (WORDLIST_ROOT / "SecLists").resolve()
        if not root.is_dir():
            raise ValueError("SecLists is not installed")
        relative = Path(relative_path.strip().strip("/")) if relative_path.strip().strip("/") else Path()
        current = (root / relative).resolve()
        if current != root and root not in current.parents:
            raise ValueError("invalid wordlist directory")
        if not current.is_dir():
            raise ValueError("wordlist directory not found")
        items: list[dict[str, Any]] = []
        try:
            children = sorted(current.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
        except OSError as exc:
            raise ValueError(f"unable to read wordlist directory: {exc}") from exc
        for child in children:
            if child.name.startswith("."):
                continue
            resolved = child.resolve()
            if resolved != root and root not in resolved.parents:
                continue
            rel = resolved.relative_to(root)
            if resolved.is_dir():
                items.append({"name": child.name, "path": str(rel), "type": "directory"})
            elif self.is_ffuf_wordlist_file(resolved):
                try:
                    size = resolved.stat().st_size
                except OSError:
                    size = 0
                items.append(
                    {
                        "name": child.name,
                        "path": str(rel),
                        "wordlist_path": str(resolved),
                        "type": "file",
                        "size": size,
                    }
                )
        return {
            "root": "SecLists",
            "path": "" if current == root else str(current.relative_to(root)),
            "items": items,
        }

    def search_ffuf_wordlists(self, query: str, limit: int = 200) -> list[dict[str, Any]]:
        query = query.strip().lower()
        if len(query) < 2:
            return []
        root = (WORDLIST_ROOT / "SecLists").resolve()
        if not root.is_dir():
            return []
        rows: list[dict[str, Any]] = []
        for path in root.rglob("*"):
            if len(rows) >= limit:
                break
            if not self.is_ffuf_wordlist_file(path):
                continue
            try:
                rel = path.resolve().relative_to(root)
                size = path.stat().st_size
            except (OSError, ValueError):
                continue
            if query not in str(rel).lower():
                continue
            rows.append(
                {
                    "name": path.name,
                    "path": str(rel),
                    "wordlist_path": str(path.resolve()),
                    "type": "file",
                    "size": size,
                }
            )
        return rows

    @staticmethod
    def normalize_ffuf_target(target_url: str) -> str:
        target = target_url.strip()
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target URL must start with http:// or https://")
        if any(character.isspace() for character in target):
            raise ValueError("target URL cannot contain whitespace")
        if "FUZZ" in target:
            return target
        path = parsed.path or "/"
        path = f"{path}{'FUZZ' if path.endswith('/') else '/FUZZ'}"
        return parsed._replace(path=path).geturl()

    @staticmethod
    def normalize_ffuf_options(options: dict[str, Any] | None) -> dict[str, Any]:
        raw = options or {}

        def bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
            try:
                value = int(raw.get(name, default))
            except (TypeError, ValueError):
                value = default
            return max(minimum, min(value, maximum))

        match_codes = str(raw.get("match_codes") or "200,204,301,302,307,308,401,403").strip()
        if not re.fullmatch(r"(?:all|[0-9,-]+)", match_codes, flags=re.IGNORECASE):
            raise ValueError("match codes must be comma-separated status codes, ranges, or all")
        return {
            "threads": bounded_int("threads", 10, 1, 100),
            "rate": bounded_int("rate", 30, 1, 1000),
            "timeout": bounded_int("timeout", 10, 1, 60),
            "max_runtime": bounded_int("max_runtime", 1800, 60, 7200),
            "match_codes": match_codes,
            "recursion": bool(raw.get("recursion", False)),
            "recursion_depth": bounded_int("recursion_depth", 1, 1, 5),
        }

    async def get_subdomain_ffuf_context(self, subdomain_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            subdomain = await conn.fetchrow(
                """
                SELECT s.id AS subdomain_id, s.subdomain, d.id AS domain_id, d.domain
                FROM subdomains s
                JOIN domains d ON d.id = s.domain_id
                WHERE s.id = $1 AND ($2::int IS NULL OR d.id = $2)
                """,
                subdomain_id,
                domain_id,
            )
            if not subdomain:
                return None
            live_hosts = await conn.fetch(
                """
                SELECT id AS live_host_id, url, status_code, title, last_seen
                FROM live_hosts
                WHERE subdomain_id = $1
                ORDER BY
                  CASE WHEN protocol = 'https' THEN 0 ELSE 1 END,
                  COALESCE(status_code, 999),
                  url
                """,
                subdomain_id,
            )
            runs = await conn.fetch(
                """
                SELECT fr.id, fr.live_host_id, fr.host_url, fr.scan_lane, fr.wordlist_path,
                       fr.started_at, fr.completed_at, fr.status, fr.hits_count, fr.error
                FROM ffuf_runs fr
                JOIN live_hosts lh ON lh.id = fr.live_host_id
                WHERE lh.subdomain_id = $1
                ORDER BY fr.started_at DESC
                LIMIT 20
                """,
                subdomain_id,
            )
            return {
                **dict(subdomain),
                "live_hosts": [dict(row) for row in live_hosts],
                "runs": [dict(row) for row in runs],
            }

    async def get_live_host_ffuf_context(self, live_host_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            live_host = await conn.fetchrow(
                """
                SELECT lh.id AS live_host_id, lh.url, lh.status_code, lh.title,
                       s.id AS subdomain_id, s.subdomain, d.id AS domain_id, d.domain
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE lh.id = $1
                  AND ($2::int IS NULL OR d.id = $2)
                """,
                live_host_id,
                domain_id,
            )
            if not live_host:
                return None
            runs = await conn.fetch(
                """
                SELECT id, live_host_id, host_url, scan_lane, wordlist_path,
                       started_at, completed_at, status, hits_count, error
                FROM ffuf_runs
                WHERE live_host_id = $1
                ORDER BY started_at DESC
                LIMIT 20
                """,
                live_host_id,
            )
            return {
                **dict(live_host),
                "live_hosts": [dict(live_host)],
                "runs": [dict(row) for row in runs],
            }

    async def start_manual_ffuf_run(
        self,
        subdomain_id: int,
        wordlist_path: str,
        live_host_id: int | None = None,
        domain_id: int | None = None,
    ) -> dict[str, Any]:
        assert self.pool is not None
        wordlist = self.validate_wordlist_path(wordlist_path)
        wordlist_sha256 = self.file_sha256(wordlist)
        async with self.pool.acquire() as conn:
            live_host = await conn.fetchrow(
                """
                SELECT lh.id AS live_host_id, lh.url, s.id AS subdomain_id, s.domain_id, d.domain
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE s.id = $1
                  AND ($2::int IS NULL OR lh.id = $2)
                  AND ($3::int IS NULL OR d.id = $3)
                ORDER BY
                  CASE WHEN lh.protocol = 'https' THEN 0 ELSE 1 END,
                  COALESCE(lh.status_code, 999),
                  lh.url
                LIMIT 1
                """,
                subdomain_id,
                live_host_id,
                domain_id,
            )
            if not live_host:
                raise ValueError("no live host found for this subdomain")
            return await self._start_manual_ffuf_run_for_live_host(conn, live_host, wordlist, wordlist_sha256)

    async def start_manual_ffuf_run_for_live_host(
        self,
        live_host_id: int,
        wordlist_path: str,
        domain_id: int | None = None,
    ) -> dict[str, Any]:
        assert self.pool is not None
        wordlist = self.validate_wordlist_path(wordlist_path)
        wordlist_sha256 = self.file_sha256(wordlist)
        async with self.pool.acquire() as conn:
            live_host = await conn.fetchrow(
                """
                SELECT lh.id AS live_host_id, lh.url, s.id AS subdomain_id, s.domain_id, d.domain
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE lh.id = $1
                  AND ($2::int IS NULL OR d.id = $2)
                """,
                live_host_id,
                domain_id,
            )
            if not live_host:
                raise ValueError("live host not found")
            return await self._start_manual_ffuf_run_for_live_host(conn, live_host, wordlist, wordlist_sha256)

    async def _start_manual_ffuf_run_for_live_host(
        self,
        conn: asyncpg.Connection,
        live_host: asyncpg.Record,
        wordlist: Path,
        wordlist_sha256: str,
    ) -> dict[str, Any]:
        running = await conn.fetchrow(
            """
            SELECT id, status, host_url, wordlist_path, started_at
            FROM ffuf_runs
            WHERE live_host_id = $1
              AND scan_lane = 'manual_dashboard'
              AND wordlist_sha256 = $2
              AND status = 'running'
            """,
            live_host["live_host_id"],
            wordlist_sha256,
        )
        if running:
            return {**dict(running), "already_running": True}
        row = await conn.fetchrow(
            """
            INSERT INTO ffuf_runs (domain_id, live_host_id, host_url, scan_lane, wordlist_path, wordlist_sha256)
            VALUES ($1, $2, $3, 'manual_dashboard', $4, $5)
            ON CONFLICT (live_host_id, scan_lane, wordlist_sha256)
            DO UPDATE SET
              started_at = NOW(),
              completed_at = NULL,
              status = 'running',
              hits_count = 0,
              error = NULL,
              host_url = EXCLUDED.host_url,
              wordlist_path = EXCLUDED.wordlist_path
            RETURNING id, status, host_url, wordlist_path, started_at
            """,
            live_host["domain_id"],
            live_host["live_host_id"],
            live_host["url"],
            str(wordlist),
            wordlist_sha256,
        )
        await conn.execute("DELETE FROM ffuf_run_hits WHERE ffuf_run_id = $1", row["id"])
        thread = threading.Thread(
            target=self.run_manual_ffuf_worker,
            args=(int(row["id"]), int(live_host["domain_id"]), int(live_host["live_host_id"]), str(live_host["url"]), str(wordlist)),
            daemon=True,
        )
        thread.start()
        return {**dict(row), "already_running": False}

    def run_manual_ffuf_worker(self, run_id: int, domain_id: int, live_host_id: int, host_url: str, wordlist_path: str) -> None:
        asyncio.run(self._run_manual_ffuf_worker(run_id, domain_id, live_host_id, host_url, wordlist_path))

    async def _run_manual_ffuf_worker(self, run_id: int, domain_id: int, live_host_id: int, host_url: str, wordlist_path: str) -> None:
        db_cfg = self.config["database"]
        conn = await asyncpg.connect(
            host=db_cfg["host"],
            port=db_cfg["port"],
            database=db_cfg["name"],
            user=db_cfg["user"],
            password=db_cfg["password"],
        )
        hits_count = 0
        try:
            scan_cfg = self.config.get("scan", {})
            command = [
                self.config.get("tools", {}).get("ffuf", "ffuf"),
                "-w",
                wordlist_path,
                "-u",
                f"{host_url.rstrip('/')}/FUZZ",
                "-mc",
                ",".join(str(status) for status in scan_cfg.get("ffuf_match_status", [200, 204, 301, 302, 307, 308, 401, 403])),
                "-t",
                str(scan_cfg.get("ffuf_threads", 10)),
                "-rate",
                str(scan_cfg.get("ffuf_rate", 30)),
                "-timeout",
                str(scan_cfg.get("ffuf_timeout_seconds", 10)),
                "-ac",
                "-noninteractive",
                "-json",
            ]
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=int(scan_cfg.get("tool_timeout_seconds", 900)),
                check=False,
            )
            for hit in self.parse_ffuf_output(result.stdout):
                url = str(hit.get("url") or "")
                if not url:
                    continue
                status_code = hit.get("status")
                path = self.endpoint_path(url)
                path_hash = hashlib.sha256(path.encode()).hexdigest()
                parameters = self.endpoint_parameters(url)
                risk_tags = sorted({tag for item in parameters for tag in item["risk_tags"]})
                endpoint_id = await conn.fetchval(
                    """
                    INSERT INTO endpoints (live_host_id, path, path_hash, method, status_code, probed_at, parameters, risk_tags, source)
                    VALUES ($1, $2, $3, 'GET', $4, CASE WHEN $4::int IS NULL THEN NULL ELSE NOW() END, $5::jsonb, $6, 'ffuf')
                    ON CONFLICT (live_host_id, path_hash, method, source)
                    DO UPDATE SET
                      last_seen = NOW(),
                      status_code = COALESCE(EXCLUDED.status_code, endpoints.status_code),
                      probed_at = COALESCE(EXCLUDED.probed_at, endpoints.probed_at),
                      parameters = EXCLUDED.parameters,
                      risk_tags = EXCLUDED.risk_tags
                    RETURNING id
                    """,
                    live_host_id,
                    path,
                    path_hash,
                    int(status_code) if status_code is not None else None,
                    json.dumps(parameters),
                    risk_tags,
                )
                await conn.execute(
                    """
                    INSERT INTO ffuf_run_hits (
                      ffuf_run_id, endpoint_id, url, path, status_code, content_length, words, lines, redirect_location, result
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
                    ON CONFLICT (ffuf_run_id, url)
                    DO UPDATE SET
                      endpoint_id = EXCLUDED.endpoint_id,
                      status_code = EXCLUDED.status_code,
                      content_length = EXCLUDED.content_length,
                      words = EXCLUDED.words,
                      lines = EXCLUDED.lines,
                      redirect_location = EXCLUDED.redirect_location,
                      result = EXCLUDED.result
                    """,
                    run_id,
                    endpoint_id,
                    url,
                    path,
                    int(status_code) if status_code is not None else None,
                    self.safe_int(hit.get("length")),
                    self.safe_int(hit.get("words")),
                    self.safe_int(hit.get("lines")),
                    hit.get("redirectlocation"),
                    json.dumps(hit),
                )
                hits_count += 1
            status = "completed" if result.returncode in {0, 1} else "failed"
            error = None if status == "completed" else (result.stderr or result.stdout)[-4000:]
            await conn.execute(
                "UPDATE ffuf_runs SET completed_at = NOW(), status = $2, hits_count = $3, error = $4 WHERE id = $1",
                run_id,
                status,
                hits_count,
                error,
            )
        except Exception as exc:
            await conn.execute(
                "UPDATE ffuf_runs SET completed_at = NOW(), status = 'failed', hits_count = $2, error = $3 WHERE id = $1",
                run_id,
                hits_count,
                repr(exc),
            )
        finally:
            await conn.close()

    @staticmethod
    def safe_int(value: Any) -> int | None:
        try:
            if value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def parse_ffuf_output(stdout: str) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        stripped = stdout.strip()
        if not stripped:
            return hits
        try:
            payload = json.loads(stripped)
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                return [item for item in payload["results"] if isinstance(item, dict)]
            if isinstance(payload, dict) and payload.get("url"):
                return [payload]
        except json.JSONDecodeError:
            pass
        for line in stripped.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("url"):
                hits.append(payload)
        return hits

    async def get_ffuf_run(self, run_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            run = await conn.fetchrow(
                """
                SELECT fr.id, fr.domain_id, d.domain, fr.live_host_id, fr.host_url, fr.scan_lane,
                       fr.wordlist_path, fr.options, fr.started_at, fr.completed_at, fr.status, fr.hits_count, fr.error
                FROM ffuf_runs fr
                LEFT JOIN domains d ON d.id = fr.domain_id
                WHERE fr.id = $1 AND ($2::int IS NULL OR fr.domain_id = $2)
                """,
                run_id,
                domain_id,
            )
            if not run:
                return None
            hits = await conn.fetch(
                """
                SELECT id, endpoint_id, url, path, status_code, content_length, words, lines, redirect_location, created_at
                FROM ffuf_run_hits
                WHERE ffuf_run_id = $1
                ORDER BY status_code NULLS LAST, url
                LIMIT 500
                """,
                run_id,
            )
            return {**dict(run), "hits": [dict(row) for row in hits]}

    async def start_ffuf_workbench_run(
        self,
        target_url: str,
        wordlist_path: str,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        assert self.pool is not None
        target = self.normalize_ffuf_target(target_url)
        wordlist = self.validate_wordlist_path(wordlist_path)
        seclists_root = (WORDLIST_ROOT / "SecLists").resolve()
        if wordlist != seclists_root and seclists_root not in wordlist.parents:
            raise ValueError("select a wordlist from SecLists")
        normalized_options = self.normalize_ffuf_options(options)
        wordlist_sha256 = self.file_sha256(wordlist)
        async with self.pool.acquire() as conn:
            running = await conn.fetchrow(
                """
                SELECT id, status, host_url, wordlist_path, options, started_at
                FROM ffuf_runs
                WHERE scan_lane = 'workbench'
                  AND host_url = $1
                  AND wordlist_sha256 = $2
                  AND status = 'running'
                ORDER BY started_at DESC
                LIMIT 1
                """,
                target,
                wordlist_sha256,
            )
            if running:
                return {**dict(running), "already_running": True}
            row = await conn.fetchrow(
                """
                INSERT INTO ffuf_runs (
                  domain_id, live_host_id, host_url, scan_lane, wordlist_path, wordlist_sha256, options
                )
                VALUES (NULL, NULL, $1, 'workbench', $2, $3, $4::jsonb)
                RETURNING id, status, host_url, wordlist_path, options, started_at
                """,
                target,
                str(wordlist),
                wordlist_sha256,
                json.dumps(normalized_options),
            )
        thread = threading.Thread(
            target=self.run_ffuf_workbench_worker,
            args=(int(row["id"]), target, str(wordlist), normalized_options),
            daemon=True,
        )
        thread.start()
        return {**dict(row), "already_running": False}

    def run_ffuf_workbench_worker(
        self,
        run_id: int,
        target_url: str,
        wordlist_path: str,
        options: dict[str, Any],
    ) -> None:
        asyncio.run(self._run_ffuf_workbench_worker(run_id, target_url, wordlist_path, options))

    async def _run_ffuf_workbench_worker(
        self,
        run_id: int,
        target_url: str,
        wordlist_path: str,
        options: dict[str, Any],
    ) -> None:
        db_cfg = self.config["database"]
        conn = await asyncpg.connect(
            host=db_cfg["host"],
            port=db_cfg["port"],
            database=db_cfg["name"],
            user=db_cfg["user"],
            password=db_cfg["password"],
        )
        hits_count = 0
        try:
            command = [
                self.config.get("tools", {}).get("ffuf", "ffuf"),
                "-w",
                wordlist_path,
                "-u",
                target_url,
                "-mc",
                str(options["match_codes"]),
                "-t",
                str(options["threads"]),
                "-rate",
                str(options["rate"]),
                "-timeout",
                str(options["timeout"]),
                "-noninteractive",
                "-json",
            ]
            if options.get("recursion"):
                command.extend(["-recursion", "-recursion-depth", str(options["recursion_depth"])])
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=int(options["max_runtime"]),
                check=False,
            )
            for hit in self.parse_ffuf_output(result.stdout):
                url = str(hit.get("url") or "")
                if not url:
                    continue
                status_code = self.safe_int(hit.get("status"))
                await conn.execute(
                    """
                    INSERT INTO ffuf_run_hits (
                      ffuf_run_id, endpoint_id, url, path, status_code, content_length,
                      words, lines, redirect_location, result
                    )
                    VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                    ON CONFLICT (ffuf_run_id, url)
                    DO UPDATE SET
                      status_code = EXCLUDED.status_code,
                      content_length = EXCLUDED.content_length,
                      words = EXCLUDED.words,
                      lines = EXCLUDED.lines,
                      redirect_location = EXCLUDED.redirect_location,
                      result = EXCLUDED.result
                    """,
                    run_id,
                    url,
                    self.endpoint_path(url),
                    status_code,
                    self.safe_int(hit.get("length")),
                    self.safe_int(hit.get("words")),
                    self.safe_int(hit.get("lines")),
                    hit.get("redirectlocation"),
                    json.dumps(hit),
                )
                hits_count += 1
            status = "completed" if result.returncode in {0, 1} else "failed"
            error = None if status == "completed" else (result.stderr or result.stdout)[-4000:]
            await conn.execute(
                """
                UPDATE ffuf_runs
                SET completed_at = NOW(), status = $2, hits_count = $3, error = $4
                WHERE id = $1
                """,
                run_id,
                status,
                hits_count,
                error,
            )
        except Exception as exc:
            await conn.execute(
                """
                UPDATE ffuf_runs
                SET completed_at = NOW(), status = 'failed', hits_count = $2, error = $3
                WHERE id = $1
                """,
                run_id,
                hits_count,
                repr(exc),
            )
        finally:
            await conn.close()

    async def get_ffuf_workbench_runs(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM ffuf_runs WHERE scan_lane = 'workbench'")
            rows = await conn.fetch(
                """
                SELECT id, host_url, wordlist_path, options, status, hits_count, error,
                       started_at, completed_at
                FROM ffuf_runs
                WHERE scan_lane = 'workbench'
                ORDER BY started_at DESC
                LIMIT $1 OFFSET $2
                """,
                limit,
                offset,
            )
        return {"rows": [dict(row) for row in rows], "total": int(total or 0)}

    async def get_ffuf_workbench_run(
        self,
        run_id: int,
        limit: int = 100,
        offset: int = 0,
        status_codes: list[int] | None = None,
        size_min: int | None = None,
        size_max: int | None = None,
        words_min: int | None = None,
        words_max: int | None = None,
    ) -> dict[str, Any] | None:
        assert self.pool is not None
        clauses = ["ffuf_run_id = $1"]
        values: list[Any] = [run_id]
        if status_codes:
            values.append(status_codes)
            clauses.append(f"status_code = ANY(${len(values)}::int[])")
        for column, value, operator in (
            ("content_length", size_min, ">="),
            ("content_length", size_max, "<="),
            ("words", words_min, ">="),
            ("words", words_max, "<="),
        ):
            if value is not None:
                values.append(value)
                clauses.append(f"{column} {operator} ${len(values)}")
        where_sql = " AND ".join(clauses)
        async with self.pool.acquire() as conn:
            run = await conn.fetchrow(
                """
                SELECT id, host_url, wordlist_path, options, status, hits_count, error,
                       started_at, completed_at
                FROM ffuf_runs
                WHERE id = $1 AND scan_lane = 'workbench'
                """,
                run_id,
            )
            if not run:
                return None
            unfiltered_total = await conn.fetchval(
                "SELECT COUNT(*) FROM ffuf_run_hits WHERE ffuf_run_id = $1",
                run_id,
            )
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM ffuf_run_hits WHERE {where_sql}",
                *values,
            )
            page_values = [*values, limit, offset]
            hits = await conn.fetch(
                f"""
                SELECT id, url, path, status_code, content_length, words, lines,
                       redirect_location, created_at
                FROM ffuf_run_hits
                WHERE {where_sql}
                ORDER BY status_code NULLS LAST, url
                LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                """,
                *page_values,
            )
        return {
            **dict(run),
            "hits": [dict(row) for row in hits],
            "hits_total": int(total or 0),
            "hits_unfiltered_total": int(unfiltered_total or 0),
        }

    async def delete_ffuf_workbench_run(self, run_id: int) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    """
                    SELECT id, host_url, wordlist_path, status, hits_count
                    FROM ffuf_runs
                    WHERE id = $1 AND scan_lane = 'workbench'
                    FOR UPDATE
                    """,
                    run_id,
                )
                if not run:
                    return None
                if run["status"] == "running":
                    raise ValueError("running FFUF workbench runs cannot be deleted until they finish")
                deleted_hits = await conn.fetchval(
                    "SELECT COUNT(*) FROM ffuf_run_hits WHERE ffuf_run_id = $1",
                    run_id,
                )
                await conn.execute("DELETE FROM ffuf_runs WHERE id = $1 AND scan_lane = 'workbench'", run_id)
        return {**dict(run), "deleted": True, "deleted_hits": int(deleted_hits or 0)}

    async def get_domains(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  d.id,
                  d.domain,
                  d.organization,
                  d.active,
                  d.created_at,
                  d.last_scan,
                  d.scan_interval_hours,
                  d.include_subdomains,
                  d.max_live_hosts,
                  d.max_wayback_urls,
                  d.max_js_assets,
                  d.enable_gau,
                  d.enable_katana,
                  d.enable_hakrawler,
                  d.enable_js_analysis,
                  d.enable_ffuf,
                  d.enable_nuclei,
                  d.enable_screenshots,
                  d.enable_port_scan,
                  d.enable_search_intelligence,
                  d.last_scan + (d.scan_interval_hours || ' hours')::interval AS next_scan,
                  EXISTS (
                    SELECT 1 FROM scan_snapshots running
                    WHERE running.domain_id = d.id AND running.scan_finished_at IS NULL
                  ) AS scan_running,
                  COALESCE(NULLIF(ss.totals->>'subdomains', '')::bigint, 0) AS subdomains,
                  COALESCE(NULLIF(ss.totals->>'live_hosts', '')::bigint, 0) AS live_hosts,
                  COALESCE(NULLIF(ss.totals->>'endpoints', '')::bigint, 0) AS endpoints,
                  COALESCE(NULLIF(ss.totals->>'js_assets', '')::bigint, 0) AS js_assets,
                  COALESCE(NULLIF(ss.totals->>'findings', '')::bigint, 0) AS findings,
                  COALESCE(NULLIF(ss.totals->>'screenshots', '')::bigint, 0) AS screenshots,
                  ss.scan_finished_at AS counts_as_of
                FROM domains d
                LEFT JOIN LATERAL (
                  SELECT snap.totals, snap.scan_finished_at
                  FROM scan_snapshots snap
                  WHERE snap.domain_id = d.id
                    AND snap.scan_finished_at IS NOT NULL
                  ORDER BY snap.scan_finished_at DESC
                  LIMIT 1
                ) ss ON TRUE
                ORDER BY d.active DESC, d.domain
                """
            )
            return [dict(row) for row in rows]

    async def create_domains(self, payload: dict[str, Any]) -> dict[str, Any]:
        assert self.pool is not None
        domains = parse_domain_values(payload.get("domains", payload.get("domain")))
        options = domain_options_from_payload(payload)
        organization = str(payload.get("organization") or "").strip()[:255] or None
        start_now = payload.get("start_now", True)
        active = payload.get("active", True)
        if not isinstance(start_now, bool) or not isinstance(active, bool):
            raise DomainValidationError("start_now and active must be true or false")
        if start_now:
            active = True

        created: list[dict[str, Any]] = []
        existing: list[dict[str, Any]] = []
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                for domain in domains:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO domains (
                          domain, organization, active, last_scan, scan_interval_hours,
                          include_subdomains, max_live_hosts, max_wayback_urls, max_js_assets,
                          enable_gau, enable_katana, enable_hakrawler, enable_js_analysis,
                          enable_ffuf, enable_nuclei, enable_screenshots, enable_port_scan,
                          enable_search_intelligence
                        )
                        VALUES (
                          $1, $2, $3, CASE WHEN $4::bool THEN NULL ELSE NOW() END, $5,
                          $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
                        )
                        ON CONFLICT (domain) DO NOTHING
                        RETURNING id, domain, organization, active, last_scan, scan_interval_hours,
                                  include_subdomains, max_live_hosts, max_wayback_urls, max_js_assets,
                                  enable_gau, enable_katana, enable_hakrawler, enable_js_analysis,
                                  enable_ffuf, enable_nuclei, enable_screenshots, enable_port_scan,
                                  enable_search_intelligence, created_at
                        """,
                        domain,
                        organization,
                        active,
                        start_now,
                        options["scan_interval_hours"],
                        options["include_subdomains"],
                        options["max_live_hosts"],
                        options["max_wayback_urls"],
                        options["max_js_assets"],
                        options["enable_gau"],
                        options["enable_katana"],
                        options["enable_hakrawler"],
                        options["enable_js_analysis"],
                        options["enable_ffuf"],
                        options["enable_nuclei"],
                        options["enable_screenshots"],
                        options["enable_port_scan"],
                        options["enable_search_intelligence"],
                    )
                    if row:
                        created.append(dict(row))
                    else:
                        duplicate = await conn.fetchrow(
                            "SELECT id, domain, organization, active, last_scan, scan_interval_hours FROM domains WHERE domain = $1",
                            domain,
                        )
                        if duplicate:
                            existing.append(dict(duplicate))
        return {"created": created, "existing": existing, "start_now": start_now}

    async def update_domain(self, domain_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
        assert self.pool is not None
        assignments: list[str] = []
        values: list[Any] = []

        if "organization" in payload:
            organization = str(payload.get("organization") or "").strip()[:255] or None
            values.append(organization)
            assignments.append(f"organization = ${len(values)}")
        if "active" in payload:
            if not isinstance(payload["active"], bool):
                raise DomainValidationError("active must be true or false")
            values.append(payload["active"])
            assignments.append(f"active = ${len(values)}")
        if "options" in payload or "preset" in payload or any(key in payload for key in DOMAIN_OPTION_KEYS):
            options = domain_options_from_payload(payload)
            for key in DOMAIN_OPTION_KEYS:
                values.append(options[key])
                assignments.append(f"{key} = ${len(values)}")
        if not assignments:
            raise DomainValidationError("no domain settings were supplied")

        values.append(domain_id)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""
                UPDATE domains
                SET {', '.join(assignments)}
                WHERE id = ${len(values)}
                RETURNING id, domain, organization, active, last_scan, scan_interval_hours,
                          include_subdomains, max_live_hosts, max_wayback_urls, max_js_assets,
                          enable_gau, enable_katana, enable_hakrawler, enable_js_analysis,
                          enable_ffuf, enable_nuclei, enable_screenshots, enable_port_scan,
                          enable_search_intelligence, created_at
                """,
                *values,
            )
        return dict(row) if row else None

    async def queue_domain_scan(self, domain_id: int) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow("SELECT id, domain FROM domains WHERE id = $1 FOR UPDATE", domain_id)
                if not row:
                    return None
                running = await conn.fetchval(
                    "SELECT EXISTS (SELECT 1 FROM scan_snapshots WHERE domain_id = $1 AND scan_finished_at IS NULL)",
                    domain_id,
                )
                if running:
                    raise ValueError("a recon scan is already running for this domain")
                await conn.execute("UPDATE domains SET active = TRUE, last_scan = NULL WHERE id = $1", domain_id)
        return {"id": int(row["id"]), "domain": row["domain"], "active": True, "status": "queued"}

    async def _domain_delete_preview(self, conn: asyncpg.Connection, domain_id: int) -> dict[str, Any] | None:
        row = await conn.fetchrow(
            """
            SELECT
              d.id, d.domain, d.organization, d.active, d.last_scan,
              COALESCE(NULLIF(latest.totals->>'subdomains', '')::bigint, 0) AS subdomains,
              COALESCE(NULLIF(latest.totals->>'live_hosts', '')::bigint, 0) AS live_hosts,
              COALESCE(NULLIF(latest.totals->>'endpoints', '')::bigint, 0) AS endpoints,
              COALESCE(NULLIF(latest.totals->>'risky_params', '')::bigint, 0) AS parameters,
              COALESCE(NULLIF(latest.totals->>'js_assets', '')::bigint, 0) AS js_assets,
              0::bigint AS js_analyses,
              COALESCE(NULLIF(latest.totals->>'findings', '')::bigint, 0) AS findings,
              COALESCE(NULLIF(latest.totals->>'screenshots', '')::bigint, 0) AS screenshots,
              latest.scan_finished_at AS counts_as_of,
              (SELECT COUNT(*) FROM scan_snapshots ss WHERE ss.domain_id = d.id) AS snapshots,
              (SELECT COUNT(*) FROM bug_jobs bj WHERE bj.domain_id = d.id) AS bug_jobs,
              (SELECT COUNT(*) FROM ffuf_runs fr WHERE fr.domain_id = d.id) AS ffuf_runs,
              (SELECT COUNT(*) FROM credential_leaks cl WHERE cl.domain_id = d.id) AS credential_leaks,
              (SELECT COUNT(*) FROM hunt_credentials hc WHERE hc.domain_id = d.id) AS hunt_credentials,
              EXISTS (SELECT 1 FROM scan_snapshots ss WHERE ss.domain_id = d.id AND ss.scan_finished_at IS NULL) AS running_scans,
              EXISTS (SELECT 1 FROM bug_jobs bj WHERE bj.domain_id = d.id AND bj.status IN ('running', 'leased', 'processing')) AS running_bug_jobs,
              EXISTS (SELECT 1 FROM ffuf_runs fr WHERE fr.domain_id = d.id AND fr.status IN ('running', 'leased', 'processing')) AS running_ffuf_runs,
              EXISTS (SELECT 1 FROM port_scan_jobs pj WHERE pj.domain_id = d.id AND pj.status IN ('running', 'leased', 'processing')) AS running_port_jobs,
              EXISTS (SELECT 1 FROM search_intel_jobs sj WHERE sj.domain_id = d.id AND sj.status IN ('running', 'leased', 'processing')) AS running_search_jobs,
              EXISTS (SELECT 1 FROM shodan_jobs shj WHERE shj.domain_id = d.id AND shj.status IN ('running', 'leased', 'processing')) AS running_shodan_jobs,
              EXISTS (SELECT 1 FROM monitor_runs mr WHERE mr.domain_id = d.id AND mr.status IN ('running', 'leased', 'processing')) AS running_monitor_jobs
            FROM domains d
            LEFT JOIN LATERAL (
              SELECT ss.totals, ss.scan_finished_at
              FROM scan_snapshots ss
              WHERE ss.domain_id = d.id AND ss.scan_finished_at IS NOT NULL
              ORDER BY ss.scan_finished_at DESC
              LIMIT 1
            ) latest ON TRUE
            WHERE d.id = $1
            """,
            domain_id,
        )
        if not row:
            return None
        result = dict(row)
        count_keys = (
            "subdomains", "live_hosts", "endpoints", "parameters", "js_assets", "js_analyses",
            "findings", "screenshots", "snapshots", "bug_jobs", "ffuf_runs", "credential_leaks", "hunt_credentials",
        )
        blocker_keys = (
            "running_scans", "running_bug_jobs", "running_ffuf_runs", "running_port_jobs",
            "running_search_jobs", "running_shodan_jobs", "running_monitor_jobs",
        )
        result["core_rows"] = sum(int(result.get(key) or 0) for key in count_keys)
        result["blockers"] = {key: 1 for key in blocker_keys if bool(result.get(key))}
        if result["active"]:
            result["blockers"]["domain_active"] = 1
        if result["hunt_credentials"]:
            result["blockers"]["hunt_credentials"] = result["hunt_credentials"]
        result["counts_estimated"] = True
        result["filesystem_note"] = "Counts are an estimate from the latest completed scan. Database records are deleted; existing screenshot files remain in the screenshot volume."
        return result

    async def get_domain_delete_preview(self, domain_id: int) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return await self._domain_delete_preview(conn, domain_id)

    async def delete_domain(self, domain_id: int, confirmation: str) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                domain = await conn.fetchrow("SELECT id, domain FROM domains WHERE id = $1 FOR UPDATE", domain_id)
                if not domain:
                    return None
                if confirmation.strip().lower().rstrip(".") != domain["domain"]:
                    raise DomainValidationError("type the exact domain name to confirm deletion")
                preview = await self._domain_delete_preview(conn, domain_id)
                if preview and preview["blockers"]:
                    raise ValueError("resolve active work and remove hunt credentials before deleting this domain")
                await conn.execute("DELETE FROM ai_assistant_queries WHERE domain_id = $1", domain_id)
                await conn.execute("DELETE FROM domains WHERE id = $1", domain_id)
        return {"deleted": True, "id": domain_id, "domain": domain["domain"], "impact": preview}

    async def get_domain_options(self) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  d.id,
                  d.domain,
                  d.organization,
                  d.active,
                  d.last_scan,
                  d.scan_interval_hours,
                  d.last_scan + (d.scan_interval_hours || ' hours')::interval AS next_scan
                FROM domains d
                ORDER BY d.active DESC, d.domain
                """
            )
            return [dict(row) for row in rows]

    async def get_stats(self, domain_id: int | None = None) -> dict:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                WITH recent_snapshots AS MATERIALIZED (
                  SELECT ss.new_counts
                  FROM scan_snapshots ss
                  WHERE ss.scan_finished_at > NOW() - INTERVAL '24 hours'
                    AND ($1::int IS NULL OR ss.domain_id = $1)
                ),
                recent AS (
                  SELECT
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_subdomains', '')::bigint, 0)), 0) AS new_subdomains_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_live_hosts', '')::bigint, 0)), 0) AS new_live_hosts_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_urls', '')::bigint, 0)), 0) AS new_endpoints_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_js_assets', '')::bigint, 0)), 0) AS new_js_assets_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_screenshots', '')::bigint, 0)), 0) AS screenshots_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'changed_fingerprints', '')::bigint, 0)), 0) AS changed_fingerprints_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'new_risky_params', '')::bigint, 0)), 0) AS risky_params_24h,
                    COALESCE(SUM(COALESCE(NULLIF(new_counts->>'nuclei_hits', '')::bigint, 0)), 0) AS nuclei_hits_24h
                  FROM recent_snapshots
                )
                SELECT
                  (SELECT COUNT(*) FROM domains d WHERE d.active = TRUE AND ($1::int IS NULL OR d.id = $1)) AS active_domains,
                  recent.new_subdomains_24h,
                  recent.new_live_hosts_24h,
                  recent.new_endpoints_24h,
                  recent.new_js_assets_24h,
                  recent.screenshots_24h,
                  recent.changed_fingerprints_24h,
                  recent.risky_params_24h,
                  recent.nuclei_hits_24h,
                  (SELECT COUNT(*) FROM alerts a LEFT JOIN findings f ON f.id = a.finding_id WHERE a.sent_at > NOW() - INTERVAL '24 hours' AND ($1::int IS NULL OR f.domain_id = $1)) AS alerts_24h
                FROM recent
                """,
                domain_id,
            )
            return dict(row)

    async def get_totals(self, domain_id: int | None = None) -> dict:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                  (SELECT COUNT(*) FROM subdomains s WHERE $1::int IS NULL OR s.domain_id = $1) AS subdomains,
                  (SELECT COUNT(*) FROM live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id WHERE $1::int IS NULL OR s.domain_id = $1) AS live_hosts,
                  (SELECT COUNT(*) FROM endpoints e JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id WHERE $1::int IS NULL OR s.domain_id = $1) AS endpoints_urls,
                  (SELECT COUNT(*) FROM js_assets ja JOIN live_hosts lh ON lh.id = ja.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id WHERE $1::int IS NULL OR s.domain_id = $1) AS js_urls,
                  (SELECT COUNT(*) FROM url_parameters up JOIN endpoints e ON e.id = up.endpoint_id JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id WHERE $1::int IS NULL OR s.domain_id = $1) AS parameters,
                  (SELECT COUNT(*) FROM findings f WHERE $1::int IS NULL OR f.domain_id = $1) AS findings,
                  (SELECT COUNT(*) FROM screenshots sc JOIN live_hosts lh ON lh.id = sc.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id WHERE $1::int IS NULL OR s.domain_id = $1) AS screenshots
                """,
                domain_id,
            )
            return dict(row)

    async def get_command_center(self, domain_id: int | None = None) -> dict:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            if domain_id is None:
                row = await conn.fetchrow(
                    """
                    WITH latest_snapshots AS MATERIALIZED (
                      SELECT DISTINCT ON (ss.domain_id) ss.domain_id, ss.totals, ss.scan_finished_at
                      FROM scan_snapshots ss
                      WHERE ss.scan_finished_at IS NOT NULL
                      ORDER BY ss.domain_id, ss.scan_finished_at DESC
                    ),
                    snapshot_totals AS (
                      SELECT
                        COALESCE(SUM(COALESCE(NULLIF(totals->>'live_hosts', '')::bigint, 0)), 0) AS live_hosts,
                        COALESCE(SUM(COALESCE(NULLIF(totals->>'js_assets', '')::bigint, 0)), 0) AS js_files,
                        MAX(scan_finished_at) AS last_scan_finished
                      FROM latest_snapshots
                    )
                    SELECT
                      (SELECT COUNT(*) FROM domains d WHERE d.active = TRUE) AS total_domains,
                      st.live_hosts,
                      (SELECT COUNT(*) FROM subdomains s WHERE s.first_seen > NOW() - INTERVAL '24 hours')
                        + (SELECT COUNT(*) FROM live_hosts lh WHERE lh.first_seen > NOW() - INTERVAL '24 hours')
                        + (SELECT COUNT(*) FROM endpoints e WHERE e.first_seen > NOW() - INTERVAL '24 hours') AS new_assets,
                      (SELECT COUNT(*) FROM network_services ns WHERE ns.state = 'open') AS open_ports,
                      st.js_files,
                      (
                        SELECT COUNT(*)
                        FROM api_surfaces aps
                        WHERE aps.surface_type = 'graphql'
                          AND COALESCE(aps.metadata->>'confidence', 'candidate') IN ('confirmed', 'probable')
                      ) AS graphql_endpoints,
                      (
                        SELECT COUNT(*)
                        FROM live_hosts lh
                        WHERE (lh.url ~* '(login|signin|sso|oauth|auth|account|admin)' OR COALESCE(lh.title, '') ~* '(login|sign in|admin|dashboard|portal)')
                          AND COALESCE(lh.status_code, 0) IN (200, 301, 302, 401, 403)
                      ) AS login_panels,
                      (SELECT COUNT(*) FROM cloud_assets ca) AS cloud_assets,
                      (
                        SELECT COUNT(*)
                        FROM findings f
                        WHERE f.is_resolved = FALSE
                          AND f.severity IN ('critical', 'high')
                          AND f.finding_type NOT IN (
                            'api_surface_discovered', 'host_fingerprint_changed',
                            'interesting_bruteforce_hit', 'interesting_exposed_path',
                            'interesting_open_port', 'js_asset_changed',
                            'js_dom_xss_candidate', 'js_dom_xss_sinks',
                            'js_secret_like_strings', 'js_sensitive_admin_surface',
                            'risky_url_parameter'
                          )
                          AND f.finding_type NOT ILIKE '%metrics%'
                      ) AS critical_findings,
                      (SELECT COUNT(*) FROM bug_jobs bj WHERE bj.status = 'queued') AS attack_playbooks,
                      (
                        SELECT COUNT(*) FROM (
                          SELECT 1
                          FROM findings f
                          WHERE f.finding_type = 'host_fingerprint_changed'
                            AND f.last_seen > NOW() - INTERVAL '7 days'
                          LIMIT 100000
                        ) recent_changes
                      ) AS recently_changed_assets,
                      (
                        SELECT COUNT(*)
                        FROM domains d
                        WHERE d.active = TRUE
                          AND (d.last_scan IS NULL OR d.last_scan < NOW() - make_interval(hours => d.scan_interval_hours))
                      ) AS scans_due,
                      st.last_scan_finished
                    FROM snapshot_totals st
                    """
                )
                return dict(row)
            row = await conn.fetchrow(
                """
                WITH latest_snapshot AS MATERIALIZED (
                  SELECT ss.totals, ss.new_counts, ss.scan_finished_at
                  FROM scan_snapshots ss
                  WHERE ss.domain_id = $1 AND ss.scan_finished_at IS NOT NULL
                  ORDER BY ss.scan_finished_at DESC
                  LIMIT 1
                )
                SELECT
                  (SELECT COUNT(*) FROM domains d WHERE d.active = TRUE AND d.id = $1) AS total_domains,
                  COALESCE(NULLIF(ls.totals->>'live_hosts', '')::bigint, 0) AS live_hosts,
                  COALESCE(NULLIF(ls.new_counts->>'new_subdomains', '')::bigint, 0)
                    + COALESCE(NULLIF(ls.new_counts->>'new_live_hosts', '')::bigint, 0)
                    + COALESCE(NULLIF(ls.new_counts->>'new_urls', '')::bigint, 0)
                    + COALESCE(NULLIF(ls.new_counts->>'new_js_assets', '')::bigint, 0) AS new_assets,
                  (SELECT COUNT(*) FROM network_services ns WHERE ns.state = 'open' AND ns.domain_id = $1) AS open_ports,
                  COALESCE(NULLIF(ls.totals->>'js_assets', '')::bigint, 0) AS js_files,
                  (
                    SELECT COUNT(*)
                    FROM api_surfaces aps
                    WHERE aps.surface_type = 'graphql'
                      AND COALESCE(aps.metadata->>'confidence', 'candidate') IN ('confirmed', 'probable')
                      AND aps.domain_id = $1
                  ) AS graphql_endpoints,
                  (
                    SELECT COUNT(*)
                    FROM live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id
                    WHERE s.domain_id = $1
                      AND (lh.url ~* '(login|signin|sso|oauth|auth|account|admin)' OR COALESCE(lh.title, '') ~* '(login|sign in|admin|dashboard|portal)')
                      AND COALESCE(lh.status_code, 0) IN (200, 301, 302, 401, 403)
                  ) AS login_panels,
                  (SELECT COUNT(*) FROM cloud_assets ca WHERE ca.domain_id = $1) AS cloud_assets,
                  (
                    SELECT COUNT(*)
                    FROM findings f
                    WHERE f.domain_id = $1
                      AND f.is_resolved = FALSE
                      AND f.severity IN ('critical', 'high')
                      AND f.finding_type NOT IN (
                        'api_surface_discovered', 'host_fingerprint_changed',
                        'interesting_bruteforce_hit', 'interesting_exposed_path',
                        'interesting_open_port', 'js_asset_changed',
                        'js_dom_xss_candidate', 'js_dom_xss_sinks',
                        'js_secret_like_strings', 'js_sensitive_admin_surface',
                        'risky_url_parameter'
                      )
                      AND f.finding_type NOT ILIKE '%metrics%'
                  ) AS critical_findings,
                  (SELECT COUNT(*) FROM bug_jobs bj WHERE bj.domain_id = $1 AND bj.status = 'queued') AS attack_playbooks,
                  (
                    SELECT COUNT(*) FROM (
                      SELECT 1 FROM findings f
                      WHERE f.domain_id = $1
                        AND f.finding_type = 'host_fingerprint_changed'
                        AND f.last_seen > NOW() - INTERVAL '7 days'
                      LIMIT 100000
                    ) recent_changes
                  ) AS recently_changed_assets,
                  (SELECT COUNT(*) FROM domains d WHERE d.active = TRUE AND d.id = $1 AND (d.last_scan IS NULL OR d.last_scan < NOW() - make_interval(hours => d.scan_interval_hours))) AS scans_due,
                  ls.scan_finished_at AS last_scan_finished
                FROM (SELECT 1) seed
                LEFT JOIN latest_snapshot ls ON TRUE
                """,
                domain_id,
            )
            return dict(row)

    def _endpoint_clauses(self, domain_id: int | None, filters: dict[str, str]) -> tuple[list[str], list[Any]]:
        clauses = ["($1::int IS NULL OR d.id = $1)"]
        values: list[Any] = [domain_id]
        if filters.get("subdomain"):
            values.append(filters["subdomain"])
            clauses.append(f"s.subdomain = ${len(values)}")
        if filters.get("live_host"):
            values.append(filters["live_host"])
            clauses.append(f"lh.url = ${len(values)}")
        if filters.get("source"):
            values.append(filters["source"])
            clauses.append(f"e.source = ${len(values)}")
        if filters.get("status_code"):
            try:
                values.append(int(filters["status_code"]))
                clauses.append(f"e.status_code = ${len(values)}")
            except ValueError:
                pass
        if filters.get("has_parameters"):
            lowered = filters["has_parameters"].lower()
            if lowered in {"1", "true", "yes", "on"}:
                clauses.append("jsonb_typeof(e.parameters) = 'array' AND jsonb_array_length(e.parameters) > 0")
            elif lowered in {"0", "false", "no", "off"}:
                clauses.append("(jsonb_typeof(e.parameters) != 'array' OR jsonb_array_length(e.parameters) = 0)")
        if filters.get("tech"):
            tech_value = filters["tech"]
            values.append(tech_value if "%" in tech_value else f"%{tech_value}%")
            clauses.append(
                f"""(
                  EXISTS (SELECT 1 FROM technologies t WHERE t.live_host_id = lh.id AND t.technology ILIKE ${len(values)})
                  OR (lh.url || e.path) ILIKE ${len(values)}
                )"""
            )
        if filters.get("contains"):
            values.append(f"%{filters['contains']}%")
            clauses.append(
                f"""(
                  (lh.url || e.path) ILIKE ${len(values)}
                  OR e.path ILIKE ${len(values)}
                  OR e.source ILIKE ${len(values)}
                  OR e.parameters::text ILIKE ${len(values)}
                  OR e.risk_tags::text ILIKE ${len(values)}
                  OR COALESCE(lh.title, '') ILIKE ${len(values)}
                  OR COALESCE(lh.webserver, '') ILIKE ${len(values)}
                )"""
            )
        if filters.get("response_size_gt"):
            try:
                values.append(int(filters["response_size_gt"]))
                clauses.append(f"COALESCE(lh.content_length, 0) > ${len(values)}")
            except ValueError:
                pass
        return clauses, values

    async def get_endpoint_export_page(
        self,
        domain_id: int | None,
        filters: dict[str, str] | None = None,
        page_size: int = 2000,
        before_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch one bounded endpoint-export page using a keyset cursor.

        The dashboard table query is intentionally rich for interactive pages,
        but using it with ``LIMIT NULL`` caused CSV downloads to materialize
        million-row domains in a Gunicorn worker. Keep exports bounded and
        resumable instead of changing the database or global worker timeout.
        """
        assert self.pool is not None
        filters = filters or {}
        clauses, values = self._endpoint_clauses(domain_id, filters)
        domain_clause = "($1::int IS NULL OR d.id = $1)"
        if before_id is not None:
            values.append(before_id)
            clauses.append(f"e.id > ${len(values)}")
        page_clauses = [clause for clause in clauses if clause != domain_clause]
        values.append(max(100, min(int(page_size), 5000)) + 1)
        limit_placeholder = f"${len(values)}"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                f"""
                WITH host_scope AS MATERIALIZED (
                  SELECT lh.id AS live_host_id, d.domain, s.subdomain,
                         lh.url AS base_url, lh.content_length AS response_size,
                         COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies
                  FROM live_hosts lh
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  JOIN domains d ON d.id = s.domain_id
                  LEFT JOIN LATERAL (
                    SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                    FROM technologies t
                    WHERE t.live_host_id = lh.id
                  ) tech ON TRUE
                  WHERE {domain_clause}
                ), page AS MATERIALIZED (
                  SELECT e.id AS endpoint_id, hs.domain, hs.subdomain, hs.base_url,
                         e.path, (hs.base_url || e.path) AS full_url,
                         e.status_code, e.probed_at, e.source, e.risk_tags,
                         e.parameters, hs.response_size, hs.technologies,
                         e.first_seen, e.last_seen
                  FROM endpoints e
                  JOIN host_scope hs ON hs.live_host_id = e.live_host_id
                  JOIN live_hosts lh ON lh.id = e.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  JOIN domains d ON d.id = s.domain_id
                  WHERE {" AND ".join(page_clauses) if page_clauses else "TRUE"}
                  ORDER BY e.id ASC
                  LIMIT {limit_placeholder}
                )
                SELECT page.domain, page.subdomain, page.base_url, page.path,
                       page.full_url, page.status_code, page.probed_at, page.source,
                       js_refs.js_references,
                       COALESCE(js_refs.js_reference_count, 0) AS js_reference_count,
                       page.risk_tags, page.parameters, page.response_size,
                       page.technologies, page.first_seen, page.last_seen,
                       page.endpoint_id
                FROM page
                LEFT JOIN LATERAL (
                  SELECT
                    (
                      SELECT ARRAY_AGG(refs.asset_url ORDER BY refs.asset_url)
                      FROM (
                        SELECT DISTINCT ja.asset_url
                        FROM endpoint_js_references ejr
                        JOIN js_assets ja ON ja.id = ejr.js_asset_id
                        WHERE ejr.endpoint_id = page.endpoint_id
                        ORDER BY ja.asset_url
                        LIMIT 3
                      ) refs
                    ) AS js_references,
                    (
                      SELECT COUNT(DISTINCT ejr.js_asset_id)::int
                      FROM endpoint_js_references ejr
                      WHERE ejr.endpoint_id = page.endpoint_id
                    ) AS js_reference_count
                ) js_refs ON TRUE
                ORDER BY page.endpoint_id ASC
                """,
                *values,
            )
        return [dict(row) for row in rows]

    def _js_asset_clauses(self, domain_id: int | None, filters: dict[str, str]) -> tuple[list[str], list[Any]]:
        clauses = ["($1::int IS NULL OR d.id = $1)"]
        values: list[Any] = [domain_id]
        if filters.get("subdomain"):
            values.append(filters["subdomain"])
            clauses.append(f"s.subdomain = ${len(values)}")
        if filters.get("live_host"):
            values.append(filters["live_host"])
            clauses.append(f"lh.url = ${len(values)}")
        if filters.get("source"):
            values.append(filters["source"])
            clauses.append(f"ja.source = ${len(values)}")
        if filters.get("status_code"):
            try:
                values.append(int(filters["status_code"]))
                clauses.append(f"ja.http_status = ${len(values)}")
            except ValueError:
                pass
        js_response = filters.get("js_response", "").strip().lower()
        if js_response == "200":
            clauses.append("ja.http_status = 200")
        elif js_response == "2xx":
            clauses.append("ja.http_status BETWEEN 200 AND 299")
        elif js_response == "3xx":
            clauses.append("ja.http_status BETWEEN 300 AND 399")
        elif js_response == "4xx":
            clauses.append("ja.http_status BETWEEN 400 AND 499")
        elif js_response == "5xx":
            clauses.append("ja.http_status BETWEEN 500 AND 599")
        elif js_response == "unknown":
            clauses.append("ja.http_status IS NULL")
        if filters.get("contains"):
            values.append(f"%{filters['contains']}%")
            clauses.append(
                f"""(
                  d.domain ILIKE ${len(values)}
                  OR s.subdomain ILIKE ${len(values)}
                  OR lh.url ILIKE ${len(values)}
                  OR ja.asset_url ILIKE ${len(values)}
                  OR ja.source ILIKE ${len(values)}
                  OR COALESCE(ja.sha256, '') ILIKE ${len(values)}
                )"""
            )
        return clauses, values

    def _table_filter_clauses(self, name: str, filters: dict[str, str], values: list[Any]) -> list[str]:
        clauses: list[str] = []
        contains = filters.get("contains")
        if name == "subdomains":
            if contains:
                values.append(f"%{contains}%")
                clauses.append(f"(d.domain ILIKE ${len(values)} OR s.subdomain ILIKE ${len(values)} OR s.ip_addresses::text ILIKE ${len(values)})")
            return clauses
        if name == "live_hosts":
            if filters.get("status_code"):
                try:
                    values.append(int(filters["status_code"]))
                    clauses.append(f"lh.status_code = ${len(values)}")
                except ValueError:
                    pass
            if filters.get("response_size_gt"):
                try:
                    values.append(int(filters["response_size_gt"]))
                    clauses.append(f"COALESCE(lh.content_length, 0) > ${len(values)}")
                except ValueError:
                    pass
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      d.domain ILIKE ${len(values)}
                      OR s.subdomain ILIKE ${len(values)}
                      OR lh.url ILIKE ${len(values)}
                      OR COALESCE(lh.title, '') ILIKE ${len(values)}
                      OR COALESCE(lh.webserver, '') ILIKE ${len(values)}
                    )"""
                )
            return clauses
        if name == "infrastructure":
            if filters.get("status_code"):
                try:
                    values.append(int(filters["status_code"]))
                    clauses.append(f"ns.port = ${len(values)}")
                except ValueError:
                    pass
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      d.domain ILIKE ${len(values)}
                      OR host(ii.ip_address) ILIKE ${len(values)}
                      OR COALESCE(ii.ptr_name, '') ILIKE ${len(values)}
                      OR COALESCE(ii.asn, '') ILIKE ${len(values)}
                      OR COALESCE(ii.asn_org, '') ILIKE ${len(values)}
                      OR COALESCE(ii.provider, '') ILIKE ${len(values)}
                      OR COALESCE(ii.classification, '') ILIKE ${len(values)}
                      OR COALESCE(ns.port::text, '') ILIKE ${len(values)}
                      OR COALESCE(ns.service, '') ILIKE ${len(values)}
                      OR COALESCE(ns.product, '') ILIKE ${len(values)}
                      OR COALESCE(ns.metadata->'shodan'->'cves', '[]'::jsonb)::text ILIKE ${len(values)}
                      OR CASE WHEN ns.metadata ? 'shodan' THEN 'shodan' ELSE 'active' END ILIKE ${len(values)}
                    )"""
                )
            return clauses
        if name == "parameters":
            if filters.get("status_code"):
                try:
                    values.append(int(filters["status_code"]))
                    clauses.append(f"e.status_code = ${len(values)}")
                except ValueError:
                    pass
            if filters.get("source"):
                values.append(filters["source"])
                clauses.append(f"e.source = ${len(values)}")
            if filters.get("tech"):
                tech_value = filters["tech"]
                values.append(tech_value if "%" in tech_value else f"%{tech_value}%")
                clauses.append(
                    f"""(
                      EXISTS (SELECT 1 FROM technologies t WHERE t.live_host_id = lh.id AND t.technology ILIKE ${len(values)})
                      OR (lh.url || e.path) ILIKE ${len(values)}
                    )"""
                )
            if filters.get("response_size_gt"):
                try:
                    values.append(int(filters["response_size_gt"]))
                    clauses.append(f"COALESCE(lh.content_length, 0) > ${len(values)}")
                except ValueError:
                    pass
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      d.domain ILIKE ${len(values)}
                      OR lh.url ILIKE ${len(values)}
                      OR e.path ILIKE ${len(values)}
                      OR up.param_name ILIKE ${len(values)}
                      OR COALESCE(up.example_value, '') ILIKE ${len(values)}
                      OR up.risk_tags::text ILIKE ${len(values)}
                    )"""
                )
            return clauses
        if name == "findings":
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      COALESCE(d.domain, '') ILIKE ${len(values)}
                      OR f.finding_type ILIKE ${len(values)}
                      OR f.severity ILIKE ${len(values)}
                      OR f.location ILIKE ${len(values)}
                      OR f.details::text ILIKE ${len(values)}
                    )"""
                )
            return clauses
        if name == "credential_leaks":
            if filters.get("verified"):
                lowered = filters["verified"].strip().lower()
                if lowered in {"1", "true", "yes", "on", "verified"}:
                    clauses.append("cl.verified IS TRUE")
                elif lowered in {"0", "false", "no", "off", "unknown", "unverified"}:
                    clauses.append("cl.verified IS FALSE")
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      COALESCE(d.domain, '') ILIKE ${len(values)}
                      OR cl.detector_name ILIKE ${len(values)}
                      OR COALESCE(cl.decoder_name, '') ILIKE ${len(values)}
                      OR cl.source_url ILIKE ${len(values)}
                      OR COALESCE(cl.source_file, '') ILIKE ${len(values)}
                      OR COALESCE(cl.redacted_secret, '') ILIKE ${len(values)}
                      OR cl.result::text ILIKE ${len(values)}
                    )"""
                )
            return clauses
        if name == "screenshots":
            if contains:
                values.append(f"%{contains}%")
                clauses.append(
                    f"""(
                      d.domain ILIKE ${len(values)}
                      OR lh.url ILIKE ${len(values)}
                      OR sc.screenshot_path ILIKE ${len(values)}
                      OR sc.capture_reason ILIKE ${len(values)}
                    )"""
                )
            if filters.get("response_size_gt"):
                try:
                    values.append(int(filters["response_size_gt"]))
                    clauses.append(f"COALESCE(sc.file_size, 0) > ${len(values)}")
                except ValueError:
                    pass
            return clauses
        return clauses

    async def _get_findings_page(
        self,
        conn: asyncpg.Connection,
        domain_id: int | None,
        limit: int,
        offset: int,
        sort: str,
        direction_sql: str,
        filters: dict[str, str],
    ) -> dict[str, Any]:
        """Return a signal-oriented findings view without mutating raw findings."""
        view = normalize_finding_view(filters.get("finding_view"))
        values: list[Any] = [domain_id]
        clauses = ["($1::int IS NULL OR f.domain_id = $1)"]

        resolution = str(filters.get("resolution") or "active").strip().lower()
        if resolution == "resolved":
            clauses.append("f.is_resolved IS TRUE")
        elif resolution != "all":
            clauses.append("f.is_resolved IS FALSE")

        severity = str(filters.get("severity") or "").strip().lower()
        if severity in {"critical", "high", "medium", "low", "info"}:
            values.append(severity)
            clauses.append(f"f.severity = ${len(values)}")

        finding_type = str(filters.get("finding_type") or "").strip()
        if finding_type:
            values.append(f"%{finding_type}%")
            clauses.append(f"f.finding_type ILIKE ${len(values)}")

        recent_days = str(filters.get("recent_days") or "").strip()
        if recent_days:
            try:
                days = max(1, min(int(recent_days), 3650))
            except ValueError:
                days = 0
            if days:
                values.append(days)
                clauses.append(f"f.last_seen >= NOW() - (${len(values)}::int * INTERVAL '1 day')")

        contains = str(filters.get("contains") or "").strip()
        if contains:
            values.append(f"%{contains}%")
            clauses.append(
                f"""(
                  COALESCE(d.domain, '') ILIKE ${len(values)}
                  OR f.finding_type ILIKE ${len(values)}
                  OR f.severity ILIKE ${len(values)}
                  OR f.location ILIKE ${len(values)}
                  OR f.details::text ILIKE ${len(values)}
                )"""
            )

        common_where = " AND ".join(clauses)
        severity_rank = "CASE LOWER(f.severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        raw_total = await conn.fetchval(
            "SELECT COUNT(*) FROM findings WHERE ($1::int IS NULL OR domain_id = $1)",
            domain_id,
        )

        if view == "raw":
            raw_sort = {
                "domain": "d.domain",
                "severity": severity_rank,
                "type": "f.finding_type",
                "finding_type": "f.finding_type",
                "location": "f.location",
                "first_seen": "f.first_seen",
                "last_seen": "f.last_seen",
            }.get(sort, "f.last_seen")
            rows_raw = await conn.fetch(
                f"""
                SELECT f.id AS finding_id, d.domain, f.finding_type,
                       f.finding_type AS signal_family, 'raw signal'::text AS signal_class,
                       f.severity, f.location, f.details, 1::bigint AS duplicate_count,
                       ARRAY[f.finding_type]::text[] AS related_types,
                       NULL::text AS validation_status, NULL::text AS analyst_status,
                       f.first_seen, f.last_seen, f.is_resolved
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE {common_where}
                ORDER BY {raw_sort} {direction_sql} NULLS LAST
                LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                """,
                *values,
                limit + 1,
                offset,
            )
            has_more = len(rows_raw) > limit
            rows = rows_raw[:limit]
            total_is_lower_bound = False
            try:
                async with conn.transaction():
                    await conn.execute("SET LOCAL statement_timeout = '5000ms'")
                    total = await conn.fetchval(
                        f"""
                        SELECT COUNT(*)
                        FROM findings f
                        LEFT JOIN domains d ON d.id = f.domain_id
                        WHERE {common_where}
                        """,
                        *values,
                    )
            except (asyncpg.QueryCanceledError, asyncio.TimeoutError):
                total = offset + len(rows) + (1 if has_more else 0)
                total_is_lower_bound = has_more
            return {
                "rows": [dict(row) for row in rows],
                "total": int(total or 0),
                "total_is_lower_bound": total_is_lower_bound,
                "raw_total": int(raw_total or 0),
                "limit": limit,
                "offset": offset,
                "view": view,
            }

        noise_types_sql = ", ".join("'" + value.replace("'", "''") + "'" for value in sorted(RISK_NOISE_FINDING_TYPES))
        review_types_sql = ", ".join("'" + value.replace("'", "''") + "'" for value in sorted(FINDING_REVIEW_TYPES))
        family_cases = " ".join(
            f"WHEN '{finding_type}' THEN '{family}'"
            for finding_type, family in sorted(FINDING_GROUP_FAMILIES.items())
        )
        scanner_condition = f"""(
          f.severity IN ('critical', 'high', 'medium')
          AND f.finding_type NOT IN ({noise_types_sql})
          AND f.finding_type NOT ILIKE '%metrics%'
        )"""
        scanner_selects = f"""
          SELECT f.id, FALSE AS is_promoted, FALSE AS is_validated
          FROM findings f
          LEFT JOIN domains d ON d.id = f.domain_id
          WHERE {common_where} AND {scanner_condition}
        """
        if view == "leads":
            scanner_selects += f"""
              UNION ALL
              SELECT f.id, FALSE AS is_promoted, FALSE AS is_validated
              FROM findings f
              LEFT JOIN domains d ON d.id = f.domain_id
              WHERE {common_where} AND f.finding_type IN ({review_types_sql})
            """

        selected_ids = f"""
          {scanner_selects}
          UNION ALL
          SELECT f.id, TRUE AS is_promoted, FALSE AS is_validated
          FROM analyst_annotations aa
          JOIN findings f
            ON aa.entity_type = 'finding'
           AND aa.entity_id = f.id
          LEFT JOIN domains d ON d.id = f.domain_id
          WHERE {common_where}
            AND (aa.bookmarked IS TRUE OR aa.status IN ('interesting', 'reviewing', 'reported', 'confirmed', 'validated') OR aa.severity_override IS NOT NULL)
          UNION ALL
          SELECT f.id, FALSE AS is_promoted, TRUE AS is_validated
          FROM validation_queue v
          JOIN findings f ON v.finding_id = f.id
          LEFT JOIN domains d ON d.id = f.domain_id
          WHERE {common_where} AND v.status IN ('confirmed', 'validated')
        """
        canonical_location = """COALESCE(
          NULLIF(LOWER(RTRIM(SPLIT_PART(SPLIT_PART(f.location, '?', 1), '#', 1), '/')), ''),
          LOWER(f.location)
        )"""
        grouped_sort = {
            "domain": "g.domain",
            "severity": "g.severity_rank",
            "type": "g.signal_family",
            "finding_type": "g.signal_family",
            "signal_class": "g.signal_class_rank",
            "location": "g.canonical_location",
            "duplicate_count": "g.duplicate_count",
            "first_seen": "g.first_seen",
            "last_seen": "g.last_seen",
        }.get(sort, "g.last_seen")
        rows_raw = await conn.fetch(
            f"""
            WITH candidate_sources AS MATERIALIZED (
              {selected_ids}
            ), selected_ids AS MATERIALIZED (
              SELECT id, BOOL_OR(is_promoted) AS is_promoted, BOOL_OR(is_validated) AS is_validated
              FROM candidate_sources
              GROUP BY id
            ), candidates AS MATERIALIZED (
              SELECT f.id AS finding_id, f.domain_id, d.domain, f.finding_type,
                     CASE f.finding_type {family_cases} ELSE f.finding_type END AS signal_family,
                     {canonical_location} AS canonical_location,
                     {severity_rank} AS severity_rank,
                     selected.is_validated, selected.is_promoted,
                     f.first_seen, f.last_seen
              FROM selected_ids selected
              JOIN findings f ON f.id = selected.id
              LEFT JOIN domains d ON d.id = f.domain_id
            ), grouped AS MATERIALIZED (
              SELECT domain_id, domain, signal_family, canonical_location,
                     COUNT(*)::bigint AS duplicate_count,
                     ARRAY_AGG(DISTINCT finding_type ORDER BY finding_type) AS related_types,
                     MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen,
                     BOOL_OR(is_validated) AS is_validated,
                     BOOL_OR(is_promoted) AS is_promoted,
                     MIN(severity_rank) AS severity_rank,
                     CASE WHEN BOOL_OR(is_validated) THEN 1 WHEN BOOL_OR(is_promoted) THEN 2 ELSE 3 END AS signal_class_rank,
                     (ARRAY_AGG(finding_id ORDER BY is_validated DESC, is_promoted DESC, severity_rank ASC, last_seen DESC, finding_id DESC))[1] AS representative_id
              FROM candidates
              GROUP BY domain_id, domain, signal_family, canonical_location
            )
            SELECT f.id AS finding_id, g.domain, f.finding_type, g.signal_family,
                   CASE WHEN g.is_validated THEN 'validated'
                        WHEN g.is_promoted THEN 'analyst promoted'
                        WHEN g.signal_family IN ({review_types_sql.replace("'js_dom_xss_candidate'", "'js_dom_xss_review'")}) THEN 'review lead'
                        ELSE 'high signal' END AS signal_class,
                   f.severity, f.location, f.details, g.duplicate_count, g.related_types,
                   validation.status AS validation_status, annotation.status AS analyst_status,
                   g.first_seen, g.last_seen, f.is_resolved,
                   COUNT(*) OVER()::bigint AS total_count
            FROM grouped g
            JOIN findings f ON f.id = g.representative_id
            LEFT JOIN LATERAL (
              SELECT v.status
              FROM validation_queue v
              WHERE v.finding_id = f.id
              ORDER BY v.updated_at DESC
              LIMIT 1
            ) validation ON TRUE
            LEFT JOIN LATERAL (
              SELECT aa.status
              FROM analyst_annotations aa
              WHERE aa.entity_type = 'finding'
                AND aa.entity_id = f.id
              ORDER BY aa.updated_at DESC
              LIMIT 1
            ) annotation ON TRUE
            ORDER BY {grouped_sort} {direction_sql} NULLS LAST
            LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
            """,
            *values,
            limit + 1,
            offset,
        )
        has_more = len(rows_raw) > limit
        rows = []
        total = 0
        for record in rows_raw[:limit]:
            row = dict(record)
            total = int(row.pop("total_count") or 0)
            rows.append(row)
        return {
            "rows": rows,
            "total": total,
            "total_is_lower_bound": False,
            "raw_total": int(raw_total or 0),
            "limit": limit,
            "offset": offset,
            "view": view,
        }

    async def get_table_page(
        self,
        name: str,
        domain_id: int | None = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "last_seen",
        direction: str = "desc",
        filters: dict[str, str] | None = None,
    ) -> dict:
        assert self.pool is not None
        filters = filters or {}
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        direction_sql = "ASC" if direction.lower() == "asc" else "DESC"
        async with self.pool.acquire() as conn:
            if name == "findings":
                return await self._get_findings_page(
                    conn, domain_id, limit, offset, sort, direction_sql, filters
                )
            if name == "urls":
                clauses, values = self._endpoint_clauses(domain_id, filters)
                sort_map = {
                    "domain": "d.domain",
                    "subdomain": "s.subdomain",
                    "full_url": "(lh.url || e.path)",
                    "url": "(lh.url || e.path)",
                    "status": "e.status_code",
                    "status_code": "e.status_code",
                    "source": "e.source",
                    "response_size": "lh.content_length",
                    "first_seen": "e.first_seen",
                    "last_seen": "e.last_seen",
                }
                outer_sort_map = {
                    "domain": "page.domain",
                    "subdomain": "page.subdomain",
                    "full_url": "page.full_url",
                    "url": "page.full_url",
                    "status": "page.status_code",
                    "status_code": "page.status_code",
                    "source": "page.source",
                    "response_size": "page.response_size",
                    "first_seen": "page.first_seen",
                    "last_seen": "page.last_seen",
                }
                order = sort_map.get(sort, "e.last_seen")
                outer_order = outer_sort_map.get(sort, "page.last_seen")
                fetch_limit = limit + 1
                if domain_id is not None and not filters and sort == "last_seen":
                    # A domain can own more than a million endpoint rows. Walking
                    # the global last_seen index until enough rows happen to match
                    # that domain makes the first page depend on unrelated data.
                    # A host outside the top N host heads cannot contribute to
                    # the top N endpoints: N other hosts already precede it.
                    # This keeps the per-host prefix scan bounded on domains
                    # with thousands of live hosts.
                    per_host_limit = offset + fetch_limit
                    rows_raw = await conn.fetch(
                        f"""
                        WITH host_scope AS MATERIALIZED (
                          SELECT lh.id AS live_host_id,
                                 d.domain,
                                 s.subdomain,
                                 lh.url AS base_url,
                                 lh.content_length AS response_size
                          FROM subdomains s
                          JOIN domains d ON d.id = s.domain_id
                          JOIN live_hosts lh ON lh.subdomain_id = s.id
                          WHERE s.domain_id = $1
                        ),
                        host_heads AS MATERIALIZED (
                          SELECT hs.*
                          FROM host_scope hs
                          CROSS JOIN LATERAL (
                            SELECT e.last_seen, e.id
                            FROM endpoints e
                            WHERE e.live_host_id = hs.live_host_id
                              AND e.last_seen IS NOT NULL
                            ORDER BY e.last_seen {direction_sql}, e.id DESC
                            LIMIT 1
                          ) head
                          ORDER BY head.last_seen {direction_sql}, head.id DESC
                          LIMIT $2
                        ),
                        candidates AS MATERIALIZED (
                          SELECT e.id AS endpoint_id,
                                 hs.domain,
                                 hs.subdomain,
                                 hs.base_url,
                                 e.path,
                                 (hs.base_url || e.path) AS full_url,
                                 e.status_code,
                                 e.probed_at,
                                 e.source,
                                 e.risk_tags,
                                 e.parameters,
                                 hs.response_size,
                                 e.first_seen,
                                 e.last_seen,
                                 hs.live_host_id
                          FROM host_heads hs
                          CROSS JOIN LATERAL (
                            SELECT e.*
                            FROM endpoints e
                            WHERE e.live_host_id = hs.live_host_id
                              AND e.last_seen IS NOT NULL
                            ORDER BY e.last_seen {direction_sql}, e.id DESC
                            LIMIT $2
                          ) e
                        ),
                        page AS MATERIALIZED (
                          SELECT *
                          FROM candidates
                          ORDER BY last_seen {direction_sql}, endpoint_id DESC
                          LIMIT $3 OFFSET $4
                        )
                        SELECT page.endpoint_id,
                               page.domain,
                               page.subdomain,
                               page.base_url,
                               page.path,
                               page.full_url,
                               page.status_code,
                               page.probed_at,
                               page.source,
                               js_refs.js_references,
                               COALESCE(js_refs.js_reference_count, 0) AS js_reference_count,
                               page.risk_tags,
                               page.parameters,
                               page.response_size,
                               COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies,
                               page.first_seen,
                               page.last_seen
                        FROM page
                        LEFT JOIN LATERAL (
                          SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                          FROM technologies t
                          WHERE t.live_host_id = page.live_host_id
                        ) tech ON TRUE
                        LEFT JOIN LATERAL (
                          SELECT
                            (
                              SELECT ARRAY_AGG(refs.asset_url ORDER BY refs.asset_url)
                              FROM (
                                SELECT DISTINCT ja.asset_url
                                FROM endpoint_js_references ejr
                                JOIN js_assets ja ON ja.id = ejr.js_asset_id
                                WHERE ejr.endpoint_id = page.endpoint_id
                                ORDER BY ja.asset_url
                                LIMIT 3
                              ) refs
                            ) AS js_references,
                            (
                              SELECT COUNT(DISTINCT ejr.js_asset_id)::int
                              FROM endpoint_js_references ejr
                              WHERE ejr.endpoint_id = page.endpoint_id
                            ) AS js_reference_count
                        ) js_refs ON TRUE
                        ORDER BY page.last_seen {direction_sql}, page.endpoint_id DESC
                        """,
                        domain_id,
                        per_host_limit,
                        fetch_limit,
                        offset,
                    )
                    has_more = len(rows_raw) > limit
                    rows = rows_raw[:limit]
                    total = await conn.fetchval(
                        """
                        SELECT COALESCE(NULLIF(totals->>'endpoints', '')::bigint, 0)
                        FROM scan_snapshots
                        WHERE domain_id = $1 AND scan_finished_at IS NOT NULL
                        ORDER BY scan_finished_at DESC
                        LIMIT 1
                        """,
                        domain_id,
                    )
                    if total is None:
                        total = offset + len(rows) + (1 if has_more else 0)
                    return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}
                rows_raw = await conn.fetch(
                    f"""
                    WITH page AS MATERIALIZED (
                      SELECT e.id AS endpoint_id,
                             d.domain,
                             s.subdomain,
                             lh.url AS base_url,
                             e.path,
                             (lh.url || e.path) AS full_url,
                             e.status_code,
                             e.probed_at,
                             e.source,
                             e.risk_tags,
                             e.parameters,
                             lh.content_length AS response_size,
                             e.first_seen,
                             e.last_seen,
                             e.live_host_id
                      FROM endpoints e
                      JOIN live_hosts lh ON lh.id = e.live_host_id
                      JOIN subdomains s ON s.id = lh.subdomain_id
                      JOIN domains d ON d.id = s.domain_id
                      WHERE {" AND ".join(clauses)}
                      ORDER BY {order} {direction_sql} NULLS LAST, e.id DESC
                      LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                    )
                    SELECT page.endpoint_id,
                           page.domain,
                           page.subdomain,
                           page.base_url,
                           page.path,
                           page.full_url,
                           page.status_code,
                           page.probed_at,
                           page.source,
                           js_refs.js_references,
                           COALESCE(js_refs.js_reference_count, 0) AS js_reference_count,
                           page.risk_tags,
                           page.parameters,
                           page.response_size,
                           COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies,
                           page.first_seen,
                           page.last_seen
                    FROM page
                    LEFT JOIN LATERAL (
                      SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                      FROM technologies t
                      WHERE t.live_host_id = page.live_host_id
                    ) tech ON TRUE
                    LEFT JOIN LATERAL (
                      SELECT
                        (
                          SELECT ARRAY_AGG(refs.asset_url ORDER BY refs.asset_url)
                          FROM (
                            SELECT DISTINCT ja.asset_url
                            FROM endpoint_js_references ejr
                            JOIN js_assets ja ON ja.id = ejr.js_asset_id
                            WHERE ejr.endpoint_id = page.endpoint_id
                            ORDER BY ja.asset_url
                            LIMIT 3
                          ) refs
                        ) AS js_references,
                        (
                          SELECT COUNT(DISTINCT ejr.js_asset_id)::int
                          FROM endpoint_js_references ejr
                          WHERE ejr.endpoint_id = page.endpoint_id
                        ) AS js_reference_count
                    ) js_refs ON TRUE
                    ORDER BY {outer_order} {direction_sql} NULLS LAST, page.endpoint_id DESC
                    """,
                    *values,
                    fetch_limit,
                    offset,
                )
                has_more = len(rows_raw) > limit
                rows = rows_raw[:limit]
                total = None
                if not filters and domain_id is None:
                    # The unfiltered endpoint tab can exceed a million rows. An
                    # exact count is expensive and does not change the visible
                    # page, so use Postgres' current row estimate for snappy UI
                    # pagination metadata.
                    total = await conn.fetchval("SELECT COALESCE(reltuples::bigint, 0) FROM pg_class WHERE oid = 'endpoints'::regclass")
                elif not filters:
                    total = await conn.fetchval(
                        """
                        SELECT COALESCE(NULLIF(totals->>'endpoints', '')::bigint, 0)
                        FROM scan_snapshots
                        WHERE domain_id = $1 AND scan_finished_at IS NOT NULL
                        ORDER BY scan_finished_at DESC
                        LIMIT 1
                        """,
                        domain_id,
                    )
                else:
                    try:
                        async with conn.transaction():
                            await conn.execute("SET LOCAL statement_timeout = '2500ms'")
                            total = await conn.fetchval(
                                f"""
                                SELECT COUNT(*)
                                FROM endpoints e
                                JOIN live_hosts lh ON lh.id = e.live_host_id
                                JOIN subdomains s ON s.id = lh.subdomain_id
                                JOIN domains d ON d.id = s.domain_id
                                WHERE {" AND ".join(clauses)}
                                """,
                                *values,
                            )
                    except (asyncpg.QueryCanceledError, asyncio.TimeoutError):
                        total = None
                if total is None:
                    total = offset + len(rows) + (1 if has_more else 0)
                return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

            if name == "js":
                clauses, values = self._js_asset_clauses(domain_id, filters)
                sort_map = {
                    "domain": "d.domain",
                    "asset_url": "ja.asset_url",
                    "status": "ja.http_status",
                    "http_status": "ja.http_status",
                    "size": "ja.size_bytes",
                    "size_bytes": "ja.size_bytes",
                    "source": "ja.source",
                    "first_seen": "ja.first_seen",
                    "last_seen": "ja.last_seen",
                }
                order = sort_map.get(sort, "ja.last_seen")
                rows_raw = await conn.fetch(
                    f"""
                    SELECT ja.id AS js_asset_id, d.domain, lh.url AS host_url, ja.asset_url, ja.source, ja.http_status, ja.size_bytes, ja.sha256, ja.first_seen, ja.last_seen
                    FROM js_assets ja
                    JOIN live_hosts lh ON lh.id = ja.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    JOIN domains d ON d.id = s.domain_id
                    WHERE {" AND ".join(clauses)}
                    ORDER BY {order} {direction_sql} NULLS LAST
                    LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                    """,
                    *values,
                    limit + 1,
                    offset,
                )
                has_more = len(rows_raw) > limit
                rows = rows_raw[:limit]
                if not filters and domain_id is None:
                    total = await conn.fetchval("SELECT COALESCE(reltuples::bigint, 0) FROM pg_class WHERE oid = 'js_assets'::regclass")
                elif not filters:
                    total = await conn.fetchval(
                        """
                        SELECT COALESCE(NULLIF(totals->>'js_assets', '')::bigint, 0)
                        FROM scan_snapshots
                        WHERE domain_id = $1 AND scan_finished_at IS NOT NULL
                        ORDER BY scan_finished_at DESC
                        LIMIT 1
                        """,
                        domain_id,
                    )
                else:
                    total = None
                if total is None:
                    try:
                        async with conn.transaction():
                            await conn.execute("SET LOCAL statement_timeout = '2500ms'")
                            total = await conn.fetchval(
                                f"""
                                SELECT COUNT(*)
                                FROM js_assets ja
                                JOIN live_hosts lh ON lh.id = ja.live_host_id
                                JOIN subdomains s ON s.id = lh.subdomain_id
                                JOIN domains d ON d.id = s.domain_id
                                WHERE {" AND ".join(clauses)}
                                """,
                                *values,
                            )
                    except (asyncpg.QueryCanceledError, asyncio.TimeoutError):
                        total = offset + len(rows) + (1 if has_more else 0)
                return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

            table_sql = {
                "subdomains": {
                    "from": "subdomains s JOIN domains d ON d.id = s.domain_id LEFT JOIN LATERAL (SELECT COUNT(*)::int AS live_host_count, ARRAY_AGG(lh.url ORDER BY lh.url) AS live_hosts FROM live_hosts lh WHERE lh.subdomain_id = s.id) lh_summary ON TRUE LEFT JOIN LATERAL (SELECT COUNT(*)::int AS ffuf_run_count, MAX(fr.started_at) AS last_ffuf_run FROM ffuf_runs fr JOIN live_hosts lh ON lh.id = fr.live_host_id WHERE lh.subdomain_id = s.id) ffuf_summary ON TRUE",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "s.id AS subdomain_id, d.domain, s.subdomain, s.is_resolved, s.ip_addresses, COALESCE(lh_summary.live_host_count, 0) AS live_host_count, COALESCE(lh_summary.live_hosts, ARRAY[]::text[]) AS live_hosts, COALESCE(ffuf_summary.ffuf_run_count, 0) AS ffuf_run_count, ffuf_summary.last_ffuf_run, s.first_seen, s.last_seen",
                    "sorts": {"domain": "d.domain", "subdomain": "s.subdomain", "is_resolved": "s.is_resolved", "live_host_count": "COALESCE(lh_summary.live_host_count, 0)", "ffuf_run_count": "COALESCE(ffuf_summary.ffuf_run_count, 0)", "last_ffuf_run": "ffuf_summary.last_ffuf_run", "first_seen": "s.first_seen", "last_seen": "s.last_seen"},
                    "default": "s.last_seen",
	                    "domain_column": "s.domain_id",
	                },
	                "live_hosts": {
	                    "from": "live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id LEFT JOIN LATERAL (SELECT COUNT(*)::int AS ffuf_run_count, MAX(fr.started_at) AS last_ffuf_run FROM ffuf_runs fr WHERE fr.live_host_id = lh.id) ffuf_summary ON TRUE",
	                    "where": "$1::int IS NULL OR d.id = $1",
	                    "select": "lh.id AS live_host_id, d.domain, s.subdomain, lh.url, lh.status_code, lh.title, lh.webserver, lh.content_length, COALESCE(ffuf_summary.ffuf_run_count, 0) AS ffuf_run_count, ffuf_summary.last_ffuf_run, lh.first_seen, lh.last_seen",
	                    "sorts": {"domain": "d.domain", "url": "lh.url", "status": "lh.status_code", "status_code": "lh.status_code", "title": "lh.title", "content_length": "lh.content_length", "ffuf_run_count": "COALESCE(ffuf_summary.ffuf_run_count, 0)", "last_ffuf_run": "ffuf_summary.last_ffuf_run", "first_seen": "lh.first_seen", "last_seen": "lh.last_seen"},
	                    "default": "lh.last_seen",
	                    "domain_column": "s.domain_id",
	                },
                "infrastructure": {
                    "from": "infrastructure_ips ii JOIN domains d ON d.id = ii.domain_id LEFT JOIN network_services ns ON ns.ip_asset_id = ii.id LEFT JOIN LATERAL (SELECT ARRAY_AGG(DISTINCT s.subdomain ORDER BY s.subdomain) AS subdomains FROM infrastructure_ip_subdomains iis JOIN subdomains s ON s.id = iis.subdomain_id WHERE iis.ip_asset_id = ii.id) host_summary ON TRUE",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "ns.id AS service_id, ii.id AS ip_asset_id, d.domain, host(ii.ip_address) AS ip_address, ii.ptr_name, ii.asn, ii.asn_org, ii.provider, ii.classification, ii.scan_eligible, COALESCE(host_summary.subdomains, ARRAY[]::text[]) AS subdomains, ns.port, ns.protocol, ns.state, CASE WHEN ns.metadata ? 'shodan' AND ns.state = 'passive_unverified' THEN 'Shodan' WHEN ns.metadata ? 'shodan' THEN 'Shodan + active' WHEN ns.id IS NOT NULL THEN 'Active' ELSE NULL END AS service_source, ns.service, ns.product, ns.version, COALESCE(ns.metadata->'shodan'->'cves', '[]'::jsonb) AS cves, ns.metadata->'shodan'->>'timestamp' AS shodan_last_seen, ii.metadata->'shodan'->>'last_update' AS shodan_host_updated, ns.first_seen, ns.last_seen, ns.last_scanned_at",
                    "sorts": {"domain": "d.domain", "ip_address": "ii.ip_address", "classification": "ii.classification", "port": "ns.port", "state": "ns.state", "service_source": "service_source", "service": "ns.service", "product": "ns.product", "shodan_last_seen": "shodan_last_seen", "first_seen": "ns.first_seen", "last_seen": "ns.last_seen", "last_scanned_at": "ns.last_scanned_at"},
                    "default": "COALESCE(ns.last_seen, ii.last_seen)",
	                    "domain_column": "ii.domain_id",
                },
                "parameters": {
                    "from": "url_parameters up JOIN endpoints e ON e.id = up.endpoint_id JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "d.domain, lh.url AS base_url, e.path, e.status_code, e.source, up.param_name, up.example_value, up.risk_tags, up.first_seen, up.last_seen",
                    "sorts": {"domain": "d.domain", "base_url": "lh.url", "path": "e.path", "status_code": "e.status_code", "source": "e.source", "param": "up.param_name", "param_name": "up.param_name", "first_seen": "up.first_seen", "last_seen": "up.last_seen"},
                    "default": "up.last_seen",
	                    "domain_column": "s.domain_id",
                },
                "findings": {
                    "from": "findings f LEFT JOIN domains d ON d.id = f.domain_id",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "d.domain, f.finding_type, f.severity, f.location, f.details, f.first_seen, f.last_seen, f.is_resolved",
                    "sorts": {"domain": "d.domain", "severity": "f.severity", "type": "f.finding_type", "finding_type": "f.finding_type", "location": "f.location", "first_seen": "f.first_seen", "last_seen": "f.last_seen"},
                    "default": "f.last_seen",
	                    "domain_column": "f.domain_id",
                },
                "credential_leaks": {
                    "from": "credential_leaks cl LEFT JOIN domains d ON d.id = cl.domain_id LEFT JOIN live_hosts lh ON lh.id = cl.live_host_id",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "cl.id AS leak_id, d.domain, lh.url AS host_url, cl.detector_name, cl.decoder_name, cl.verified, cl.redacted_secret, cl.source_url, cl.source_file, cl.line_number, cl.first_seen, cl.last_seen, cl.is_resolved",
                    "sorts": {"domain": "d.domain", "detector_name": "cl.detector_name", "verified": "cl.verified", "source_url": "cl.source_url", "source_file": "cl.source_file", "first_seen": "cl.first_seen", "last_seen": "cl.last_seen"},
                    "default": "cl.last_seen",
	                    "domain_column": "cl.domain_id",
                },
                "screenshots": {
                    "from": "screenshots sc JOIN live_hosts lh ON lh.id = sc.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id",
                    "where": "$1::int IS NULL OR d.id = $1",
                    "select": "d.domain, lh.url, sc.screenshot_path, sc.capture_reason, sc.file_size, sc.captured_at, sc.last_seen",
                    "sorts": {"domain": "d.domain", "url": "lh.url", "capture_reason": "sc.capture_reason", "file_size": "sc.file_size", "captured_at": "sc.captured_at", "last_seen": "sc.last_seen"},
                    "default": "sc.captured_at",
	                    "domain_column": "s.domain_id",
                },
            }
            spec = table_sql.get(name)
            if not spec:
                return {"rows": [], "total": 0, "limit": limit, "offset": offset}
            order = spec["sorts"].get(sort, spec["default"])
            values: list[Any] = [domain_id]
            domain_clause = f"{spec['domain_column']} = $1" if domain_id is not None else f"({spec['where']})"
            clauses = [domain_clause, *self._table_filter_clauses(name, filters, values)]
            nulls_sql = "NULLS LAST"
            if name == "findings" and sort == "last_seen":
                # The existing findings timeline index uses PostgreSQL's native
                # DESC null ordering. Current findings always have last_seen, so
                # exclude impossible nulls and let the index serve the first page.
                clauses.append("f.last_seen IS NOT NULL")
                nulls_sql = ""
            rows_raw = await conn.fetch(
                f"""
                SELECT {spec['select']}
                FROM {spec['from']}
                WHERE {" AND ".join(clauses)}
                ORDER BY {order} {direction_sql} {nulls_sql}
                LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                """,
                *values,
                limit + 1,
                offset,
            )
            has_more = len(rows_raw) > limit
            rows = rows_raw[:limit]
            estimate_tables = {
                "subdomains": "subdomains",
                "live_hosts": "live_hosts",
                "parameters": "url_parameters",
                "findings": "findings",
                "credential_leaks": "credential_leaks",
                "screenshots": "screenshots",
            }
            total = None
            if domain_id is None and not filters and name in estimate_tables:
                relation = estimate_tables[name]
                total = await conn.fetchval(
                    "SELECT COALESCE(reltuples::bigint, 0) FROM pg_class WHERE oid = $1::regclass",
                    relation,
                )
            elif domain_id is not None and not filters and name in {"subdomains", "live_hosts", "parameters", "findings", "screenshots"}:
                snapshot_key = {
                    "subdomains": "subdomains",
                    "live_hosts": "live_hosts",
                    "findings": "findings",
                    "screenshots": "screenshots",
                }.get(name)
                if snapshot_key:
                    total = await conn.fetchval(
                        """
                        SELECT COALESCE(NULLIF(totals->>$2, '')::bigint, 0)
                        FROM scan_snapshots
                        WHERE domain_id = $1 AND scan_finished_at IS NOT NULL
                        ORDER BY scan_finished_at DESC
                        LIMIT 1
                        """,
                        domain_id,
                        snapshot_key,
                    )
                else:
                    total = await conn.fetchval(
                        """
                        WITH latest AS (
                          SELECT COALESCE(NULLIF(totals->>'endpoints', '')::numeric, 0) AS endpoints
                          FROM scan_snapshots
                          WHERE domain_id = $1 AND scan_finished_at IS NOT NULL
                          ORDER BY scan_finished_at DESC
                          LIMIT 1
                        )
                        SELECT CASE
                          WHEN all_endpoints.reltuples <= 0 THEN 0
                          ELSE ROUND(all_parameters.reltuples * latest.endpoints / all_endpoints.reltuples)::bigint
                        END
                        FROM latest
                        CROSS JOIN pg_class all_parameters
                        CROSS JOIN pg_class all_endpoints
                        WHERE all_parameters.oid = 'url_parameters'::regclass
                          AND all_endpoints.oid = 'endpoints'::regclass
                        """,
                        domain_id,
                    )
            else:
                try:
                    async with conn.transaction():
                        await conn.execute("SET LOCAL statement_timeout = '2500ms'")
                        total = await conn.fetchval(
                            f"SELECT COUNT(*) FROM {spec['from']} WHERE {' AND '.join(clauses)}",
                            *values,
                        )
                except (asyncpg.QueryCanceledError, asyncio.TimeoutError):
                    total = None
            if total is None:
                total = offset + len(rows) + (1 if has_more else 0)
            else:
                total = max(int(total), offset + len(rows) + (1 if has_more else 0))
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_tab_filter_options(self, domain_id: int, tab: str) -> dict[str, list]:
        assert self.pool is not None
        result = {
            "subdomains": [],
            "live_hosts": [],
            "sources": [],
            "source_counts": [],
            "js_sources": [],
            "js_source_counts": [],
            "statuses": [],
            "status_counts": [],
            "endpoint_status_counts": [],
            "live_host_status_counts": [],
            "js_status_counts": [],
            "parameter_status_counts": [],
            "technologies": [],
        }
        async with self.pool.acquire() as conn:
            if tab in {"urls", "parameters"}:
                if tab == "urls":
                    option_rows = await conn.fetch(
                        """
                        SELECT e.source, e.status_code, COUNT(*)::int AS count
                        FROM endpoints e
                        JOIN live_hosts lh ON lh.id = e.live_host_id
                        JOIN subdomains s ON s.id = lh.subdomain_id
                        WHERE s.domain_id = $1
                        GROUP BY GROUPING SETS ((e.source), (e.status_code))
                        """,
                        domain_id,
                    )
                else:
                    option_rows = await conn.fetch(
                        """
                        SELECT e.source, e.status_code, COUNT(*)::int AS count
                        FROM url_parameters up
                        JOIN endpoints e ON e.id = up.endpoint_id
                        JOIN live_hosts lh ON lh.id = e.live_host_id
                        JOIN subdomains s ON s.id = lh.subdomain_id
                        WHERE s.domain_id = $1
                        GROUP BY GROUPING SETS ((e.source), (e.status_code))
                        """,
                        domain_id,
                    )
                source_rows = sorted(
                    (dict(row) for row in option_rows if row["source"] is not None),
                    key=lambda row: (-row["count"], row["source"]),
                )
                status_rows = sorted(
                    ({"status_code": row["status_code"], "count": row["count"]} for row in option_rows if row["source"] is None and row["status_code"] is not None),
                    key=lambda row: row["status_code"],
                )
                result["sources"] = [row["source"] for row in source_rows]
                result["source_counts"] = source_rows
                result["endpoint_status_counts" if tab == "urls" else "parameter_status_counts"] = status_rows
                technologies = await conn.fetch(
                    """
                    SELECT DISTINCT t.technology
                    FROM technologies t
                    JOIN live_hosts lh ON lh.id = t.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    WHERE s.domain_id = $1
                    ORDER BY t.technology
                    LIMIT 500
                    """,
                    domain_id,
                )
                result["technologies"] = [row["technology"] for row in technologies]
            elif tab == "live_hosts":
                statuses = await conn.fetch(
                    """
                    SELECT lh.status_code, COUNT(*)::int AS count
                    FROM live_hosts lh
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    WHERE lh.status_code IS NOT NULL AND s.domain_id = $1
                    GROUP BY lh.status_code
                    ORDER BY lh.status_code
                    """,
                    domain_id,
                )
                result["live_host_status_counts"] = [dict(row) for row in statuses]
            elif tab == "js":
                sources = await conn.fetch(
                    """
                    SELECT ja.source, COUNT(*)::int AS count
                    FROM js_assets ja
                    JOIN live_hosts lh ON lh.id = ja.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    WHERE s.domain_id = $1
                    GROUP BY ja.source
                    ORDER BY count DESC, ja.source
                    """,
                    domain_id,
                )
                result["js_sources"] = [row["source"] for row in sources]
                result["js_source_counts"] = [dict(row) for row in sources]
        return result

    async def get_endpoint_filter_options(self, domain_id: int | None = None) -> dict[str, list]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            subdomains = await conn.fetch(
                """
                SELECT DISTINCT s.subdomain
                FROM subdomains s
                WHERE $1::int IS NULL OR s.domain_id = $1
                ORDER BY s.subdomain
                LIMIT 500
                """,
                domain_id,
            )
            live_hosts = await conn.fetch(
                """
                SELECT DISTINCT lh.url
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE $1::int IS NULL OR s.domain_id = $1
                ORDER BY lh.url
                LIMIT 500
                """,
                domain_id,
            )
            sources = await conn.fetch(
                """
                SELECT e.source, COUNT(*)::int AS count
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE $1::int IS NULL OR s.domain_id = $1
                GROUP BY e.source
                ORDER BY count DESC, e.source
                """,
                domain_id,
            )
            js_sources = await conn.fetch(
                """
                SELECT ja.source, COUNT(*)::int AS count
                FROM js_assets ja
                JOIN live_hosts lh ON lh.id = ja.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE $1::int IS NULL OR s.domain_id = $1
                GROUP BY ja.source
                ORDER BY count DESC, ja.source
                """,
                domain_id,
            )
            statuses = await conn.fetch(
                """
                SELECT status_code, SUM(count)::int AS count
                FROM (
                  SELECT e.status_code, COUNT(*)::int AS count
                  FROM endpoints e
                  JOIN live_hosts lh ON lh.id = e.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE e.status_code IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                  GROUP BY e.status_code
                  UNION ALL
                  SELECT lh.status_code, COUNT(*)::int AS count
                  FROM live_hosts lh
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE lh.status_code IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                  GROUP BY lh.status_code
                  UNION ALL
                  SELECT ja.http_status AS status_code, COUNT(*)::int AS count
                  FROM js_assets ja
                  JOIN live_hosts lh ON lh.id = ja.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE ja.http_status IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                  GROUP BY ja.http_status
                ) status_counts
                GROUP BY status_code
                ORDER BY status_code
                """,
                domain_id,
            )
            endpoint_statuses = await conn.fetch(
                """
                SELECT e.status_code, COUNT(*)::int AS count
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE e.status_code IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                GROUP BY e.status_code
                ORDER BY e.status_code
                """,
                domain_id,
            )
            live_host_statuses = await conn.fetch(
                """
                SELECT lh.status_code, COUNT(*)::int AS count
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE lh.status_code IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                GROUP BY lh.status_code
                ORDER BY lh.status_code
                """,
                domain_id,
            )
            js_statuses = await conn.fetch(
                """
                SELECT ja.http_status AS status_code, COUNT(*)::int AS count
                FROM js_assets ja
                JOIN live_hosts lh ON lh.id = ja.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE ja.http_status IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                GROUP BY ja.http_status
                ORDER BY ja.http_status
                """,
                domain_id,
            )
            parameter_statuses = await conn.fetch(
                """
                SELECT e.status_code, COUNT(*)::int AS count
                FROM url_parameters up
                JOIN endpoints e ON e.id = up.endpoint_id
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE e.status_code IS NOT NULL AND ($1::int IS NULL OR s.domain_id = $1)
                GROUP BY e.status_code
                ORDER BY e.status_code
                """,
                domain_id,
            )
            technologies = await conn.fetch(
                """
                SELECT DISTINCT t.technology
                FROM technologies t
                JOIN live_hosts lh ON lh.id = t.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                WHERE $1::int IS NULL OR s.domain_id = $1
                ORDER BY t.technology
                LIMIT 500
                """,
                domain_id,
            )
        return {
            "subdomains": [row["subdomain"] for row in subdomains],
            "live_hosts": [row["url"] for row in live_hosts],
            "sources": [row["source"] for row in sources],
            "source_counts": [dict(row) for row in sources],
            "js_sources": [row["source"] for row in js_sources],
            "js_source_counts": [dict(row) for row in js_sources],
            "statuses": [row["status_code"] for row in statuses],
            "status_counts": [dict(row) for row in statuses],
            "endpoint_status_counts": [dict(row) for row in endpoint_statuses],
            "live_host_status_counts": [dict(row) for row in live_host_statuses],
            "js_status_counts": [dict(row) for row in js_statuses],
            "parameter_status_counts": [dict(row) for row in parameter_statuses],
            "technologies": [row["technology"] for row in technologies],
        }

    async def get_table(
        self,
        name: str,
        domain_id: int | None = None,
        limit: int | None = TABLE_LIMIT,
        filters: dict[str, str] | None = None,
    ) -> list[dict]:
        assert self.pool is not None
        filters = filters or {}
        if name == "findings" and filters:
            async with self.pool.acquire() as conn:
                page = await self._get_findings_page(
                    conn,
                    domain_id,
                    min(int(limit or 5000), 5000),
                    0,
                    "last_seen",
                    "DESC",
                    filters,
                )
                return page["rows"]
        if name == "urls":
            clauses = ["($1::int IS NULL OR d.id = $1)"]
            values: list[Any] = [domain_id]
            if filters.get("subdomain"):
                values.append(filters["subdomain"])
                clauses.append(f"s.subdomain = ${len(values)}")
            if filters.get("live_host"):
                values.append(filters["live_host"])
                clauses.append(f"lh.url = ${len(values)}")
            if filters.get("source"):
                values.append(filters["source"])
                clauses.append(f"e.source = ${len(values)}")
            if filters.get("status_code"):
                try:
                    values.append(int(filters["status_code"]))
                    clauses.append(f"e.status_code = ${len(values)}")
                except ValueError:
                    pass
            if filters.get("has_parameters"):
                lowered = filters["has_parameters"].lower()
                if lowered in {"1", "true", "yes", "on"}:
                    clauses.append("jsonb_array_length(e.parameters) > 0")
                elif lowered in {"0", "false", "no", "off"}:
                    clauses.append("jsonb_array_length(e.parameters) = 0")
            if filters.get("tech"):
                tech_value = filters["tech"]
                values.append(tech_value if "%" in tech_value else f"%{tech_value}%")
                clauses.append(
                    f"""
                    (
                    EXISTS (
                      SELECT 1
                      FROM technologies t
                      WHERE t.live_host_id = lh.id
                        AND t.technology ILIKE ${len(values)}
                    )
                    OR (lh.url || e.path) ILIKE ${len(values)}
                    )
                    """
                )
            if filters.get("contains"):
                values.append(f"%{filters['contains']}%")
                clauses.append(
                    f"""
                    (
                      (lh.url || e.path) ILIKE ${len(values)}
                      OR e.path ILIKE ${len(values)}
                      OR e.source ILIKE ${len(values)}
                      OR e.parameters::text ILIKE ${len(values)}
                      OR e.risk_tags::text ILIKE ${len(values)}
                      OR COALESCE(lh.title, '') ILIKE ${len(values)}
                      OR COALESCE(lh.webserver, '') ILIKE ${len(values)}
                    )
                    """
                )
            if filters.get("response_size_gt"):
                try:
                    values.append(int(filters["response_size_gt"]))
                    clauses.append(f"COALESCE(lh.content_length, 0) > ${len(values)}")
                except ValueError:
                    pass
            sql = f"""
                SELECT d.domain, s.subdomain, lh.url AS base_url, e.path, (lh.url || e.path) AS full_url,
                       e.status_code, e.probed_at, e.source, js_refs.js_references,
                       COALESCE(js_refs.js_reference_count, 0) AS js_reference_count,
                       e.risk_tags, e.parameters, lh.content_length AS response_size,
                       COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies, e.first_seen, e.last_seen
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                LEFT JOIN LATERAL (
                  SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                  FROM technologies t
                  WHERE t.live_host_id = lh.id
                ) tech ON TRUE
                LEFT JOIN LATERAL (
                  SELECT
                    (
                      SELECT ARRAY_AGG(refs.asset_url ORDER BY refs.asset_url)
                      FROM (
                        SELECT DISTINCT ja.asset_url
                        FROM endpoint_js_references ejr
                        JOIN js_assets ja ON ja.id = ejr.js_asset_id
                        WHERE ejr.endpoint_id = e.id
                        ORDER BY ja.asset_url
                        LIMIT 3
                      ) refs
                    ) AS js_references,
                    (
                      SELECT COUNT(DISTINCT ejr.js_asset_id)::int
                      FROM endpoint_js_references ejr
                      WHERE ejr.endpoint_id = e.id
                    ) AS js_reference_count
                ) js_refs ON TRUE
                WHERE {" AND ".join(clauses)}
                ORDER BY e.last_seen DESC
            """
            if limit is not None:
                sql += f"\nLIMIT {int(limit)}"
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(sql, *values)
                return [dict(row) for row in rows]

        if name == "js":
            clauses, values = self._js_asset_clauses(domain_id, filters)
            sql = f"""
                SELECT d.domain, lh.url AS host_url, ja.asset_url, ja.source, ja.http_status, ja.size_bytes, ja.sha256, ja.first_seen, ja.last_seen
                FROM js_assets ja
                JOIN live_hosts lh ON lh.id = ja.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE {" AND ".join(clauses)}
                ORDER BY ja.last_seen DESC
            """
            if limit is not None:
                sql += f"\nLIMIT {int(limit)}"
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(sql, *values)
                return [dict(row) for row in rows]

        queries = {
            "subdomains": """
                SELECT d.domain, s.subdomain, s.is_resolved, s.ip_addresses, s.first_seen, s.last_seen
                FROM subdomains s
                JOIN domains d ON d.id = s.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY s.last_seen DESC
            """,
            "live_hosts": """
                SELECT d.domain, s.subdomain, lh.url, lh.status_code, lh.title, lh.webserver, lh.content_length, lh.first_seen, lh.last_seen
                FROM live_hosts lh
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY lh.last_seen DESC
            """,
            "parameters": """
                SELECT d.domain, lh.url AS base_url, e.path, up.param_name, up.example_value, up.risk_tags, up.first_seen, up.last_seen
                FROM url_parameters up
                JOIN endpoints e ON e.id = up.endpoint_id
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY cardinality(up.risk_tags) DESC, up.last_seen DESC
            """,
            "findings": """
                SELECT d.domain, f.finding_type, f.severity, f.location, f.details, f.first_seen, f.last_seen, f.is_resolved
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY
                  CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  f.last_seen DESC
            """,
            "credential_leaks": """
                SELECT cl.id AS leak_id, d.domain, lh.url AS host_url, cl.detector_name, cl.decoder_name, cl.verified,
                       cl.redacted_secret, cl.source_url, cl.source_file, cl.line_number, cl.first_seen, cl.last_seen, cl.is_resolved
                FROM credential_leaks cl
                LEFT JOIN domains d ON d.id = cl.domain_id
                LEFT JOIN live_hosts lh ON lh.id = cl.live_host_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY cl.verified DESC, cl.last_seen DESC
            """,
            "screenshots": """
                SELECT d.domain, lh.url, sc.screenshot_path, sc.capture_reason, sc.file_size, sc.captured_at, sc.last_seen
                FROM screenshots sc
                JOIN live_hosts lh ON lh.id = sc.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY sc.captured_at DESC
            """,
            "snapshots": """
                SELECT d.domain, ss.scan_finished_at, ss.duration_seconds, ss.first_run, ss.totals, ss.new_counts
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY ss.scan_finished_at DESC
            """,
        }
        if name not in queries:
            return []
        sql = queries[name]
        if limit is not None:
            sql += f"\nLIMIT {int(limit)}"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, domain_id)
            return [dict(row) for row in rows]

    async def get_parameter_clusters(self, domain_id: int | None = None) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            if domain_id is None:
                rows = await conn.fetch(
                    """
                    SELECT param_name, risk_tags, occurrence_count, domain_count, domains, last_seen
                    FROM parameter_risk_clusters
                    ORDER BY occurrence_count DESC, domain_count DESC
                    LIMIT 50
                    """
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT
                      up.param_name,
                      ARRAY_REMOVE(ARRAY_AGG(DISTINCT tag), NULL) AS risk_tags,
                      COUNT(*) AS occurrence_count,
                      COUNT(DISTINCT d.id) AS domain_count,
                      ARRAY_AGG(DISTINCT d.domain) AS domains,
                      MAX(up.last_seen) AS last_seen
                    FROM url_parameters up
                    JOIN endpoints e ON e.id = up.endpoint_id
                    JOIN live_hosts lh ON lh.id = e.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    JOIN domains d ON d.id = s.domain_id
                    LEFT JOIN LATERAL UNNEST(up.risk_tags) AS tag ON TRUE
                    WHERE d.id = $1
                    GROUP BY up.param_name
                    ORDER BY COUNT(*) DESC
                    LIMIT 50
                    """,
                    domain_id,
                )
            return [dict(row) for row in rows]

    async def get_review_queue(self, view_name: str, limit: int = 50) -> list[dict]:
        assert self.pool is not None
        if view_name not in {"ai_review_endpoint_queue", "ai_review_js_queue", "ai_review_findings_queue", "ai_triage_queue"}:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(f"SELECT review_item FROM {view_name} LIMIT {int(limit)}")
            results = []
            for row in rows:
                item = normalize_json(row["review_item"])
                results.append(dict(item))
            return results

    async def get_ai_triage(self, domain_id: int | None = None, limit: int = 50) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            if domain_id is not None:
                rows = await conn.fetch(
                    """
                    WITH priority_order(priority, rank) AS (
                      VALUES ('critical'::text, 1), ('high'::text, 2),
                             ('medium'::text, 3), ('low'::text, 4), ('info'::text, 5)
                    )
                    SELECT item.id, d.domain, item.item_type, item.title,
                           item.location, item.priority, item.score, item.reasons,
                           item.recommended_actions, item.run_profiles, item.alert,
                           item.first_seen, item.last_seen
                    FROM priority_order po
                    CROSS JOIN LATERAL (
                      SELECT ati.*
                      FROM ai_triage_items ati
                      WHERE ati.domain_id = $1
                        AND ati.resolved = FALSE
                        AND ati.priority = po.priority
                      ORDER BY ati.score DESC, ati.last_seen DESC
                      LIMIT $2
                    ) item
                    LEFT JOIN domains d ON d.id = item.domain_id
                    ORDER BY po.rank, item.score DESC, item.last_seen DESC
                    LIMIT $2
                    """,
                    domain_id,
                    int(limit),
                )
                return [dict(row) for row in rows]
            rows = await conn.fetch(
                """
                SELECT
                  ati.id,
                  d.domain,
                  ati.item_type,
                  ati.title,
                  ati.location,
                  ati.priority,
                  ati.score,
                  ati.reasons,
                  ati.recommended_actions,
                  ati.run_profiles,
                  ati.alert,
                  ati.first_seen,
                  ati.last_seen
                FROM ai_triage_items ati
                LEFT JOIN domains d ON d.id = ati.domain_id
                WHERE ati.resolved = FALSE
                  AND ($1::int IS NULL OR ati.domain_id = $1)
                ORDER BY
                  CASE ati.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  ati.score DESC,
                  ati.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            return [dict(row) for row in rows]

    async def get_asset_events(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            where_sql = "ae.domain_id = $1" if domain_id is not None else "$1::int IS NULL"
            rows_raw = await conn.fetch(
                f"""
                SELECT ae.id, d.domain, ae.event_type, ae.entity_type, ae.entity_id, ae.location, ae.severity, ae.payload, ae.first_seen, ae.last_seen
                FROM asset_events ae
                LEFT JOIN domains d ON d.id = ae.domain_id
                WHERE {where_sql}
                ORDER BY ae.last_seen DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit + 1,
                offset,
            )
            has_more = len(rows_raw) > limit
            rows = rows_raw[:limit]
            if domain_id is None:
                total = await conn.fetchval("SELECT COALESCE(reltuples::bigint, 0) FROM pg_class WHERE oid = 'asset_events'::regclass")
                lower_bound = False
            else:
                total = offset + len(rows) + (1 if has_more else 0)
                lower_bound = has_more
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "total_is_lower_bound": lower_bound, "limit": limit, "offset": offset}

    async def get_risk_scores(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            finding_rows = await conn.fetch(
                """
                SELECT f.id, f.domain_id, d.domain, f.finding_type, f.severity,
                       f.location, f.details, f.last_seen,
                       validation.status AS validation_status,
                       validation.priority AS validation_priority
                FROM findings f
                JOIN domains d ON d.id = f.domain_id
                LEFT JOIN LATERAL (
                  SELECT v.status, v.priority
                  FROM validation_queue v
                  WHERE v.source_table = 'findings' AND v.source_id = f.id
                  ORDER BY v.updated_at DESC
                  LIMIT 1
                ) validation ON TRUE
                WHERE f.is_resolved = FALSE
                  AND f.severity IN ('critical', 'high', 'medium')
                  AND f.finding_type NOT IN (
                    'api_surface_discovered', 'host_fingerprint_changed',
                    'interesting_bruteforce_hit', 'interesting_exposed_path',
                    'interesting_open_port', 'js_asset_changed',
                    'js_dom_xss_candidate', 'js_dom_xss_sinks',
                    'js_secret_like_strings', 'js_sensitive_admin_surface',
                    'risky_url_parameter'
                  )
                  AND f.finding_type NOT ILIKE '%metrics%'
                  AND ($1::int IS NULL OR f.domain_id = $1)
                """,
                domain_id,
            )
            api_rows = await conn.fetch(
                """
                SELECT aps.id, aps.domain_id, d.domain, aps.surface_type,
                       aps.location, aps.status_code, aps.auth_required,
                       aps.methods, aps.operations_count, aps.risk_flags,
                       aps.metadata->>'confidence' AS confidence, aps.last_seen
                FROM api_surfaces aps
                JOIN domains d ON d.id = aps.domain_id
                WHERE aps.metadata->>'confidence' IN ('confirmed', 'probable')
                  AND ($1::int IS NULL OR aps.domain_id = $1)
                """,
                domain_id,
            )
            credential_rows = await conn.fetch(
                """
                SELECT cl.id, cl.domain_id, d.domain, cl.detector_name,
                       cl.detector_type, cl.source_url, cl.source_file,
                       cl.redacted_secret, cl.last_seen
                FROM credential_leaks cl
                JOIN domains d ON d.id = cl.domain_id
                WHERE cl.verified = TRUE AND cl.is_resolved = FALSE
                  AND ($1::int IS NULL OR cl.domain_id = $1)
                """,
                domain_id,
            )
            annotation_rows = await conn.fetch(
                """
                SELECT aa.id, aa.domain_id, d.domain, aa.entity_type,
                       aa.entity_id, aa.entity_key, aa.location,
                       aa.status, aa.severity_override, aa.tags, aa.bookmarked,
                       aa.notes, aa.updated_at
                FROM analyst_annotations aa
                LEFT JOIN domains d ON d.id = aa.domain_id
                WHERE (aa.bookmarked = TRUE OR aa.status IN ('interesting', 'reviewing', 'reported')
                       OR aa.severity_override IS NOT NULL)
                """
            )
            root_domain_rows = await conn.fetch("SELECT id, domain FROM domains WHERE active = TRUE")

        now = datetime.utcnow()
        candidates: list[dict[str, Any]] = []

        def freshness_penalty(last_seen: Any) -> int:
            if not isinstance(last_seen, datetime):
                return 10
            age_days = max(0, (now - last_seen).days)
            if age_days > 90:
                return 20
            if age_days > 30:
                return 10
            return 0

        for record in finding_rows:
            row = dict(record)
            location = canonical_risk_location(row.get("location"))
            if not location:
                continue
            details = normalize_json(row.get("details"))
            details = details if isinstance(details, dict) else {}
            severity = str(row.get("severity") or "medium").lower()
            validation_status = str(row.get("validation_status") or "unvalidated")
            score = {"critical": 82, "high": 70, "medium": 52}.get(severity, 35)
            score -= freshness_penalty(row.get("last_seen"))
            if validation_status in {"confirmed", "validated"}:
                score = max(score, 92)
            title = str(details.get("template_name") or row.get("finding_type") or "Scanner finding")
            candidates.append({
                "id": row["id"], "domain_id": row["domain_id"], "domain": row["domain"],
                "entity_type": "finding", "entity_id": row["id"], "entity_key": f"finding:{row['id']}",
                "location": location, "score": max(0, score), "priority": risk_priority(max(0, score)),
                "signal_type": row["finding_type"], "confidence": "validated" if score >= 90 else "scanner_candidate",
                "validation_status": validation_status,
                "reasons": [title, f"{severity} scanner severity", "Requires current manual validation"],
                "recommended_actions": ["Reproduce with a safe baseline and negative control", "Confirm current impact before reporting"],
                "run_profiles": ["validation"], "updated_at": row.get("last_seen"),
                "analyst_status": None, "analyst_tags": [], "bookmarked": False,
                "severity_override": None, "notes": None,
            })

        for record in api_rows:
            row = dict(record)
            location = canonical_risk_location(row.get("location"))
            if not location:
                continue
            confidence = str(row.get("confidence") or "probable")
            score = 48 if confidence == "confirmed" else 42
            if int(row.get("operations_count") or 0) > 0:
                score += 5
            risk_flags = list(row.get("risk_flags") or [])
            score += min(8, len(risk_flags) * 2)
            score -= freshness_penalty(row.get("last_seen"))
            reasons = [f"{confidence} {row['surface_type']} surface"]
            if row.get("status_code") is not None:
                reasons.append(f"HTTP {row['status_code']}")
            if row.get("auth_required") is False:
                reasons.append("Protocol reachable without authentication")
            if risk_flags:
                reasons.append("Signals: " + ", ".join(str(item) for item in risk_flags[:4]))
            candidates.append({
                "id": row["id"], "domain_id": row["domain_id"], "domain": row["domain"],
                "entity_type": "api_surface", "entity_id": row["id"], "entity_key": f"api_surface:{row['id']}",
                "location": location, "score": max(0, score), "priority": risk_priority(max(0, score)),
                "signal_type": row["surface_type"], "confidence": confidence,
                "validation_status": "surface_confirmed" if confidence == "confirmed" else "needs_validation",
                "reasons": reasons,
                "recommended_actions": ["Review operation, object, and field authorization", "Do not treat endpoint presence as a vulnerability"],
                "run_profiles": ["api"], "updated_at": row.get("last_seen"),
                "analyst_status": None, "analyst_tags": [], "bookmarked": False,
                "severity_override": None, "notes": None,
            })

        for record in credential_rows:
            row = dict(record)
            location = canonical_risk_location(row.get("source_url") or row.get("source_file"))
            if not location:
                continue
            candidates.append({
                "id": row["id"], "domain_id": row["domain_id"], "domain": row["domain"],
                "entity_type": "credential_leak", "entity_id": row["id"], "entity_key": f"credential_leak:{row['id']}",
                "location": location, "score": 92, "priority": "critical",
                "signal_type": row.get("detector_name") or row.get("detector_type") or "verified_credential",
                "confidence": "verified", "validation_status": "verified",
                "reasons": ["Verified unresolved credential exposure", str(row.get("redacted_secret") or "secret redacted")],
                "recommended_actions": ["Review scope and impact without using the credential", "Rotate and purge exposed material"],
                "run_profiles": ["secrets"], "updated_at": row.get("last_seen"),
                "analyst_status": None, "analyst_tags": [], "bookmarked": False,
                "severity_override": None, "notes": None,
            })

        for record in annotation_rows:
            row = dict(record)
            if not row.get("domain_id") and row.get("location"):
                try:
                    hostname = (urlsplit(str(row["location"])).hostname or str(row["location"])).lower().rstrip(".")
                except ValueError:
                    hostname = str(row["location"]).lower().rstrip(".")
                matches = [
                    item for item in root_domain_rows
                    if hostname == str(item["domain"]).lower()
                    or hostname.endswith("." + str(item["domain"]).lower())
                ]
                if matches:
                    best = max(matches, key=lambda item: len(str(item["domain"])))
                    row["domain_id"] = best["id"]
                    row["domain"] = best["domain"]
            if domain_id is not None and row.get("domain_id") != domain_id:
                continue
            location = canonical_risk_location(row.get("location"))
            if not location:
                continue
            score = 68 if row.get("bookmarked") else 62
            override = str(row.get("severity_override") or "").lower()
            priority = override if override in RISK_PRIORITY_RANK else risk_priority(score)
            candidates.append({
                "id": row["id"], "domain_id": row.get("domain_id"), "domain": row.get("domain"),
                "entity_type": row.get("entity_type") or "annotation", "entity_id": row.get("entity_id"),
                "entity_key": row.get("entity_key"), "location": location,
                "score": score, "priority": priority, "signal_type": "analyst_selected",
                "confidence": "analyst_selected", "validation_status": row.get("status") or "interesting",
                "reasons": ["Manually selected by analyst"],
                "recommended_actions": ["Review saved notes and perform the recorded decisive test"],
                "run_profiles": ["manual_review"], "updated_at": row.get("updated_at"),
                "analyst_status": row.get("status"), "analyst_tags": list(row.get("tags") or []),
                "bookmarked": bool(row.get("bookmarked")), "severity_override": row.get("severity_override"),
                "notes": row.get("notes"),
            })

        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in candidates:
            location_identity = re.sub(r"(?i)^https?://", "", str(row["location"])).lower().rstrip("/")
            key = (str(row.get("domain") or "").lower(), location_identity)
            grouped.setdefault(key, []).append(row)

        deduped: list[dict[str, Any]] = []
        for rows in grouped.values():
            rows.sort(
                key=lambda item: (
                    RISK_PRIORITY_RANK.get(str(item.get("priority")), 0),
                    int(item.get("score") or 0),
                    item.get("updated_at") or datetime.min,
                ),
                reverse=True,
            )
            winner = dict(rows[0])
            winner["duplicate_count"] = len(rows)
            winner["signal_type"] = sorted({str(item.get("signal_type")) for item in rows if item.get("signal_type")})
            winner["reasons"] = list(dict.fromkeys(
                str(reason) for item in rows for reason in (item.get("reasons") or []) if reason
            ))[:8]
            winner["recommended_actions"] = list(dict.fromkeys(
                str(action) for item in rows for action in (item.get("recommended_actions") or []) if action
            ))[:6]
            winner["run_profiles"] = sorted({
                str(profile) for item in rows for profile in (item.get("run_profiles") or []) if profile
            })
            winner["source_records"] = len(rows)
            deduped.append(winner)

        deduped.sort(
            key=lambda row: (
                RISK_PRIORITY_RANK.get(str(row.get("severity_override") or row.get("priority")), 0),
                int(row.get("score") or 0),
                row.get("updated_at") or datetime.min,
            ),
            reverse=True,
        )
        return {
            "rows": deduped[offset:offset + limit],
            "total": len(deduped),
            "total_is_lower_bound": False,
            "limit": limit,
            "offset": offset,
            "selection": "validated, confirmed-surface, analyst-selected, and non-noise scanner candidates",
        }

    async def get_bookmarks(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM analyst_annotations WHERE bookmarked = TRUE AND ($1::int IS NULL OR domain_id = $1)",
                domain_id,
            )
            rows = await conn.fetch(
                """
		                SELECT
	                  aa.id,
	                  d.domain,
	                  aa.entity_type,
	                  aa.entity_id,
		                  COALESCE(
		                    NULLIF(aa.location, ''),
		                    CASE aa.entity_type
		                      WHEN 'live_host' THEN (SELECT lh.url FROM live_hosts lh WHERE lh.id = aa.entity_id)
		                      WHEN 'endpoint' THEN (SELECT lh.url || e.path FROM endpoints e JOIN live_hosts lh ON lh.id = e.live_host_id WHERE e.id = aa.entity_id)
		                      WHEN 'subdomain' THEN (SELECT sd.subdomain FROM subdomains sd WHERE sd.id = aa.entity_id)
		                      WHEN 'js_asset' THEN (SELECT ja.asset_url FROM js_assets ja WHERE ja.id = aa.entity_id)
		                      WHEN 'finding' THEN (SELECT f.location FROM findings f WHERE f.id = aa.entity_id)
		                    END,
		                    CASE
		                      WHEN aa.entity_id IS NOT NULL THEN '[unresolved ' || aa.entity_type || ' #' || aa.entity_id::text || ']'
		                      ELSE '[unresolved saved bookmark]'
		                    END
		                  ) AS location,
	                  COALESCE(aa.severity_override, CASE WHEN aa.entity_type = 'finding' THEN (SELECT f.severity FROM findings f WHERE f.id = aa.entity_id) END) AS priority,
	                  NULL::int AS score,
                  aa.status,
                  aa.tags,
                  aa.notes,
                  aa.assigned_to,
                  aa.updated_at
                FROM analyst_annotations aa
                LEFT JOIN domains d ON d.id = aa.domain_id
                WHERE aa.bookmarked = TRUE
                  AND (CASE WHEN $1::int IS NULL THEN TRUE ELSE aa.domain_id = $1 END)
                ORDER BY aa.updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_cloud_assets(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM cloud_assets WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT ca.id, d.domain, ca.provider, ca.asset_type, ca.identifier, ca.location, ca.source, ca.metadata, ca.first_seen, ca.last_seen
                FROM cloud_assets ca
                LEFT JOIN domains d ON d.id = ca.domain_id
                WHERE $1::int IS NULL OR ca.domain_id = $1
                ORDER BY ca.last_seen DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_api_surfaces(
        self,
        domain_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
        confidence: str | None = None,
    ) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        confidence = confidence if confidence in {"confirmed", "probable", "candidate", "rejected"} else None
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM api_surfaces
                WHERE ($1::int IS NULL OR domain_id = $1)
                  AND ($2::text IS NULL OR metadata->>'confidence' = $2)
                """,
                domain_id,
                confidence,
            )
            rows = await conn.fetch(
                """
                SELECT aps.id, d.domain, lh.url AS host_url, aps.surface_type, aps.location, aps.source, aps.status_code,
                       aps.auth_required, aps.schema_url, aps.methods, aps.operations_count, aps.risk_flags, aps.metadata,
                       aps.metadata->>'confidence' AS confidence,
                       aps.first_seen, aps.last_seen
                FROM api_surfaces aps
                LEFT JOIN domains d ON d.id = aps.domain_id
                LEFT JOIN live_hosts lh ON lh.id = aps.live_host_id
                WHERE ($1::int IS NULL OR aps.domain_id = $1)
                  AND ($2::text IS NULL OR aps.metadata->>'confidence' = $2)
                ORDER BY
                  CASE COALESCE(aps.metadata->>'confidence', 'candidate')
                    WHEN 'confirmed' THEN 1
                    WHEN 'probable' THEN 2
                    WHEN 'candidate' THEN 3
                    ELSE 4
                  END,
                  cardinality(aps.risk_flags) DESC,
                  aps.operations_count DESC,
                  aps.last_seen DESC
                LIMIT $3 OFFSET $4
                """,
                domain_id,
                confidence,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_evidence_packs(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            if domain_id is not None:
                rows_raw = await conn.fetch(
                    """
                    WITH severity_order(severity, rank) AS (
                      VALUES ('critical'::text, 1), ('high'::text, 2),
                             ('medium'::text, 3), ('low'::text, 4), ('info'::text, 5)
                    )
                    SELECT ep.id, d.domain, ep.source_table, ep.source_id,
                           ep.title, ep.location, ep.severity, ep.summary,
                           ep.artifacts, ep.updated_at
                    FROM severity_order so
                    CROSS JOIN LATERAL (
                      SELECT item.*
                      FROM evidence_packs item
                      WHERE item.domain_id = $1 AND item.severity = so.severity
                      ORDER BY item.updated_at DESC
                      LIMIT $2
                    ) ep
                    LEFT JOIN domains d ON d.id = ep.domain_id
                    ORDER BY so.rank, ep.updated_at DESC
                    LIMIT $2 OFFSET $3
                    """,
                    domain_id,
                    offset + limit + 1,
                    offset,
                )
                has_more = len(rows_raw) > limit
                rows = rows_raw[:limit]
                total = offset + len(rows) + (1 if has_more else 0)
                return {"rows": [dict(row) for row in rows], "total": total, "total_is_lower_bound": has_more, "limit": limit, "offset": offset}
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM evidence_packs WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT ep.id, d.domain, ep.source_table, ep.source_id, ep.title, ep.location, ep.severity, ep.summary, ep.request, ep.response, ep.artifacts, ep.raw, ep.updated_at
                FROM evidence_packs ep
                LEFT JOIN domains d ON d.id = ep.domain_id
                WHERE $1::int IS NULL OR ep.domain_id = $1
                ORDER BY
                  CASE ep.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  ep.updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_validation_queue(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM validation_queue WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT vq.id, d.domain, vq.finding_id, vq.evidence_pack_id, vq.source_table, vq.source_id, vq.status, vq.priority, vq.location, vq.validation_steps, vq.notes, vq.updated_at
                FROM validation_queue vq
                LEFT JOIN domains d ON d.id = vq.domain_id
                WHERE $1::int IS NULL OR vq.domain_id = $1
                ORDER BY
                  CASE vq.status WHEN 'needs_validation' THEN 1 WHEN 'validating' THEN 2 WHEN 'validated' THEN 3 WHEN 'false_positive' THEN 4 ELSE 5 END,
                  CASE vq.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  vq.updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_research_evidence_feed(self, domain_id: int | None = None, limit: int = 100) -> dict[str, Any]:
        """Return recent evidence metadata without loading large request/response bodies."""
        assert self.pool is not None
        limit = max(20, min(int(limit), 150))
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT ep.id, ep.domain_id, d.domain, ep.source_table, ep.source_id,
                       ep.title, ep.location, ep.severity, ep.summary, ep.artifacts,
                       (ep.request IS NOT NULL) AS has_request,
                       (ep.response IS NOT NULL) AS has_response,
                       (ep.raw IS NOT NULL) AS has_raw_evidence,
                       ep.updated_at
                FROM evidence_packs ep
                LEFT JOIN domains d ON d.id = ep.domain_id
                WHERE $1::int IS NULL OR ep.domain_id = $1
                ORDER BY ep.id DESC
                LIMIT $2
                """,
                domain_id,
                limit,
            )
        return {"rows": [dict(row) for row in rows], "total": len(rows), "limit": limit}

    async def get_research_validation_feed(self, domain_id: int | None = None, limit: int = 100) -> dict[str, Any]:
        """Return recent validation work without an expensive full-table count."""
        assert self.pool is not None
        limit = max(20, min(int(limit), 150))
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT vq.id, vq.domain_id, d.domain, vq.finding_id,
                       vq.evidence_pack_id, vq.source_table, vq.source_id,
                       vq.status, vq.priority, vq.location, vq.validation_steps,
                       vq.notes, vq.updated_at
                FROM validation_queue vq
                LEFT JOIN domains d ON d.id = vq.domain_id
                WHERE $1::int IS NULL OR vq.domain_id = $1
                ORDER BY vq.id DESC
                LIMIT $2
                """,
                domain_id,
                limit,
            )
        return {"rows": [dict(row) for row in rows], "total": len(rows), "limit": limit}

    async def get_attack_playbooks(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            if domain_id is not None:
                rows_raw = await conn.fetch(
                    """
                    WITH status_order(status, status_rank) AS (
                      VALUES ('queued'::text, 1), ('testing'::text, 2),
                             ('validated'::text, 3), ('dismissed'::text, 4)
                    ), priority_order(priority, priority_rank) AS (
                      VALUES ('critical'::text, 1), ('high'::text, 2),
                             ('medium'::text, 3), ('low'::text, 4), ('info'::text, 5)
                    )
                    SELECT ap.id, d.domain, ap.status, ap.priority, ap.confidence,
                           ap.check_type, ap.owasp_category, ap.target_url,
                           ap.reasons, ap.validation_steps, ap.stop_conditions,
                           ap.safety_notes, ap.source_table, ap.source_id, ap.updated_at
                    FROM status_order so
                    CROSS JOIN priority_order po
                    CROSS JOIN LATERAL (
                      SELECT item.*
                      FROM attack_playbooks item
                      WHERE item.domain_id = $1
                        AND item.status = so.status
                        AND item.priority = po.priority
                      ORDER BY item.updated_at DESC
                      LIMIT $2
                    ) ap
                    LEFT JOIN domains d ON d.id = ap.domain_id
                    ORDER BY so.status_rank, po.priority_rank, ap.updated_at DESC
                    LIMIT $2 OFFSET $3
                    """,
                    domain_id,
                    offset + limit + 1,
                    offset,
                )
                has_more = len(rows_raw) > limit
                rows = rows_raw[:limit]
                total = offset + len(rows) + (1 if has_more else 0)
                return {"rows": [dict(row) for row in rows], "total": total, "total_is_lower_bound": has_more, "limit": limit, "offset": offset}
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM attack_playbooks WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT
                  ap.id,
                  d.domain,
                  ap.status,
                  ap.priority,
                  ap.confidence,
                  ap.check_type,
                  ap.owasp_category,
                  ap.target_url,
                  ap.reasons,
                  ap.validation_steps,
                  ap.stop_conditions,
                  ap.safety_notes,
                  ap.source_table,
                  ap.source_id,
                  ap.updated_at
                FROM attack_playbooks ap
                LEFT JOIN domains d ON d.id = ap.domain_id
                WHERE $1::int IS NULL OR ap.domain_id = $1
                ORDER BY
                  CASE ap.status WHEN 'queued' THEN 1 WHEN 'testing' THEN 2 WHEN 'validated' THEN 3 WHEN 'dismissed' THEN 4 ELSE 5 END,
                  CASE ap.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  ap.updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_bug_jobs(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        min_visible_priority = int(self.config.get("scan", {}).get("bug_jobs_dashboard_min_priority", 85) or 85)
        fetch_limit = 2500
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  bj.id,
                  d.domain,
                  bj.status,
                  bj.priority,
                  bj.scope_ok,
                  bj.asset_type,
                  bj.asset_value,
                  bj.job_type,
                  bj.hypothesis,
                  bj.finding_status,
                  bj.confidence,
                  bj.attempt_count,
                  bj.max_attempts,
                  bj.source_table,
                  bj.source_id,
                  bj.source_observed_at,
                  bj.prompt_path,
                  bj.codex_output_path,
                  bj.result_summary,
                  bj.error,
                  bj.created_at,
                  bj.started_at,
                  bj.finished_at,
                  bj.updated_at
                FROM bug_jobs bj
                LEFT JOIN domains d ON d.id = bj.domain_id
                WHERE ($1::int IS NULL OR bj.domain_id = $1)
                  AND bj.status IN ('queued', 'running', 'prepared', 'done', 'failed')
                  AND (bj.status <> 'queued' OR bj.priority >= $4::int)
                ORDER BY
                  CASE bj.status
                    WHEN 'running' THEN 0
                    WHEN 'queued' THEN 1
                    WHEN 'prepared' THEN 2
                    WHEN 'done' THEN 3
                    WHEN 'failed' THEN 4
                    ELSE 5
                  END,
                  bj.scope_ok DESC,
                  bj.priority DESC,
                  bj.updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                fetch_limit,
                offset,
                min_visible_priority,
            )
            page_rows = []
            seen_queued_assets: set[str] = set()
            for row in rows:
                item = dict(row)
                asset_type = str(item.get("asset_type") or "")
                key_asset_type = "endpoint" if asset_type in {"playbook", "finding"} else asset_type
                canonical_asset = canonical_bug_job_display_key(key_asset_type, str(item.get("asset_value") or ""))
                parsed_asset = urlsplit(canonical_asset)
                if parsed_asset.scheme and parsed_asset.netloc:
                    canonical_asset = urlunsplit((parsed_asset.scheme, parsed_asset.netloc, parsed_asset.path or "/", "", ""))
                dedupe_key = "|".join(
                    [
                        str(item.get("domain") or ""),
                        key_asset_type,
                        canonical_asset,
                    ]
                )
                if dedupe_key in seen_queued_assets:
                    continue
                seen_queued_assets.add(dedupe_key)
                page_rows.append(item)
                if len(page_rows) >= limit:
                    break
            return {"rows": page_rows, "total": offset + len(page_rows), "limit": limit, "offset": offset}

    async def get_codex_worker_overview(
        self,
        domain_id: int | None = None,
        limit: int = 80,
        status: str = "",
        outcome: str = "",
    ) -> dict[str, Any]:
        assert self.pool is not None
        limit = max(20, min(int(limit), 150))
        recent_days = max(1, min(int(self.config.get("scan", {}).get("bug_jobs_recent_window_days", 30) or 30), 365))
        artifact_ids = recent_codex_job_ids(self.config, limit=600)
        select_sql = """
            SELECT bj.id, bj.domain_id, d.domain, bj.target, bj.status, bj.priority,
                   bj.scope_ok, bj.asset_type, bj.asset_value, bj.job_type, bj.job_category,
                   bj.hypothesis, bj.finding_status, bj.confidence,
                   bj.outcome_class, bj.vulnerability_class,
                   bj.manual_review_priority, bj.alert_signals,
                   bj.attempt_count, bj.max_attempts, bj.source_table, bj.source_id,
                   bj.source_observed_at, bj.prompt_path, bj.codex_output_path,
                   bj.result_summary, bj.error, bj.codex_alerted_at,
                   bj.codex_alert_kind, bj.vpn_failover_attempted,
                   bj.vpn_failover_succeeded, bj.vpn_failover_reason,
                   bj.vpn_egress_before, bj.vpn_egress_after,
                   bj.vpn_retry_output_path, bj.vpn_failover_at,
                   bj.created_at, bj.started_at,
                   bj.finished_at, bj.updated_at,
                   EXTRACT(EPOCH FROM (COALESCE(bj.finished_at, NOW()) - bj.started_at))::int AS duration_seconds
            FROM bug_jobs bj
            LEFT JOIN domains d ON d.id = bj.domain_id
        """
        async with self.pool.acquire() as conn:
            summary = await conn.fetchrow(
                """
                SELECT COUNT(*)::int AS total,
                       COUNT(*) FILTER (WHERE status = 'queued')::int AS queued,
                       COUNT(*) FILTER (WHERE status = 'running')::int AS running,
                       COUNT(*) FILTER (WHERE status = 'prepared')::int AS prepared,
                       COUNT(*) FILTER (WHERE status = 'done')::int AS done,
                       COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
                       COUNT(*) FILTER (WHERE codex_alert_kind = 'confirmed')::int AS confirmed,
                       COUNT(*) FILTER (WHERE finding_status = 'possible')::int AS leads,
                       COUNT(*) FILTER (WHERE finding_status = 'none')::int AS no_finding,
                       COUNT(*) FILTER (WHERE codex_alert_kind = 'review')::int AS review_alerts,
                       COUNT(*) FILTER (WHERE vpn_failover_attempted)::int AS vpn_attempted,
                       COUNT(*) FILTER (WHERE vpn_failover_succeeded)::int AS vpn_succeeded
                FROM bug_jobs
                WHERE started_at >= NOW() - ($2::int * INTERVAL '1 day')
                  AND ($1::int IS NULL OR domain_id = $1)
                  AND status IN ('queued', 'running', 'prepared', 'done', 'failed')
                """,
                domain_id,
                recent_days,
            )
            rows: list[asyncpg.Record] = []
            roi_rows = await conn.fetch(
                """
                SELECT job_category,
                       COUNT(*) FILTER (WHERE status = 'done')::int AS completed,
                       COUNT(*) FILTER (
                         WHERE status = 'done' AND (
                           outcome_class = 'CONFIRMED_UNIQUE'
                           OR model_result_alert_eligible = TRUE
                         )
                       )::int AS credible,
                       COUNT(*) FILTER (
                         WHERE status = 'done' AND (
                           outcome_class = 'CONFIRMED_UNIQUE' OR finding_status = 'confirmed'
                         )
                       )::int AS confirmed,
                       COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
                       COALESCE(AVG(EXTRACT(EPOCH FROM (finished_at - started_at)))
                         FILTER (WHERE status = 'done' AND started_at IS NOT NULL), 0)::int AS avg_seconds
                FROM bug_jobs
                WHERE started_at >= NOW() - ($2::int * INTERVAL '1 day')
                  AND ($1::int IS NULL OR domain_id = $1)
                  AND job_category IS NOT NULL
                GROUP BY job_category
                ORDER BY job_category
                """,
                domain_id,
                recent_days,
            )
            job_type_roi_rows = await conn.fetch(
                """
                SELECT job_type, job_category,
                       COUNT(*) FILTER (WHERE status = 'done')::int AS completed,
                       COUNT(*) FILTER (
                         WHERE status = 'done' AND (
                           outcome_class = 'CONFIRMED_UNIQUE'
                           OR model_result_alert_eligible = TRUE
                         )
                       )::int AS credible,
                       COUNT(*) FILTER (WHERE status = 'done' AND outcome_class = 'CONFIRMED_UNIQUE')::int AS confirmed
                FROM bug_jobs
                WHERE updated_at >= NOW() - ($2::int * INTERVAL '1 day')
                  AND ($1::int IS NULL OR domain_id = $1)
                GROUP BY job_type, job_category
                HAVING COUNT(*) FILTER (WHERE status = 'done') > 0
                ORDER BY credible DESC, completed DESC
                LIMIT 20
                """,
                domain_id,
                recent_days,
            )
            focus_rows = await conn.fetch(
                """
                SELECT d.domain,
                       COUNT(*) FILTER (WHERE bj.status = 'done')::int AS completed,
                       COUNT(*) FILTER (
                         WHERE bj.status = 'done' AND (
                           bj.outcome_class = 'CONFIRMED_UNIQUE'
                           OR bj.model_result_alert_eligible = TRUE
                         )
                       )::int AS credible,
                       COUNT(*) FILTER (
                         WHERE bj.status = 'done' AND (
                           bj.outcome_class = 'CONFIRMED_UNIQUE' OR bj.finding_status = 'confirmed'
                         )
                       )::int AS confirmed,
                       COUNT(DISTINCT bj.job_type)::int AS families_tested
                FROM bug_jobs bj
                JOIN domains d ON d.id = bj.domain_id
                WHERE bj.started_at >= NOW() - ($1::int * INTERVAL '1 day')
                GROUP BY d.domain
                HAVING COUNT(*) FILTER (WHERE bj.status = 'done') > 0
                ORDER BY credible DESC, confirmed DESC, completed DESC
                LIMIT 10
                """,
                recent_days,
            )
            if artifact_ids and status not in {"queued", "running", "prepared", "failed"}:
                completed_clauses = ["bj.id = ANY($1::bigint[])", "($2::int IS NULL OR bj.domain_id = $2)"]
                completed_values: list[Any] = [artifact_ids, domain_id]
                if status == "done":
                    completed_clauses.append("bj.status = 'done'")
                if outcome == "leads":
                    completed_clauses.append("bj.finding_status IN ('possible', 'confirmed')")
                elif outcome == "confirmed":
                    completed_clauses.append("bj.finding_status = 'confirmed'")
                elif outcome == "none":
                    completed_clauses.append("bj.finding_status = 'none'")
                elif outcome == "review":
                    completed_clauses.append("bj.codex_alert_kind = 'review'")
                completed_values.append(limit)
                rows.extend(
                    await conn.fetch(
                        f"{select_sql} WHERE {' AND '.join(completed_clauses)} ORDER BY bj.updated_at DESC LIMIT $3",
                        *completed_values,
                    )
                )
            if not outcome and status != "done":
                active_statuses = [status] if status in {"queued", "running", "prepared", "failed"} else ["running", "queued", "prepared", "failed"]
                active_limit = min(limit, 40)
                rows.extend(
                    await conn.fetch(
                        f"""{select_sql}
                        WHERE bj.status = ANY($1::varchar[])
                          AND ($2::int IS NULL OR bj.domain_id = $2)
                        ORDER BY CASE bj.status WHEN 'running' THEN 0 WHEN 'queued' THEN 1 WHEN 'prepared' THEN 2 ELSE 3 END,
                                 bj.priority DESC, bj.updated_at DESC
                        LIMIT $3""",
                        active_statuses,
                        domain_id,
                        active_limit,
                    )
                )
        deduped_rows: list[asyncpg.Record] = []
        seen_ids: set[int] = set()
        for row in rows:
            row_id = int(row["id"])
            if row_id in seen_ids:
                continue
            seen_ids.add(row_id)
            deduped_rows.append(row)
        rows = deduped_rows[:limit]
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            # List rendering must remain DB-only. Artifact files live on block
            # storage and are loaded only when the analyst opens a job detail.
            result = load_codex_summary(item.get("result_summary"))
            artifact_error = None
            item.pop("result_summary", None)
            # The list view needs only display metadata. Full evidence and test
            # arrays are loaded on demand by the job-detail endpoint.
            item["result"] = {
                key: result.get(key)
                for key in ("title", "finding_status", "outcome_class")
                if result.get(key) is not None
            }
            item["artifact_error"] = artifact_error
            item["display_title"] = result.get("title") or item.get("hypothesis") or f"{item.get('job_type')} review"
            item["display_outcome"] = result.get("outcome_class") or item.get("finding_status") or item.get("status")
            item["tests_count"] = len(result.get("tests_performed") or [])
            item["evidence_count"] = len(result.get("evidence_files") or [])
            items.append(item)
        worker_state = read_codex_worker_state(self.config)
        allocations = worker_state.get("category_allocations") or normalized_allocations(
            self.config.get("scan", {}).get("codex_worker_category_allocations")
        )
        roi = []
        for row in roi_rows:
            item = dict(row)
            completed = int(item.get("completed") or 0)
            item["conversion_rate"] = round((int(item.get("credible") or 0) / completed) * 100, 1) if completed else 0
            item["allocation"] = round(float(allocations.get(item.get("job_category"), 0)) * 100, 1)
            roi.append(item)
        job_type_roi = []
        for row in job_type_roi_rows:
            item = dict(row)
            completed = int(item.get("completed") or 0)
            item["conversion_rate"] = round((int(item.get("credible") or 0) / completed) * 100, 1) if completed else 0
            job_type_roi.append(item)
        focus = []
        for row in focus_rows:
            item = dict(row)
            completed = int(item.get("completed") or 0)
            item["conversion_rate"] = round((int(item.get("credible") or 0) / completed) * 100, 1) if completed else 0
            focus.append(item)
        return {
            "worker": worker_state,
            "summary": dict(summary or {}),
            "recent_days": recent_days,
            "rows": items,
            "roi_by_category": roi,
            "roi_by_job_type": job_type_roi,
            "focus_domains": focus,
        }

    async def get_codex_worker_job(self, job_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT bj.id, bj.domain_id, d.domain, bj.target, bj.status, bj.priority,
                       bj.scope_ok, bj.asset_type, bj.asset_value, bj.job_type,
                       bj.hypothesis, bj.safety_notes,
                       bj.finding_status, bj.confidence, bj.attempt_count, bj.max_attempts,
                       bj.source_table, bj.source_id, bj.source_observed_at,
                       bj.prompt_path, bj.codex_output_path, bj.result_summary, bj.error,
                       bj.codex_alerted_at, bj.codex_alert_kind,
                       bj.codex_alert_suppressed_reason, bj.vpn_failover_attempted,
                       bj.vpn_failover_succeeded, bj.vpn_failover_reason,
                       bj.vpn_egress_before, bj.vpn_egress_after,
                       bj.vpn_retry_output_path, bj.vpn_failover_at,
                       bj.created_at, bj.started_at,
                       bj.finished_at, bj.updated_at,
                       EXTRACT(EPOCH FROM (COALESCE(bj.finished_at, NOW()) - bj.started_at))::int AS duration_seconds
                FROM bug_jobs bj
                LEFT JOIN domains d ON d.id = bj.domain_id
                WHERE bj.id = $1 AND ($2::int IS NULL OR bj.domain_id = $2)
                """,
                int(job_id),
                domain_id,
            )
        if not row:
            return None
        item = dict(row)
        result, artifact_error = load_codex_result(self.config, item.get("codex_output_path"), item.get("result_summary"))
        item.pop("result_summary", None)
        item["result"] = result
        item["artifact_error"] = artifact_error
        return item

    async def get_research_leads(
        self,
        domain_id: int | None = None,
        limit: int = 100,
        outcome: str = "attention",
        search: str = "",
        analyst_status: str = "",
    ) -> dict[str, Any]:
        """Return a compact, evidence-oriented lead queue for the research panel."""
        assert self.pool is not None
        limit = max(20, min(int(limit), 150))
        search = str(search or "").strip()[:300]
        analyst_status = str(analyst_status or "").strip().lower()[:40]
        recent_days = max(1, min(int(self.config.get("scan", {}).get("bug_jobs_recent_window_days", 30) or 30), 365))
        fetch_limit = min(600, max(limit * 4, 120))
        artifact_ids = recent_codex_job_ids(self.config, limit=600)
        if not artifact_ids:
            return {
                "rows": [],
                "total": 0,
                "candidate_count": 0,
                "recent_days": recent_days,
                "summary": {"confirmed": 0, "review_alerts": 0, "running": 0, "worker_status": "idle"},
                "filters": {"outcome": outcome, "search": search, "analyst_status": analyst_status},
            }
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT bj.id, bj.domain_id, d.domain, bj.target, bj.status, bj.priority,
                       bj.scope_ok, bj.asset_type, bj.asset_value, bj.job_type,
                       bj.hypothesis, bj.finding_status, bj.confidence,
                       bj.source_table, bj.source_id, bj.source_observed_at,
                       bj.codex_output_path, bj.result_summary, bj.codex_alert_kind,
                       bj.created_at, bj.started_at, bj.finished_at, bj.updated_at,
                       aa.status AS analyst_status, aa.severity_override,
                       aa.tags AS analyst_tags, aa.bookmarked, aa.assigned_to
                FROM bug_jobs bj
                LEFT JOIN domains d ON d.id = bj.domain_id
                LEFT JOIN analyst_annotations aa
                  ON aa.entity_type = 'bug_job'
                 AND aa.entity_key = 'bug_job:' || bj.id::text
                WHERE bj.id = ANY($1::bigint[])
                  AND bj.scope_ok = TRUE
                  AND bj.finding_status IN ('possible', 'confirmed')
                  AND bj.updated_at >= NOW() - ($3::int * INTERVAL '1 day')
                  AND ($2::int IS NULL OR bj.domain_id = $2)
                  AND ($4::text = '' OR aa.status = $4)
                  AND (
                    $5::text = ''
                    OR d.domain ILIKE '%' || $5 || '%'
                    OR bj.asset_value ILIKE '%' || $5 || '%'
                    OR bj.job_type ILIKE '%' || $5 || '%'
                    OR COALESCE(bj.hypothesis, '') ILIKE '%' || $5 || '%'
                  )
                ORDER BY
                  CASE WHEN bj.finding_status = 'confirmed' THEN 0
                       WHEN bj.codex_alert_kind = 'review' THEN 1 ELSE 2 END,
                  bj.confidence DESC NULLS LAST,
                  bj.priority DESC,
                  bj.updated_at DESC
                LIMIT $6
                """,
                artifact_ids,
                domain_id,
                recent_days,
                analyst_status,
                search,
                fetch_limit,
            )
            running = await conn.fetchval(
                "SELECT COUNT(*) FROM bug_jobs WHERE status = 'running' AND ($1::int IS NULL OR domain_id = $1)",
                domain_id,
            )
        wanted_outcome = str(outcome or "attention").strip().lower()
        items: list[dict[str, Any]] = []
        attention_outcomes = {"CONFIRMED", "CONFIRMED_UNIQUE", "STRONG_CANDIDATE", "NEEDS_MANUAL_REVIEW"}
        for row in rows:
            item = dict(row)
            result, artifact_error = load_codex_result(self.config, item.get("codex_output_path"), item.get("result_summary"))
            item.pop("result_summary", None)
            outcome_class = str(result.get("outcome_class") or item.get("finding_status") or "possible").upper()
            if wanted_outcome == "confirmed" and item.get("finding_status") != "confirmed":
                continue
            if wanted_outcome == "strong" and outcome_class != "STRONG_CANDIDATE":
                continue
            if wanted_outcome == "manual" and outcome_class != "NEEDS_MANUAL_REVIEW":
                continue
            if wanted_outcome == "blocked" and outcome_class not in {"BLOCKED", "INCONCLUSIVE", "LOCAL_MODEL_ONLY"}:
                continue
            if wanted_outcome == "attention" and outcome_class not in attention_outcomes and not item.get("codex_alert_kind"):
                continue
            item["artifact_error"] = artifact_error
            item["display_title"] = result.get("title") or item.get("hypothesis") or f"{item.get('job_type')} review"
            item["display_outcome"] = outcome_class
            item["display_summary"] = result.get("observed_anomaly") or result.get("impact") or item.get("hypothesis")
            item["affected_endpoint"] = result.get("affected_endpoint") or item.get("asset_value")
            item["vulnerability_class"] = result.get("vulnerability_class") or result.get("owasp_category") or item.get("job_type")
            item["manual_review_priority"] = result.get("manual_review_priority")
            item["tests_count"] = len(result.get("tests_performed") or [])
            item["evidence_count"] = len(result.get("evidence_files") or [])
            items.append(item)
            if len(items) >= limit:
                break
        worker_status = "idle"
        state_path = codex_artifact_root(self.config) / ".worker_state.json"
        try:
            if state_path.is_file() and state_path.stat().st_size <= 256 * 1024:
                worker_state = json.loads(state_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(worker_state, dict):
                    worker_status = str(worker_state.get("status") or worker_state.get("worker") or "idle")
        except (OSError, ValueError, json.JSONDecodeError):
            worker_status = "unknown"
        return {
            "rows": items,
            "total": len(items),
            "candidate_count": len(rows),
            "recent_days": recent_days,
            "summary": {
                "confirmed": sum(1 for item in items if item.get("finding_status") == "confirmed"),
                "review_alerts": sum(1 for item in items if item.get("codex_alert_kind") == "review"),
                "running": int(running or 0),
                "worker_status": worker_status,
            },
            "filters": {"outcome": wanted_outcome, "search": search, "analyst_status": analyst_status},
        }

    async def get_research_lead_context(self, job_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        """Build the bounded context needed to validate one Codex-generated lead."""
        item = await self.get_codex_worker_job(job_id, domain_id)
        if item is None:
            return None
        assert self.pool is not None
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        domain_id = int(item["domain_id"])
        source_table = str(item.get("source_table") or "")
        source_id = item.get("source_id")
        asset_value = str(item.get("asset_value") or "")
        affected_endpoint = str(result.get("affected_endpoint") or asset_value)
        parsed = urlsplit(affected_endpoint if "://" in affected_endpoint else asset_value)
        hostname = (parsed.hostname or "").lower().rstrip(".")

        async with self.pool.acquire() as conn:
            annotation = await conn.fetchrow(
                """
                SELECT id, status, severity_override, tags, bookmarked, notes, assigned_to, updated_at
                FROM analyst_annotations
                WHERE entity_type = 'bug_job' AND entity_key = $1
                """,
                f"bug_job:{job_id}",
            )
            source_finding = None
            if source_table in {"finding", "findings"} and source_id is not None:
                source_finding = await conn.fetchrow(
                    """
                    SELECT id, finding_type, severity, location, first_seen, last_seen, is_new, is_resolved
                    FROM findings WHERE id = $1 AND domain_id = $2
                    """,
                    int(source_id),
                    domain_id,
                )
            evidence = await conn.fetch(
                """
                SELECT id, source_table, source_id, title, location, severity, summary, artifacts, updated_at
                FROM evidence_packs
                WHERE domain_id = $1
                  AND ((source_table = 'bug_jobs' AND source_id = $2)
                    OR (source_table = $3 AND source_id = $4))
                ORDER BY updated_at DESC
                LIMIT 30
                """,
                domain_id,
                job_id,
                source_table,
                int(source_id) if source_id is not None else None,
            )
            validations = await conn.fetch(
                """
                SELECT id, finding_id, evidence_pack_id, source_table, source_id,
                       status, priority, location, validation_steps, notes, updated_at
                FROM validation_queue
                WHERE domain_id = $1
                  AND ((source_table = 'bug_jobs' AND source_id = $2)
                    OR (source_table = $3 AND source_id = $4))
                ORDER BY updated_at DESC
                LIMIT 30
                """,
                domain_id,
                job_id,
                source_table,
                int(source_id) if source_id is not None else None,
            )
            playbooks = await conn.fetch(
                """
                SELECT id, status, priority, confidence, check_type, owasp_category,
                       target_url, reasons, validation_steps, stop_conditions, safety_notes, updated_at
                FROM attack_playbooks
                WHERE domain_id = $1 AND check_type = $2
                ORDER BY updated_at DESC
                LIMIT 20
                """,
                domain_id,
                str(item.get("job_type") or ""),
            )
            authz = await conn.fetch(
                """
                SELECT id, endpoint, method, actor, object_owner, status_code,
                       response_hash, content_length, sensitive_keywords, metadata, created_at
                FROM authz_observations
                WHERE bug_job_id = $1
                ORDER BY created_at DESC
                LIMIT 30
                """,
                job_id,
            )
            live_hosts = []
            endpoints = []
            technologies = []
            js_assets = []
            api_surfaces = []
            services = []
            credential_leaks = []
            if hostname:
                live_hosts = await conn.fetch(
                    """
                    SELECT lh.id, lh.url, lh.port, lh.protocol, lh.status_code, lh.title,
                           lh.webserver, lh.content_length, lh.first_seen, lh.last_seen,
                           sd.id AS subdomain_id, sd.subdomain, sd.is_resolved, sd.ip_addresses
                    FROM live_hosts lh
                    JOIN subdomains sd ON sd.id = lh.subdomain_id
                    WHERE sd.domain_id = $1 AND sd.subdomain = $2
                    ORDER BY lh.last_seen DESC
                    LIMIT 12
                    """,
                    domain_id,
                    hostname,
                )
                host_ids = [int(row["id"]) for row in live_hosts]
                if host_ids:
                    endpoints = await conn.fetch(
                        """
                        SELECT e.id, lh.url AS host_url, e.method, e.path, e.status_code,
                               e.parameters, e.risk_tags, e.source, e.probed_at, e.last_seen
                        FROM endpoints e
                        JOIN live_hosts lh ON lh.id = e.live_host_id
                        WHERE e.live_host_id = ANY($1::int[])
                        ORDER BY cardinality(e.risk_tags) DESC, e.last_seen DESC
                        LIMIT 80
                        """,
                        host_ids,
                    )
                    technologies = await conn.fetch(
                        """
                        SELECT t.live_host_id, t.technology, t.version, t.last_seen
                        FROM technologies t
                        WHERE t.live_host_id = ANY($1::int[])
                        ORDER BY t.technology, t.version
                        LIMIT 60
                        """,
                        host_ids,
                    )
                    js_assets = await conn.fetch(
                        """
                        SELECT ja.id, ja.live_host_id, ja.asset_url, ja.source, ja.sha256,
                               ja.size_bytes, ja.http_status, ja.first_seen, ja.last_seen,
                               (jar.id IS NOT NULL) AS analyzed
                        FROM js_assets ja
                        LEFT JOIN js_analysis_results jar ON jar.js_asset_id = ja.id
                        WHERE ja.live_host_id = ANY($1::int[])
                          AND (ja.asset_url = $2 OR ja.asset_url = $3 OR ja.last_seen >= NOW() - INTERVAL '30 days')
                        ORDER BY CASE WHEN ja.asset_url IN ($2, $3) THEN 0 ELSE 1 END, ja.last_seen DESC
                        LIMIT 30
                        """,
                        host_ids,
                        asset_value,
                        affected_endpoint,
                    )
                    api_surfaces = await conn.fetch(
                        """
                        SELECT id, surface_type, location, source, status_code, auth_required,
                               schema_url, methods, operations_count, risk_flags, metadata, last_seen
                        FROM api_surfaces
                        WHERE domain_id = $1 AND live_host_id = ANY($2::int[])
                        ORDER BY operations_count DESC, last_seen DESC
                        LIMIT 30
                        """,
                        domain_id,
                        host_ids,
                    )
                services = await conn.fetch(
                    """
                    SELECT ns.id, host(ii.ip_address) AS ip_address, ii.classification, ii.provider,
                           ns.port, ns.protocol, ns.state, ns.service, ns.product, ns.version,
                           ns.extra_info, ns.metadata, ns.last_scanned_at
                    FROM subdomains sd
                    JOIN infrastructure_ip_subdomains iis ON iis.subdomain_id = sd.id
                    JOIN infrastructure_ips ii ON ii.id = iis.ip_asset_id
                    JOIN network_services ns ON ns.ip_asset_id = ii.id
                    WHERE sd.domain_id = $1 AND sd.subdomain = $2
                    ORDER BY CASE ns.state WHEN 'open' THEN 0 ELSE 1 END, ns.port
                    LIMIT 40
                    """,
                    domain_id,
                    hostname,
                )
                credential_leaks = await conn.fetch(
                    """
                    SELECT id, detector_name, detector_type, source_type, source_url,
                           verified, redacted_secret, line_number, first_seen, last_seen, is_resolved
                    FROM credential_leaks
                    WHERE domain_id = $1 AND source_url IN ($2, $3)
                    ORDER BY verified DESC, last_seen DESC
                    LIMIT 20
                    """,
                    domain_id,
                    asset_value,
                    affected_endpoint,
                )
            related_rows = await conn.fetch(
                """
                SELECT id, job_type, asset_type, asset_value, hypothesis, finding_status,
                       confidence, codex_alert_kind, source_table, source_id, updated_at,
                       codex_output_path, result_summary
                FROM bug_jobs
                WHERE domain_id = $1 AND id <> $2
                  AND job_type = $3
                  AND finding_status IN ('possible', 'confirmed')
                  AND updated_at >= NOW() - INTERVAL '30 days'
                ORDER BY confidence DESC NULLS LAST, updated_at DESC
                LIMIT 30
                """,
                domain_id,
                job_id,
                str(item.get("job_type") or ""),
            )

        related: list[dict[str, Any]] = []
        for row in related_rows:
            related_item = dict(row)
            related_result, _ = load_codex_result(
                self.config,
                related_item.pop("codex_output_path", None),
                related_item.pop("result_summary", None),
            )
            related_item["display_title"] = related_result.get("title") or related_item.get("hypothesis")
            related_item["display_outcome"] = related_result.get("outcome_class") or related_item.get("finding_status")
            related.append(related_item)

        return {
            "lead": item,
            "hostname": hostname,
            "annotation": dict(annotation) if annotation else None,
            "source_finding": dict(source_finding) if source_finding else None,
            "evidence_packs": [dict(row) for row in evidence],
            "validations": [dict(row) for row in validations],
            "playbooks": [dict(row) for row in playbooks],
            "authz_observations": [dict(row) for row in authz],
            "live_hosts": [dict(row) for row in live_hosts],
            "endpoints": [dict(row) for row in endpoints],
            "technologies": [dict(row) for row in technologies],
            "js_assets": [dict(row) for row in js_assets],
            "api_surfaces": [dict(row) for row in api_surfaces],
            "services": [dict(row) for row in services],
            "credential_leaks": [dict(row) for row in credential_leaks],
            "related_leads": related,
        }

    async def queue_research_validation(self, job_id: int, domain_id: int | None = None) -> dict[str, Any] | None:
        item = await self.get_codex_worker_job(job_id, domain_id)
        if item is None:
            return None
        assert self.pool is not None
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        steps = [str(step)[:2000] for step in (result.get("safe_reproduction_steps") or []) if str(step).strip()][:20]
        if not steps and result.get("recommended_next_step"):
            steps = [str(result["recommended_next_step"])[:2000]]
        location = str(result.get("affected_endpoint") or item.get("asset_value") or item.get("target") or "")
        priority_score = int(item.get("priority") or 0)
        priority = "high" if priority_score >= 98 else "medium" if priority_score >= 90 else "low"
        note = str(result.get("manual_review_reason") or result.get("recommended_next_step") or item.get("hypothesis") or "")[:5000]
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO validation_queue (
                  domain_id, source_table, source_id, queue_key, status, priority,
                  location, validation_steps, notes
                )
                VALUES ($1, 'bug_jobs', $2, $3, 'needs_validation', $4, $5, $6, $7)
                ON CONFLICT (queue_key)
                DO UPDATE SET
                  status = CASE WHEN validation_queue.status = 'validated' THEN validation_queue.status ELSE 'needs_validation' END,
                  priority = EXCLUDED.priority,
                  location = EXCLUDED.location,
                  validation_steps = EXCLUDED.validation_steps,
                  notes = EXCLUDED.notes,
                  updated_at = NOW()
                RETURNING *
                """,
                int(item["domain_id"]),
                job_id,
                f"bug-job:{job_id}",
                priority,
                location,
                steps,
                note,
            )
        return dict(row)

    async def create_ai_assistant_query(
        self,
        payload: dict[str, Any],
        domain_id: int | None = None,
    ) -> dict[str, Any]:
        assert self.pool is not None
        scan = self.config.get("scan", {})
        if not bool(scan.get("ai_assistant_enabled", True)):
            raise ValueError("AI assistant is disabled")
        question = re.sub(r"\s+", " ", str(payload.get("question") or "").strip())
        max_chars = max(200, min(int(scan.get("ai_assistant_max_question_chars", 3000) or 3000), 8000))
        if len(question) < 3:
            raise ValueError("question must contain at least 3 characters")
        if len(question) > max_chars:
            raise ValueError(f"question exceeds the {max_chars} character limit")
        section = str(payload.get("section") or "overview").strip().lower()
        if section not in AI_ASSISTANT_SECTIONS:
            raise ValueError("unknown research section")
        mode = str(payload.get("mode") or "tab_assistant").strip().lower()
        if mode not in AI_ASSISTANT_MODES:
            raise ValueError("unknown assistant mode")
        requested_thread = str(payload.get("thread_id") or "").strip()
        try:
            thread_id = uuid.UUID(requested_thread) if requested_thread else uuid.uuid4()
        except ValueError as exc:
            raise ValueError("invalid assistant thread id") from exc
        selected_context = sanitize_ai_context(payload.get("selected_context") or {})
        serialized_context = json.dumps(selected_context, separators=(",", ":"), default=str)
        if len(serialized_context.encode("utf-8")) > 32768:
            selected_context = {"notice": "selected context exceeded 32 KB and was omitted"}
        queue_limit = max(1, min(int(scan.get("ai_assistant_max_queued", 20) or 20), 100))
        daily_limit = max(1, min(int(scan.get("ai_assistant_max_queries_per_day", 50) or 50), 500))
        async with self.pool.acquire() as conn:
            if domain_id is not None:
                exists = await conn.fetchval("SELECT EXISTS(SELECT 1 FROM domains WHERE id = $1)", domain_id)
                if not exists:
                    raise ValueError("selected domain does not exist")
            queue_count = await conn.fetchval(
                "SELECT COUNT(*) FROM ai_assistant_queries WHERE status IN ('queued', 'running')"
            )
            if int(queue_count or 0) >= queue_limit:
                raise ValueError("AI assistant queue is full; wait for existing questions to finish")
            daily_count = await conn.fetchval(
                "SELECT COUNT(*) FROM ai_assistant_queries WHERE created_at >= date_trunc('day', NOW())"
            )
            if int(daily_count or 0) >= daily_limit:
                raise ValueError("AI assistant daily query budget is exhausted")
            row = await conn.fetchrow(
                """
                INSERT INTO ai_assistant_queries (
                  thread_id, domain_id, mode, section, question, selected_context,
                  status, max_attempts, available_at
                )
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'queued', $7, NOW())
                RETURNING id, thread_id, domain_id, mode, section, question, status,
                          answer, model, error, created_at, started_at, finished_at, updated_at
                """,
                thread_id,
                domain_id,
                mode,
                section,
                question,
                json.dumps(selected_context, default=str),
                max(1, min(int(scan.get("ai_assistant_max_attempts", 2) or 2), 4)),
            )
        return dict(row)

    async def get_ai_assistant_query(self, query_id: int) -> dict[str, Any] | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT q.id, q.thread_id, q.domain_id, d.domain, q.mode, q.section,
                       q.question, q.status, q.answer, q.model, q.error,
                       q.created_at, q.started_at, q.finished_at, q.updated_at
                FROM ai_assistant_queries q
                LEFT JOIN domains d ON d.id = q.domain_id
                WHERE q.id = $1
                """,
                query_id,
            )
        if not row:
            return None
        item = dict(row)
        item["answer"] = normalize_json(item.get("answer")) or {}
        return item

    async def get_ai_assistant_history(self, thread_id: str, limit: int = 30) -> dict[str, Any]:
        assert self.pool is not None
        try:
            parsed_thread = uuid.UUID(str(thread_id))
        except ValueError as exc:
            raise ValueError("invalid assistant thread id") from exc
        limit = max(1, min(int(limit), 50))
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT q.id, q.thread_id, q.domain_id, d.domain, q.mode, q.section,
                       q.question, q.status, q.answer, q.model, q.error,
                       q.created_at, q.started_at, q.finished_at, q.updated_at
                FROM ai_assistant_queries q
                LEFT JOIN domains d ON d.id = q.domain_id
                WHERE q.thread_id = $1
                ORDER BY q.id DESC
                LIMIT $2
                """,
                parsed_thread,
                limit,
            )
        items = []
        for row in reversed(rows):
            item = dict(row)
            item["answer"] = normalize_json(item.get("answer")) or {}
            items.append(item)
        return {"rows": items, "total": len(items), "thread_id": str(parsed_thread)}

    async def get_ai_assistant_conversations(
        self, domain_id: int | None = None, limit: int = 50
    ) -> dict[str, Any]:
        assert self.pool is not None
        limit = max(1, min(int(limit), 100))
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                WITH conversation AS (
                  SELECT q.thread_id, q.domain_id, d.domain, q.section, q.mode,
                         q.question AS latest_question, q.status AS latest_status,
                         q.created_at AS latest_at,
                         COUNT(*) OVER (PARTITION BY q.thread_id)::int AS message_count,
                         ROW_NUMBER() OVER (PARTITION BY q.thread_id ORDER BY q.id DESC) AS row_number
                  FROM ai_assistant_queries q
                  LEFT JOIN domains d ON d.id = q.domain_id
                  WHERE $1::int IS NULL OR q.domain_id = $1
                )
                SELECT thread_id, domain_id, domain, section, mode, latest_question,
                       latest_status, latest_at, message_count
                FROM conversation
                WHERE row_number = 1
                ORDER BY latest_at DESC
                LIMIT $2
                """,
                domain_id,
                limit,
            )
        return {"rows": [dict(row) for row in rows], "total": len(rows)}

    async def delete_ai_assistant_thread(self, thread_id: str) -> dict[str, Any]:
        assert self.pool is not None
        try:
            parsed_thread = uuid.UUID(str(thread_id))
        except ValueError as exc:
            raise ValueError("invalid assistant thread id") from exc
        async with self.pool.acquire() as conn:
            active = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM ai_assistant_queries WHERE thread_id = $1 AND status IN ('queued', 'running'))",
                parsed_thread,
            )
            if active:
                raise ValueError("wait for the active question to finish before clearing this conversation")
            result = await conn.execute("DELETE FROM ai_assistant_queries WHERE thread_id = $1", parsed_thread)
        return {"thread_id": str(parsed_thread), "deleted": int(result.rsplit(" ", 1)[-1])}

    async def clear_ai_assistant_history(self, domain_id: int | None = None) -> dict[str, Any]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                DELETE FROM ai_assistant_queries
                WHERE ($1::int IS NULL OR domain_id = $1)
                  AND status NOT IN ('queued', 'running')
                """,
                domain_id,
            )
        return {"domain_id": domain_id, "deleted": int(result.rsplit(" ", 1)[-1])}

    async def get_ai_assistant_status(self) -> dict[str, Any]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            counts = await conn.fetchrow(
                """
                SELECT COUNT(*) FILTER (WHERE status = 'queued')::int AS queued,
                       COUNT(*) FILTER (WHERE status = 'running')::int AS running,
                       COUNT(*) FILTER (WHERE status = 'done')::int AS done_today,
                       COUNT(*) FILTER (WHERE status = 'failed')::int AS failed_today
                FROM ai_assistant_queries
                WHERE created_at >= date_trunc('day', NOW()) OR status IN ('queued', 'running')
                """
            )
        state: dict[str, Any] = {}
        state_path = ai_assistant_artifact_root(self.config) / ".worker_state.json"
        try:
            if state_path.is_file() and state_path.stat().st_size <= 65536:
                decoded = json.loads(state_path.read_text(encoding="utf-8", errors="replace"))
                state = decoded if isinstance(decoded, dict) else {}
        except (OSError, ValueError, json.JSONDecodeError):
            state = {}
        return {
            **dict(counts or {}),
            "enabled": bool(self.config.get("scan", {}).get("ai_assistant_enabled", True)),
            "model": str(self.config.get("scan", {}).get("ai_assistant_model") or self.config.get("scan", {}).get("codex_worker_model") or "codex"),
            "worker": sanitize_ai_context(state),
        }

    async def get_monitor_targets(self, domain_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM monitor_targets WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT
                  mt.id, mt.domain_id, d.domain, mt.name, mt.start_url, mt.auth_type, mt.login_url, mt.login_email,
                  mt.username_selector, mt.password_selector, mt.submit_selector,
                  mt.auth_check_url, mt.auth_check_selector, mt.auth_check_text, mt.auth_failure_text,
                  mt.auth_status, mt.auth_last_checked_at, mt.auth_last_error,
                  (mt.cookie_secret_ref IS NOT NULL AND mt.cookie_secret_ref <> '') AS has_cookie,
                  (mt.password_secret_ref IS NOT NULL AND mt.password_secret_ref <> '') AS has_password,
                  mt.interval_hours, mt.enabled, mt.alert_min_risk, mt.last_run_at, mt.last_error,
                  mt.extra_routes, mt.metadata, mt.updated_at,
                  COALESCE(events.count, 0) AS event_count,
                  COALESCE(items.count, 0) AS intel_count
                FROM monitor_targets mt
                LEFT JOIN domains d ON d.id = mt.domain_id
                LEFT JOIN LATERAL (
                  SELECT COUNT(*)::int AS count FROM monitor_events me WHERE me.monitor_id = mt.id
                ) events ON TRUE
                LEFT JOIN LATERAL (
                  SELECT COUNT(*)::int AS count FROM monitor_intel_items mi WHERE mi.monitor_id = mt.id
                ) items ON TRUE
                LEFT JOIN LATERAL (
                  SELECT mr.id, mr.status, mr.started_at, mr.finished_at
                  FROM monitor_runs mr
                  WHERE mr.monitor_id = mt.id
                  ORDER BY mr.started_at DESC
                  LIMIT 1
                ) latest_run ON TRUE
                WHERE $1::int IS NULL OR mt.domain_id = $1
                ORDER BY mt.enabled DESC, mt.last_run_at DESC NULLS FIRST, mt.id DESC
                LIMIT $2 OFFSET $3
                """,
                domain_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_monitor_events(
        self,
        domain_id: int | None = None,
        monitor_id: int | None = None,
        run_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM monitor_events me
                WHERE ($1::int IS NULL OR me.domain_id = $1)
                  AND ($2::int IS NULL OR me.monitor_id = $2)
                  AND ($3::int IS NULL OR me.run_id = $3)
                """,
                domain_id,
                monitor_id,
                run_id,
            )
            rows = await conn.fetch(
                """
                SELECT me.id, me.run_id, me.monitor_id, d.domain, mt.name AS monitor, me.event_type, me.item_type, me.value, me.severity,
                       me.summary, me.payload, me.first_seen, me.last_seen
                FROM monitor_events me
                JOIN monitor_targets mt ON mt.id = me.monitor_id
                LEFT JOIN domains d ON d.id = me.domain_id
                WHERE ($1::int IS NULL OR me.domain_id = $1)
                  AND ($2::int IS NULL OR me.monitor_id = $2)
                  AND ($3::int IS NULL OR me.run_id = $3)
                ORDER BY
                  CASE me.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  me.last_seen DESC
                LIMIT $4 OFFSET $5
                """,
                domain_id,
                monitor_id,
                run_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_monitor_runs(
        self,
        domain_id: int | None = None,
        monitor_id: int | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM monitor_runs mr
                WHERE ($1::int IS NULL OR mr.domain_id = $1)
                  AND ($2::int IS NULL OR mr.monitor_id = $2)
                  AND ($3::text IS NULL OR mr.status = $3)
                """,
                domain_id,
                monitor_id,
                status,
            )
            rows = await conn.fetch(
                """
                SELECT mr.id, mr.monitor_id, d.domain, mt.name AS monitor, mr.status, mr.started_at, mr.finished_at,
                       mr.duration_seconds, mr.auth_status, mr.new_items_count, mr.new_events_count,
                       mr.scripts_count, mr.requests_count, mr.error, mr.summary
                FROM monitor_runs mr
                JOIN monitor_targets mt ON mt.id = mr.monitor_id
                LEFT JOIN domains d ON d.id = mr.domain_id
                WHERE ($1::int IS NULL OR mr.domain_id = $1)
                  AND ($2::int IS NULL OR mr.monitor_id = $2)
                  AND ($3::text IS NULL OR mr.status = $3)
                ORDER BY mr.started_at DESC
                LIMIT $4 OFFSET $5
                """,
                domain_id,
                monitor_id,
                status,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def get_monitor_intel(self, domain_id: int | None = None, monitor_id: int | None = None, limit: int = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM monitor_intel_items mi
                WHERE ($1::int IS NULL OR mi.domain_id = $1)
                  AND ($2::int IS NULL OR mi.monitor_id = $2)
                """,
                domain_id,
                monitor_id,
            )
            rows = await conn.fetch(
                """
                SELECT mi.id, mi.monitor_id, d.domain, mt.name AS monitor, mi.item_type, mi.value, mi.risk,
                       mi.source_url, mi.metadata, mi.first_seen, mi.last_seen
                FROM monitor_intel_items mi
                JOIN monitor_targets mt ON mt.id = mi.monitor_id
                LEFT JOIN domains d ON d.id = mi.domain_id
                WHERE ($1::int IS NULL OR mi.domain_id = $1)
                  AND ($2::int IS NULL OR mi.monitor_id = $2)
                ORDER BY mi.last_seen DESC
                LIMIT $3 OFFSET $4
                """,
                domain_id,
                monitor_id,
                limit,
                offset,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def upsert_monitor_target(self, payload: dict[str, Any], domain_id: int | None = None) -> dict:
        assert self.pool is not None
        start_url = str(payload.get("start_url") or "").strip()
        if not start_url.startswith(("http://", "https://")):
            raise ValueError("start_url must be http:// or https://")
        target_domain_id = domain_id or payload.get("domain_id")
        if not target_domain_id:
            parsed_host = (urlsplit(start_url).hostname or "").lower()
            async with self.pool.acquire() as conn:
                target_domain_id = await conn.fetchval(
                    "SELECT id FROM domains WHERE $1 = domain OR $1 LIKE ('%.' || domain) ORDER BY length(domain) DESC LIMIT 1",
                    parsed_host,
                )
        if not target_domain_id:
            raise ValueError("select a recon domain for this monitor")
        auth_type = str(payload.get("auth_type") or "none").strip().lower()
        if auth_type not in {"none", "cookie", "login"}:
            auth_type = "none"
        extra_routes = payload.get("extra_routes") or []
        if isinstance(extra_routes, str):
            extra_routes = [line.strip() for line in extra_routes.splitlines() if line.strip()]
        metadata = {"max_seconds": int(payload.get("max_seconds") or 45)}
        name = str(payload.get("name") or start_url).strip()[:160]
        monitor_id = payload.get("id") or payload.get("monitor_id")
        enabled_value = payload.get("enabled", True)
        enabled = enabled_value if isinstance(enabled_value, bool) else str(enabled_value).lower() in {"1", "true", "yes", "on"}
        auth_check_url = str(payload.get("auth_check_url") or "").strip() or None
        auth_check_selector = str(payload.get("auth_check_selector") or "").strip() or None
        auth_check_text = str(payload.get("auth_check_text") or "").strip() or None
        auth_failure_text = str(payload.get("auth_failure_text") or "").strip() or None
        async with self.pool.acquire() as conn:
            if monitor_id:
                row = await conn.fetchrow(
                    """
                    UPDATE monitor_targets
                    SET domain_id = $2,
                        name = $3,
                        start_url = $4,
                        auth_type = $5,
                        cookie_secret_ref = COALESCE(NULLIF($6, ''), cookie_secret_ref),
                        login_url = $7,
                        login_email = $8,
                        password_secret_ref = COALESCE(NULLIF($9, ''), password_secret_ref),
                        username_selector = $10,
                        password_selector = $11,
                        submit_selector = $12,
                        auth_check_url = $13,
                        auth_check_selector = $14,
                        auth_check_text = $15,
                        auth_failure_text = $16,
                        extra_routes = $17::jsonb,
                        interval_hours = $18,
                        enabled = $19,
                        alert_min_risk = $20,
                        metadata = $21::jsonb,
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING id, domain_id, name, start_url, auth_type, interval_hours, enabled, alert_min_risk, last_run_at, last_error
                    """,
                    int(monitor_id),
                    int(target_domain_id),
                    name,
                    start_url,
                    auth_type,
                    str(payload.get("cookie") or payload.get("cookie_secret_ref") or "").strip(),
                    str(payload.get("login_url") or "").strip() or None,
                    str(payload.get("login_email") or "").strip() or None,
                    str(payload.get("password") or payload.get("password_secret_ref") or "").strip(),
                    str(payload.get("username_selector") or "").strip() or None,
                    str(payload.get("password_selector") or "").strip() or None,
                    str(payload.get("submit_selector") or "").strip() or None,
                    auth_check_url,
                    auth_check_selector,
                    auth_check_text,
                    auth_failure_text,
                    json.dumps(extra_routes),
                    max(1, int(payload.get("interval_hours") or 24)),
                    enabled,
                    str(payload.get("alert_min_risk") or "medium").strip().lower(),
                    json.dumps(metadata),
                )
                if not row:
                    raise ValueError("monitor not found")
                return dict(row)
            row = await conn.fetchrow(
                """
                INSERT INTO monitor_targets (
                  domain_id, name, start_url, auth_type, cookie_secret_ref, login_url, login_email, password_secret_ref,
                  username_selector, password_selector, submit_selector,
                  auth_check_url, auth_check_selector, auth_check_text, auth_failure_text,
                  extra_routes, interval_hours, enabled, alert_min_risk, metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17, COALESCE($18, TRUE), $19, $20::jsonb)
                ON CONFLICT (domain_id, start_url)
                DO UPDATE SET
                  name = EXCLUDED.name,
                  auth_type = EXCLUDED.auth_type,
                  cookie_secret_ref = COALESCE(NULLIF(EXCLUDED.cookie_secret_ref, ''), monitor_targets.cookie_secret_ref),
                  login_url = EXCLUDED.login_url,
                  login_email = EXCLUDED.login_email,
                  password_secret_ref = COALESCE(NULLIF(EXCLUDED.password_secret_ref, ''), monitor_targets.password_secret_ref),
                  username_selector = EXCLUDED.username_selector,
                  password_selector = EXCLUDED.password_selector,
                  submit_selector = EXCLUDED.submit_selector,
                  auth_check_url = EXCLUDED.auth_check_url,
                  auth_check_selector = EXCLUDED.auth_check_selector,
                  auth_check_text = EXCLUDED.auth_check_text,
                  auth_failure_text = EXCLUDED.auth_failure_text,
                  extra_routes = EXCLUDED.extra_routes,
                  interval_hours = EXCLUDED.interval_hours,
                  enabled = EXCLUDED.enabled,
                  alert_min_risk = EXCLUDED.alert_min_risk,
                  metadata = EXCLUDED.metadata,
                  updated_at = NOW()
                RETURNING id, domain_id, name, start_url, auth_type, interval_hours, enabled, alert_min_risk, last_run_at, last_error
                """,
                int(target_domain_id),
                name,
                start_url,
                auth_type,
                str(payload.get("cookie") or payload.get("cookie_secret_ref") or "").strip(),
                str(payload.get("login_url") or "").strip() or None,
                str(payload.get("login_email") or "").strip() or None,
                str(payload.get("password") or payload.get("password_secret_ref") or "").strip(),
                str(payload.get("username_selector") or "").strip() or None,
                str(payload.get("password_selector") or "").strip() or None,
                str(payload.get("submit_selector") or "").strip() or None,
                auth_check_url,
                auth_check_selector,
                auth_check_text,
                auth_failure_text,
                json.dumps(extra_routes),
                max(1, int(payload.get("interval_hours") or 24)),
                enabled,
                str(payload.get("alert_min_risk") or "medium").strip().lower(),
                json.dumps(metadata),
            )
            return dict(row)

    async def start_monitor_run(self, monitor: dict[str, Any]) -> int:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            return int(await conn.fetchval(
                """
                INSERT INTO monitor_runs (monitor_id, domain_id, status)
                VALUES ($1, $2, 'running')
                RETURNING id
                """,
                int(monitor["id"]),
                int(monitor["domain_id"]),
            ))

    async def finish_monitor_run(
        self,
        monitor: dict[str, Any],
        run_id: int,
        status: str,
        stats: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        assert self.pool is not None
        stats = stats or {}
        result = result or {}
        auth = result.get("auth") or {}
        auth_status = str(auth.get("status") or ("error" if error else "unchecked"))
        auth_error = error if error else (None if auth_status in {"ok", "unchecked", "not_required"} else auth_status)
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE monitor_runs
                SET status = $2,
                    finished_at = NOW(),
                    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at)),
                    auth_status = $3,
                    new_items_count = $4,
                    new_events_count = $5,
                    scripts_count = $6,
                    requests_count = $7,
                    error = $8,
                    summary = $9::jsonb
                WHERE id = $1
                """,
                run_id,
                status,
                auth_status,
                int(stats.get("new_items") or 0),
                int(stats.get("new_events") or 0),
                int(stats.get("scripts") or 0),
                int(stats.get("requests") or 0),
                error,
                json.dumps({"auth": auth, "start_url": result.get("start_url")}, default=str),
            )
            await conn.execute(
                """
                UPDATE monitor_targets
                SET last_run_at = NOW(),
                    last_error = $2,
                    auth_status = $3,
                    auth_last_checked_at = NOW(),
                    auth_last_error = $4,
                    updated_at = NOW()
                WHERE id = $1
                """,
                int(monitor["id"]),
                error,
                auth_status,
                auth_error,
            )

    async def record_monitor_run_result(self, monitor: dict[str, Any], result: dict[str, Any], run_id: int | None = None) -> dict[str, int]:
        assert self.pool is not None
        new_items = 0
        new_events = 0
        items = list(result.get("items") or [])
        for script in result.get("scripts") or []:
            if script.get("sha256"):
                items.append({
                    "item_type": "js_content_hash",
                    "value": script.get("sha256"),
                    "risk": "info",
                    "source_url": script.get("url"),
                    "metadata": {"url": script.get("url"), "status": script.get("status"), "size_bytes": script.get("size_bytes")},
                    "item_key": hashlib.sha256(f"js_content_hash|{script.get('sha256')}".encode()).hexdigest(),
                })
        async with self.pool.acquire() as conn:
            for item in items:
                item_type = str(item.get("item_type") or "unknown")
                value = str(item.get("value") or "").strip()
                if not value:
                    continue
                item_key = str(item.get("item_key") or hashlib.sha256(f"{item_type}|{value}".encode()).hexdigest())
                risk = str(item.get("risk") or "info")
                source_url = item.get("source_url")
                metadata = item.get("metadata") or {}
                row = await conn.fetchrow(
                    """
                    INSERT INTO monitor_intel_items (monitor_id, domain_id, item_type, item_key, value, risk, source_url, metadata)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
                    ON CONFLICT (monitor_id, item_type, item_key)
                    DO UPDATE SET last_seen = NOW(), value = EXCLUDED.value, risk = EXCLUDED.risk, source_url = EXCLUDED.source_url, metadata = EXCLUDED.metadata
                    RETURNING (xmax = 0) AS inserted
                    """,
                    int(monitor["id"]),
                    int(monitor["domain_id"]),
                    item_type,
                    item_key,
                    value,
                    risk,
                    source_url,
                    json.dumps(metadata),
                )
                if not row or not row["inserted"]:
                    continue
                new_items += 1
                await conn.execute(
                    """
                    INSERT INTO monitor_events (monitor_id, domain_id, event_type, item_type, item_key, value, severity, summary, payload)
                    VALUES ($1, $2, 'new_monitor_intel', $3, $4, $5, $6, $7, $8::jsonb)
                    ON CONFLICT (monitor_id, event_type, item_key)
                    DO UPDATE SET last_seen = NOW(), severity = EXCLUDED.severity, payload = EXCLUDED.payload
                    """,
                    int(monitor["id"]),
                    int(monitor["domain_id"]),
                    item_type,
                    item_key,
                    value,
                    risk,
                    f"New {item_type}: {value}",
                    json.dumps({"source_url": source_url, "metadata": metadata, "monitor": monitor.get("name")}),
                )
                if run_id:
                    await conn.execute("UPDATE monitor_events SET run_id = COALESCE(run_id, $2) WHERE monitor_id = $1 AND event_type = 'new_monitor_intel' AND item_key = $3", int(monitor["id"]), int(run_id), item_key)
                new_events += 1
        return {"new_items": new_items, "new_events": new_events, "scripts": len(result.get("scripts") or []), "requests": len(result.get("requests") or [])}

    async def run_monitor_now(self, monitor_id: int, domain_id: int | None = None) -> dict:
        assert self.pool is not None
        monitor_id = int(monitor_id)
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM monitor_targets WHERE id = $1 AND ($2::int IS NULL OR domain_id = $2)",
                monitor_id,
                domain_id,
            )
            if not row:
                raise ValueError("monitor not found")
            monitor = dict(row)
        metadata = normalize_json(monitor.get("metadata"))
        if not isinstance(metadata, dict):
            metadata = {}
        lock_conn = await self.pool.acquire()
        lock_acquired = False
        try:
            lock_acquired = bool(await lock_conn.fetchval("SELECT pg_try_advisory_lock($1, $2)", 817263546, monitor_id))
            if not lock_acquired:
                raise ValueError("monitor is already running")
            run_id = await self.start_monitor_run(monitor)
            result = await run_browser_monitor({
                "start_url": monitor.get("start_url"),
                "auth_type": monitor.get("auth_type"),
                "cookie_secret_ref": monitor.get("cookie_secret_ref"),
                "login_url": monitor.get("login_url"),
                "login_email": monitor.get("login_email"),
                "password_secret_ref": monitor.get("password_secret_ref"),
                "username_selector": monitor.get("username_selector"),
                "password_selector": monitor.get("password_selector"),
                "submit_selector": monitor.get("submit_selector"),
                "auth_check_url": monitor.get("auth_check_url"),
                "auth_check_selector": monitor.get("auth_check_selector"),
                "auth_check_text": monitor.get("auth_check_text"),
                "auth_failure_text": monitor.get("auth_failure_text"),
                "extra_routes": normalize_json(monitor.get("extra_routes")) if monitor.get("extra_routes") else [],
                "max_seconds": metadata.get("max_seconds", 45),
            })
            stats = await self.record_monitor_run_result(monitor, result, run_id)
            await self.finish_monitor_run(monitor, run_id, "success", stats, result)
            return {"monitor_id": monitor_id, "run_id": run_id, **stats, "auth_status": (result.get("auth") or {}).get("status")}
        except Exception as exc:
            if "run_id" in locals():
                await self.finish_monitor_run(monitor, run_id, "failed", error=repr(exc))
            else:
                async with self.pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE monitor_targets SET last_run_at = NOW(), last_error = $2, updated_at = NOW() WHERE id = $1",
                        int(monitor["id"]),
                        repr(exc),
                    )
            raise
        finally:
            if lock_acquired:
                try:
                    await lock_conn.execute("SELECT pg_advisory_unlock($1, $2)", 817263546, monitor_id)
                finally:
                    await self.pool.release(lock_conn)
            else:
                await self.pool.release(lock_conn)

    async def get_active_hunt_results(self, domain_id: int | None = None, limit: int | None = 100, offset: int = 0) -> dict:
        assert self.pool is not None
        limit_value = max(10, min(int(limit or 100), 500)) if limit is not None else None
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                "SELECT COUNT(*) FROM active_hunt_results WHERE $1::int IS NULL OR domain_id = $1",
                domain_id,
            )
            limit_sql = "" if limit_value is None else f"LIMIT {limit_value} OFFSET {offset}"
            rows = await conn.fetch(
                f"""
                SELECT
                  ahr.id,
                  d.domain,
                  ahr.run_id,
                  ahr.scope,
                  ahr.check_type,
                  ahr.target_url,
                  ahr.source_url,
                  ahr.parameter_name,
                  ahr.http_status,
                  ahr.finding,
                  ahr.confidence,
                  ahr.severity,
                  ahr.request,
                  ahr.response,
                  ahr.evidence,
                  ahr.created_at
                FROM active_hunt_results ahr
                LEFT JOIN domains d ON d.id = ahr.domain_id
                WHERE $1::int IS NULL OR ahr.domain_id = $1
                ORDER BY
                  CASE WHEN ahr.finding IS NULL OR ahr.finding = '' THEN 1 ELSE 0 END,
                  CASE ahr.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                  CASE ahr.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                  ahr.created_at DESC,
                  ahr.id DESC
                {limit_sql}
                """,
                domain_id,
            )
            return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit_value, "offset": offset}

    async def upsert_annotation(self, payload: dict[str, Any], domain_id: int | None = None) -> dict:
        assert self.pool is not None
        entity_type = str(payload.get("entity_type") or "").strip()
        entity_id = payload.get("entity_id")
        entity_key = str(payload.get("entity_key") or "").strip()
        location = str(payload.get("location") or "").strip()
        if not entity_key:
            if entity_id is not None:
                entity_key = f"{entity_type}:{int(entity_id)}"
            else:
                entity_key = hashlib.sha256(f"{entity_type}|{location}".encode()).hexdigest()
        tags = payload.get("tags") or []
        if isinstance(tags, str):
            tags = [item.strip() for item in tags.split(",") if item.strip()]
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO analyst_annotations (
                  domain_id, entity_type, entity_id, entity_key, location, status, severity_override, tags, bookmarked, notes, assigned_to
                )
                VALUES ($1, $2, $3, $4, NULLIF($5, ''), COALESCE($6, 'new'), $7, $8, COALESCE($9, FALSE), $10, $11)
                ON CONFLICT (entity_type, entity_key)
                DO UPDATE SET
                  domain_id = COALESCE(EXCLUDED.domain_id, analyst_annotations.domain_id),
                  entity_id = COALESCE(EXCLUDED.entity_id, analyst_annotations.entity_id),
                  location = COALESCE(EXCLUDED.location, analyst_annotations.location),
                  status = EXCLUDED.status,
                  severity_override = EXCLUDED.severity_override,
                  tags = EXCLUDED.tags,
                  bookmarked = CASE WHEN $9::bool IS NULL THEN analyst_annotations.bookmarked ELSE EXCLUDED.bookmarked END,
                  notes = EXCLUDED.notes,
                  assigned_to = EXCLUDED.assigned_to,
                  updated_at = NOW()
                RETURNING *
                """,
                domain_id,
                entity_type,
                int(entity_id) if entity_id is not None else None,
                entity_key,
                location,
                payload.get("status"),
                payload.get("severity_override"),
                tags,
                bool(payload["bookmarked"]) if "bookmarked" in payload else None,
                payload.get("notes"),
                payload.get("assigned_to"),
            )
            return dict(row)

    async def update_validation_status(self, validation_id: int, status: str, notes: str | None = None) -> dict | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE validation_queue
                SET status = $2, notes = COALESCE($3, notes), updated_at = NOW()
                WHERE id = $1
                RETURNING *
                """,
                validation_id,
                status,
                notes,
            )
            return dict(row) if row else None

    @staticmethod
    def report_page(page: dict, limit: int) -> dict:
        page = dict(page)
        page["rows"] = list(page.get("rows") or [])[:limit]
        page["limit"] = limit
        return page

    async def build_report_bundle(
        self,
        domain_id: int | None = None,
        limit: int = 50,
        sections: list[str] | None = None,
        validation_status: str | None = None,
    ) -> dict:
        selected = sections or ["risk", "playbooks", "validation", "evidence", "events", "cloud", "api"]
        bundle: dict[str, Any] = {
            "generated_at": f"{datetime.utcnow().isoformat(timespec='seconds')} UTC",
            "domain_id": domain_id,
            "sections": selected,
        }
        if domain_id:
            domains = await self.get_domains()
            found = next((item for item in domains if item["id"] == domain_id), None)
            if found:
                bundle["domain"] = found["domain"]
        if "risk" in selected:
            bundle["risk"] = self.report_page(await self.get_risk_scores(domain_id, limit=limit), limit)
        if "playbooks" in selected:
            bundle["playbooks"] = self.report_page(await self.get_attack_playbooks(domain_id, limit=limit), limit)
        if "validation" in selected:
            validation = await self.get_validation_queue(domain_id, limit=limit)
            if validation_status:
                validation["rows"] = [row for row in validation["rows"] if row.get("status") == validation_status]
                validation["filtered_status"] = validation_status
            bundle["validation"] = self.report_page(validation, limit)
        if "evidence" in selected:
            bundle["evidence"] = self.report_page(await self.get_evidence_packs(domain_id, limit=limit), limit)
        if "events" in selected:
            bundle["events"] = self.report_page(await self.get_asset_events(domain_id, limit=limit), limit)
        if "cloud" in selected:
            bundle["cloud"] = self.report_page(await self.get_cloud_assets(domain_id, limit=limit), limit)
        if "api" in selected:
            bundle["api"] = self.report_page(await self.get_api_surfaces(domain_id, limit=limit), limit)
        return bundle

    async def build_report_markdown(
        self,
        domain_id: int | None = None,
        limit: int = 50,
        sections: list[str] | None = None,
        validation_status: str | None = None,
    ) -> str:
        bundle = await self.build_report_bundle(domain_id, limit, sections, validation_status)
        title = "Recon Report"
        if bundle.get("domain"):
            title = f"Recon Report: {bundle['domain']}"
        lines = [f"# {title}", "", f"Generated: {bundle['generated_at']}", ""]
        if "risk" in bundle:
            lines.append("## Highest Risk Assets")
            for item in bundle["risk"]["rows"][:limit]:
                lines.append(f"- **{item['priority']} / {item['score']}** `{item['location']}` - {', '.join(item.get('reasons') or [])}")
            lines.append("")
        if "playbooks" in bundle:
            lines.append("## Attack Playbooks")
            for item in bundle["playbooks"]["rows"][:limit]:
                reasons = ", ".join(item.get("reasons") or [])
                lines.append(f"- **{item['priority']} / {item['check_type']}** `{item['target_url']}` - {item['owasp_category']} {reasons}")
            lines.append("")
        if "validation" in bundle:
            heading = "Validation Queue"
            if bundle["validation"].get("filtered_status"):
                heading += f" ({bundle['validation']['filtered_status']})"
            lines.append(f"## {heading}")
            for item in bundle["validation"]["rows"][:limit]:
                lines.append(f"- **{item['priority']} / {item['status']}** `{item['location']}`")
            lines.append("")
        if "evidence" in bundle:
            lines.append("## Evidence Packs")
            for item in bundle["evidence"]["rows"][:limit]:
                lines.append(f"- **{item['severity']}** `{item['location']}` - {item['summary'] or item['title']}")
            lines.append("")
        if "events" in bundle:
            lines.append("## Recent Changes")
            for item in bundle["events"]["rows"][:limit]:
                lines.append(f"- `{item['event_type']}` {item['entity_type']} `{item['location']}`")
            lines.append("")
        if "cloud" in bundle:
            lines.append("## Cloud Assets")
            for item in bundle["cloud"]["rows"][:limit]:
                lines.append(f"- **{item['provider']} / {item['asset_type']}** `{item['identifier']}` - {item['location']}")
            lines.append("")
        if "api" in bundle:
            lines.append("## API Surfaces")
            for item in bundle["api"]["rows"][:limit]:
                flags = ", ".join(item.get("risk_flags") or [])
                lines.append(f"- **{item['surface_type']}** `{item['location']}` status={item.get('status_code') or 'unknown'} ops={item.get('operations_count') or 0} {flags}")
            lines.append("")
        return "\n".join(lines)

    async def get_focus_cards(self, domain_id: int | None = None, limit: int = 12) -> dict[str, list[dict]]:
        assert self.pool is not None
        risk_page = await self.get_risk_scores(domain_id, limit=max(10, min(int(limit), 50)), offset=0)
        high_signal_endpoints = []
        for item in risk_page.get("rows") or []:
            high_signal_endpoints.append(
                {
                    "domain": item.get("domain"),
                    "full_url": item.get("location"),
                    "location": item.get("location"),
                    "status_code": None,
                    "source": item.get("entity_type"),
                    "parameters": [],
                    "risk_tags": item.get("reasons") or [],
                    "reasons": item.get("reasons") or [],
                    "priority": item.get("severity_override") or item.get("priority"),
                    "score": item.get("score"),
                    "last_seen": item.get("updated_at"),
                }
            )
        async with self.pool.acquire() as conn:
            notable_findings = await conn.fetch(
                """
                SELECT d.domain, f.severity, f.finding_type, f.location, f.details, f.first_seen, f.last_seen, f.is_resolved
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND f.severity IN ('critical', 'high', 'medium')
                  AND f.finding_type NOT IN (
                    'api_surface_discovered', 'host_fingerprint_changed',
                    'interesting_bruteforce_hit', 'interesting_exposed_path',
                    'interesting_open_port', 'js_asset_changed',
                    'js_dom_xss_candidate', 'js_dom_xss_sinks',
                    'js_secret_like_strings', 'js_sensitive_admin_surface',
                    'risky_url_parameter'
                  )
                  AND f.finding_type NOT ILIKE '%metrics%'
                ORDER BY f.severity, f.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
        return {
            "high_signal_endpoints": high_signal_endpoints,
            "notable_findings": [dict(row) for row in notable_findings],
        }

    async def get_researcher_focus(self, domain_id: int | None = None, limit: int = 50) -> dict[str, list[dict]]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            high_signal_endpoints = await conn.fetch(
                """
                WITH recent_endpoints AS MATERIALIZED (
                  SELECT e.*
                  FROM endpoints e
                  JOIN live_hosts lh ON lh.id = e.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE $1::int IS NULL OR s.domain_id = $1
                  ORDER BY e.last_seen DESC
                  LIMIT 10000
                )
                SELECT
                  d.domain,
                  s.subdomain,
                  lh.url AS base_url,
                  e.path,
                  (lh.url || e.path) AS full_url,
                  e.status_code,
                  lh.content_length AS response_size,
                  e.source,
                  e.parameters,
                  e.risk_tags,
                  COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies,
                  ARRAY_REMOVE(ARRAY[
                    CASE WHEN cardinality(e.risk_tags) > 0 THEN 'risk tags' END,
                    CASE WHEN jsonb_array_length(e.parameters) > 0 THEN 'parameters' END,
                    CASE WHEN (lh.url || e.path) ~* '(admin|internal|debug|graphql|api|swagger|openapi|actuator|config|backup|token|auth|login)' THEN 'sensitive path' END,
                    CASE WHEN e.source = 'js_analysis' THEN 'from js analysis' END,
                    CASE WHEN lh.content_length > 100000 THEN 'large response' END,
                    CASE WHEN EXISTS (SELECT 1 FROM technologies t WHERE t.live_host_id = lh.id AND t.technology ILIKE '%graphql%') THEN 'graphql tech' END
                  ], NULL) AS reasons,
                  e.first_seen,
                  e.last_seen
                FROM recent_endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                LEFT JOIN LATERAL (
                  SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                  FROM technologies t
                  WHERE t.live_host_id = lh.id
                ) tech ON TRUE
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND (
                    cardinality(e.risk_tags) > 0
                    OR jsonb_array_length(e.parameters) > 0
                    OR (lh.url || e.path) ~* '(admin|internal|debug|graphql|api|swagger|openapi|actuator|config|backup|token|auth|login)'
                    OR e.source = 'js_analysis'
                    OR lh.content_length > 100000
                    OR EXISTS (SELECT 1 FROM technologies t WHERE t.live_host_id = lh.id AND t.technology ILIKE '%graphql%')
                  )
                ORDER BY
                  cardinality(e.risk_tags) DESC,
                  jsonb_array_length(e.parameters) DESC,
                  e.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            exposed_admin = await conn.fetch(
                """
                WITH recent_endpoints AS MATERIALIZED (
                  SELECT e.*
                  FROM endpoints e
                  JOIN live_hosts lh ON lh.id = e.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE $1::int IS NULL OR s.domain_id = $1
                  ORDER BY e.last_seen DESC
                  LIMIT 10000
                )
                SELECT d.domain, s.subdomain, (lh.url || e.path) AS full_url, e.status_code, e.source, e.first_seen, e.last_seen
                FROM recent_endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND (lh.url || e.path) ~* '(admin|debug|internal|actuator|swagger|openapi|config|backup)'
                  AND COALESCE(e.status_code, 0) IN (200, 401, 403)
                ORDER BY
                  CASE e.status_code WHEN 200 THEN 1 WHEN 401 THEN 2 WHEN 403 THEN 3 ELSE 4 END,
                  e.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            js_intel = await conn.fetch(
                """
                SELECT d.domain, ja.asset_url, ja.http_status, ja.size_bytes, ja.source, jar.risk_summary, jar.extraction, jar.analyzed_at
                FROM js_analysis_results jar
                JOIN js_assets ja ON ja.id = jar.js_asset_id
                JOIN live_hosts lh ON lh.id = ja.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND (
                    COALESCE(jsonb_array_length(jar.extraction->'tokens_or_secret_like_strings'), 0) > 0
                    OR COALESCE(jsonb_array_length(jar.extraction->'dangerous_dom_sinks'), 0) > 0
                    OR COALESCE(jsonb_array_length(jar.extraction->'graphql_hints'), 0) > 0
                    OR COALESCE((jar.risk_summary->>'api_url_count')::int, 0) > 0
                  )
                ORDER BY jar.analyzed_at DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            notable_findings = await conn.fetch(
                """
                SELECT d.domain, f.severity, f.finding_type, f.location, f.details, f.first_seen, f.last_seen, f.is_resolved
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND (f.severity IN ('critical', 'high', 'medium') OR f.finding_type LIKE 'nuclei_%')
                ORDER BY
                  CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  f.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            host_changes = await conn.fetch(
                """
                SELECT d.domain, f.location, f.details, f.first_seen, f.last_seen
                FROM findings f
                LEFT JOIN domains d ON d.id = f.domain_id
                WHERE ($1::int IS NULL OR d.id = $1)
                  AND f.finding_type = 'host_fingerprint_changed'
                ORDER BY f.last_seen DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            status_breakdown = await conn.fetch(
                """
                SELECT e.status_code, COUNT(*) AS count
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE e.status_code IS NOT NULL AND ($1::int IS NULL OR d.id = $1)
                GROUP BY e.status_code
                ORDER BY count DESC, e.status_code
                LIMIT 20
                """,
                domain_id,
            )
            tech_breakdown = await conn.fetch(
                """
                SELECT t.technology, COUNT(DISTINCT lh.id) AS host_count, MAX(t.last_seen) AS last_seen
                FROM technologies t
                JOIN live_hosts lh ON lh.id = t.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                GROUP BY t.technology
                ORDER BY host_count DESC, t.technology
                LIMIT 25
                """,
                domain_id,
            )
            growth_24h = await conn.fetch(
                """
                SELECT
                  d.domain,
                  COALESCE(sd.count, 0) AS new_subdomains,
                  COALESCE(lh.count, 0) AS new_live_hosts,
                  COALESCE(ep.count, 0) AS new_endpoints,
                  COALESCE(ja.count, 0) AS new_js_assets
                FROM domains d
                LEFT JOIN (
                  SELECT domain_id, COUNT(*) AS count
                  FROM subdomains
                  WHERE first_seen > NOW() - INTERVAL '24 hours'
                  GROUP BY domain_id
                ) sd ON sd.domain_id = d.id
                LEFT JOIN (
                  SELECT s.domain_id, COUNT(*) AS count
                  FROM live_hosts lh
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE lh.first_seen > NOW() - INTERVAL '24 hours'
                  GROUP BY s.domain_id
                ) lh ON lh.domain_id = d.id
                LEFT JOIN (
                  SELECT s.domain_id, COUNT(*) AS count
                  FROM endpoints e
                  JOIN live_hosts lh ON lh.id = e.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE e.first_seen > NOW() - INTERVAL '24 hours'
                  GROUP BY s.domain_id
                ) ep ON ep.domain_id = d.id
                LEFT JOIN (
                  SELECT s.domain_id, COUNT(*) AS count
                  FROM js_assets ja
                  JOIN live_hosts lh ON lh.id = ja.live_host_id
                  JOIN subdomains s ON s.id = lh.subdomain_id
                  WHERE ja.first_seen > NOW() - INTERVAL '24 hours'
                  GROUP BY s.domain_id
                ) ja ON ja.domain_id = d.id
                WHERE $1::int IS NULL OR d.id = $1
                  AND (COALESCE(sd.count, 0) + COALESCE(lh.count, 0) + COALESCE(ep.count, 0) + COALESCE(ja.count, 0)) > 0
                ORDER BY new_endpoints DESC, new_live_hosts DESC, new_subdomains DESC, d.domain
                LIMIT 25
                """,
                domain_id,
            )
        return {
            "high_signal_endpoints": [dict(row) for row in high_signal_endpoints],
            "exposed_admin": [dict(row) for row in exposed_admin],
            "js_intel": [dict(row) for row in js_intel],
            "notable_findings": [dict(row) for row in notable_findings],
            "host_changes": [dict(row) for row in host_changes],
            "status_breakdown": [dict(row) for row in status_breakdown],
            "tech_breakdown": [dict(row) for row in tech_breakdown],
            "growth_24h": [dict(row) for row in growth_24h],
        }

    async def get_scan_options(self, domain_id: int | None = None, limit: int = 100) -> list[dict]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                  ss.id,
                  d.domain,
                  ss.scan_started_at,
                  ss.scan_finished_at,
                  ss.duration_seconds,
                  ss.first_run,
                  ss.new_counts,
                  ss.totals,
                  ss.metadata
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                WHERE $1::int IS NULL OR d.id = $1
                ORDER BY ss.scan_finished_at DESC
                LIMIT $2
                """,
                domain_id,
                int(limit),
            )
            return [dict(row) for row in rows]

    async def get_scan(self, scan_id: int, domain_id: int | None = None) -> dict | None:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                  ss.id,
                  ss.domain_id,
                  d.domain,
                  ss.scan_started_at,
                  ss.scan_finished_at,
                  ss.duration_seconds,
                  ss.first_run,
                  ss.new_counts,
                  ss.totals,
                  ss.metadata
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                WHERE ss.id = $1
                  AND ($2::int IS NULL OR d.id = $2)
                """,
                scan_id,
                domain_id,
            )
            return dict(row) if row else None

    async def get_scan_table(
        self,
        name: str,
        scan_id: int,
        limit: int | None = TABLE_LIMIT,
        offset: int = 0,
        filters: dict[str, str] | None = None,
    ) -> list[dict]:
        assert self.pool is not None
        if name not in SCAN_TABLES:
            return []
        filters = filters or {}
        offset = max(0, int(offset))
        if name == "urls":
            clauses, values = self._scan_url_clauses(scan_id, filters)
            sql = f"""
                SELECT d.domain, s.subdomain, lh.url AS base_url, e.path, (lh.url || e.path) AS full_url, e.status_code, e.probed_at, e.source, js_refs.js_references, e.risk_tags, e.parameters, lh.content_length AS response_size, COALESCE(tech.technologies, ARRAY[]::text[]) AS technologies, e.first_seen, e.last_seen
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN subdomains s ON s.domain_id = d.id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN endpoints e ON e.live_host_id = lh.id
                LEFT JOIN LATERAL (
                  SELECT ARRAY_AGG(DISTINCT t.technology ORDER BY t.technology) AS technologies
                  FROM technologies t
                  WHERE t.live_host_id = lh.id
                ) tech ON TRUE
                LEFT JOIN LATERAL (
                  SELECT ARRAY_AGG(DISTINCT ja.asset_url ORDER BY ja.asset_url) AS js_references
                  FROM endpoint_js_references ejr
                  JOIN js_assets ja ON ja.id = ejr.js_asset_id
                  WHERE ejr.endpoint_id = e.id
                ) js_refs ON TRUE
                WHERE {" AND ".join(clauses)}
                ORDER BY e.first_seen DESC
            """
            if limit is not None:
                sql += f"\nLIMIT {int(limit)}"
                if offset:
                    sql += f"\nOFFSET {offset}"
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(sql, *values)
                return [dict(row) for row in rows]

        if name == "js":
            clauses, values = self._scan_js_clauses(scan_id, filters)
            sql = f"""
                SELECT d.domain, lh.url AS host_url, ja.asset_url, ja.source, ja.http_status, ja.size_bytes, ja.sha256, ja.first_seen, ja.last_seen
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN subdomains s ON s.domain_id = d.id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN js_assets ja ON ja.live_host_id = lh.id
                WHERE {" AND ".join(clauses)}
                ORDER BY ja.first_seen DESC
            """
            if limit is not None:
                sql += f"\nLIMIT {int(limit)}"
                if offset:
                    sql += f"\nOFFSET {offset}"
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(sql, *values)
                return [dict(row) for row in rows]

        if name == "parameters":
            clauses, values = self._scan_parameter_clauses(scan_id, filters)
            sql = SCAN_PARAMETER_SCOPE_SQL + f"""
                SELECT d.domain, lh.url AS base_url, e.path, e.status_code, e.source,
                       up.param_name, up.example_value, up.risk_tags, up.first_seen, up.last_seen
                FROM scan_parameters up
                JOIN domains d ON d.id = up.domain_id
                JOIN subdomains s ON s.domain_id = up.domain_id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN endpoints e ON e.id = up.endpoint_id AND e.live_host_id = lh.id
                WHERE {" AND ".join(clauses)}
                ORDER BY cardinality(up.risk_tags) DESC, up.first_seen DESC
            """
            if limit is not None:
                sql += f"\nLIMIT {int(limit)}"
                if offset:
                    sql += f"\nOFFSET {offset}"
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(sql, *values)
                return [dict(row) for row in rows]

        queries = {
            "subdomains": """
                SELECT d.domain, s.subdomain, s.is_resolved, s.ip_addresses, s.first_seen, s.last_seen
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN subdomains s ON s.domain_id = d.id
                WHERE ss.id = $1
                  AND s.first_seen >= ss.scan_started_at
                  AND s.first_seen <= ss.scan_finished_at
                ORDER BY s.first_seen DESC
            """,
            "live_hosts": """
                SELECT d.domain, s.subdomain, lh.url, lh.status_code, lh.title, lh.webserver, lh.content_length, lh.first_seen, lh.last_seen
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN subdomains s ON s.domain_id = d.id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                WHERE ss.id = $1
                  AND lh.first_seen >= ss.scan_started_at
                  AND lh.first_seen <= ss.scan_finished_at
                ORDER BY lh.first_seen DESC
            """,
            "findings": """
                SELECT d.domain, f.finding_type, f.severity, f.location, f.details, f.first_seen, f.last_seen, f.is_resolved
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN findings f ON f.domain_id = d.id
                WHERE ss.id = $1
                  AND f.first_seen >= ss.scan_started_at
                  AND f.first_seen <= ss.scan_finished_at
                ORDER BY
                  CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  f.first_seen DESC
            """,
            "screenshots": """
                SELECT d.domain, lh.url, sc.screenshot_path, sc.capture_reason, sc.file_size, sc.captured_at, sc.last_seen
                FROM scan_snapshots ss
                JOIN domains d ON d.id = ss.domain_id
                JOIN subdomains s ON s.domain_id = d.id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN screenshots sc ON sc.live_host_id = lh.id
                WHERE ss.id = $1
                  AND sc.captured_at >= ss.scan_started_at
                  AND sc.captured_at <= ss.scan_finished_at
                ORDER BY sc.captured_at DESC
            """,
        }
        sql = queries[name]
        if limit is not None:
            sql += f"\nLIMIT {int(limit)}"
            if offset:
                sql += f"\nOFFSET {offset}"
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(sql, scan_id)
            return [dict(row) for row in rows]

    async def get_scan_table_page(
        self,
        name: str,
        scan_id: int,
        limit: int = TABLE_LIMIT,
        offset: int = 0,
        filters: dict[str, str] | None = None,
    ) -> dict:
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        scoped_filters = filters if name in {"urls", "js", "parameters"} else None
        counts = await self.get_scan_counts(scan_id, scoped_filters, only=name)
        rows = await self.get_scan_table(name, scan_id, limit=limit, offset=offset, filters=scoped_filters)
        return {"rows": rows, "total": int(counts.get(name, 0)), "limit": limit, "offset": offset}

    async def get_scan_ai_triage_page(self, scan_id: int, limit: int = TABLE_LIMIT, offset: int = 0) -> dict:
        assert self.pool is not None
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM scan_snapshots ss
                JOIN ai_triage_items ati ON ati.domain_id = ss.domain_id
                WHERE ss.id = $1
                  AND ati.first_seen >= ss.scan_started_at
                  AND ati.first_seen <= ss.scan_finished_at
                  AND ati.resolved = FALSE
                """,
                scan_id,
            )
            rows = await conn.fetch(
                """
                SELECT
                  ati.id,
                  d.domain,
                  ati.item_type,
                  ati.title,
                  ati.location,
                  ati.priority,
                  ati.score,
                  ati.reasons,
                  ati.recommended_actions,
                  ati.run_profiles,
                  ati.alert,
                  ati.first_seen,
                  ati.last_seen
                FROM scan_snapshots ss
                JOIN ai_triage_items ati ON ati.domain_id = ss.domain_id
                JOIN domains d ON d.id = ss.domain_id
                WHERE ss.id = $1
                  AND ati.first_seen >= ss.scan_started_at
                  AND ati.first_seen <= ss.scan_finished_at
                  AND ati.resolved = FALSE
                ORDER BY
                  CASE ati.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
                  ati.score DESC,
                  ati.last_seen DESC
                LIMIT $2 OFFSET $3
                """,
                scan_id,
                limit,
                offset,
            )
        return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def search_scan_database(self, scan_id: int, query: str, limit: int = SEARCH_LIMIT) -> list[dict]:
        assert self.pool is not None
        query = query.strip()
        if len(query) < 2:
            return []
        needle = f"%{query}%"
        per_table = max(10, int(limit) // 8)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM (
                  SELECT 'subdomains' AS result_type, d.domain, s.subdomain AS title, s.subdomain AS location, NULL::text AS severity, s.first_seen, s.last_seen, jsonb_build_object('is_resolved', s.is_resolved, 'ip_addresses', s.ip_addresses) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id
                  WHERE ss.id = $2 AND s.first_seen >= ss.scan_started_at AND s.first_seen <= ss.scan_finished_at AND s.subdomain ILIKE $1
                  ORDER BY s.last_seen DESC
                  LIMIT $3
                ) subdomains
                UNION ALL
                SELECT * FROM (
                  SELECT 'live_hosts' AS result_type, d.domain, lh.url AS title, lh.url AS location, NULL::text AS severity, lh.first_seen, lh.last_seen, jsonb_build_object('status_code', lh.status_code, 'title', lh.title, 'webserver', lh.webserver) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id JOIN live_hosts lh ON lh.subdomain_id = s.id
                  WHERE ss.id = $2 AND lh.first_seen >= ss.scan_started_at AND lh.first_seen <= ss.scan_finished_at AND (lh.url ILIKE $1 OR COALESCE(lh.title, '') ILIKE $1 OR COALESCE(lh.webserver, '') ILIKE $1)
                  ORDER BY lh.last_seen DESC
                  LIMIT $3
                ) live_hosts
                UNION ALL
                SELECT * FROM (
                  SELECT 'infrastructure' AS result_type, d.domain,
                         (host(ii.ip_address) || COALESCE(':' || ns.port::text, '')) AS title,
                         (host(ii.ip_address) || COALESCE(':' || ns.port::text, '')) AS location,
                         CASE WHEN ns.port IN (2375,2376,6443,10250,9200,9300,27017,6379,11211) THEN 'high' ELSE NULL::text END AS severity,
                         COALESCE(ns.first_seen, ii.first_seen) AS first_seen,
                         COALESCE(ns.last_seen, ii.last_seen) AS last_seen,
                         jsonb_build_object(
                           'classification', ii.classification,
                           'provider', ii.provider,
                           'asn', ii.asn,
                           'ptr_name', ii.ptr_name,
                           'port', ns.port,
                           'state', ns.state,
                           'service', ns.service,
                           'product', ns.product,
                           'version', ns.version
                         ) AS details
                  FROM infrastructure_ips ii
                  JOIN domains d ON d.id = ii.domain_id
                  LEFT JOIN network_services ns ON ns.ip_asset_id = ii.id
                  WHERE ($2::int IS NULL OR d.id = $2)
                    AND (
                      host(ii.ip_address) ILIKE $1
                      OR COALESCE(ii.ptr_name, '') ILIKE $1
                      OR COALESCE(ii.asn, '') ILIKE $1
                      OR COALESCE(ii.asn_org, '') ILIKE $1
                      OR COALESCE(ii.provider, '') ILIKE $1
                      OR COALESCE(ns.port::text, '') ILIKE $1
                      OR COALESCE(ns.service, '') ILIKE $1
                      OR COALESCE(ns.product, '') ILIKE $1
                    )
                  ORDER BY COALESCE(ns.last_seen, ii.last_seen) DESC
                  LIMIT $3
                ) infrastructure
                UNION ALL
                SELECT * FROM (
                  SELECT 'endpoints' AS result_type, d.domain, e.path AS title, (lh.url || e.path) AS location, NULL::text AS severity, e.first_seen, e.last_seen, jsonb_build_object('source', e.source, 'status_code', e.status_code, 'risk_tags', e.risk_tags, 'parameters', e.parameters) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id JOIN live_hosts lh ON lh.subdomain_id = s.id JOIN endpoints e ON e.live_host_id = lh.id
                  WHERE ss.id = $2 AND e.first_seen >= ss.scan_started_at AND e.first_seen <= ss.scan_finished_at AND ((lh.url || e.path) ILIKE $1 OR e.path ILIKE $1 OR e.source ILIKE $1 OR e.parameters::text ILIKE $1 OR e.risk_tags::text ILIKE $1)
                  ORDER BY e.last_seen DESC
                  LIMIT $3
                ) endpoints
                UNION ALL
                SELECT * FROM (
                  SELECT 'js_assets' AS result_type, d.domain, ja.asset_url AS title, ja.asset_url AS location, NULL::text AS severity, ja.first_seen, ja.last_seen, jsonb_build_object('source', ja.source, 'http_status', ja.http_status, 'sha256', ja.sha256) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id JOIN live_hosts lh ON lh.subdomain_id = s.id JOIN js_assets ja ON ja.live_host_id = lh.id
                  WHERE ss.id = $2 AND ja.first_seen >= ss.scan_started_at AND ja.first_seen <= ss.scan_finished_at AND (ja.asset_url ILIKE $1 OR ja.source ILIKE $1 OR COALESCE(ja.sha256, '') ILIKE $1)
                  ORDER BY ja.last_seen DESC
                  LIMIT $3
                ) js_assets
                UNION ALL
                SELECT * FROM (
                  SELECT 'parameters' AS result_type, d.domain, up.param_name AS title, (lh.url || e.path) AS location, NULL::text AS severity, up.first_seen, up.last_seen, jsonb_build_object('example_value', up.example_value, 'risk_tags', up.risk_tags) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id JOIN live_hosts lh ON lh.subdomain_id = s.id JOIN endpoints e ON e.live_host_id = lh.id JOIN url_parameters up ON up.endpoint_id = e.id
                  WHERE ss.id = $2 AND up.first_seen >= ss.scan_started_at AND up.first_seen <= ss.scan_finished_at AND (up.param_name ILIKE $1 OR COALESCE(up.example_value, '') ILIKE $1 OR up.risk_tags::text ILIKE $1 OR (lh.url || e.path) ILIKE $1)
                  ORDER BY up.last_seen DESC
                  LIMIT $3
                ) parameters
                UNION ALL
                SELECT * FROM (
                  SELECT 'findings' AS result_type, d.domain, f.finding_type AS title, f.location, f.severity, f.first_seen, f.last_seen, f.details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN findings f ON f.domain_id = d.id
                  WHERE ss.id = $2 AND f.first_seen >= ss.scan_started_at AND f.first_seen <= ss.scan_finished_at AND (f.finding_type ILIKE $1 OR f.severity ILIKE $1 OR f.location ILIKE $1 OR f.details::text ILIKE $1)
                  ORDER BY f.last_seen DESC
                  LIMIT $3
                ) findings
                UNION ALL
                SELECT * FROM (
                  SELECT 'screenshots' AS result_type, d.domain, sc.screenshot_path AS title, lh.url AS location, NULL::text AS severity, sc.captured_at AS first_seen, sc.last_seen, jsonb_build_object('capture_reason', sc.capture_reason, 'screenshot_path', sc.screenshot_path) AS details
                  FROM scan_snapshots ss JOIN domains d ON d.id = ss.domain_id JOIN subdomains s ON s.domain_id = d.id JOIN live_hosts lh ON lh.subdomain_id = s.id JOIN screenshots sc ON sc.live_host_id = lh.id
                  WHERE ss.id = $2 AND sc.captured_at >= ss.scan_started_at AND sc.captured_at <= ss.scan_finished_at AND (sc.screenshot_path ILIKE $1 OR sc.capture_reason ILIKE $1 OR lh.url ILIKE $1)
                  ORDER BY sc.last_seen DESC
                  LIMIT $3
                ) screenshots
                ORDER BY last_seen DESC
                LIMIT $4
                """,
                needle,
                scan_id,
                per_table,
                int(limit),
            )
            return [dict(row) for row in rows]

    async def get_scan_bundle(
        self,
        scan_id: int,
        limit: int | None = TABLE_LIMIT,
        filters: dict[str, str] | None = None,
    ) -> dict[str, list[dict]]:
        return {name: await self.get_scan_table(name, scan_id, limit, filters if name in {"urls", "js", "parameters"} else None) for name in sorted(SCAN_TABLES)}

    def _scan_parameter_clauses(self, scan_id: int, filters: dict[str, str]) -> tuple[list[str], list[Any]]:
        clauses = ["TRUE"]
        values: list[Any] = [scan_id]
        if filters.get("status_code"):
            try:
                values.append(int(filters["status_code"]))
                clauses.append(f"e.status_code = ${len(values)}")
            except ValueError:
                pass
        return clauses, values

    def _scan_url_clauses(self, scan_id: int, filters: dict[str, str]) -> tuple[list[str], list[Any]]:
        clauses = [
            "ss.id = $1",
            "e.first_seen >= ss.scan_started_at",
            "e.first_seen <= ss.scan_finished_at",
        ]
        values: list[Any] = [scan_id]
        if filters.get("subdomain"):
            values.append(filters["subdomain"])
            clauses.append(f"s.subdomain = ${len(values)}")
        if filters.get("live_host"):
            values.append(filters["live_host"])
            clauses.append(f"lh.url = ${len(values)}")
        if filters.get("source"):
            values.append(filters["source"])
            clauses.append(f"e.source = ${len(values)}")
        if filters.get("status_code"):
            try:
                values.append(int(filters["status_code"]))
                clauses.append(f"e.status_code = ${len(values)}")
            except ValueError:
                pass
        if filters.get("has_parameters"):
            lowered = filters["has_parameters"].lower()
            if lowered in {"1", "true", "yes", "on"}:
                clauses.append("jsonb_typeof(e.parameters) = 'array' AND jsonb_array_length(e.parameters) > 0")
            elif lowered in {"0", "false", "no", "off"}:
                clauses.append("(jsonb_typeof(e.parameters) != 'array' OR jsonb_array_length(e.parameters) = 0)")
        if filters.get("tech"):
            tech_value = filters["tech"]
            values.append(tech_value if "%" in tech_value else f"%{tech_value}%")
            clauses.append(
                f"""
                (
                EXISTS (
                  SELECT 1
                  FROM technologies t
                  WHERE t.live_host_id = lh.id
                    AND t.technology ILIKE ${len(values)}
                )
                OR (lh.url || e.path) ILIKE ${len(values)}
                )
                """
            )
        if filters.get("contains"):
            values.append(f"%{filters['contains']}%")
            clauses.append(
                f"""
                (
                  (lh.url || e.path) ILIKE ${len(values)}
                  OR e.path ILIKE ${len(values)}
                  OR e.source ILIKE ${len(values)}
                  OR e.parameters::text ILIKE ${len(values)}
                  OR e.risk_tags::text ILIKE ${len(values)}
                  OR COALESCE(lh.title, '') ILIKE ${len(values)}
                  OR COALESCE(lh.webserver, '') ILIKE ${len(values)}
                )
                """
            )
        if filters.get("response_size_gt"):
            try:
                values.append(int(filters["response_size_gt"]))
                clauses.append(f"COALESCE(lh.content_length, 0) > ${len(values)}")
            except ValueError:
                pass
        return clauses, values

    def _scan_js_clauses(self, scan_id: int, filters: dict[str, str]) -> tuple[list[str], list[Any]]:
        clauses = [
            "ss.id = $1",
            "ja.first_seen >= ss.scan_started_at",
            "ja.first_seen <= ss.scan_finished_at",
        ]
        values: list[Any] = [scan_id]
        if filters.get("subdomain"):
            values.append(filters["subdomain"])
            clauses.append(f"s.subdomain = ${len(values)}")
        if filters.get("live_host"):
            values.append(filters["live_host"])
            clauses.append(f"lh.url = ${len(values)}")
        if filters.get("source"):
            values.append(filters["source"])
            clauses.append(f"ja.source = ${len(values)}")
        if filters.get("status_code"):
            try:
                values.append(int(filters["status_code"]))
                clauses.append(f"ja.http_status = ${len(values)}")
            except ValueError:
                pass
        js_response = filters.get("js_response", "").strip().lower()
        if js_response == "200":
            clauses.append("ja.http_status = 200")
        elif js_response == "2xx":
            clauses.append("ja.http_status BETWEEN 200 AND 299")
        elif js_response == "3xx":
            clauses.append("ja.http_status BETWEEN 300 AND 399")
        elif js_response == "4xx":
            clauses.append("ja.http_status BETWEEN 400 AND 499")
        elif js_response == "5xx":
            clauses.append("ja.http_status BETWEEN 500 AND 599")
        elif js_response == "unknown":
            clauses.append("ja.http_status IS NULL")
        if filters.get("contains"):
            values.append(f"%{filters['contains']}%")
            clauses.append(
                f"""(
                  d.domain ILIKE ${len(values)}
                  OR s.subdomain ILIKE ${len(values)}
                  OR lh.url ILIKE ${len(values)}
                  OR ja.asset_url ILIKE ${len(values)}
                  OR ja.source ILIKE ${len(values)}
                  OR COALESCE(ja.sha256, '') ILIKE ${len(values)}
                )"""
            )
        return clauses, values

    async def get_scan_parameter_status_options(self, scan_id: int) -> dict:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                SCAN_PARAMETER_SCOPE_SQL + """
                SELECT e.status_code, COUNT(*)::int AS count
                FROM scan_parameters up
                JOIN subdomains s ON s.domain_id = up.domain_id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN endpoints e ON e.id = up.endpoint_id AND e.live_host_id = lh.id
                WHERE e.status_code IS NOT NULL
                GROUP BY e.status_code
                ORDER BY e.status_code
                """,
                scan_id,
            )
        return {"parameter_status_counts": [dict(row) for row in rows]}

    async def get_scan_counts(self, scan_id: int, filters: dict[str, str] | None = None,
                              only: str | None = None) -> dict[str, int]:
        assert self.pool is not None
        filters = filters or {}
        counts: dict[str, int] = {}
        queries = {
            "subdomains": """
                SELECT COUNT(*)
                FROM scan_snapshots ss
                JOIN subdomains s ON s.domain_id = ss.domain_id
                WHERE ss.id = $1
                  AND s.first_seen >= ss.scan_started_at
                  AND s.first_seen <= ss.scan_finished_at
            """,
            "live_hosts": """
                SELECT COUNT(*)
                FROM scan_snapshots ss
                JOIN subdomains s ON s.domain_id = ss.domain_id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                WHERE ss.id = $1
                  AND lh.first_seen >= ss.scan_started_at
                  AND lh.first_seen <= ss.scan_finished_at
            """,
            "findings": """
                SELECT COUNT(*)
                FROM scan_snapshots ss
                JOIN findings f ON f.domain_id = ss.domain_id
                WHERE ss.id = $1
                  AND f.first_seen >= ss.scan_started_at
                  AND f.first_seen <= ss.scan_finished_at
            """,
            "screenshots": """
                SELECT COUNT(*)
                FROM scan_snapshots ss
                JOIN subdomains s ON s.domain_id = ss.domain_id
                JOIN live_hosts lh ON lh.subdomain_id = s.id
                JOIN screenshots sc ON sc.live_host_id = lh.id
                WHERE ss.id = $1
                  AND sc.captured_at >= ss.scan_started_at
                  AND sc.captured_at <= ss.scan_finished_at
            """,
        }
        async with self.pool.acquire() as conn:
            for name, sql in queries.items():
                if only is not None and name != only:
                    continue
                counts[name] = int(await conn.fetchval(sql, scan_id) or 0)
            if only is None or only == "parameters":
                clauses, values = self._scan_parameter_clauses(scan_id, filters)
                counts["parameters"] = int(await conn.fetchval(
                    SCAN_PARAMETER_SCOPE_SQL + f"""
                    SELECT COUNT(*)
                    FROM scan_parameters up
                    JOIN subdomains s ON s.domain_id = up.domain_id
                    JOIN live_hosts lh ON lh.subdomain_id = s.id
                    JOIN endpoints e ON e.id = up.endpoint_id AND e.live_host_id = lh.id
                    WHERE {" AND ".join(clauses)}
                    """,
                    *values,
                ) or 0)
            if only is None or only == "urls":
                clauses, values = self._scan_url_clauses(scan_id, filters)
                counts["urls"] = int(
                    await conn.fetchval(
                        f"""
                        SELECT COUNT(*)
                        FROM scan_snapshots ss
                        JOIN domains d ON d.id = ss.domain_id
                        JOIN subdomains s ON s.domain_id = d.id
                        JOIN live_hosts lh ON lh.subdomain_id = s.id
                        JOIN endpoints e ON e.live_host_id = lh.id
                        WHERE {" AND ".join(clauses)}
                        """,
                        *values,
                    )
                    or 0
                )
            if only is None or only == "js":
                clauses, values = self._scan_js_clauses(scan_id, filters)
                counts["js"] = int(
                    await conn.fetchval(
                        f"""
                        SELECT COUNT(*)
                        FROM scan_snapshots ss
                        JOIN domains d ON d.id = ss.domain_id
                        JOIN subdomains s ON s.domain_id = d.id
                        JOIN live_hosts lh ON lh.subdomain_id = s.id
                        JOIN js_assets ja ON ja.live_host_id = lh.id
                        WHERE {" AND ".join(clauses)}
                        """,
                        *values,
                    )
                    or 0
                )
        return counts

    async def search_endpoint_paths(
        self,
        query: str,
        domain_id: int | None = None,
        limit: int = TABLE_LIMIT,
        offset: int = 0,
    ) -> dict:
        assert self.pool is not None
        query = query.strip()
        limit = max(10, min(int(limit), 250))
        offset = max(0, int(offset))
        if not query:
            return {"rows": [], "total": 0, "limit": limit, "offset": offset}
        needle = f"{query}%" if query.startswith("/") else f"%{query}%"
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                """
                SELECT COUNT(*)
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE ($2::int IS NULL OR d.id = $2)
                  AND (e.path ILIKE $1 OR (lh.url || e.path) ILIKE $1)
                """,
                needle,
                domain_id,
            )
            rows = await conn.fetch(
                """
                SELECT
                  'endpoints' AS result_type,
                  d.domain,
                  e.path AS title,
                  (lh.url || e.path) AS location,
                  NULL::text AS severity,
                  e.first_seen,
                  e.last_seen,
                  jsonb_build_object(
                    'base_url', lh.url,
                    'subdomain', s.subdomain,
                    'source', e.source,
                    'status_code', e.status_code,
                    'risk_tags', e.risk_tags,
                    'parameters', e.parameters
                  ) AS details
                FROM endpoints e
                JOIN live_hosts lh ON lh.id = e.live_host_id
                JOIN subdomains s ON s.id = lh.subdomain_id
                JOIN domains d ON d.id = s.domain_id
                WHERE ($2::int IS NULL OR d.id = $2)
                  AND (e.path ILIKE $1 OR (lh.url || e.path) ILIKE $1)
                ORDER BY
                  CASE WHEN e.path ILIKE $1 THEN 0 ELSE 1 END,
                  e.last_seen DESC
                LIMIT $3 OFFSET $4
                """,
                needle,
                domain_id,
                limit,
                offset,
            )
        return {"rows": [dict(row) for row in rows], "total": int(total or 0), "limit": limit, "offset": offset}

    async def search_database(self, query: str, domain_id: int | None = None, limit: int = SEARCH_LIMIT) -> list[dict]:
        assert self.pool is not None
        query = query.strip()
        if len(query) < 2:
            return []
        structured = re.findall(r'(\w+):(?:"([^"]+)"|/([^/]+)/|(\S+))', query)
        if structured:
            filters: dict[str, str] = {}
            free_terms: list[str] = []
            port_filter: int | None = None
            for key, quoted, regex_value, plain in re.findall(r'(\w+):(?:"([^"]+)"|/([^/]+)/|(\S+))', query):
                value = quoted or regex_value or plain
                if key in {"status", "status_code"}:
                    filters["status_code"] = value
                elif key == "tech":
                    filters["tech"] = value
                elif key in {"contains", "title", "url"}:
                    filters["contains"] = value
                elif key == "port":
                    try:
                        port_filter = int(value)
                    except ValueError:
                        pass
                elif key == "regex":
                    filters["regex"] = value
            if port_filter is not None:
                async with self.pool.acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT 'infrastructure' AS result_type, d.domain,
                               (host(ii.ip_address) || ':' || ns.port::text) AS title,
                               (host(ii.ip_address) || ':' || ns.port::text) AS location,
                               CASE WHEN ns.port IN (2375,2376,6443,10250,9200,9300,27017,6379,11211) THEN 'high' ELSE NULL::text END AS severity,
                               ns.first_seen, ns.last_seen,
                               jsonb_build_object(
                                 'classification', ii.classification,
                                 'provider', ii.provider,
                                 'asn', ii.asn,
                                 'ptr_name', ii.ptr_name,
                                 'state', ns.state,
                                 'service', ns.service,
                                 'product', ns.product,
                                 'version', ns.version
                               ) AS details
                        FROM network_services ns
                        JOIN infrastructure_ips ii ON ii.id = ns.ip_asset_id
                        JOIN domains d ON d.id = ns.domain_id
                        WHERE ns.port = $1
                          AND ns.state = 'open'
                          AND ($2::int IS NULL OR ns.domain_id = $2)
                        ORDER BY ns.last_seen DESC
                        LIMIT $3
                        """,
                        port_filter,
                        domain_id,
                        int(limit),
                    )
                    return [dict(row) for row in rows]
            clauses, values = self._endpoint_clauses(domain_id, filters)
            if free_terms:
                values.append(f"%{' '.join(free_terms)}%")
                clauses.append(f"(lh.url || e.path) ILIKE ${len(values)}")
            if filters.get("regex"):
                values.append(filters["regex"])
                clauses.append(f"(lh.url || e.path) ~* ${len(values)}")
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    f"""
                    SELECT 'endpoints' AS result_type, d.domain, e.path AS title, (lh.url || e.path) AS location,
                           NULL::text AS severity, e.first_seen, e.last_seen,
                           jsonb_build_object('source', e.source, 'status_code', e.status_code, 'risk_tags', e.risk_tags, 'parameters', e.parameters, 'title', lh.title, 'webserver', lh.webserver) AS details
                    FROM endpoints e
                    JOIN live_hosts lh ON lh.id = e.live_host_id
                    JOIN subdomains s ON s.id = lh.subdomain_id
                    JOIN domains d ON d.id = s.domain_id
                    WHERE {" AND ".join(clauses)}
                    ORDER BY e.last_seen DESC
                    LIMIT ${len(values) + 1}
                    """,
                    *values,
                    int(limit),
                )
                return [dict(row) for row in rows]
        needle = f"%{query}%"
        per_table = max(10, int(limit) // 8)
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM (
                  SELECT 'subdomains' AS result_type, d.domain, s.subdomain AS title, s.subdomain AS location, NULL::text AS severity, s.first_seen, s.last_seen, jsonb_build_object('is_resolved', s.is_resolved, 'ip_addresses', s.ip_addresses) AS details
                  FROM subdomains s JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND s.subdomain ILIKE $1
                  ORDER BY s.last_seen DESC
                  LIMIT $3
                ) subdomains
                UNION ALL
                SELECT * FROM (
                  SELECT 'live_hosts' AS result_type, d.domain, lh.url AS title, lh.url AS location, NULL::text AS severity, lh.first_seen, lh.last_seen, jsonb_build_object('status_code', lh.status_code, 'title', lh.title, 'webserver', lh.webserver) AS details
                  FROM live_hosts lh JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND (lh.url ILIKE $1 OR COALESCE(lh.title, '') ILIKE $1 OR COALESCE(lh.webserver, '') ILIKE $1)
                  ORDER BY lh.last_seen DESC
                  LIMIT $3
                ) live_hosts
                UNION ALL
                SELECT * FROM (
                  SELECT 'endpoints' AS result_type, d.domain, e.path AS title, (lh.url || e.path) AS location, NULL::text AS severity, e.first_seen, e.last_seen, jsonb_build_object('source', e.source, 'status_code', e.status_code, 'risk_tags', e.risk_tags, 'parameters', e.parameters) AS details
                  FROM endpoints e JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND ((lh.url || e.path) ILIKE $1 OR e.path ILIKE $1 OR e.source ILIKE $1 OR e.parameters::text ILIKE $1 OR e.risk_tags::text ILIKE $1)
                  ORDER BY e.last_seen DESC
                  LIMIT $3
                ) endpoints
                UNION ALL
                SELECT * FROM (
                  SELECT 'js_assets' AS result_type, d.domain, ja.asset_url AS title, ja.asset_url AS location, NULL::text AS severity, ja.first_seen, ja.last_seen, jsonb_build_object('source', ja.source, 'http_status', ja.http_status, 'sha256', ja.sha256) AS details
                  FROM js_assets ja JOIN live_hosts lh ON lh.id = ja.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND (ja.asset_url ILIKE $1 OR ja.source ILIKE $1 OR COALESCE(ja.sha256, '') ILIKE $1)
                  ORDER BY ja.last_seen DESC
                  LIMIT $3
                ) js_assets
                UNION ALL
                SELECT * FROM (
                  SELECT 'parameters' AS result_type, d.domain, up.param_name AS title, (lh.url || e.path) AS location, NULL::text AS severity, up.first_seen, up.last_seen, jsonb_build_object('example_value', up.example_value, 'risk_tags', up.risk_tags) AS details
                  FROM url_parameters up JOIN endpoints e ON e.id = up.endpoint_id JOIN live_hosts lh ON lh.id = e.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND (up.param_name ILIKE $1 OR COALESCE(up.example_value, '') ILIKE $1 OR up.risk_tags::text ILIKE $1 OR (lh.url || e.path) ILIKE $1)
                  ORDER BY up.last_seen DESC
                  LIMIT $3
                ) parameters
                UNION ALL
                SELECT * FROM (
                  SELECT 'findings' AS result_type, d.domain, f.finding_type AS title, f.location, f.severity, f.first_seen, f.last_seen, f.details
                  FROM findings f LEFT JOIN domains d ON d.id = f.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND (f.finding_type ILIKE $1 OR f.severity ILIKE $1 OR f.location ILIKE $1 OR f.details::text ILIKE $1)
                  ORDER BY f.last_seen DESC
                  LIMIT $3
                ) findings
                UNION ALL
                SELECT * FROM (
                  SELECT 'screenshots' AS result_type, d.domain, sc.screenshot_path AS title, lh.url AS location, NULL::text AS severity, sc.captured_at AS first_seen, sc.last_seen, jsonb_build_object('capture_reason', sc.capture_reason, 'screenshot_path', sc.screenshot_path) AS details
                  FROM screenshots sc JOIN live_hosts lh ON lh.id = sc.live_host_id JOIN subdomains s ON s.id = lh.subdomain_id JOIN domains d ON d.id = s.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2) AND (sc.screenshot_path ILIKE $1 OR sc.capture_reason ILIKE $1 OR lh.url ILIKE $1)
                  ORDER BY sc.last_seen DESC
                  LIMIT $3
                ) screenshots
                UNION ALL
                SELECT * FROM (
                  SELECT 'search_intelligence' AS result_type, d.domain, COALESCE(sir.title, sir.category) AS title,
                         sir.url AS location, NULL::text AS severity, sir.first_seen, sir.last_seen,
                         jsonb_build_object(
                           'provider', sir.provider,
                           'category', sir.category,
                           'snippet', sir.snippet,
                           'query', sir.query,
                           'is_in_scope', sir.is_in_scope,
                           'status_code', sir.status_code,
                           'risk_tags', sir.risk_tags
                         ) AS details
                  FROM search_intel_results sir
                  JOIN domains d ON d.id = sir.domain_id
                  WHERE ($2::int IS NULL OR d.id = $2)
                    AND (sir.url ILIKE $1 OR COALESCE(sir.title, '') ILIKE $1
                         OR COALESCE(sir.snippet, '') ILIKE $1 OR sir.query ILIKE $1)
                  ORDER BY sir.last_seen DESC
                  LIMIT $3
                ) search_intelligence
                ORDER BY last_seen DESC
                LIMIT $4
                """,
                needle,
                domain_id,
                per_table,
                int(limit),
            )
            return [dict(row) for row in rows]

    def search_intelligence_status(self) -> dict[str, Any]:
        cfg = self.config.get("search_intelligence", {})
        provider = provider_from_config(cfg)
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "configured": provider is not None,
            "provider": provider.name if provider else None,
            "interval_hours": int(cfg.get("interval_hours", 168)),
            "query_count": min(
                int(cfg.get("max_queries_per_domain", 12)),
                12,
            ),
        }

    async def get_search_intel_runs(
        self,
        domain_id: int | None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT sir.id, sir.domain_id, d.domain, sir.provider, sir.status,
                       sir.query_count, sir.result_count, sir.new_result_count,
                       sir.in_scope_count, sir.started_at, sir.completed_at,
                       sir.error, sir.summary
                FROM search_intel_runs sir
                JOIN domains d ON d.id = sir.domain_id
                WHERE $1::int IS NULL OR sir.domain_id = $1
                ORDER BY sir.started_at DESC
                LIMIT $2
                """,
                domain_id,
                max(1, min(int(limit), 200)),
            )
        return [dict(row) for row in rows]

    async def get_search_intel_results(
        self,
        domain_id: int | None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "last_seen",
        direction: str = "desc",
        run_id: int | None = None,
        category: str = "",
        scope: str = "",
        contains: str = "",
    ) -> dict[str, Any]:
        assert self.pool is not None
        limit = max(10, min(int(limit), 5000))
        offset = max(0, int(offset))
        values: list[Any] = [domain_id]
        clauses = ["($1::int IS NULL OR sir.domain_id = $1)"]
        join = ""
        if run_id is not None:
            values.append(run_id)
            join = "JOIN search_intel_run_results sirr ON sirr.result_id = sir.id"
            clauses.append(f"sirr.run_id = ${len(values)}")
        if category:
            values.append(category)
            clauses.append(f"sir.category = ${len(values)}")
        if scope in {"in", "out"}:
            values.append(scope == "in")
            clauses.append(f"sir.is_in_scope = ${len(values)}")
        if contains:
            values.append(f"%{contains}%")
            clauses.append(
                f"(sir.url ILIKE ${len(values)} OR COALESCE(sir.title, '') ILIKE ${len(values)} "
                f"OR COALESCE(sir.snippet, '') ILIKE ${len(values)} OR sir.query ILIKE ${len(values)})"
            )
        sort_map = {
            "domain": "d.domain",
            "provider": "sir.provider",
            "category": "sir.category",
            "rank": "rank",
            "url": "sir.url",
            "status_code": "sir.status_code",
            "is_in_scope": "sir.is_in_scope",
            "first_seen": "sir.first_seen",
            "last_seen": "sir.last_seen",
        }
        order = sort_map.get(sort, "sir.last_seen")
        direction_sql = "ASC" if direction.lower() == "asc" else "DESC"
        rank_sql = "sirr.rank" if run_id is not None else "NULL::integer"
        async with self.pool.acquire() as conn:
            total = await conn.fetchval(
                f"""
                SELECT COUNT(DISTINCT sir.id)
                FROM search_intel_results sir
                JOIN domains d ON d.id = sir.domain_id
                {join}
                WHERE {" AND ".join(clauses)}
                """,
                *values,
            )
            rows = await conn.fetch(
                f"""
                SELECT sir.id, sir.domain_id, d.domain, sir.provider, sir.category,
                       {rank_sql} AS rank, sir.url, sir.hostname, sir.title,
                       sir.snippet, sir.display_link, sir.is_in_scope,
                       sir.status_code, sir.risk_tags, sir.query,
                       sir.endpoint_id, sir.first_run_id, sir.last_run_id,
                       sir.first_seen, sir.last_seen
                FROM search_intel_results sir
                JOIN domains d ON d.id = sir.domain_id
                {join}
                WHERE {" AND ".join(clauses)}
                ORDER BY {order} {direction_sql} NULLS LAST, sir.id DESC
                LIMIT ${len(values) + 1} OFFSET ${len(values) + 2}
                """,
                *values,
                limit,
                offset,
            )
        return {
            "rows": [dict(row) for row in rows],
            "total": int(total or 0),
            "limit": limit,
            "offset": offset,
            "status": self.search_intelligence_status(),
        }

    async def queue_search_intel_run(self, domain_id: int) -> dict[str, Any]:
        status = self.search_intelligence_status()
        if not status["enabled"]:
            raise ValueError("search intelligence is disabled")
        if not status["configured"]:
            raise ValueError(
                "configure GOOGLE_CSE_API_KEY and GOOGLE_CSE_ENGINE_ID, "
                "SERPER_API_KEY, or SERPAPI_API_KEY"
            )
        assert self.pool is not None
        async with self.pool.acquire() as conn:
            domain = await conn.fetchval(
                """
                SELECT domain
                FROM domains
                WHERE id = $1
                  AND active = TRUE
                  AND COALESCE(enable_search_intelligence, TRUE) = TRUE
                """,
                domain_id,
            )
            if not domain:
                raise ValueError("active search-enabled domain not found")
            job_id = await conn.fetchval(
                """
                INSERT INTO search_intel_jobs (
                    domain_id, dedupe_key, status, priority, attempts,
                    available_at, lease_owner, lease_expires_at, error, updated_at
                )
                VALUES ($1, 'domain:' || $1::text, 'queued', 100, 0,
                        NOW(), NULL, NULL, NULL, NOW())
                ON CONFLICT (dedupe_key)
                DO UPDATE SET status = 'queued',
                              priority = 100,
                              attempts = 0,
                              available_at = NOW(),
                              lease_owner = NULL,
                              lease_expires_at = NULL,
                              error = NULL,
                              updated_at = NOW()
                WHERE search_intel_jobs.status <> 'running'
                RETURNING id
                """,
                domain_id,
            )
        if not job_id:
            raise ValueError("search intelligence is already running for this domain")
        return {"id": int(job_id), "domain_id": domain_id, "domain": domain, "status": "queued"}


config = load_config()
dashboard = Dashboard(config)
runner = asyncio.Runner()
runner_lock = threading.Lock()
PAGE_CACHE: dict[str, tuple[float, Any]] = {}
PAGE_CACHE_LOCK = threading.Lock()


def run_async(coro, timeout: int = 15, lock_timeout: int = 15):
    if not runner_lock.acquire(timeout=lock_timeout):
        try:
            coro.close()
        except AttributeError:
            pass
        raise TimeoutError("dashboard query runner is busy")
    try:
        return runner.run(asyncio.wait_for(coro, timeout=timeout))
    finally:
        runner_lock.release()


def cached_value(key: str, ttl_seconds: int, loader):
    now = time.monotonic()
    with PAGE_CACHE_LOCK:
        cached = PAGE_CACHE.get(key)
    if cached and now - cached[0] < ttl_seconds:
        return cached[1]
    value = loader()
    with PAGE_CACHE_LOCK:
        PAGE_CACHE[key] = (now, value)
    return value


def cached_value_stale_ok(key: str, ttl_seconds: int, loader, stale_seconds: int = 300):
    now = time.monotonic()
    with PAGE_CACHE_LOCK:
        cached = PAGE_CACHE.get(key)
    if cached and now - cached[0] < ttl_seconds:
        return cached[1]
    try:
        value = loader()
    except TimeoutError:
        if cached and now - cached[0] < stale_seconds:
            return cached[1]
        raise
    with PAGE_CACHE_LOCK:
        PAGE_CACHE[key] = (now, value)
    return value


def invalidate_domain_caches() -> None:
    """Drop process-local and shared dashboard caches after domain mutations."""
    with PAGE_CACHE_LOCK:
        PAGE_CACHE.clear()
    cache_root = Path(os.getenv("RECON_DASHBOARD_CACHE_DIR", "/app/logs/dashboard-cache"))
    try:
        for path in cache_root.glob("*.json"):
            path.unlink(missing_ok=True)
    except OSError:
        # Cache invalidation is best-effort; API reads remain authoritative.
        pass


def dashboard_csrf_token() -> str:
    token = session.get("recon_dashboard_csrf")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session["recon_dashboard_csrf"] = token
    return token


def require_dashboard_csrf() -> None:
    expected = str(session.get("recon_dashboard_csrf") or "")
    provided = str(request.headers.get("X-CSRF-Token") or "")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        abort(403, description="invalid dashboard CSRF token")


def shared_json_cache(key: str, ttl_seconds: int, loader, stale_seconds: int = 300, timeout_fallback=None):
    """Process-shared cache for expensive Gunicorn dashboard aggregates."""
    cache_root = Path(os.getenv("RECON_DASHBOARD_CACHE_DIR", "/app/logs/dashboard-cache"))
    cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    value_path = cache_root / f"{digest}.json"
    lock_path = cache_root / f"{digest}.lock"

    def read_cached(max_age: int) -> Any | None:
        try:
            if time.time() - value_path.stat().st_mtime > max_age:
                return None
            return json.loads(value_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def write_cached(value: Any) -> None:
        temporary = value_path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        temporary.write_text(
            json.dumps(value, default=lambda item: item.isoformat() if hasattr(item, "isoformat") else str(item)),
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, value_path)

    cached = read_cached(ttl_seconds)
    if cached is not None:
        return cached
    stale_before_refresh = read_cached(stale_seconds)
    if stale_before_refresh is not None:
        def refresh_in_background() -> None:
            try:
                with lock_path.open("a+", encoding="utf-8") as lock_handle:
                    try:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        return
                    try:
                        if read_cached(ttl_seconds) is None:
                            write_cached(loader())
                    except (OSError, TimeoutError, ValueError):
                        return
                    finally:
                        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                return

        threading.Thread(
            target=refresh_in_background,
            name=f"dashboard-cache-{digest[:8]}",
            daemon=True,
        ).start()
        return stale_before_refresh

    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            stale = read_cached(stale_seconds)
            if stale is not None:
                return stale
            for _ in range(50):
                time.sleep(0.1)
                cached = read_cached(ttl_seconds)
                if cached is not None:
                    return cached
            try:
                return loader()
            except TimeoutError:
                if timeout_fallback is not None:
                    return timeout_fallback()
                raise
        try:
            cached = read_cached(ttl_seconds)
            if cached is not None:
                return cached
            try:
                value = loader()
            except TimeoutError:
                if stale_before_refresh is not None:
                    return stale_before_refresh
                if timeout_fallback is not None:
                    return timeout_fallback()
                raise
            write_cached(value)
            return value
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


run_async(dashboard.init(), timeout=90, lock_timeout=30)


def dashboard_remember_lifetime() -> tuple[timedelta, int]:
    """Return a bounded remember-browser lifetime and its display value."""
    raw_days = os.getenv("RECON_DASHBOARD_REMEMBER_DAYS")
    if raw_days is not None:
        try:
            days = int(raw_days)
        except ValueError:
            days = 30
    else:
        # Preserve deployments that still configure the previous hours setting.
        try:
            legacy_hours = int(os.getenv("RECON_DASHBOARD_SESSION_HOURS", "720"))
        except ValueError:
            legacy_hours = 720
        days = max(1, round(legacy_hours / 24))

    days = max(1, min(days, 365))
    return timedelta(days=days), days


dashboard_remember_duration, dashboard_remember_days = dashboard_remember_lifetime()
app = Flask(__name__)
dashboard_auth = config.get("dashboard", {}).get("auth", {})
dashboard_password = str(dashboard_auth.get("password") or "")
app.config.update(
    SECRET_KEY=hashlib.sha256(f"recon-dashboard-session:{dashboard_password}".encode()).digest(),
    SESSION_COOKIE_NAME="recon_dashboard_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("RECON_DASHBOARD_SESSION_COOKIE_SECURE", "true").lower() in {"1", "true", "yes", "on"},
    PERMANENT_SESSION_LIFETIME=dashboard_remember_duration,
    SESSION_REFRESH_EACH_REQUEST=True,
)


def dashboard_basic_authorized() -> bool:
    auth_cfg = config.get("dashboard", {}).get("auth", {})
    auth = request.authorization
    return bool(
        auth
        and hmac.compare_digest(auth.username or "", str(auth_cfg.get("username") or ""))
        and hmac.compare_digest(auth.password or "", str(auth_cfg.get("password") or ""))
    )


def dashboard_authorized() -> bool:
    return dashboard_basic_authorized() or session.get("recon_dashboard_authenticated") is True


def safe_dashboard_next(raw: str) -> str:
    candidate = str(raw or "").strip()
    if not candidate.startswith("/") or candidate.startswith("//"):
        return "/"
    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        return "/"
    return candidate


@app.before_request
def require_dashboard_auth():
    auth_cfg = config.get("dashboard", {}).get("auth", {})
    if (
        not auth_cfg.get("enabled", False)
        or request.path in {"/healthz", "/login"}
        or request.endpoint == "static"
    ):
        return None
    if dashboard_authorized():
        return None
    if request.path.startswith("/api/") or request.path.startswith("/download/"):
        return jsonify({"error": "authentication_required", "login_url": url_for("dashboard_login")}), 401
    return redirect(url_for("dashboard_login", next=safe_dashboard_next(request.full_path.rstrip("?"))))


@app.after_request
def dashboard_security_headers(response: Response) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    if request.path == "/login":
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
    return response


@app.route("/login", methods=["GET", "POST"])
def dashboard_login():
    auth_cfg = config.get("dashboard", {}).get("auth", {})
    next_path = safe_dashboard_next(request.values.get("next", ""))
    if not auth_cfg.get("enabled", False) or dashboard_authorized():
        return redirect(next_path)

    error = None
    status = 200
    username = str(request.form.get("username") or "")[:128]
    remember = request.form.get("remember") == "on"
    if request.method == "POST":
        password = str(request.form.get("password") or "")
        valid = (
            hmac.compare_digest(username, str(auth_cfg.get("username") or ""))
            and hmac.compare_digest(password, str(auth_cfg.get("password") or ""))
        )
        if valid:
            session.clear()
            session["recon_dashboard_authenticated"] = True
            session["username"] = str(auth_cfg.get("username") or "")
            session.permanent = remember
            return redirect(next_path)
        error = "The username or password is incorrect."
        status = 401
        time.sleep(0.15)

    return render_template(
        "login.html",
        error=error,
        username=username,
        remember=remember,
        remember_days=dashboard_remember_days,
        next_path=next_path,
        portal_name="Recon Command Center",
        portal_mark="RC",
        portal_context="Attack-surface operations",
        portal_description="Private access to recon intelligence, validation queues, and evidence.",
    ), status


@app.get("/logout")
def dashboard_logout():
    session.clear()
    return redirect(url_for("dashboard_login"))


@app.errorhandler(TimeoutError)
def dashboard_timeout(exc: TimeoutError):
    return Response(f"dashboard query timed out: {exc}\n", status=503, mimetype="text/plain")


@app.template_filter("fmt")
def fmt(value: Any) -> str:
    value = normalize_json(value)
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str)
    return str(value)


def selected_domain_id() -> int | None:
    raw = request.args.get("domain_id", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def selected_int_arg(name: str) -> int | None:
    raw = request.args.get(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def selected_ffuf_hit_filters() -> dict[str, Any]:
    status_codes: list[int] = []
    raw_status = request.args.get("status", "").strip()
    if raw_status:
        try:
            status_codes = sorted(
                {
                    int(value.strip())
                    for value in raw_status.split(",")
                    if value.strip()
                }
            )
        except ValueError as exc:
            raise ValueError("status must contain comma-separated HTTP status codes") from exc
        if any(value < 100 or value > 599 for value in status_codes):
            raise ValueError("status codes must be between 100 and 599")

    filters: dict[str, Any] = {"status_codes": status_codes or None}
    for key in ("size_min", "size_max", "words_min", "words_max"):
        raw = request.args.get(key, "").strip()
        if not raw:
            filters[key] = None
            continue
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{key} must be an integer") from exc
        if value < 0:
            raise ValueError(f"{key} cannot be negative")
        filters[key] = value
    if filters["size_min"] is not None and filters["size_max"] is not None and filters["size_min"] > filters["size_max"]:
        raise ValueError("size_min cannot exceed size_max")
    if filters["words_min"] is not None and filters["words_max"] is not None and filters["words_min"] > filters["words_max"]:
        raise ValueError("words_min cannot exceed words_max")
    return filters


def selected_monitor_domain_id() -> int | None:
    return selected_int_arg("monitor_domain_id")


def selected_scan_id() -> int | None:
    raw = request.args.get("scan_id", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def selected_search_query() -> str:
    return request.args.get("q", "").strip()


def selected_row_limit() -> int:
    raw = request.args.get("limit", str(TABLE_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = TABLE_LIMIT
    return max(25, min(value, 5000))


def selected_api_limit() -> int:
    raw = request.args.get("limit", str(TABLE_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = TABLE_LIMIT
    return max(10, min(value, 250))


def selected_report_limit() -> int:
    raw = request.args.get("limit", str(TABLE_LIMIT)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = TABLE_LIMIT
    return max(1, min(value, 250))


def selected_report_sections() -> list[str]:
    raw = request.args.get("sections", "").strip()
    if not raw:
        return ["risk", "playbooks", "validation", "evidence", "events", "cloud", "api"]
    sections = [item.strip().lower() for item in raw.split(",") if item.strip()]
    return [item for item in sections if item in REPORT_SECTIONS] or ["risk", "playbooks", "validation", "evidence", "events", "cloud", "api"]


def selected_offset() -> int:
    raw = request.args.get("offset", "0").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 0
    return max(0, value)


def selected_sort() -> str:
    return request.args.get("sort", "last_seen").strip() or "last_seen"


def selected_direction() -> str:
    raw = request.args.get("direction", "desc").strip().lower()
    return "asc" if raw == "asc" else "desc"


def selected_endpoint_filters() -> dict[str, str]:
    allowed = {
        "subdomain", "live_host", "source", "status_code", "status", "js_response",
        "has_parameters", "tech", "contains", "response_size_gt", "finding_view",
        "severity", "finding_type", "resolution", "recent_days",
    }
    filters = {key: request.args.get(key, "").strip() for key in allowed if request.args.get(key, "").strip()}
    if filters.get("status") and not filters.get("status_code"):
        filters["status_code"] = filters["status"]
    return filters


def selected_full_dashboard() -> bool:
    return request.args.get("full", "").strip().lower() in {"1", "true", "yes", "on"}


def query_with_filters(domain_id: int | None, filters: dict[str, str]) -> str:
    params: dict[str, Any] = {}
    if domain_id:
        params["domain_id"] = domain_id
    for key in (
        "subdomain", "live_host", "source", "status_code", "js_response", "has_parameters",
        "tech", "contains", "response_size_gt", "finding_view", "severity",
        "finding_type", "resolution", "recent_days",
    ):
        if filters.get(key):
            params[key] = filters[key]
    return ("?" + urlencode(params)) if params else ""


def preset_query(domain_id: int | None, filters: dict[str, str]) -> str:
    params: dict[str, Any] = {}
    if domain_id:
        params["domain_id"] = domain_id
    params.update(filters)
    return "?" + urlencode(params)


@app.route("/screenshots/<path:filename>")
def screenshot_file(filename: str):
    return send_from_directory(SCREENSHOT_ROOT, filename)


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


RESEARCH_SECTIONS = {
    "overview": ("Research overview", "Prioritized intelligence, validation pressure, and current worker activity."),
    "leads": ("Lead workspace", "Investigate one evidence-backed hypothesis at a time."),
    "workers": ("Codex workers", "Review focused worker execution, outcomes, and artifacts."),
    "validation": ("Validation queue", "Turn strong signals into confirmed findings or killed hypotheses."),
    "evidence": ("Evidence library", "Inspect current proof packages linked to research leads."),
    "endpoints": ("Endpoint intelligence", "Prioritize live routes by behavior, provenance, and attack relevance."),
    "javascript": ("JavaScript intelligence", "Review current browser-delivered assets and analysis targets."),
    "ffuf": ("FFUF intelligence", "Inspect controlled discovery runs and their useful results."),
}


def render_research_panel(section: str, job_id: int | None = None):
    title, summary = RESEARCH_SECTIONS[section]
    return render_template(
        "research_panel.html",
        initial_section=section,
        section_title=title,
        section_summary=summary,
        initial_job_id=job_id,
        initial_domain_id=selected_domain_id(),
    )


from hackbot_gateway import install_hackbot_routes

install_hackbot_routes(
    app,
    authorized=dashboard_authorized,
    csrf_token=dashboard_csrf_token,
    require_csrf=require_dashboard_csrf,
    auth_enabled=lambda: bool(config.get("dashboard", {}).get("auth", {}).get("enabled", False)),
    hunt_ui_enabled=os.environ.get("HACKBOT_HUNT_UI_ENABLED") == "1",
)


@app.route("/research")
@app.route("/research/")
def research_panel():
    return render_research_panel("overview")


@app.get("/hunts")
def hunt_panel():
    return render_template(
        "hunt_panel.html",
        domains=run_async(dashboard.get_domain_options()),
        initial_domain_id=selected_domain_id(),
        csrf_token=dashboard_csrf_token(),
    )


@app.get("/agentic")
def agentic_panel():
    return render_template(
        "agentic_panel.html",
        domains=run_async(dashboard.get_domain_options()),
        initial_domain_id=selected_domain_id(),
        csrf_token=dashboard_csrf_token(),
    )


@app.route("/research/leads/<int:job_id>")
def research_lead_panel(job_id: int):
    return render_research_panel("leads", job_id)


@app.route("/research/<section>")
def research_section_panel(section: str):
    if section not in RESEARCH_SECTIONS:
        abort(404)
    return render_research_panel(section)


@app.route("/")
def index():
    domain_id = selected_domain_id()
    domains = run_async(dashboard.get_domain_options())
    if domain_id and not any(item["id"] == domain_id for item in domains):
        domain_id = None
    selected_domain = next((item for item in domains if item["id"] == domain_id), None)
    initial_scan_id = selected_scan_id()
    scan_options = cached_value(f"scan_options|{domain_id or 'all'}", 20, lambda: run_async(dashboard.get_scan_options(domain_id, limit=100)))
    return render_template_string(
        """
        <!doctype html>
        <html lang="en">
        <head>
          <title>Recon Command Center</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <link rel="stylesheet" href="{{ url_for('static', filename='ai_assistant.css') }}">
          <style>
            :root {
              color-scheme: dark;
              --bg: #090d12;
              --surface: #101722;
              --surface-2: #121c29;
              --surface-3: #172232;
              --line: #223044;
              --line-2: #2c3d55;
              --text: #e7edf5;
              --muted: #8ea0b5;
              --faint: #627287;
              --accent: #38bdf8;
              --green: #22c55e;
              --red: #f87171;
              --orange: #fb923c;
              --purple: #a78bfa;
              --blue: #60a5fa;
              --shadow: rgba(0, 0, 0, .38);
            }
            * { box-sizing: border-box; }
            [hidden] { display: none !important; }
            body { margin: 0; background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
            button, input, select { font: inherit; }
            .shell { min-height: 100vh; }
            .topbar { position: sticky; top: 0; z-index: 20; background: rgba(9, 13, 18, .96); border-bottom: 1px solid var(--line); backdrop-filter: blur(12px); }
            .top-inner { max-width: 1920px; margin: 0 auto; padding: .75rem 1rem; display: grid; grid-template-columns: auto minmax(320px, 1fr) auto; gap: .75rem; align-items: center; }
            .brand { display: flex; flex-direction: column; gap: .1rem; min-width: 13rem; }
            .brand h1 { margin: 0; font-size: .98rem; letter-spacing: .02em; text-transform: uppercase; }
            .brand span { color: var(--muted); font-size: .78rem; }
            .omnibar { position: relative; }
            .omnibar input { width: 100%; height: 2.5rem; border-radius: 7px; border: 1px solid var(--line); background: #0c121a; color: var(--text); padding: 0 .85rem; outline: none; }
            .omnibar input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(56,189,248,.12); }
            .scope { display: flex; gap: .5rem; align-items: center; }
            select, .btn { height: 2.35rem; border-radius: 7px; border: 1px solid var(--line); background: #0c121a; color: var(--text); padding: 0 .7rem; }
            .btn { cursor: pointer; display: inline-flex; align-items: center; gap: .35rem; }
            .btn.primary { border-color: rgba(56,189,248,.4); background: rgba(56,189,248,.16); color: #bae6fd; }
            .btn.danger { border-color: rgba(248,113,113,.45); background: rgba(248,113,113,.13); color: #fecaca; }
            .row-actions { display: inline-flex; align-items: center; gap: .35rem; white-space: nowrap; }
            main { max-width: 1920px; margin: 0 auto; padding: .85rem 1rem 2rem; }
            .command { position: sticky; top: 4.05rem; z-index: 15; background: linear-gradient(180deg, rgba(9,13,18,.98), rgba(9,13,18,.9)); padding-bottom: .7rem; }
            .metrics { display: grid; grid-template-columns: repeat(10, minmax(124px, 1fr)); gap: .55rem; }
            .metric { min-height: 5.2rem; border: 1px solid var(--line); background: linear-gradient(180deg, var(--surface-2), #0d141d); border-radius: 8px; padding: .62rem; cursor: pointer; box-shadow: 0 8px 24px var(--shadow); }
            .metric:hover { border-color: var(--line-2); background: var(--surface-3); }
            .metric .label { color: var(--muted); font-size: .68rem; text-transform: uppercase; letter-spacing: .055em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .metric .value { margin-top: .34rem; font-size: 1.45rem; font-weight: 740; }
            .metric .hint { margin-top: .2rem; color: var(--faint); font-size: .72rem; }
            .risk { color: var(--red); } .live { color: var(--green); } .info { color: var(--blue); } .cloud { color: var(--purple); } .warn { color: var(--orange); }
            .layout { display: grid; grid-template-columns: 15.5rem minmax(0, 1fr); gap: .75rem; margin-top: .75rem; }
            .rail { position: sticky; top: 10.2rem; align-self: start; border: 1px solid var(--line); background: var(--surface); border-radius: 8px; overflow: hidden; }
            .nav-btn { width: 100%; border: 0; border-bottom: 1px solid var(--line); background: transparent; color: var(--muted); display: flex; justify-content: space-between; padding: .75rem .8rem; text-align: left; cursor: pointer; }
            .nav-btn:hover, .nav-btn.active { color: var(--text); background: var(--surface-3); }
            .nav-btn.active { border-left: 3px solid var(--accent); padding-left: calc(.8rem - 3px); }
            .workspace { min-width: 0; display: grid; gap: .75rem; }
            .panel { border: 1px solid var(--line); background: var(--surface); border-radius: 8px; overflow: hidden; box-shadow: 0 12px 28px var(--shadow); }
            .panel-head { min-height: 3.2rem; display: flex; align-items: center; justify-content: space-between; gap: .75rem; padding: .65rem .8rem; border-bottom: 1px solid var(--line); }
            .panel-title { display: flex; align-items: center; gap: .55rem; }
            .panel-title h2 { margin: 0; font-size: .9rem; letter-spacing: .02em; text-transform: uppercase; }
            .meta { color: var(--muted); font-size: .78rem; }
            .toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: .45rem; padding: .6rem .8rem; border-bottom: 1px solid var(--line); background: rgba(255,255,255,.015); }
            .toolbar input, .toolbar select { height: 2rem; min-width: 9rem; border-radius: 6px; border: 1px solid var(--line); background: #0c121a; color: var(--text); padding: 0 .55rem; }
            .toolbar textarea, .monitor-form textarea { border-radius: 6px; border: 1px solid var(--line); background: #0c121a; color: var(--text); padding: .55rem; min-height: 4.4rem; resize: vertical; font: inherit; }
            .monitor-layout { width: 100%; display: grid; gap: .65rem; }
            .monitor-form { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .5rem; width: 100%; }
            .monitor-form label { display: grid; gap: .24rem; color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; }
            .monitor-form input, .monitor-form select { min-width: 0; width: 100%; height: 2rem; border-radius: 6px; border: 1px solid var(--line); background: #0c121a; color: var(--text); padding: 0 .55rem; }
            .monitor-form .wide { grid-column: span 2; }
            .monitor-form .full { grid-column: 1 / -1; }
            .monitor-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: .55rem; }
            .monitor-run-strip { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .5rem; }
            .monitor-run-card { border: 1px solid var(--line); background: #0b121b; border-radius: 8px; padding: .62rem; cursor: pointer; }
            .monitor-run-card:hover, .monitor-run-card.active { border-color: var(--accent); background: rgba(56,189,248,.08); }
            .monitor-run-card .run-top { display: flex; justify-content: space-between; gap: .45rem; align-items: center; }
            .monitor-run-card .run-counts { display: grid; grid-template-columns: repeat(3, 1fr); gap: .35rem; margin-top: .5rem; }
            .monitor-run-card .run-counts span { border: 1px solid var(--line); border-radius: 6px; padding: .32rem; color: var(--muted); background: rgba(255,255,255,.02); font-size: .72rem; }
            .monitor-run-card .run-counts strong { display: block; color: var(--text); font-size: .94rem; }
            .monitor-config { border: 1px solid var(--line); border-radius: 8px; background: rgba(255,255,255,.015); }
            .monitor-config summary { cursor: pointer; padding: .65rem .75rem; color: var(--text); border-bottom: 1px solid transparent; }
            .monitor-config[open] summary { border-bottom-color: var(--line); }
            .monitor-config .monitor-form { padding: .65rem; }
            .ffuf-workbench { width: 100%; display: grid; grid-template-columns: minmax(300px, .85fr) minmax(420px, 1.15fr); gap: .75rem; }
            .ffuf-browser, .ffuf-launcher { min-width: 0; border: 1px solid var(--line); border-radius: 8px; background: #0b121b; overflow: hidden; }
            .ffuf-section-head { display: flex; align-items: center; justify-content: space-between; gap: .5rem; padding: .62rem .7rem; border-bottom: 1px solid var(--line); }
            .ffuf-section-head strong { font-size: .82rem; text-transform: uppercase; }
            .ffuf-browser-tools { display: grid; grid-template-columns: 1fr auto; gap: .45rem; padding: .55rem .65rem; border-bottom: 1px solid var(--line); }
            .ffuf-browser-tools input, .ffuf-launcher input, .ffuf-launcher select { width: 100%; min-width: 0; height: 2.15rem; border-radius: 6px; border: 1px solid var(--line); background: #080e15; color: var(--text); padding: 0 .55rem; }
            .ffuf-breadcrumbs { display: flex; flex-wrap: wrap; align-items: center; gap: .2rem; padding: .48rem .65rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: .76rem; }
            .ffuf-crumb { border: 0; background: transparent; color: var(--accent); padding: .1rem .2rem; cursor: pointer; }
            .ffuf-tree { height: 24rem; overflow: auto; }
            .ffuf-entry { width: 100%; min-height: 2.45rem; display: grid; grid-template-columns: 1.3rem minmax(0,1fr) auto; gap: .45rem; align-items: center; border: 0; border-bottom: 1px solid rgba(34,48,68,.7); background: transparent; color: var(--text); padding: .45rem .65rem; text-align: left; cursor: pointer; }
            .ffuf-entry:hover, .ffuf-entry.selected { background: rgba(56,189,248,.09); }
            .ffuf-entry .kind { color: var(--muted); font-family: ui-monospace, monospace; }
            .ffuf-entry .entry-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .ffuf-entry .entry-size { color: var(--faint); font-size: .72rem; }
            .ffuf-form { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .55rem; padding: .7rem; }
            .ffuf-form label { display: grid; gap: .25rem; color: var(--muted); font-size: .72rem; text-transform: uppercase; }
            .ffuf-form .full { grid-column: 1 / -1; }
            .ffuf-selected { grid-column: 1 / -1; min-height: 2.5rem; padding: .55rem .65rem; border: 1px solid var(--line); border-radius: 6px; background: #080e15; color: var(--muted); }
            .ffuf-selected strong { color: var(--text); }
            .ffuf-advanced { grid-column: 1 / -1; border: 1px solid var(--line); border-radius: 6px; }
            .ffuf-advanced summary { cursor: pointer; padding: .5rem .6rem; color: var(--muted); }
            .ffuf-options { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: .5rem; padding: .6rem; border-top: 1px solid var(--line); }
            .ffuf-recursion { display: flex !important; grid-template-columns: none !important; flex-direction: row; align-items: center; gap: .45rem !important; }
            .ffuf-recursion input { width: 1rem; height: 1rem; }
            .ffuf-message { grid-column: 1 / -1; min-height: 1.2rem; color: var(--muted); font-size: .78rem; }
            .source-tabs { display: flex; flex-wrap: wrap; gap: .4rem; padding: .55rem .8rem; border-bottom: 1px solid var(--line); background: rgba(15,23,42,.32); }
            .source-tab { border: 1px solid var(--line); background: #0c121a; color: var(--muted); border-radius: 999px; padding: .34rem .65rem; font-size: .76rem; cursor: pointer; }
            .source-tab:hover, .source-tab.active { color: var(--text); border-color: var(--accent); background: rgba(56,189,248,.1); }
            .data-shell { height: min(64vh, 760px); overflow: auto; contain: content; }
            table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .82rem; }
            th { position: sticky; top: 0; z-index: 3; background: #0d141d; color: var(--muted); font-size: .68rem; letter-spacing: .05em; text-transform: uppercase; cursor: pointer; user-select: none; resize: horizontal; overflow: auto; }
            th, td { border-bottom: 1px solid var(--line); padding: .56rem .65rem; text-align: left; vertical-align: top; }
            tbody tr { cursor: pointer; }
            tbody tr:hover, tbody tr.selected { background: rgba(56,189,248,.08); }
            .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
            .clip { max-width: 46rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .badge { display: inline-flex; align-items: center; border-radius: 999px; padding: .12rem .42rem; border: 1px solid var(--line-2); color: var(--muted); background: rgba(255,255,255,.03); font-size: .72rem; margin: 0 .18rem .18rem 0; white-space: nowrap; }
            .badge.red { color: #fecaca; border-color: rgba(248,113,113,.35); background: rgba(248,113,113,.12); }
            .badge.orange { color: #fed7aa; border-color: rgba(251,146,60,.35); background: rgba(251,146,60,.12); }
            .badge.green { color: #bbf7d0; border-color: rgba(34,197,94,.35); background: rgba(34,197,94,.12); }
            .badge.blue { color: #bfdbfe; border-color: rgba(96,165,250,.35); background: rgba(96,165,250,.12); }
            .badge.purple { color: #ddd6fe; border-color: rgba(167,139,250,.35); background: rgba(167,139,250,.12); }
            .pager { display: flex; align-items: center; justify-content: space-between; gap: .75rem; padding: .65rem .8rem; border-top: 1px solid var(--line); color: var(--muted); }
            .split { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
            .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: .65rem; padding: .75rem; }
            .intel-card { border: 1px solid var(--line); background: #0c121a; border-radius: 8px; padding: .75rem; cursor: pointer; }
            .intel-card:hover { border-color: var(--accent); }
            .drawer { position: fixed; inset: 0 0 0 auto; width: min(48rem, 100vw); background: #0b1119; border-left: 1px solid var(--line-2); transform: translateX(105%); transition: transform .16s ease; z-index: 40; box-shadow: -20px 0 55px rgba(0,0,0,.5); display: flex; flex-direction: column; }
            .drawer.open { transform: translateX(0); }
            .drawer-head { padding: .85rem; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; gap: .75rem; }
            .drawer-body { padding: .85rem; overflow: auto; display: grid; gap: .75rem; }
            pre { margin: 0; white-space: pre-wrap; word-break: break-word; color: #cbd5e1; background: #080c12; border: 1px solid var(--line); border-radius: 8px; padding: .75rem; }
            .empty, .loading { color: var(--muted); padding: 1rem; }
            .screenshot-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: .65rem; padding: .75rem; }
            .shot { border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #0c121a; }
            .shot img { width: 100%; aspect-ratio: 16 / 10; object-fit: cover; display: block; background: #05070a; }
            .shot div { padding: .5rem; color: var(--muted); font-size: .78rem; }
            .codex-console { display: grid; gap: .65rem; padding: .7rem; background: #090e15; }
            .codex-summary { display: grid; grid-template-columns: repeat(7, minmax(92px, 1fr)); gap: .45rem; }
            .codex-stat { min-height: 4.2rem; border: 1px solid var(--line); border-radius: 7px; padding: .52rem .58rem; background: #0c131d; }
            .codex-stat strong { display: block; margin-top: .24rem; font-size: 1.12rem; color: var(--text); }
            .codex-stat span { color: var(--muted); font-size: .66rem; text-transform: uppercase; }
            .codex-controls { display: flex; align-items: center; flex-wrap: wrap; gap: .45rem; }
            .codex-controls select, .codex-controls input { height: 2.1rem; min-width: 9rem; border: 1px solid var(--line); border-radius: 6px; background: #080e15; color: var(--text); padding: 0 .55rem; }
            .codex-controls input { flex: 1; min-width: 14rem; }
            .codex-worker-state { margin-left: auto; display: inline-flex; align-items: center; gap: .4rem; color: var(--muted); font-size: .76rem; }
            .codex-roi-grid { display: grid; grid-template-columns: 1.35fr .85fr; gap: .55rem; }
            .codex-roi-panel { min-width: 0; border: 1px solid var(--line); border-radius: 7px; background: #0b121b; overflow: hidden; }
            .codex-roi-panel h3 { margin: 0; padding: .48rem .6rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: .68rem; text-transform: uppercase; }
            .codex-roi-table { width: 100%; font-size: .72rem; }
            .codex-roi-table th, .codex-roi-table td { padding: .38rem .5rem; white-space: nowrap; }
            .codex-roi-table th { position: static; cursor: default; resize: none; font-size: .62rem; }
            .status-dot { width: .55rem; height: .55rem; border-radius: 50%; flex: 0 0 auto; background: var(--faint); box-shadow: 0 0 0 3px rgba(98,114,135,.12); }
            .status-dot.running, .status-dot.done, .status-dot.confirmed { background: var(--green); box-shadow: 0 0 0 3px rgba(34,197,94,.13); }
            .status-dot.queued, .status-dot.prepared, .status-dot.possible { background: var(--orange); box-shadow: 0 0 0 3px rgba(251,146,60,.13); }
            .status-dot.failed { background: var(--red); box-shadow: 0 0 0 3px rgba(248,113,113,.13); }
            .codex-layout { display: grid; grid-template-columns: minmax(280px, .72fr) minmax(460px, 1.28fr); min-height: 37rem; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #0b121b; }
            .codex-list { min-width: 0; max-height: 67vh; overflow: auto; border-right: 1px solid var(--line); }
            .codex-group-title { position: sticky; top: 0; z-index: 2; padding: .48rem .65rem; color: var(--muted); background: #0d151f; border-bottom: 1px solid var(--line); font-size: .66rem; text-transform: uppercase; }
            .codex-job { width: 100%; min-height: 5.2rem; border: 0; border-bottom: 1px solid var(--line); background: transparent; color: var(--text); padding: .62rem .7rem; text-align: left; cursor: pointer; }
            .codex-job:hover, .codex-job.active { background: rgba(56,189,248,.08); }
            .codex-job.active { box-shadow: inset 3px 0 var(--accent); }
            .codex-job-top { display: flex; align-items: center; gap: .43rem; }
            .codex-job-top strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: .8rem; }
            .codex-job-id { margin-left: auto; color: var(--faint); font-family: ui-monospace, monospace; font-size: .68rem; }
            .codex-job-title { margin-top: .38rem; color: #c9d5e4; font-size: .76rem; line-height: 1.35; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
            .codex-job-meta { margin-top: .38rem; display: flex; justify-content: space-between; gap: .5rem; color: var(--faint); font-size: .68rem; }
            .codex-detail { min-width: 0; max-height: 67vh; overflow: auto; }
            .codex-detail-head { position: sticky; top: 0; z-index: 3; padding: .8rem .9rem; border-bottom: 1px solid var(--line); background: rgba(11,18,27,.97); }
            .codex-detail-head h3 { margin: .35rem 0 .25rem; font-size: 1rem; line-height: 1.35; }
            .codex-detail-body { display: grid; gap: .8rem; padding: .85rem .9rem 1.2rem; }
            .codex-facts { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: .45rem; }
            .codex-fact { border: 1px solid var(--line); border-radius: 6px; background: #080e15; padding: .48rem; min-width: 0; }
            .codex-fact span { display: block; color: var(--faint); font-size: .62rem; text-transform: uppercase; }
            .codex-fact strong { display: block; margin-top: .22rem; font-size: .76rem; overflow: hidden; text-overflow: ellipsis; }
            .codex-section h4 { margin: 0 0 .42rem; color: var(--muted); font-size: .68rem; text-transform: uppercase; }
            .codex-section p { margin: 0; color: #c8d4e3; font-size: .8rem; line-height: 1.55; }
            .codex-timeline { display: grid; gap: 0; }
            .codex-event { position: relative; display: grid; grid-template-columns: 1rem minmax(0,1fr); gap: .55rem; padding: 0 0 .8rem; }
            .codex-event:not(:last-child)::before { content: ""; position: absolute; left: .275rem; top: .65rem; bottom: -.05rem; width: 1px; background: var(--line-2); }
            .codex-event .status-dot { margin-top: .25rem; width: .58rem; height: .58rem; }
            .codex-event strong { font-size: .78rem; }
            .codex-event p { margin: .2rem 0 0; color: var(--muted); font-size: .76rem; line-height: 1.48; white-space: pre-wrap; word-break: break-word; }
            .codex-path-list { display: grid; gap: .3rem; }
            .codex-path { padding: .4rem .48rem; border: 1px solid var(--line); border-radius: 5px; background: #080e15; color: var(--muted); font: .7rem ui-monospace, monospace; word-break: break-all; }
            .domain-dialog { width: min(88rem, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); padding: 0; overflow: hidden; border: 1px solid var(--line-2); border-radius: 8px; background: #0b1119; color: var(--text); box-shadow: 0 24px 80px rgba(0,0,0,.7); }
            .domain-dialog::backdrop { background: rgba(2,6,12,.78); backdrop-filter: blur(3px); }
            .domain-dialog-head { position: sticky; top: 0; z-index: 3; min-height: 3.5rem; display: flex; align-items: center; justify-content: space-between; gap: .75rem; padding: .75rem .9rem; border-bottom: 1px solid var(--line); background: #0d151f; }
            .domain-dialog-head h2 { margin: 0; font-size: .94rem; text-transform: uppercase; }
            .domain-manager-body { display: grid; grid-template-columns: minmax(20rem, .72fr) minmax(36rem, 1.28fr); height: min(42rem, calc(100dvh - 5.75rem)); min-height: 0; overflow: hidden; }
            .domain-editor { min-height: 0; padding: .85rem; border-right: 1px solid var(--line); overflow: auto; }
            .domain-inventory { min-width: 0; min-height: 0; overflow: auto; overscroll-behavior: contain; scrollbar-gutter: stable; }
            .domain-section-title { margin: 0 0 .65rem; color: var(--muted); font-size: .7rem; text-transform: uppercase; }
            .domain-form { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .58rem; }
            .domain-form label { display: grid; gap: .28rem; color: var(--muted); font-size: .68rem; text-transform: uppercase; }
            .domain-form .full { grid-column: 1 / -1; }
            .domain-form input, .domain-form select, .domain-form textarea, .domain-search input, .domain-search select { width: 100%; min-width: 0; border: 1px solid var(--line); border-radius: 6px; background: #080e15; color: var(--text); padding: .52rem .58rem; }
            .domain-form textarea { min-height: 5.7rem; resize: vertical; }
            .domain-form-help { color: var(--faint); font-size: .7rem; line-height: 1.45; text-transform: none; }
            .domain-options { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .38rem .55rem; padding: .55rem; border: 1px solid var(--line); border-radius: 6px; }
            .domain-options label { display: flex; align-items: center; gap: .45rem; min-height: 1.75rem; color: var(--muted); font-size: .72rem; text-transform: none; }
            .domain-options input { width: 1rem; height: 1rem; padding: 0; }
            .domain-actions { grid-column: 1 / -1; display: flex; flex-wrap: wrap; gap: .45rem; align-items: center; }
            .domain-message { min-height: 1.3rem; color: var(--muted); font-size: .74rem; }
            .domain-search { position: sticky; top: 0; z-index: 2; display: grid; grid-template-columns: 1fr 10rem; gap: .5rem; padding: .68rem; border-bottom: 1px solid var(--line); background: #0b1119; }
            .domain-table { width: 100%; font-size: .76rem; }
            .domain-table th { top: 3.75rem; }
            .domain-table td { vertical-align: middle; }
            .domain-table .domain-name { min-width: 10rem; }
            .domain-table .domain-stats { white-space: nowrap; color: var(--muted); }
            .domain-table .domain-controls { min-width: 15rem; white-space: nowrap; }
            .domain-table .btn { height: 1.85rem; padding: 0 .48rem; font-size: .7rem; }
            .domain-delete-body { padding: .9rem; display: grid; gap: .75rem; }
            .domain-impact-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: .45rem; }
            .domain-impact { border: 1px solid var(--line); border-radius: 6px; background: #080e15; padding: .48rem; }
            .domain-impact span { display: block; color: var(--faint); font-size: .62rem; text-transform: uppercase; }
            .domain-impact strong { display: block; margin-top: .2rem; font-size: .95rem; }
            .domain-warning { border-left: 3px solid var(--orange); background: rgba(251,146,60,.08); padding: .65rem .72rem; color: #fed7aa; font-size: .78rem; line-height: 1.45; }
            .domain-delete-confirm { display: grid; gap: .3rem; color: var(--muted); font-size: .72rem; }
            .domain-delete-confirm input { width: 100%; border: 1px solid var(--line); border-radius: 6px; background: #080e15; color: var(--text); padding: .58rem; }
            @media (max-width: 1200px) { .metrics { grid-template-columns: repeat(5, 1fr); } .layout { grid-template-columns: 1fr; } .rail { position: static; display: grid; grid-template-columns: repeat(4, 1fr); } }
            @media (max-width: 1100px) { .codex-summary { grid-template-columns: repeat(4, 1fr); } .codex-layout { grid-template-columns: minmax(250px, .8fr) minmax(380px, 1.2fr); } }
            @media (max-width: 900px) { .monitor-form { grid-template-columns: repeat(2, minmax(0, 1fr)); } .monitor-form .wide { grid-column: 1 / -1; } .ffuf-workbench, .codex-layout, .codex-roi-grid, .domain-manager-body { grid-template-columns: 1fr; } .domain-manager-body { display: block; height: auto; max-height: calc(100dvh - 5.75rem); overflow-y: auto; } .domain-editor { border-right: 0; border-bottom: 1px solid var(--line); overflow: visible; } .domain-inventory { overflow: visible; } .codex-list { max-height: 25rem; border-right: 0; border-bottom: 1px solid var(--line); } .codex-detail { max-height: none; } }
            @media (max-width: 720px) { .top-inner { grid-template-columns: 1fr; } .metrics { grid-template-columns: repeat(2, 1fr); } .split { grid-template-columns: 1fr; } .rail { grid-template-columns: repeat(2, 1fr); } .command { position: static; } .monitor-form, .domain-form, .domain-search { grid-template-columns: 1fr; } .domain-dialog { width: calc(100vw - .75rem); max-height: calc(100dvh - .75rem); } .domain-dialog-head { align-items: flex-start; } .domain-dialog-head .meta { display: none; } .domain-manager-body { max-height: calc(100dvh - 4.25rem); } .domain-form .full { grid-column: 1; } .domain-options { grid-template-columns: 1fr; } .domain-impact-grid { grid-template-columns: repeat(2, 1fr); } .domain-table, .domain-table tbody, .domain-table tr, .domain-table td { display: block; width: 100%; } .domain-table thead { display: none; } .domain-table tr { padding: .55rem .65rem; border-bottom: 1px solid var(--line); } .domain-table td { min-width: 0 !important; padding: .28rem 0; border: 0; white-space: normal !important; } .domain-table td::before { content: attr(data-label); display: block; margin-bottom: .12rem; color: var(--faint); font-size: .62rem; text-transform: uppercase; } .domain-table .domain-controls { display: flex; flex-wrap: wrap; gap: .35rem; } .ffuf-form, .ffuf-options { grid-template-columns: 1fr; } .codex-summary { grid-template-columns: repeat(2, 1fr); } .codex-facts { grid-template-columns: repeat(2, 1fr); } .codex-worker-state { width: 100%; margin-left: 0; } }
          </style>
        </head>
        <body>
          <svg width="0" height="0" style="position:absolute" aria-hidden="true">
            <symbol id="i-bot" viewBox="0 0 24 24"><rect x="4" y="7" width="16" height="13" rx="2"/><path d="M9 11h.01M15 11h.01M8 16h8M12 3v4"/></symbol>
            <symbol id="i-send" viewBox="0 0 24 24"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></symbol>
            <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
            <symbol id="i-close" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></symbol>
            <symbol id="i-history" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></symbol>
            <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/></symbol>
          </svg>
          <div class="shell">
            <header class="topbar">
              <div class="top-inner">
                <div class="brand">
                  <h1>Recon Command Center</h1>
                  <span>{{ selected_domain.domain if selected_domain else "All monitored domains" }}</span>
                </div>
                <div class="ai-search-stack">
                  <div class="omnibar">
                    <input id="globalSearch" autocomplete="off" placeholder='Filter recon: tech:graphql status:200 contains:login'>
                  </div>
                  <form class="ai-omnibar" id="aiSearchForm" role="search">
                    <svg><use href="#i-bot"></use></svg>
                    <input id="aiSearchInput" type="search" placeholder="Ask AI across every root domain and recon table" autocomplete="off" maxlength="3000" aria-label="Ask AI across recon data">
                    <button type="submit" title="Ask AI" aria-label="Ask AI"><svg><use href="#i-send"></use></svg></button>
                  </form>
                </div>
                <form class="scope" method="get" action="/">
                  <select name="domain_id" onchange="this.form.submit()">
                    <option value="">All domains</option>
                    {% for domain in domains %}
                    <option value="{{ domain.id }}" {% if domain.id == domain_id %}selected{% endif %}>{{ domain.domain }}</option>
                    {% endfor %}
                  </select>
                  <button class="btn" type="button" id="manageDomainsBtn"><svg width="16" height="16" aria-hidden="true"><use href="#i-plus"></use></svg> Domains</button>
                  <a class="btn" href="/research{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Research</a>
                  <a class="btn" href="/hunts{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Hunts</a>
                  <a class="btn" href="/agentic{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Agentic</a>
                  <a class="btn" href="/hackbot">HackBot</a>
                  <a class="btn" href="/logout">Sign out</a>
                  <button class="btn primary" type="button" id="refreshBtn">Refresh</button>
                </form>
              </div>
            </header>
            <main>
              <section class="command" id="commandCenter">
                <div class="metrics" id="metrics"><div class="loading">Loading command center...</div></div>
              </section>
              <section class="layout">
                <nav class="rail" id="nav"></nav>
                <div class="workspace">
                  <section class="panel" id="focusPanel">
                    <div class="panel-head">
                      <div class="panel-title"><h2>Most Interesting Targets</h2><span class="meta">prioritized analyst queue</span></div>
                      <button class="btn" data-open-tab="triage">Triage</button>
                    </div>
                    <div class="cards" id="focusCards"><div class="loading">Loading high-signal targets...</div></div>
                  </section>
                  <section class="panel">
                    <div class="panel-head">
                      <div class="panel-title"><h2 id="gridTitle">Data Grid</h2><span class="meta" id="gridMeta"></span></div>
                      <div class="scope">
                        <button class="btn primary" id="askSelectedRow" disabled>Ask AI about selected</button>
                        <button class="btn" id="columnsBtn">Columns</button>
                        <a class="btn" id="downloadLink" href="#">Download</a>
                      </div>
                    </div>
                    <div class="toolbar" id="gridToolbar">
                      <select id="scanScope">
                        <option value="">All data</option>
                        {% for scan in scan_options %}
                        <option value="{{ scan.id }}" {% if scan.id == initial_scan_id %}selected{% endif %}>{{ scan.domain }} | {{ scan.scan_finished_at }} | {{ "first" if scan.first_run else "delta" }}</option>
                        {% endfor %}
                      </select>
                      <input id="quickFilter" data-filter-control="quick" placeholder="Search current tab">
                      <select id="pageSize"><option>25</option><option selected>50</option><option>100</option><option>250</option></select>
                      <select id="statusFilter" data-filter-control="status"><option value="">Any status</option></select>
                      <select id="jsResponseFilter" data-filter-control="jsResponse">
                        <option value="">All JS responses</option>
                        <option value="200">200 OK only</option>
                        <option value="2xx">All successful (2xx)</option>
                        <option value="3xx">Redirects (3xx)</option>
                        <option value="4xx">Client errors (4xx)</option>
                        <option value="5xx">Server errors (5xx)</option>
                        <option value="unknown">Unknown / not fetched</option>
                      </select>
                      <select id="paramFilter" data-filter-control="params"><option value="">Parameters</option><option value="true">Has parameters</option><option value="false">No parameters</option></select>
                      <select id="techFilter" data-filter-control="tech"><option value="">Any tech</option></select>
                      <select id="confidenceFilter" data-filter-control="confidence"><option value="">Any confidence</option><option value="confirmed">Confirmed</option><option value="probable">Probable</option><option value="candidate">Candidate</option><option value="rejected">Rejected</option></select>
                      <input id="responseSizeFilter" data-filter-control="responseSize" inputmode="numeric" placeholder="Size > bytes">
                      <select id="findingViewFilter" data-filter-control="findingView">
                        <option value="leads">Priority findings</option>
                        <option value="actionable">Strict findings</option>
                        <option value="raw">Raw signals</option>
                      </select>
                      <select id="findingSeverityFilter" data-filter-control="findingSeverity">
                        <option value="">Any severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
                      </select>
                      <input id="findingTypeFilter" data-filter-control="findingType" placeholder="Finding type">
                      <select id="findingResolutionFilter" data-filter-control="findingResolution">
                        <option value="active">Open only</option><option value="all">Open + resolved</option><option value="resolved">Resolved only</option>
                      </select>
                      <select id="findingRecentFilter" data-filter-control="findingRecent">
                        <option value="">Any age</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option><option value="365">Last year</option>
                      </select>
                    </div>
                    <div class="source-tabs" id="sourceTabs" hidden></div>
                    <div class="data-shell"><table id="grid"></table></div>
                    <div class="pager">
                      <span id="pageInfo">No rows loaded</span>
                      <span><button class="btn" id="prevPage">Previous</button> <button class="btn" id="nextPage">Next</button></span>
                    </div>
                  </section>
                  <section class="panel" id="secondaryPanel">
                    <div class="panel-head"><div class="panel-title"><h2>Live Scan Stream</h2><span class="meta">compact polling feed</span></div></div>
                    <div class="cards" id="liveFeed"><div class="loading">Waiting for scan events...</div></div>
                  </section>
                </div>
              </section>
            </main>
          </div>
          <dialog class="domain-dialog" id="domainManagerDialog" aria-labelledby="domainManagerTitle">
            <div class="domain-dialog-head">
              <div><h2 id="domainManagerTitle">Manage root domains</h2><div class="meta">Add, schedule, pause, and safely remove recon scopes</div></div>
              <button class="btn" type="button" id="closeDomainManager">Close</button>
            </div>
            <div class="domain-manager-body">
              <section class="domain-editor">
                <h3 class="domain-section-title" id="domainEditorTitle">Add root domains</h3>
                <form class="domain-form" id="domainForm">
                  <input type="hidden" name="domain_id">
                  <label class="full">Root domains
                    <textarea name="domains" required placeholder="example.com&#10;example.org"></textarea>
                    <span class="domain-form-help">One per line or comma-separated. URLs and <code>*.</code> wildcards are normalized to hostnames.</span>
                  </label>
                  <label>Organization<input name="organization" maxlength="255" placeholder="Optional program name"></label>
                  <label>Scan preset
                    <select name="preset">
                      <option value="standard">Standard · usual 48h setup</option>
                      <option value="light">Light · archive and JS focused</option>
                      <option value="expanded">Expanded · active tools enabled</option>
                    </select>
                  </label>
                  <label>Rerun interval (hours)<input name="scan_interval_hours" type="number" min="1" max="8760" value="48" required></label>
                  <label>Max live hosts<input name="max_live_hosts" type="number" min="1" placeholder="Framework default"></label>
                  <label>Max archive URLs<input name="max_wayback_urls" type="number" min="1" placeholder="Framework default"></label>
                  <label>Max JS assets<input name="max_js_assets" type="number" min="1" placeholder="Framework default"></label>
                  <div class="domain-options">
                    <label><input type="checkbox" name="include_subdomains" checked> Include subdomains</label>
                    <label><input type="checkbox" name="enable_search_intelligence" checked> Search intelligence</label>
                    <label><input type="checkbox" name="enable_gau" checked> GAU archives</label>
                    <label><input type="checkbox" name="enable_katana" checked> Katana crawl</label>
                    <label><input type="checkbox" name="enable_hakrawler" checked> Hakrawler crawl</label>
                    <label><input type="checkbox" name="enable_js_analysis" checked> JavaScript analysis</label>
                    <label><input type="checkbox" name="enable_ffuf"> Automated FFUF</label>
                    <label><input type="checkbox" name="enable_nuclei"> Nuclei</label>
                    <label><input type="checkbox" name="enable_screenshots" checked> Screenshots</label>
                    <label><input type="checkbox" name="enable_port_scan"> Port scan</label>
                  </div>
                  <div class="domain-options" id="newDomainOptions">
                    <label><input type="checkbox" name="active" checked> Enable scheduled recon</label>
                    <label><input type="checkbox" name="start_now" checked> Start first scan immediately</label>
                  </div>
                  <div class="domain-actions">
                    <button class="btn primary" type="submit" id="saveDomainButton">Add domains</button>
                    <button class="btn" type="button" id="cancelDomainEdit" hidden>Cancel edit</button>
                  </div>
                  <div class="domain-message full" id="domainMessage" role="status"></div>
                </form>
              </section>
              <section class="domain-inventory">
                <div class="domain-search">
                  <input id="domainManagerSearch" type="search" placeholder="Filter root domains">
                  <select id="domainManagerStatus"><option value="">All states</option><option value="active">Active</option><option value="paused">Paused</option><option value="running">Running</option></select>
                </div>
                <table class="domain-table">
                  <thead><tr><th>Domain</th><th>State</th><th>Schedule</th><th>Surface</th><th>Actions</th></tr></thead>
                  <tbody id="domainManagerRows"><tr><td colspan="5" class="loading">Loading domains...</td></tr></tbody>
                </table>
              </section>
            </div>
          </dialog>
          <dialog class="domain-dialog" id="domainDeleteDialog" aria-labelledby="domainDeleteTitle">
            <div class="domain-dialog-head">
              <div><h2 id="domainDeleteTitle">Delete root-domain data</h2><div class="meta" id="domainDeleteSubtitle"></div></div>
              <button class="btn" type="button" id="closeDomainDelete">Close</button>
            </div>
            <div class="domain-delete-body">
              <div class="domain-impact-grid" id="domainDeleteImpact"></div>
              <div class="domain-warning" id="domainDeleteWarning"></div>
              <label class="domain-delete-confirm">Type the exact root domain to confirm
                <input id="domainDeleteConfirmation" autocomplete="off" spellcheck="false">
              </label>
              <div class="domain-actions">
                <button class="btn danger" type="button" id="confirmDomainDelete" disabled><svg width="16" height="16" aria-hidden="true"><use href="#i-trash"></use></svg> Delete domain data</button>
                <button class="btn" type="button" id="cancelDomainDelete">Cancel</button>
              </div>
            </div>
          </dialog>
          <aside class="drawer" id="drawer">
            <div class="drawer-head">
              <div><strong id="drawerTitle">Details</strong><div class="meta" id="drawerPosition"></div></div>
              <div class="scope">
                <button class="btn" id="drawerPrev">Previous</button>
                <button class="btn" id="drawerNext">Next</button>
                <button class="btn" id="closeDrawer">Close</button>
              </div>
            </div>
            <div class="drawer-body" id="drawerBody"></div>
          </aside>
          <button class="ai-assistant-toggle" id="aiAssistantToggle" title="Open AI assistant" aria-label="Open AI assistant">
            <svg><use href="#i-bot"></use></svg><span id="aiAssistantBadge" hidden></span>
          </button>
          <div class="ai-assistant-backdrop" id="aiAssistantBackdrop" hidden></div>
          <aside class="ai-assistant-drawer" id="aiAssistantDrawer" aria-label="AI assistant" aria-hidden="true">
            <header class="ai-drawer-head">
              <div><span>Codex</span><strong id="aiAssistantTitle">Recon AI assistant</strong><small id="aiAssistantScope">{{ selected_domain.domain if selected_domain else "All root domains" }}</small></div>
              <div class="ai-head-actions">
                <button id="aiHistoryToggle" title="Conversation history" aria-label="Conversation history"><svg><use href="#i-history"></use></svg></button>
                <button id="aiClearThread" title="Clear current conversation" aria-label="Clear current conversation"><svg><use href="#i-trash"></use></svg></button>
                <button id="aiNewThread" title="New conversation" aria-label="New conversation"><svg><use href="#i-plus"></use></svg></button>
                <button id="aiAssistantClose" title="Close assistant" aria-label="Close assistant"><svg><use href="#i-close"></use></svg></button>
              </div>
            </header>
            <div class="ai-status-row"><span class="health-dot" id="aiWorkerDot"></span><span id="aiWorkerStatus">Checking worker</span><span id="aiModelName"></span></div>
            <div class="ai-selected-note" id="aiSelectedNote">No record selected · searching this domain and all recon categories</div>
            <section class="ai-history-panel" id="aiHistoryPanel" hidden>
              <div class="ai-history-toolbar"><strong>Conversation history</strong><button type="button" id="aiClearHistory">Clear scope history</button></div>
              <div class="ai-history-list" id="aiHistoryList"></div>
            </section>
            <div class="ai-messages" id="aiMessages" aria-live="polite"><div class="ai-empty"><svg><use href="#i-bot"></use></svg><strong>Ask about recon data or select a row</strong></div></div>
            <form class="ai-compose" id="aiAssistantForm">
              <textarea id="aiAssistantInput" rows="3" maxlength="3000" placeholder="Ask about the selected row, current tab, or root domain" aria-label="Ask about recon data"></textarea>
              <button id="aiAssistantSubmit" type="submit">Ask</button>
            </form>
          </aside>
          <script>
            window.RECON_DASHBOARD_ASSISTANT = {
              initialDomainId: {{ domain_id|tojson }},
              initialSection: {{ (request.args.get('tab') or 'urls')|tojson }}
            };
            const DASHBOARD_CSRF = {{ csrf_token|tojson }};
            const DOMAIN_ID = {{ domain_id|tojson }};
            const INITIAL_SCAN_ID = {{ initial_scan_id|tojson }};
            const DOMAINS = {{ js_domains|tojson }};
            const URL_STATE = new URLSearchParams(location.search);
            const tabs = {
              urls: { label: "Endpoints", api: "/api/results/urls", download: "/download/urls", sort: "last_seen" },
              live_hosts: { label: "Live Hosts", api: "/api/results/live_hosts", download: "/download/live_hosts", sort: "last_seen" },
              infrastructure: { label: "Infrastructure", api: "/api/results/infrastructure", download: "/download/infrastructure", sort: "last_seen" },
              subdomains: { label: "Subdomains", api: "/api/results/subdomains", download: "/download/subdomains", sort: "last_seen" },
              js: { label: "JS Files", api: "/api/results/js", download: "/download/js", sort: "last_seen" },
              credential_leaks: { label: "Leak Credentials", api: "/api/results/credential_leaks", download: "/download/credential_leaks", sort: "last_seen" },
              parameters: { label: "Parameters", api: "/api/results/parameters", download: "/download/parameters", sort: "last_seen" },
              findings: { label: "Findings", api: "/api/results/findings", download: "/download/findings", sort: "last_seen" },
              screenshots: { label: "Screenshots", api: "/api/results/screenshots", download: "/download/screenshots", sort: "captured_at" },
              risk: { label: "Risk", api: "/api/risk", download: "/download/report.md?sections=risk", sort: "score" },
              bookmarks: { label: "Bookmarks", api: "/api/bookmarks", download: "/download/bookmarks", sort: "updated_at" },
              events: { label: "Changes", api: "/api/events", download: "/download/report.md?sections=events", sort: "last_seen" },
              monitors: { label: "Change Monitor", api: "/api/monitor-events", download: "/download/monitor-events", sort: "last_seen", custom: "monitors" },
              ffuf_workbench: { label: "FFUF Workbench", api: "/api/ffuf/workbench/runs", download: "#", sort: "started_at", custom: "ffuf_workbench" },
              cloud: { label: "Cloud", api: "/api/cloud", download: "/download/report.md?sections=cloud", sort: "last_seen" },
              api_surfaces: { label: "API Security", api: "/api/api-surfaces", download: "/download/report.md?sections=api", sort: "last_seen" },
              active_hunt: { label: "Active Hunt", api: "/api/active-hunt", download: "/download/active-hunt", sort: "created_at" },
              codex_worker: { label: "Codex Worker", api: "/api/codex-worker", download: "#", sort: "updated_at", custom: "codex_worker" },
              bug_jobs: { label: "Bug Jobs", api: "/api/bug-jobs", download: "/download/bug-jobs", sort: "priority" },
              playbooks: { label: "Playbooks", api: "/api/playbooks", download: "/download/playbooks", sort: "updated_at" },
              validation: { label: "Validation", api: "/api/validation", download: "/download/report.md?sections=validation", sort: "updated_at" },
              evidence: { label: "Evidence", api: "/api/evidence", download: "/download/report.md?sections=evidence", sort: "updated_at" },
              triage: { label: "AI Triage", api: "/api/ai-triage", download: "/download/ai-triage", custom: "triage" },
              search_intel: { label: "Google Dorks", api: "/api/search-intelligence/results", download: "/download/search-intelligence", sort: "last_seen", custom: "search_intel" },
              search: { label: "Global Search", api: "/api/search", download: "/download/search", custom: "search" }
            };
            const scanTabs = new Set(["urls", "live_hosts", "subdomains", "js", "parameters", "findings", "screenshots"]);
            const filterCaps = {
              urls: { quick: true, status: true, params: true, source: true, tech: true, responseSize: true },
              live_hosts: { quick: true, status: true, responseSize: true },
              infrastructure: { quick: true },
              subdomains: { quick: true },
              js: { quick: true, jsResponse: true, source: true },
              credential_leaks: { quick: true },
              parameters: { quick: true, status: true, source: true, tech: true, responseSize: true },
              findings: { quick: true, findingView: true, findingSeverity: true, findingType: true, findingResolution: true, findingRecent: true },
              screenshots: { quick: true, responseSize: true },
              api_surfaces: { confidence: true },
              bug_jobs: { quick: true },
              search_intel: { quick: true }
            };
            const emptyFilterOptions = () => ({ sources: [], source_counts: [], js_sources: [], js_source_counts: [], status_counts: [], endpoint_status_counts: [], live_host_status_counts: [], js_status_counts: [], parameter_status_counts: [], technologies: [] });
            let filterOptions = emptyFilterOptions();
            const initialTab = URL_STATE.get("tab") || "urls";
            let state = { tab: "urls", offset: 0, limit: 50, sort: "last_seen", direction: "desc", rows: [], selected: 0, filters: {}, gridResult: {}, scanId: INITIAL_SCAN_ID ? String(INITIAL_SCAN_ID) : "", monitorView: URL_STATE.get("monitor_view") || "", monitorRunId: URL_STATE.get("run_id") || "", searchIntelRunId: URL_STATE.get("dork_run_id") || "", searchIntelCategory: URL_STATE.get("dork_category") || "", searchIntelScope: URL_STATE.get("dork_scope") || "", codexStatus: URL_STATE.get("worker_status") || "", codexOutcome: URL_STATE.get("worker_outcome") || "", codexSearch: "", codexJobId: URL_STATE.get("job_id") || "", ffufPath: "", ffufWordlist: null, ffufDraft: {} };
            const $ = (id) => document.getElementById(id);
            function isTypingTarget(target) {
              if (!target) return false;
              const tag = String(target.tagName || "").toLowerCase();
              return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
            }
            const activeCaps = () => {
              if (state.scanId && state.tab === "parameters") return { status: true };
              if (state.scanId && scanTabs.has(state.tab) && !["urls", "js"].includes(state.tab)) return {};
              return filterCaps[state.tab] || {};
            };
            function pruneFilters() {
              const caps = activeCaps();
              const allowed = new Set();
              if (caps.quick) allowed.add("contains");
              if (caps.status) allowed.add("status_code");
              if (caps.jsResponse) allowed.add("js_response");
              if (caps.params) allowed.add("has_parameters");
              if (caps.source) allowed.add("source");
              if (caps.tech) allowed.add("tech");
              if (caps.confidence) allowed.add("confidence");
              if (caps.responseSize) allowed.add("response_size_gt");
              if (caps.findingView) allowed.add("finding_view");
              if (caps.findingSeverity) allowed.add("severity");
              if (caps.findingType) allowed.add("finding_type");
              if (caps.findingResolution) allowed.add("resolution");
              if (caps.findingRecent) allowed.add("recent_days");
              for (const key of Object.keys(state.filters)) if (!allowed.has(key)) delete state.filters[key];
            }
            function defaultFiltersFor(tab) {
              return tab === "findings" ? { finding_view: "leads", resolution: "active" } : {};
            }
            const params = () => {
              pruneFilters();
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
              p.set("limit", state.limit); p.set("offset", state.offset); p.set("sort", state.sort); p.set("direction", state.direction);
              for (const [k, v] of Object.entries(state.filters)) if (v) p.set(k, v);
              return p;
            };
            const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
            const fmt = (v) => Array.isArray(v) ? v.map(x => `<span class="badge blue">${esc(x)}</span>`).join("") : (typeof v === "object" && v ? `<pre>${esc(JSON.stringify(v, null, 2))}</pre>` : esc(v ?? ""));
            const badge = (v) => {
              const s = String(v ?? "");
              let c = s.match(/critical|high/i) ? "red" : s.match(/medium|403|401/i) ? "orange" : s.match(/200|live|active/i) ? "green" : s.match(/cloud|aws|azure|gcp/i) ? "purple" : "blue";
              return `<span class="badge ${c}">${esc(s)}</span>`;
            };
            const domainPresets = {
              standard: {scan_interval_hours:48, include_subdomains:true, enable_search_intelligence:true, enable_gau:true, enable_katana:true, enable_hakrawler:true, enable_js_analysis:true, enable_ffuf:false, enable_nuclei:false, enable_screenshots:true, enable_port_scan:false},
              light: {scan_interval_hours:72, include_subdomains:true, enable_search_intelligence:true, enable_gau:true, enable_katana:false, enable_hakrawler:false, enable_js_analysis:true, enable_ffuf:false, enable_nuclei:false, enable_screenshots:true, enable_port_scan:false},
              expanded: {scan_interval_hours:48, include_subdomains:true, enable_search_intelligence:true, enable_gau:true, enable_katana:true, enable_hakrawler:true, enable_js_analysis:true, enable_ffuf:true, enable_nuclei:true, enable_screenshots:true, enable_port_scan:true}
            };
            const domainOptionNames = ["include_subdomains","enable_search_intelligence","enable_gau","enable_katana","enable_hakrawler","enable_js_analysis","enable_ffuf","enable_nuclei","enable_screenshots","enable_port_scan"];
            let managedDomains = [];
            let deleteDomainCandidate = null;
            let domainManagerDirty = false;
            function domainApiHeaders() { return {"Content-Type":"application/json", "X-CSRF-Token":DASHBOARD_CSRF}; }
            async function domainApi(url, options = {}) {
              const response = await fetch(url, options);
              const payload = await response.json().catch(() => ({}));
              if (!response.ok) throw new Error(payload.error || `Domain request failed (${response.status})`);
              return payload;
            }
            function nullableNumber(value) {
              const text = String(value ?? "").trim();
              return text ? Number(text) : null;
            }
            function applyDomainPreset(name) {
              const preset = domainPresets[name] || domainPresets.standard;
              const form = $("domainForm");
              form.elements.scan_interval_hours.value = preset.scan_interval_hours;
              for (const option of domainOptionNames) form.elements[option].checked = Boolean(preset[option]);
            }
            function resetDomainForm() {
              const form = $("domainForm");
              form.reset();
              form.elements.domain_id.value = "";
              form.elements.domains.readOnly = false;
              form.elements.preset.value = "standard";
              form.elements.active.checked = true;
              form.elements.start_now.checked = true;
              form.elements.start_now.closest("label").hidden = false;
              $("domainEditorTitle").textContent = "Add root domains";
              $("saveDomainButton").textContent = "Add domains";
              $("cancelDomainEdit").hidden = true;
              $("domainMessage").textContent = "";
              applyDomainPreset("standard");
            }
            function editManagedDomain(domainId) {
              const row = managedDomains.find(item => Number(item.id) === Number(domainId));
              if (!row) return;
              const form = $("domainForm");
              form.elements.domain_id.value = row.id;
              form.elements.domains.value = row.domain;
              form.elements.domains.readOnly = true;
              form.elements.organization.value = row.organization || "";
              form.elements.preset.value = "standard";
              form.elements.scan_interval_hours.value = row.scan_interval_hours || 48;
              form.elements.max_live_hosts.value = row.max_live_hosts || "";
              form.elements.max_wayback_urls.value = row.max_wayback_urls || "";
              form.elements.max_js_assets.value = row.max_js_assets || "";
              for (const option of domainOptionNames) form.elements[option].checked = Boolean(row[option]);
              form.elements.active.checked = Boolean(row.active);
              form.elements.start_now.checked = false;
              form.elements.start_now.closest("label").hidden = true;
              $("domainEditorTitle").textContent = `Settings · ${row.domain}`;
              $("saveDomainButton").textContent = "Save settings";
              $("cancelDomainEdit").hidden = false;
              $("domainMessage").textContent = "";
              form.scrollIntoView({behavior:"smooth", block:"start"});
            }
            function managedDomainState(row) {
              if (row.scan_running) return "running";
              return row.active ? "active" : "paused";
            }
            function renderManagedDomains() {
              const query = $("domainManagerSearch").value.trim().toLowerCase();
              const status = $("domainManagerStatus").value;
              const rows = managedDomains.filter(row => (!query || `${row.domain} ${row.organization || ""}`.toLowerCase().includes(query)) && (!status || managedDomainState(row) === status));
              $("domainManagerRows").innerHTML = rows.length ? rows.map(row => {
                const currentState = managedDomainState(row);
                const stateBadge = currentState === "running" ? '<span class="badge orange">running</span>' : currentState === "active" ? '<span class="badge green">active</span>' : '<span class="badge">paused</span>';
                const next = row.active ? (row.next_scan ? new Date(row.next_scan).toLocaleString() : "queued") : "not scheduled";
                return `<tr>
                  <td class="domain-name" data-label="Domain"><strong>${esc(row.domain)}</strong><div class="meta">${esc(row.organization || "No organization")}</div></td>
                  <td data-label="State">${stateBadge}</td>
                  <td data-label="Schedule"><strong>${esc(row.scan_interval_hours)}h</strong><div class="meta">${esc(next)}</div></td>
                  <td class="domain-stats" data-label="Surface">${esc(row.subdomains || 0)} subs · ${esc(row.live_hosts || 0)} live<br>${esc(row.endpoints || 0)} URLs · ${esc(row.js_assets || 0)} JS</td>
                  <td class="domain-controls" data-label="Actions">
                    <button class="btn" type="button" data-domain-action="edit" data-domain-id="${row.id}">Settings</button>
                    <button class="btn" type="button" data-domain-action="scan" data-domain-id="${row.id}" ${row.scan_running ? "disabled" : ""}>Scan now</button>
                    <button class="btn" type="button" data-domain-action="toggle" data-domain-id="${row.id}">${row.active ? "Pause" : "Resume"}</button>
                    <button class="btn danger" type="button" data-domain-action="delete" data-domain-id="${row.id}">Delete</button>
                  </td>
                </tr>`;
              }).join("") : '<tr><td colspan="5" class="empty">No domains match this filter.</td></tr>';
            }
            async function loadManagedDomains() {
              $("domainManagerRows").innerHTML = '<tr><td colspan="5" class="loading">Loading domains...</td></tr>';
              managedDomains = await domainApi("/api/domains");
              renderManagedDomains();
            }
            async function mutateManagedDomain(domainId, action) {
              const row = managedDomains.find(item => Number(item.id) === Number(domainId));
              if (!row) return;
              try {
                if (action === "scan") {
                  await domainApi(`/api/domains/${domainId}/scan`, {method:"POST", headers:domainApiHeaders(), body:"{}"});
                  $("domainMessage").textContent = `${row.domain} is queued for immediate recon.`;
                } else {
                  await domainApi(`/api/domains/${domainId}`, {method:"PATCH", headers:domainApiHeaders(), body:JSON.stringify({active:!row.active})});
                  $("domainMessage").textContent = `${row.domain} ${row.active ? "paused" : "resumed"}. Pausing prevents future scans but does not terminate work already running.`;
                }
                domainManagerDirty = true;
                await loadManagedDomains();
              } catch (error) { $("domainMessage").textContent = error.message; }
            }
            async function openDomainDelete(domainId) {
              const dialog = $("domainDeleteDialog");
              $("domainDeleteImpact").innerHTML = '<div class="loading">Calculating deletion impact...</div>';
              $("domainDeleteWarning").textContent = "";
              $("domainDeleteConfirmation").value = "";
              $("confirmDomainDelete").disabled = true;
              dialog.showModal();
              try {
                deleteDomainCandidate = await domainApi(`/api/domains/${domainId}/deletion-impact`);
                $("domainDeleteSubtitle").textContent = deleteDomainCandidate.domain;
                const fields = [["Subdomains","subdomains"],["Live hosts","live_hosts"],["Endpoints","endpoints"],["Risky params","parameters"],["JS assets","js_assets"],["Findings","findings"],["Bug jobs","bug_jobs"],["FFUF runs","ffuf_runs"]];
                $("domainDeleteImpact").innerHTML = fields.map(([label,key]) => `<div class="domain-impact"><span>${label}</span><strong>${esc(deleteDomainCandidate[key] || 0)}</strong></div>`).join("");
                const blockerNames = Object.keys(deleteDomainCandidate.blockers || {});
                $("domainDeleteWarning").textContent = blockerNames.length
                  ? `Deletion is blocked: ${blockerNames.join(", ").replaceAll("_", " ")}. Pause this domain and wait for running work to finish.`
                  : `This permanently deletes approximately ${deleteDomainCandidate.core_rows || 0} core database rows and all cascaded recon records. ${deleteDomainCandidate.filesystem_note}`;
                $("domainDeleteConfirmation").dispatchEvent(new Event("input"));
              } catch (error) { $("domainDeleteWarning").textContent = error.message; }
            }
            async function submitDomainDelete() {
              if (!deleteDomainCandidate) return;
              const button = $("confirmDomainDelete");
              button.disabled = true;
              button.textContent = "Deleting...";
              try {
                await domainApi(`/api/domains/${deleteDomainCandidate.id}`, {method:"DELETE", headers:domainApiHeaders(), body:JSON.stringify({delete_data:true, confirm_domain:$("domainDeleteConfirmation").value})});
                const deletedCurrent = Number(deleteDomainCandidate.id) === Number(DOMAIN_ID);
                domainManagerDirty = true;
                $("domainDeleteDialog").close();
                deleteDomainCandidate = null;
                if (deletedCurrent) return location.assign("/");
                await loadManagedDomains();
                $("domainMessage").textContent = "Domain data deleted.";
              } catch (error) {
                $("domainDeleteWarning").textContent = error.message;
              } finally {
                button.textContent = "Delete domain data";
              }
            }
            const columns = {
              urls: [["domain","Domain"],["subdomain","Subdomain"],["full_url","URL"],["status_code","Status"],["response_size","Size"],["technologies","Tech"],["source","Source"],["js_references","JS ref"],["risk_tags","Risk"],["last_seen","Seen"]],
	              live_hosts: [["ffuf_action","FFUF"],["domain","Domain"],["url","URL"],["status_code","Status"],["title","Title"],["webserver","Server"],["content_length","Size"],["ffuf_run_count","Runs"],["last_ffuf_run","Last FFUF"],["last_seen","Seen"]],
              infrastructure: [["domain","Domain"],["ip_address","IP"],["classification","Class"],["provider","Provider"],["asn","ASN"],["subdomains","Subdomains"],["port","Port"],["state","State"],["service_source","Source"],["service","Service"],["product","Product"],["version","Version"],["cves","CVEs"],["shodan_last_seen","Shodan Seen"],["last_scanned_at","Verified"]],
              subdomains: [["domain","Domain"],["subdomain","Subdomain"],["is_resolved","Resolved"],["ip_addresses","IPs"],["live_host_count","Live"],["last_seen","Seen"]],
              js: [["domain","Domain"],["asset_url","Asset"],["http_status","Status"],["size_bytes","Size"],["source","Source"],["last_seen","Seen"]],
              credential_leaks: [["domain","Domain"],["detector_name","Detector"],["verified","Verified"],["redacted_secret","Redacted"],["source_url","Source URL"],["source_file","Source File"],["line_number","Line"],["last_seen","Seen"]],
              parameters: [["domain","Domain"],["base_url","Host"],["path","Path"],["status_code","Status"],["source","Source"],["param_name","Param"],["example_value","Example"],["risk_tags","Risk"],["last_seen","Seen"]],
              findings: [["signal_class","Class"],["severity","Severity"],["domain","Domain"],["signal_family","Signal"],["location","Location"],["duplicate_count","Variants"],["validation_status","Validation"],["analyst_status","Analyst"],["related_types","Evidence types"],["last_seen","Seen"]],
              screenshots: [["domain","Domain"],["url","URL"],["capture_reason","Reason"],["file_size","Size"],["captured_at","Captured"],["screenshot_path","Screenshot"]],
              risk: [["priority","Priority"],["score","Score"],["domain","Domain"],["signal_type","Signal"],["confidence","Confidence"],["validation_status","Validation"],["location","Location"],["duplicate_count","Variants"],["reasons","Why it is here"],["updated_at","Updated"]],
              bookmarks: [["domain","Domain"],["entity_type","Type"],["location","Location"],["priority","Priority"],["score","Score"],["status","Status"],["tags","Tags"],["notes","Notes"],["updated_at","Updated"]],
              events: [["domain","Domain"],["event_type","Event"],["entity_type","Type"],["location","Location"],["severity","Severity"],["payload","Payload"],["last_seen","Seen"]],
              monitors: [["severity","Severity"],["domain","Domain"],["monitor","Monitor"],["item_type","Type"],["value","Value"],["summary","Summary"],["first_seen","First Seen"],["last_seen","Last Seen"]],
              monitor_runs: [["run_actions",""],["id","Run"],["status","Status"],["auth_status","Auth"],["domain","Domain"],["monitor","Monitor"],["new_events_count","New"],["scripts_count","JS"],["requests_count","Requests"],["duration_seconds","Seconds"],["error","Error"],["started_at","Started"],["finished_at","Finished"]],
              monitor_intel: [["risk","Risk"],["domain","Domain"],["monitor","Monitor"],["item_type","Type"],["value","Value"],["source_url","Source"],["first_seen","First Seen"],["last_seen","Last Seen"]],
              ffuf_workbench: [["ffuf_run_action",""],["id","Run"],["status","Status"],["host_url","Target"],["wordlist_path","Wordlist"],["hits_count","Hits"],["started_at","Started"],["completed_at","Finished"],["error","Error"]],
              cloud: [["domain","Domain"],["provider","Provider"],["asset_type","Type"],["identifier","Identifier"],["location","Location"],["source","Source"],["last_seen","Seen"]],
              api_surfaces: [["domain","Domain"],["surface_type","Type"],["confidence","Confidence"],["location","Location"],["status_code","Status"],["auth_required","Auth"],["methods","Methods"],["operations_count","Ops"],["risk_flags","Risk"],["source","Source"],["last_seen","Seen"]],
              active_hunt: [["severity","Severity"],["confidence","Confidence"],["domain","Domain"],["check_type","Check"],["http_status","Status"],["finding","Finding"],["target_url","Target"],["parameter_name","Param"],["evidence","Evidence"],["created_at","Run Time"]],
              bug_jobs: [["priority","Priority"],["status","Status"],["scope_ok","Scope"],["domain","Domain"],["job_type","Job"],["asset_type","Asset Type"],["source_table","Source"],["source_id","Source ID"],["source_observed_at","Source First Seen"],["asset_value","Asset"],["hypothesis","Hypothesis"],["finding_status","Finding"],["confidence","Confidence"],["attempt_count","Attempts"],["prompt_path","Prompt"],["codex_output_path","Output"],["updated_at","Updated"]],
              search_intel: [["domain","Domain"],["category","Category"],["rank","Rank"],["url","Indexed URL"],["status_code","Status"],["is_in_scope","Scope"],["title","Title"],["snippet","Snippet"],["risk_tags","Signals"],["provider","Provider"],["last_seen","Seen"]],
              playbooks: [["priority","Priority"],["status","Status"],["confidence","Confidence"],["domain","Domain"],["check_type","Check"],["owasp_category","OWASP"],["target_url","Target"],["reasons","Reasons"],["validation_steps","Steps"],["updated_at","Updated"]],
              validation: [["priority","Priority"],["status","Status"],["domain","Domain"],["location","Location"],["validation_steps","Steps"],["notes","Notes"],["updated_at","Updated"]],
              evidence: [["severity","Severity"],["domain","Domain"],["title","Title"],["location","Location"],["summary","Summary"],["source_table","Source"],["updated_at","Updated"]]
            };
            const visible = JSON.parse(localStorage.getItem("recon-visible-columns") || "{}");
            const aiSourceTypes = {
              urls: "endpoints", live_hosts: "live_hosts", infrastructure: "network_services",
              subdomains: "subdomains", js: "js_assets", credential_leaks: "credential_leaks",
              parameters: "url_parameters", findings: "findings", screenshots: "screenshots",
              api_surfaces: "api_surfaces", active_hunt: "active_hunt_results", bug_jobs: "bug_jobs",
              playbooks: "attack_playbooks", validation: "validation_queue", evidence: "evidence_packs",
              ffuf_workbench: "ffuf_runs", cloud: "cloud_assets", events: "asset_events",
              monitors: "monitor_events", codex_worker: "bug_jobs", search_intel: "search_intelligence_results"
            };
            function aiContextForRow(row) {
              const context = {
                source_type: aiSourceTypes[state.tab] || state.tab,
                source_id: row.id ?? row.source_id ?? row.endpoint_id ?? row.live_host_id ?? null,
                section: state.tab,
                domain: row.domain || null,
                title: row.title || row.finding_type || row.job_type || row.subdomain || row.asset_value || row.location || row.url || row.full_url || `${tabs[state.tab]?.label || state.tab} record`,
                location: row.full_url || row.url || row.location || row.asset_url || row.subdomain || row.target_url || row.host_url || null,
              };
              for (const [key, value] of Object.entries(row)) {
                if (Object.keys(context).length >= 32) break;
                if (/request|response|raw|cookie|authorization|password|secret|token|banner/i.test(key)) continue;
                if (value === null || ["string", "number", "boolean"].includes(typeof value)) context[key] = typeof value === "string" ? value.slice(0, 1500) : value;
                else if (Array.isArray(value)) context[key] = value.slice(0, 30);
              }
              return context;
            }
            function selectRowForAI(row) {
              if (!row) return;
              window.dispatchEvent(new CustomEvent("recon:context", { detail: aiContextForRow(row) }));
              $("askSelectedRow").disabled = false;
            }
            async function loadFilterOptions() {
              const requestedTab = state.tab;
              const caps = activeCaps();
              if ((!DOMAIN_ID && !state.scanId) || (!caps.source && !caps.status && !caps.tech)) {
                filterOptions = emptyFilterOptions();
                renderFilterControls();
                renderSourceTabs();
                return;
              }
              try {
                const p = new URLSearchParams({ tab: requestedTab });
                if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
                if (state.scanId && requestedTab === "parameters") p.set("scan_id", state.scanId);
                const r = await fetch(`/api/filter-options?${p}`);
                if (r.ok && state.tab === requestedTab) filterOptions = await r.json();
              } catch (e) {
                if (state.tab === requestedTab) filterOptions = emptyFilterOptions();
              }
              if (state.tab !== requestedTab) return;
              renderFilterControls();
              renderSourceTabs();
            }
            function withDomain(url) {
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
              return p.toString() ? `${url}?${p}` : url;
            }
            function downloadWithFilters(url) {
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
              pruneFilters();
              for (const [k, v] of Object.entries(state.filters)) if (v) p.set(k, v);
              if (!p.toString()) return url;
              return `${url}${url.includes("?") ? "&" : "?"}${p}`;
            }
            function endpointWithParams(url, extra = {}) {
              const p = params();
              for (const [key, value] of Object.entries(extra)) if (value) p.set(key, value);
              return `${url}?${p}`;
            }
            function globalPageParams(url, extra = {}) {
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("monitor_domain_id", DOMAIN_ID);
              p.set("limit", state.limit);
              p.set("offset", state.offset);
              p.set("sort", state.sort);
              p.set("direction", state.direction);
              for (const [key, value] of Object.entries(extra)) if (value) p.set(key, value);
              return `${url}?${p}`;
            }
            function monitorReferenceParams(url, extra = {}) {
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("monitor_domain_id", DOMAIN_ID);
              p.set("limit", 250);
              p.set("offset", 0);
              for (const [key, value] of Object.entries(extra)) if (value) p.set(key, value);
              return `${url}?${p}`;
            }
            function activeDataUrl(tab) {
              if (state.scanId && scanTabs.has(state.tab)) {
                return `/api/scans/${state.scanId}/${state.tab}`;
              }
              return tab.api;
            }
            function monitorDownloadUrl(view) {
              const base = view === "runs" ? "/download/monitor-runs" : view === "intel" ? "/download/monitor-intel" : view === "errors" ? "/download/monitor-runs" : "/download/monitor-events";
              const extra = view === "errors" ? { status: "failed" } : {};
              if (view === "events" && state.monitorRunId) extra.run_id = state.monitorRunId;
              return globalPageParams(base, extra);
            }
            function activeDownloadUrl(tab) {
              if (tab.custom === "monitors") {
                return monitorDownloadUrl(state.monitorView || "events");
              }
              if (state.scanId && scanTabs.has(state.tab)) {
                return downloadWithFilters(`/download/scan/${state.scanId}/${state.tab}`);
              }
              return downloadWithFilters(tab.download);
            }
            function renderSourceTabs() {
              const el = $("sourceTabs");
              if (!el) return;
              const caps = activeCaps();
              if (!caps.source) {
                el.hidden = true;
                return;
              }
              el.hidden = false;
              const active = state.filters.source || "";
              const counts = state.tab === "js" ? (filterOptions.js_source_counts || []) : (filterOptions.source_counts || []);
              const sources = counts.length ? counts.map(item => [item.source, `${item.source} (${item.count})`]) : (state.tab === "js" ? (filterOptions.js_sources || []) : (filterOptions.sources || [])).map(item => [item, item]);
              el.innerHTML = [["", "All sources"], ...sources].map(([value, label]) => `<button type="button" class="source-tab ${value === active ? "active" : ""}" data-source-tab data-source="${esc(value)}">${esc(label)}</button>`).join("");
              document.querySelectorAll("[data-source-tab]").forEach(btn => btn.onclick = () => {
                const value = btn.dataset.source || "";
                if (value) state.filters.source = value;
                else delete state.filters.source;
                state.offset = 0;
                loadGrid();
              });
            }
            function renderFilterControls() {
              const caps = activeCaps();
              pruneFilters();
              $("scanScope").hidden = state.tab === "monitors" || state.tab === "ffuf_workbench" || state.tab === "search_intel";
              document.querySelectorAll("[data-filter-control]").forEach(el => {
                el.hidden = !caps[el.dataset.filterControl];
              });
              const statusMap = {
                urls: filterOptions.endpoint_status_counts || [],
                live_hosts: filterOptions.live_host_status_counts || [],
                js: filterOptions.js_status_counts || [],
                parameters: filterOptions.parameter_status_counts || []
              };
              const statuses = statusMap[state.tab] || filterOptions.status_counts || [];
              $("statusFilter").innerHTML = `<option value="">Any status</option>` + statuses.map(item => `<option value="${esc(item.status_code)}">${esc(item.status_code)} (${esc(item.count)})</option>`).join("");
              $("techFilter").innerHTML = `<option value="">Any tech</option>` + (filterOptions.technologies || []).map(item => `<option value="${esc(item)}">${esc(item)}</option>`).join("");
              $("quickFilter").value = state.filters.contains || "";
              $("statusFilter").value = state.filters.status_code || "";
              $("jsResponseFilter").value = state.filters.js_response || "";
              $("paramFilter").value = state.filters.has_parameters || "";
              $("techFilter").value = state.filters.tech || "";
              $("confidenceFilter").value = state.filters.confidence || "";
              $("responseSizeFilter").value = state.filters.response_size_gt || "";
              $("findingViewFilter").value = state.filters.finding_view || "leads";
              $("findingSeverityFilter").value = state.filters.severity || "";
              $("findingTypeFilter").value = state.filters.finding_type || "";
              $("findingResolutionFilter").value = state.filters.resolution || "active";
              $("findingRecentFilter").value = state.filters.recent_days || "";
            }
            function renderNav() {
              $("nav").innerHTML = Object.entries(tabs).map(([key, tab]) => `<button class="nav-btn ${key === state.tab ? "active" : ""}" data-tab="${key}"><span>${tab.label}</span><span id="count-${key}"></span></button>`).join("");
              document.querySelectorAll("[data-tab]").forEach(btn => btn.onclick = () => switchTab(btn.dataset.tab));
            }
            async function loadMetrics() {
              try {
                const r = await fetch(withDomain("/api/command-center"));
                const m = await r.json();
                if (!r.ok) throw new Error(m.error || `Command center failed (${r.status})`);
                const cards = [
                  ["total_domains","Domains","urls","info"],["live_hosts","Live Hosts","live_hosts","live"],["new_assets","New Assets","search","green"],
                  ["open_ports","Ports","infrastructure","warn"],["js_files","JS Files","js","info"],["graphql_endpoints","GraphQL","api_surfaces","purple"],
                  ["login_panels","Login Panels","urls","orange"],["cloud_assets","Cloud Assets","cloud","cloud"],["critical_findings","Priority Leads","risk","risk"],["attack_playbooks","Bug Jobs","bug_jobs","purple"],["recently_changed_assets","Changed","events","warn"]
                ];
                $("metrics").innerHTML = cards.map(([key, label, tab, cls]) => `<div class="metric" data-metric="${key}" data-tab="${tab}"><div class="label">${label}</div><div class="value ${cls}">${esc(m[key] ?? 0)}</div><div class="hint">${key === "scans_due" ? "scan status" : "drill down"}</div></div>`).join("");
                document.querySelectorAll("[data-metric]").forEach(card => card.onclick = () => applyMetric(card.dataset.metric, card.dataset.tab));
              } catch (error) {
                $("metrics").innerHTML = `<div class="empty">Command center unavailable. Use Refresh to retry.</div>`;
              }
            }
            function applyMetric(metric, tab) {
              state.filters = {};
              if (metric === "graphql_endpoints") state.filters.tech = "graphql";
              if (metric === "login_panels") state.filters.contains = "login";
              switchTab(tab || "urls", false);
            }
            async function loadFocus() {
              try {
                const p = new URLSearchParams({ limit: "12", compact: "1" });
                if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
                const r = await fetch(`/api/focus?${p}`);
                const data = await r.json();
                if (!r.ok) throw new Error(data.error || `Focus feed failed (${r.status})`);
                const focusSeen = new Set();
                const items = [...(data.high_signal_endpoints || []), ...(data.notable_findings || [])].filter(item => {
                  const raw = String(item.full_url || item.location || item.asset_url || "");
                  const key = `${String(item.domain || "").toLowerCase()}|${raw.toLowerCase().replace(/^https?:[/]{2}/, "").replace(/[?#].*$/, "").replace(/[/]$/, "")}`;
                  if (!raw || focusSeen.has(key)) return false;
                  focusSeen.add(key);
                  return true;
                }).slice(0, 12);
                $("focusCards").innerHTML = items.length ? items.map((item, i) => `<div class="intel-card" data-focus="${i}"><div>${badge(item.severity || item.status_code || "target")} ${badge(item.domain || "")}</div><h3 class="mono clip">${esc(item.full_url || item.location || item.asset_url || "")}</h3><div class="meta">${fmt(item.reasons || item.risk_tags || item.finding_type || "")}</div></div>`).join("") : `<div class="empty">No prioritized targets for this scope yet.</div>`;
                document.querySelectorAll("[data-focus]").forEach(el => el.onclick = () => openDrawer(items[Number(el.dataset.focus)]));
              } catch (error) {
                $("focusCards").innerHTML = `<div class="empty">Priority feed unavailable. Use Refresh to retry.</div>`;
              }
            }
            async function loadGrid() {
              const tab = tabs[state.tab];
              const scoped = state.scanId && scanTabs.has(state.tab);
              const dedicatedWorkbench = tab.custom === "ffuf_workbench";
              const dedicatedConsole = dedicatedWorkbench || tab.custom === "codex_worker";
              $("commandCenter").hidden = dedicatedConsole;
              $("focusPanel").hidden = dedicatedConsole;
              $("secondaryPanel").hidden = dedicatedConsole;
              $("gridToolbar").hidden = tab.custom === "codex_worker";
              $("grid").parentElement.hidden = tab.custom === "codex_worker";
              $("pageInfo").parentElement.hidden = tab.custom === "codex_worker";
              renderFilterControls();
              $("columnsBtn").hidden = false;
              $("downloadLink").hidden = false;
              $("gridTitle").textContent = scoped ? `${tab.label} · selected scan` : tab.label;
              renderSourceTabs();
              $("downloadLink").href = activeDownloadUrl(tab);
              $("grid").innerHTML = `<tr><td class="loading">Loading ${tab.label}...</td></tr>`;
              if (tab.custom === "triage") return loadSimpleList("/api/ai-triage", "triage");
              if (tab.custom === "search") return loadSearch();
              if (tab.custom === "search_intel") return loadSearchIntelligence();
              if (tab.custom === "monitors") return loadMonitors();
              if (tab.custom === "ffuf_workbench") return loadFfufWorkbench();
              if (tab.custom === "codex_worker") return loadCodexWorker();
              try {
                const r = await fetch(endpointWithParams(activeDataUrl(tab)));
                const data = await r.json();
                if (!r.ok) throw new Error(data.error || `${tab.label} failed (${r.status})`);
                state.rows = data.rows || [];
                state.gridResult = data;
                renderTable(state.rows, data.total || 0, Boolean(data.total_is_lower_bound));
              } catch (error) {
                state.rows = [];
                $("gridMeta").textContent = "request failed";
                $("grid").innerHTML = `<tbody><tr><td class="empty">Unable to load ${esc(tab.label)}. Use Refresh to retry.</td></tr></tbody>`;
              }
            }
            function activeColumns() {
              const base = columns[state.tab] || [];
              const hidden = visible[state.tab] || {};
              return base.filter(([key]) => !hidden[key]);
            }
            function renderTable(rows, total, totalIsLowerBound = false) {
              const cols = activeColumns();
              const totalLabel = totalIsLowerBound ? `${total}+` : total;
              const rawLabel = state.tab === "findings" && Number.isFinite(Number(state.gridResult?.raw_total))
                ? ` · ${Number(state.gridResult.raw_total).toLocaleString()} raw retained`
                : "";
              $("gridMeta").textContent = `${rows.length} shown of ${Number(totalLabel).toLocaleString ? (totalIsLowerBound ? `${Number(total).toLocaleString()}+` : Number(total).toLocaleString()) : totalLabel}${rawLabel}`;
              $("pageInfo").textContent = total ? `${state.offset + 1}-${Math.min(state.offset + rows.length, total)} of ${totalLabel}` : `0 of 0`;
              $("prevPage").disabled = state.offset <= 0;
              $("nextPage").disabled = rows.length === 0 || state.offset + rows.length >= total;
              const head = `<thead><tr>${cols.map(([key,label]) => key.endsWith("_action") ? `<th>${label}</th>` : `<th data-sort="${key}">${label}</th>`).join("")}</tr></thead>`;
              const body = rows.map((row, i) => `<tr data-row="${i}" class="${i === state.selected ? "selected" : ""}">${cols.map(([key]) => `<td class="${/url|path|location|asset|subdomain|details/.test(key) ? "mono" : ""} ${/url|path|location|asset/.test(key) ? "clip" : ""}">${cell(key, row[key], row)}</td>`).join("")}</tr>`).join("");
              $("grid").innerHTML = head + `<tbody>${body || `<tr><td class="empty" colspan="${cols.length}">No rows matched this view.</td></tr>`}</tbody>`;
              document.querySelectorAll("[data-row]").forEach(row => row.onclick = () => {
                state.selected = Number(row.dataset.row);
                renderSelected();
                const selectedRow = state.rows[state.selected];
                selectRowForAI(selectedRow);
                if (state.tab === "monitors" && (state.monitorView === "runs" || state.monitorView === "errors")) return openMonitorRunChanges(selectedRow);
                if (state.tab === "ffuf_workbench") return openFfufWorkbenchRun(selectedRow.id, 0);
                openDrawer(selectedRow);
              });
              document.querySelectorAll("[data-open-ffuf]").forEach(btn => btn.onclick = (event) => {
                event.stopPropagation();
                const idx = Number(btn.dataset.openFfuf);
                if (!Number.isNaN(idx)) openDrawerAt(idx);
              });
              document.querySelectorAll("[data-open-ffuf-workbench]").forEach(btn => btn.onclick = (event) => {
                event.stopPropagation();
                openFfufWorkbenchRun(Number(btn.dataset.openFfufWorkbench), 0);
              });
              document.querySelectorAll("[data-delete-ffuf-workbench]").forEach(btn => btn.onclick = (event) => {
                event.stopPropagation();
                deleteFfufWorkbenchRun(Number(btn.dataset.deleteFfufWorkbench), btn.dataset.ffufTarget || "");
              });
              document.querySelectorAll("[data-sort]").forEach(th => th.onclick = () => { state.sort = th.dataset.sort; state.direction = state.direction === "desc" ? "asc" : "desc"; loadGrid(); });
            }
            function cell(key, value, row) {
              if (key === "run_actions") return `<button type="button" class="btn" data-open-run="${esc(row.id)}">Changes</button>`;
              if (key === "ffuf_action") return row.live_host_id ? `<button type="button" class="btn primary" data-open-ffuf="${esc(state.rows.indexOf(row))}">Run</button>` : "";
              if (key === "ffuf_run_action") return `<span class="row-actions"><button type="button" class="btn primary" data-open-ffuf-workbench="${esc(row.id)}">Results</button><button type="button" class="btn danger" data-delete-ffuf-workbench="${esc(row.id)}" data-ffuf-target="${esc(row.host_url || "")}" ${row.status === "running" ? "disabled title=\\\"Running runs cannot be deleted until they finish.\\\"" : ""}>Delete</button></span>`;
              if (state.tab === "ffuf_workbench" && key === "wordlist_path") return esc(String(value || "").replace("/app/wordlists/SecLists/", ""));
              if (key === "is_in_scope") return badge(value ? "in scope" : "external");
              if (key === "status_code" || key === "http_status" || key === "severity" || key === "priority" || key === "status" || key === "confidence" || key === "auth_status" || key === "risk" || key === "signal_class" || key === "validation_status" || key === "analyst_status") return value ? badge(value) : "";
              if (state.tab === "monitors" && (state.monitorView === "runs" || state.monitorView === "errors") && key === "id") return `<a href="/download/monitor-events?run_id=${esc(value)}" title="Download changes for this run">${esc(value)}</a>`;
              if (key === "js_references") {
                const refs = Array.isArray(value) ? value.filter(Boolean) : [];
                if (!refs.length) return "";
                const count = Number(row.js_reference_count || refs.length);
                const suffix = refs.length === 1 ? "file" : "files";
                const sample = count > refs.length ? `sample: ${refs[0]}` : refs[0];
                return `${badge(`${count} JS ${suffix}`)} <span class="meta clip">${esc(sample)}</span>`;
              }
              if (key === "risk_tags" || key === "technologies" || key === "ip_addresses" || key === "risk_flags" || key === "methods" || key === "validation_steps" || key === "stop_conditions" || key === "safety_notes" || key === "reasons" || key === "analyst_tags" || key === "related_types") return fmt(value);
              if (key === "details" || key === "parameters" || key === "evidence" || key === "request" || key === "response") return `<span class="meta">${esc(JSON.stringify(value || {})).slice(0, 180)}</span>`;
              if (key === "screenshot_path" && value) return `<a href="/screenshots/${esc(value)}" target="_blank">open</a>`;
              return esc(value ?? "");
            }
            function renderSelected() {
              document.querySelectorAll("[data-row]").forEach(row => row.classList.toggle("selected", Number(row.dataset.row) === state.selected));
            }
	            function detailRow(row) {
	              const copy = { ...row };
	              if (state.tab === "bookmarks") {
	                delete copy.entity_key;
	                delete copy.entity_id;
	              }
	              return copy;
	            }
            function updateDrawerNav() {
              const hasRows = state.rows.length > 0 && state.selected >= 0 && state.selected < state.rows.length;
              $("drawerPosition").textContent = hasRows ? `${state.selected + 1} of ${state.rows.length} shown` : "";
              $("drawerPrev").disabled = !hasRows || state.selected <= 0;
              $("drawerNext").disabled = !hasRows || state.selected >= state.rows.length - 1;
            }
            function openDrawerAt(index) {
              if (index < 0 || index >= state.rows.length) return;
              state.selected = index;
              renderSelected();
              openDrawer(state.rows[state.selected]);
            }
            async function loadSimpleList(url, type) {
              const target = state.scanId && type === "triage" ? endpointWithParams(`/api/scans/${state.scanId}/triage`) : withDomain(url);
              const r = await fetch(target);
              const payload = await r.json();
              const rows = Array.isArray(payload) ? payload : (payload.rows || []);
              state.rows = rows;
              const cols = [["priority","Priority"],["score","Score"],["domain","Domain"],["item_type","Type"],["location","Location"],["reasons","Reasons"],["last_seen","Seen"]];
              columns[type] = cols; state.tab = type;
              renderTable(rows, Array.isArray(payload) ? rows.length : (payload.total || rows.length));
            }
            function codexDuration(seconds) {
              const n = Math.max(0, Number(seconds || 0));
              if (!n) return "-";
              if (n < 60) return `${n}s`;
              const hours = Math.floor(n / 3600);
              const minutes = Math.floor((n % 3600) / 60);
              return hours ? `${hours}h ${minutes}m` : `${minutes}m`;
            }
            function codexItemText(value) {
              if (value === null || value === undefined) return "";
              return typeof value === "object" ? JSON.stringify(value) : String(value);
            }
            function codexSection(title, value) {
              if (value === null || value === undefined || value === "" || (Array.isArray(value) && !value.length)) return "";
              const body = Array.isArray(value)
                ? `<div class="codex-timeline">${value.map(item => `<div class="codex-event"><span class="status-dot done"></span><div><p>${esc(codexItemText(item))}</p></div></div>`).join("")}</div>`
                : `<p>${esc(codexItemText(value))}</p>`;
              return `<section class="codex-section"><h4>${esc(title)}</h4>${body}</section>`;
            }
            function codexGroup(row) {
              if (row.status === "running") return "Running";
              if (row.finding_status === "confirmed" || row.finding_status === "possible" || row.codex_alert_kind === "review") return "Leads and findings";
              if (row.status === "queued" || row.status === "prepared") return "Queued";
              if (row.status === "failed") return "Failed";
              return "Completed";
            }
            function codexJobCard(row) {
              const result = row.result || {};
              const outcome = String(result.finding_status || row.finding_status || row.status || "unknown").toLowerCase();
              const selected = String(row.id) === String(state.codexJobId || "");
              return `<button type="button" class="codex-job ${selected ? "active" : ""}" data-codex-job="${esc(row.id)}">
                <div class="codex-job-top"><span class="status-dot ${esc(outcome)}"></span><strong>${esc(row.target || row.domain || "Unknown target")}</strong><span class="codex-job-id">#${esc(row.id)}</span></div>
                <div class="codex-job-title">${esc(row.display_title || row.hypothesis || row.job_type || "Codex review")}</div>
                <div class="codex-job-meta"><span>${esc(String(row.job_type || "").replaceAll("_", " "))}</span><span>${esc(row.updated_at || "")}</span></div>
              </button>`;
            }
            function renderCodexJobList(rows) {
              const needle = state.codexSearch.trim().toLowerCase();
              const filtered = needle ? rows.filter(row => [row.target, row.domain, row.asset_value, row.job_type, row.display_title, row.finding_status].some(value => String(value || "").toLowerCase().includes(needle))) : rows;
              const groupOrder = ["Running", "Leads and findings", "Queued", "Completed", "Failed"];
              const html = groupOrder.map(group => {
                const items = filtered.filter(row => codexGroup(row) === group);
                return items.length ? `<div class="codex-group-title">${group} · ${items.length}</div>${items.map(codexJobCard).join("")}` : "";
              }).join("");
              $("codexJobList").innerHTML = html || `<div class="empty">No worker jobs match this view.</div>`;
              document.querySelectorAll("[data-codex-job]").forEach(button => button.onclick = () => openCodexJob(button.dataset.codexJob));
            }
            function renderCodexDetail(job) {
              const r = job.result || {};
              const status = String(r.finding_status || job.finding_status || job.status || "unknown").toLowerCase();
              const tests = Array.isArray(r.tests_performed) ? r.tests_performed : [];
              const evidence = Array.isArray(r.evidence_files) ? r.evidence_files : [];
              const sources = Array.isArray(r.data_sources_used) ? r.data_sources_used : [];
              const skills = Array.isArray(r.skills_used) ? r.skills_used : [];
              const alertSignals = Array.isArray(r.alert_signals) ? r.alert_signals : [];
              const confidence = r.confidence ?? job.confidence;
              const timeline = [
                ["queued", "Job queued", job.created_at, job.hypothesis || `${job.job_type} on ${job.asset_value}`],
                ...(job.started_at ? [["running", "Codex worker started", job.started_at, `Attempt ${job.attempt_count || 1} · ${r.active_request_count || 0} active requests`]] : []),
                ...(job.vpn_failover_attempted ? [[job.vpn_failover_succeeded ? "done" : "failed", job.vpn_failover_succeeded ? "Alternate egress retry completed" : "Alternate egress retry stopped", job.vpn_failover_at, job.vpn_failover_reason || "VPN failover audited"]] : []),
                ...(tests.length ? [["done", `Tests performed · ${tests.length}`, "", tests.map(codexItemText).join("\\n")]] : []),
                ...(r.observed_anomaly ? [[status === "possible" ? "possible" : "done", "Observed result", "", r.observed_anomaly]] : []),
                ...((job.finished_at || job.error) ? [[job.status === "failed" ? "failed" : status, job.status === "failed" ? "Worker failed" : "Worker completed", job.finished_at || job.updated_at, job.error || r.impact || "Result recorded"]] : []),
              ];
              $("codexDetail").innerHTML = `
                <div class="codex-detail-head">
                  <div>${badge(job.status || "")} ${badge(r.finding_status || job.finding_status || "unclassified")} ${r.manual_review_priority ? badge(`${r.manual_review_priority} review`) : ""}</div>
                  <h3>${esc(r.title || job.hypothesis || `${job.job_type} review`)}</h3>
                  <div class="meta mono">${esc(job.asset_value || r.affected_endpoint || "")}</div>
                  <button class="btn primary" id="askCodexJob">Ask AI about this job</button>
                </div>
                <div class="codex-detail-body">
                  <div class="codex-facts">
                    <div class="codex-fact"><span>Job</span><strong>#${esc(job.id)}</strong></div>
                    <div class="codex-fact"><span>Family</span><strong>${esc(String(job.job_category || "-").replaceAll("_", " "))}</strong></div>
                    <div class="codex-fact"><span>Confidence</span><strong>${confidence === null || confidence === undefined ? "-" : `${esc(confidence)}%`}</strong></div>
                    <div class="codex-fact"><span>Duration</span><strong>${esc(codexDuration(job.duration_seconds))}</strong></div>
                    <div class="codex-fact"><span>Evidence</span><strong>${esc(evidence.length)}</strong></div>
                    <div class="codex-fact"><span>VPN retry</span><strong>${job.vpn_failover_attempted ? (job.vpn_failover_succeeded ? "completed" : "stopped") : "not used"}</strong></div>
                  </div>
                  ${codexSection("Impact", r.impact)}
                  ${codexSection("Observed anomaly", r.observed_anomaly)}
                  ${codexSection("Alert signals", alertSignals)}
                  <section class="codex-section"><h4>Worker activity</h4><div class="codex-timeline">${timeline.map(event => `<div class="codex-event"><span class="status-dot ${esc(event[0])}"></span><div><strong>${esc(event[1])}</strong>${event[2] ? `<span class="meta"> · ${esc(event[2])}</span>` : ""}<p>${esc(event[3])}</p></div></div>`).join("")}</div></section>
                  ${codexSection("Safe reproduction", r.safe_reproduction_steps)}
                  ${codexSection("Roles tested", r.roles_tested)}
                  ${codexSection("Data sources", sources)}
                  ${codexSection("Skills used", skills)}
                  ${codexSection("Manual review reason", r.manual_review_reason)}
                  ${codexSection("Recommended next step", r.recommended_next_step)}
                  ${job.vpn_failover_attempted ? codexSection("Alternate egress audit", `${job.vpn_failover_reason || "Recorded"}${job.vpn_egress_before || job.vpn_egress_after ? ` · ${job.vpn_egress_before || "unknown"} -> ${job.vpn_egress_after || "unknown"}` : ""}`) : ""}
                  ${job.artifact_error ? codexSection("Artifact status", job.artifact_error) : ""}
                  ${evidence.length ? `<section class="codex-section"><h4>Evidence files</h4><div class="codex-path-list">${evidence.map(item => `<div class="codex-path">${esc(typeof item === "object" ? (item.path || JSON.stringify(item)) : item)}</div>`).join("")}</div></section>` : ""}
                </div>`;
              selectRowForAI(job);
              $("askCodexJob").onclick = () => window.ReconAI?.open();
            }
            async function openCodexJob(jobId) {
              state.codexJobId = String(jobId || "");
              const nextUrl = new URL(location.href);
              nextUrl.searchParams.set("job_id", state.codexJobId);
              history.replaceState(null, "", nextUrl);
              renderCodexJobList(state.rows);
              $("codexDetail").innerHTML = `<div class="loading">Loading job #${esc(jobId)}...</div>`;
              const response = await fetch(`/api/codex-worker/jobs/${encodeURIComponent(jobId)}${DOMAIN_ID ? `?domain_id=${DOMAIN_ID}` : ""}`);
              const job = await response.json();
              if (!response.ok) {
                $("codexDetail").innerHTML = `<div class="empty">${esc(job.error || "Unable to load worker job")}</div>`;
                return;
              }
              renderCodexDetail(job);
            }
            async function loadCodexWorker() {
              $("columnsBtn").hidden = true;
              $("downloadLink").hidden = true;
              $("gridTitle").textContent = "Codex Worker";
              $("gridMeta").textContent = "activity and reviewed leads";
              const p = new URLSearchParams({limit: "100"});
              if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
              if (state.codexStatus) p.set("status", state.codexStatus);
              if (state.codexOutcome) p.set("outcome", state.codexOutcome);
              const response = await fetch(`/api/codex-worker?${p}`);
              const data = await response.json();
              if (!response.ok) {
                $("sourceTabs").hidden = false;
                $("sourceTabs").innerHTML = `<div class="empty">${esc(data.error || "Unable to load Codex worker activity")}</div>`;
                return;
              }
              state.rows = data.rows || [];
              const s = data.summary || {};
              const worker = data.worker || {};
              const vpn = worker.vpn_failover || {};
              const roi = data.roi_by_category || [];
              const focusDomains = data.focus_domains || [];
              const roiRows = roi.map(item => `<tr><td>${esc(String(item.job_category || "").replaceAll("_", " "))}</td><td>${esc(item.allocation || 0)}%</td><td>${esc(item.completed || 0)}</td><td>${esc(item.credible || 0)}</td><td>${esc(item.confirmed || 0)}</td><td>${esc(item.conversion_rate || 0)}%</td><td>${esc(codexDuration(item.avg_seconds || 0))}</td></tr>`).join("");
              const focusRows = focusDomains.map(item => `<tr><td>${esc(item.domain || "-")}</td><td>${esc(item.completed || 0)}</td><td>${esc(item.credible || 0)}</td><td>${esc(item.confirmed || 0)}</td><td>${esc(item.conversion_rate || 0)}%</td></tr>`).join("");
              $("sourceTabs").hidden = false;
              $("sourceTabs").innerHTML = `<div class="codex-console">
                <div class="codex-summary">
                  <div class="codex-stat"><span>Processed</span><strong>${esc(s.done || 0)}</strong></div>
                  <div class="codex-stat"><span>Running</span><strong>${esc(s.running || 0)}</strong></div>
                  <div class="codex-stat"><span>Queued</span><strong>${esc(s.queued || 0)}</strong></div>
                  <div class="codex-stat"><span>Leads</span><strong>${esc(s.leads || 0)}</strong></div>
                  <div class="codex-stat"><span>Confirmed</span><strong>${esc(s.confirmed || 0)}</strong></div>
                  <div class="codex-stat"><span>No finding</span><strong>${esc(s.no_finding || 0)}</strong></div>
                  <div class="codex-stat"><span>Failed</span><strong>${esc(s.failed || 0)}</strong></div>
                  <div class="codex-stat"><span>VPN retries</span><strong>${esc(s.vpn_attempted || 0)}</strong></div>
                  <div class="codex-stat"><span>VPN completed</span><strong>${esc(s.vpn_succeeded || 0)}</strong></div>
                </div>
                <div class="codex-controls">
                  <select id="codexStatus"><option value="">All states</option>${["running","queued","prepared","done","failed"].map(value => `<option value="${value}" ${value === state.codexStatus ? "selected" : ""}>${value}</option>`).join("")}</select>
                  <select id="codexOutcome"><option value="">All outcomes</option><option value="leads" ${state.codexOutcome === "leads" ? "selected" : ""}>Leads and findings</option><option value="confirmed" ${state.codexOutcome === "confirmed" ? "selected" : ""}>Confirmed only</option><option value="review" ${state.codexOutcome === "review" ? "selected" : ""}>Review alerts</option><option value="none" ${state.codexOutcome === "none" ? "selected" : ""}>No finding</option></select>
                  <input id="codexSearch" value="${esc(state.codexSearch)}" placeholder="Filter target, asset, job type, or title">
                  <button type="button" class="btn" id="codexRefresh">Refresh</button>
                  <span class="codex-worker-state"><span class="status-dot ${esc(worker.status || "")}"></span>${esc(worker.status || "unknown")} · ${esc(worker.active_count || 0)}/${esc(worker.parallelism || 1)} active · jobs ${esc((worker.current_job_ids || []).join(", ") || "-")} · ${esc(worker.daily_started_count || 0)} started today · VPN ${esc(vpn.status || (vpn.enabled ? "unknown" : "disabled"))}${vpn.public_ip ? ` (${esc(vpn.public_ip)})` : ""} · last ${esc(worker.updated_at || "unknown")}</span>
                </div>
                <div class="codex-roi-grid">
                  <section class="codex-roi-panel"><h3>Hunting family yield · ${esc(data.recent_days || 30)} days</h3><table class="codex-roi-table"><thead><tr><th>Family</th><th>Share</th><th>Done</th><th>Credible</th><th>Confirmed</th><th>Yield</th><th>Avg time</th></tr></thead><tbody>${roiRows || `<tr><td colspan="7">No completed jobs in this window.</td></tr>`}</tbody></table></section>
                  <section class="codex-roi-panel"><h3>Programs worth deeper work</h3><table class="codex-roi-table"><thead><tr><th>Domain</th><th>Done</th><th>Credible</th><th>Confirmed</th><th>Yield</th></tr></thead><tbody>${focusRows || `<tr><td colspan="5">No yield data yet.</td></tr>`}</tbody></table></section>
                </div>
                <div class="codex-layout"><aside class="codex-list" id="codexJobList"></aside><article class="codex-detail" id="codexDetail"><div class="empty">Select a worker job to inspect its activity and evidence.</div></article></div>
                <div class="meta">Showing ${esc(state.rows.length)} recent jobs from the last ${esc(data.recent_days || 30)} days.</div>
              </div>`;
              renderCodexJobList(state.rows);
              $("codexStatus").onchange = event => { state.codexStatus = event.target.value; loadCodexWorker(); };
              $("codexOutcome").onchange = event => { state.codexOutcome = event.target.value; loadCodexWorker(); };
              $("codexSearch").oninput = event => { state.codexSearch = event.target.value; renderCodexJobList(state.rows); };
              $("codexRefresh").onclick = loadCodexWorker;
              const preferred = state.rows.find(row => String(row.id) === String(state.codexJobId)) || state.rows.find(row => row.status === "running") || state.rows.find(row => row.finding_status === "confirmed" || row.finding_status === "possible") || state.rows[0];
              if (preferred) openCodexJob(preferred.id);
            }
            async function loadSearch() {
              const q = $("globalSearch").value.trim();
              const p = new URLSearchParams(); if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID); p.set("q", q);
              p.set("limit", state.limit);
              p.set("offset", state.offset);
              const r = await fetch(state.scanId ? `/api/scans/${state.scanId}/search?${p}` : `/api/search?${p}`);
              const payload = q ? await r.json() : [];
              const rows = Array.isArray(payload) ? payload : (payload.rows || []);
              columns.search = [["result_type","Type"],["domain","Domain"],["title","Title"],["location","Location"],["severity","Severity"],["details","Details"],["last_seen","Seen"]];
              state.rows = rows; renderTable(rows, Array.isArray(payload) ? rows.length : (payload.total || rows.length));
            }
            async function loadSearchIntelligence() {
              const runsResp = await fetch(withDomain("/api/search-intelligence/runs"));
              const runsPayload = await runsResp.json();
              const runs = runsPayload.rows || [];
              const providerStatus = runsPayload.status || {};
              const categories = ["inventory", "auth", "admin", "api", "redirect", "upload", "documents", "javascript", "configuration", "errors", "cloud", "staging"];
              $("sourceTabs").hidden = false;
              $("sourceTabs").innerHTML = `
                <div class="monitor-layout">
                  <div class="toolbar">
                    <span class="badge ${providerStatus.configured ? "green" : "orange"}">${providerStatus.configured ? esc(providerStatus.provider) : "provider not configured"}</span>
                    <span class="meta">${esc(providerStatus.query_count || 12)} curated queries · every ${esc(providerStatus.interval_hours || 168)}h</span>
                    <select id="dorkRunFilter">
                      <option value="">All runs</option>
                      ${runs.map(run => `<option value="${esc(run.id)}" ${String(run.id) === String(state.searchIntelRunId || "") ? "selected" : ""}>Run ${esc(run.id)} · ${esc(run.domain)} · ${esc(run.started_at)} · ${esc(run.new_result_count || 0)} new</option>`).join("")}
                    </select>
                    <select id="dorkCategoryFilter">
                      <option value="">All categories</option>
                      ${categories.map(category => `<option value="${category}" ${category === state.searchIntelCategory ? "selected" : ""}>${category}</option>`).join("")}
                    </select>
                    <select id="dorkScopeFilter">
                      <option value="">Any scope</option>
                      <option value="in" ${state.searchIntelScope === "in" ? "selected" : ""}>In scope</option>
                      <option value="out" ${state.searchIntelScope === "out" ? "selected" : ""}>External references</option>
                    </select>
                    <button type="button" class="btn primary" id="runDorksNow" ${!DOMAIN_ID || !providerStatus.configured ? "disabled" : ""}>Run now</button>
                  </div>
                  <div class="monitor-run-strip">
                    ${runs.length ? runs.slice(0, 8).map(run => `
                      <div class="monitor-run-card ${String(run.id) === String(state.searchIntelRunId || "") ? "active" : ""}" data-dork-run="${esc(run.id)}">
                        <div class="run-top"><strong>Run ${esc(run.id)}</strong>${badge(run.status)}</div>
                        <div class="meta">${esc(run.domain)} · ${esc(run.provider)}</div>
                        <div class="run-counts">
                          <span><strong>${esc(run.result_count || 0)}</strong>results</span>
                          <span><strong>${esc(run.new_result_count || 0)}</strong>new</span>
                          <span><strong>${esc(run.in_scope_count || 0)}</strong>in scope</span>
                        </div>
                      </div>`).join("") : `<div class="empty">No Google dork runs recorded yet.</div>`}
                  </div>
                </div>`;
              const p = new URLSearchParams();
              if (DOMAIN_ID) p.set("domain_id", DOMAIN_ID);
              p.set("limit", state.limit);
              p.set("offset", state.offset);
              p.set("sort", state.sort);
              p.set("direction", state.direction);
              if (state.searchIntelRunId) p.set("run_id", state.searchIntelRunId);
              if (state.searchIntelCategory) p.set("category", state.searchIntelCategory);
              if (state.searchIntelScope) p.set("scope", state.searchIntelScope);
              if (state.filters.contains) p.set("contains", state.filters.contains);
              const download = new URLSearchParams(p);
              download.delete("limit");
              download.delete("offset");
              download.delete("sort");
              download.delete("direction");
              $("downloadLink").href = `/download/search-intelligence?${download}`;
              $("gridTitle").textContent = state.searchIntelRunId ? `Google Dorks · Run ${state.searchIntelRunId}` : "Google Dorks · All Results";
              const response = await fetch(`/api/search-intelligence/results?${p}`);
              const data = await response.json();
              state.rows = data.rows || [];
              renderTable(state.rows, data.total || 0);
              $("dorkRunFilter").onchange = event => {
                state.searchIntelRunId = event.target.value;
                state.offset = 0;
                loadSearchIntelligence();
              };
              $("dorkCategoryFilter").onchange = event => {
                state.searchIntelCategory = event.target.value;
                state.offset = 0;
                loadSearchIntelligence();
              };
              $("dorkScopeFilter").onchange = event => {
                state.searchIntelScope = event.target.value;
                state.offset = 0;
                loadSearchIntelligence();
              };
              document.querySelectorAll("[data-dork-run]").forEach(card => card.onclick = () => {
                state.searchIntelRunId = card.dataset.dorkRun || "";
                state.offset = 0;
                loadSearchIntelligence();
              });
              $("runDorksNow").onclick = async () => {
                const button = $("runDorksNow");
                button.disabled = true;
                button.textContent = "Queueing...";
                const resp = await fetch("/api/search-intelligence/run", {
                  method: "POST",
                  headers: {"Content-Type": "application/json"},
                  body: JSON.stringify({domain_id: DOMAIN_ID})
                });
                const payload = await resp.json();
                button.textContent = resp.ok ? "Queued" : "Run now";
                if (!resp.ok) {
                  button.disabled = false;
                  $("sourceTabs").insertAdjacentHTML("afterbegin", `<div class="badge red">${esc(payload.error || "Unable to queue dork run")}</div>`);
                  return;
                }
                setTimeout(loadSearchIntelligence, 1200);
              };
            }
            function domainOptions(selected) {
              return DOMAINS.map(d => `<option value="${esc(d.id)}" ${String(d.id) === String(selected || "") ? "selected" : ""}>${esc(d.domain)}</option>`).join("");
            }
            function parseMaybeJson(value, fallback) {
              if (value === null || value === undefined || value === "") return fallback;
              if (Array.isArray(value) || typeof value === "object") return value;
              try { return JSON.parse(value); } catch (e) { return fallback; }
            }
            function monitorRunCard(row) {
              const active = String(row.id) === String(state.monitorRunId || "");
              return `
                <div class="monitor-run-card ${active ? "active" : ""}" data-open-run="${esc(row.id)}">
                  <div class="run-top"><strong>Run ${esc(row.id)}</strong>${badge(row.status || "")}</div>
                  <div class="meta mono clip">${esc(row.started_at || "")}</div>
                  <div class="meta">${esc(row.monitor || "")} · ${esc(row.domain || "")}</div>
                  <div class="run-counts">
                    <span><strong>${esc(row.new_events_count || 0)}</strong>new</span>
                    <span><strong>${esc(row.scripts_count || 0)}</strong>JS</span>
                    <span><strong>${esc(row.requests_count || 0)}</strong>req</span>
                  </div>
                </div>`;
            }
            function openMonitorRunChanges(row) {
              if (!row || !row.id) return;
              state.monitorRunId = String(row.id);
              state.monitorView = "events";
              state.offset = 0;
              const nextUrl = new URL(location.href);
              nextUrl.searchParams.set("tab", "monitors");
              nextUrl.searchParams.set("monitor_view", "events");
              nextUrl.searchParams.set("run_id", state.monitorRunId);
              history.replaceState(null, "", nextUrl);
              loadMonitors();
            }
            async function loadMonitors() {
              state.monitorView ||= "runs";
              const activeView = state.monitorView;
              const runExtra = activeView === "errors" ? { status: "failed" } : {};
              const runsUrl = activeView === "runs" || activeView === "errors"
                ? globalPageParams("/api/monitor-runs", runExtra)
                : monitorReferenceParams("/api/monitor-runs", runExtra);
              const [monResp, runsResp] = await Promise.all([
                fetch(monitorReferenceParams("/api/monitors")),
                fetch(runsUrl)
              ]);
              const monitors = await monResp.json();
              const runsData = await runsResp.json();
              const monitorRows = monitors.rows || [];
              const runRows = runsData.rows || [];
              if (activeView === "events" && !state.monitorRunId && runRows.length) state.monitorRunId = String(runRows[0].id);
              const selectedRun = runRows.find(r => String(r.id) === String(state.monitorRunId || "")) || null;
              let data = runsData;
              if (activeView === "intel") {
                const resp = await fetch(globalPageParams("/api/monitor-intel"));
                data = await resp.json();
              } else if (activeView === "events") {
                if (selectedRun) {
                  const resp = await fetch(globalPageParams("/api/monitor-events", { run_id: selectedRun.id }));
                  data = await resp.json();
                } else {
                  data = { rows: [], total: 0 };
                }
              }
              const viewButtons = [["runs", "Runs"], ["events", selectedRun ? `Run ${selectedRun.id} Changes` : "Run Changes"], ["intel", "All Intel"], ["errors", "Errors"]];
              columns.monitors = activeView === "runs" || activeView === "errors" ? columns.monitor_runs : activeView === "intel" ? columns.monitor_intel : [["severity","Severity"],["run_id","Run"],["domain","Domain"],["monitor","Monitor"],["item_type","Type"],["value","Value"],["summary","Summary"],["first_seen","First Seen"],["last_seen","Last Seen"]];
              $("downloadLink").href = monitorDownloadUrl(activeView);
              $("gridTitle").textContent = activeView === "events" && selectedRun ? `Change Monitor · Run ${selectedRun.id}` : activeView === "intel" ? "Change Monitor · All Intel" : activeView === "errors" ? "Change Monitor · Failed Runs" : "Change Monitor · Runs";
              $("sourceTabs").hidden = false;
              $("sourceTabs").innerHTML = `
                <div class="monitor-layout">
                  <div class="source-tabs" style="padding:0;border:0;background:transparent">
                    ${viewButtons.map(([key, label]) => `<button type="button" class="source-tab ${activeView === key ? "active" : ""}" data-monitor-view="${key}">${label}</button>`).join("")}
                  </div>
                  <div class="monitor-run-strip">
                    ${runRows.length ? runRows.slice(0, 12).map(monitorRunCard).join("") : `<div class="empty">No monitor runs recorded yet.</div>`}
                  </div>
                  <div class="monitor-cards">
                    ${monitorRows.length ? monitorRows.map(m => `
                      <div class="intel-card" data-monitor-json="${esc(JSON.stringify(m))}">
                        <div>${badge(m.enabled ? "enabled" : "disabled")} ${badge(m.auth_type || "none")} ${badge(m.auth_status || "unchecked")} ${badge(`${m.event_count || 0} changes`)}</div>
                        <h3 class="mono clip">${esc(m.name || m.start_url)}</h3>
                        <div class="meta mono clip">${esc(m.start_url)}</div>
                        <div class="meta">${esc(m.domain || "")} · every ${esc(m.interval_hours || 24)}h · ${esc(m.last_run_at || "never run")}</div>
                        ${m.auth_last_error ? `<div class="badge orange">auth: ${esc(String(m.auth_last_error).slice(0, 140))}</div>` : ""}
                        ${m.last_error ? `<div class="badge red">${esc(String(m.last_error).slice(0, 180))}</div>` : ""}
                        <div class="scope" style="margin-top:.55rem"><button class="btn" data-monitor-edit="${esc(m.id)}">Edit</button><button class="btn primary" data-monitor-run="${esc(m.id)}">Run now</button></div>
                      </div>`).join("") : `<div class="empty">No change monitors configured yet.</div>`}
                  </div>
                  <details class="monitor-config" id="monitorConfig">
                    <summary>Configure monitors</summary>
                    <form class="monitor-form" id="monitorForm">
                      <input type="hidden" name="id" id="monitorId">
                      <label>Monitor domain<select name="domain_id" id="monitorDomain"><option value="">Select target domain</option>${domainOptions()}</select></label>
                      <label class="wide">Monitor name<input name="name" placeholder="Amplitude authenticated app"></label>
                      <label class="wide">Start URL<input name="start_url" required placeholder="https://app.amplitude.com/"></label>
                      <label>Auth type<select name="auth_type"><option value="none">No auth</option><option value="cookie">Cookie header</option><option value="login">Login form</option></select></label>
                      <label>Interval hours<input name="interval_hours" type="number" min="1" value="24"></label>
                      <label>Max seconds<input name="max_seconds" type="number" min="10" max="180" value="60"></label>
                      <label>Alert risk<select name="alert_min_risk"><option value="medium">medium+</option><option value="high">high+</option><option value="info">all</option></select></label>
                      <label class="wide">Login URL<input name="login_url" placeholder="https://app.example.com/login"></label>
                      <label>Login email<input name="login_email" autocomplete="username"></label>
                      <label>Password or ref<input name="password" type="password" autocomplete="current-password" placeholder="or file:/root/secret.txt"></label>
                      <label>Username selector<input name="username_selector" placeholder="input[type=email]"></label>
                      <label>Password selector<input name="password_selector" placeholder="input[type=password]"></label>
                      <label>Submit selector<input name="submit_selector" placeholder="button[type=submit]"></label>
                      <label class="wide">Auth check URL<input name="auth_check_url" placeholder="/dashboard or https://app.example.com/dashboard"></label>
                      <label>Auth selector<input name="auth_check_selector" placeholder="[data-testid=workspace]"></label>
                      <label>Required text<input name="auth_check_text" placeholder="Workspace"></label>
                      <label>Failure text<input name="auth_failure_text" placeholder="Sign in"></label>
                      <label class="full">Cookie header or ref<textarea name="cookie" placeholder="Cookie: session=... or file:/root/amplitude_cookie.txt or env:AMPLITUDE_COOKIE"></textarea></label>
                      <label class="full">Extra routes to browse<textarea name="extra_routes" placeholder="/dashboard&#10;/settings&#10;/integrations"></textarea></label>
                      <label><span>Enabled</span><select name="enabled"><option value="true">enabled</option><option value="false">disabled</option></select></label>
                      <div class="scope"><button class="btn primary" id="saveMonitor" type="submit">Save Monitor</button><button class="btn" id="newMonitor" type="button">New</button></div>
                    </form>
                  </details>
                </div>`;
              document.querySelectorAll("[data-monitor-view]").forEach(btn => btn.onclick = () => {
                state.monitorView = btn.dataset.monitorView;
                state.offset = 0;
                const nextUrl = new URL(location.href);
                nextUrl.searchParams.set("tab", "monitors");
                nextUrl.searchParams.set("monitor_view", state.monitorView);
                if (state.monitorRunId) nextUrl.searchParams.set("run_id", state.monitorRunId);
                else nextUrl.searchParams.delete("run_id");
                history.replaceState(null, "", nextUrl);
                loadMonitors();
              });
              document.querySelectorAll("[data-open-run]").forEach(btn => btn.onclick = (e) => {
                e.stopPropagation();
                const run = runRows.find(item => String(item.id) === String(btn.dataset.openRun));
                openMonitorRunChanges(run || {id: btn.dataset.openRun});
              });
              const resetForm = () => { $("monitorForm").reset(); $("monitorId").value = ""; $("saveMonitor").textContent = "Save Monitor"; $("monitorConfig").open = true; };
              $("newMonitor").onclick = resetForm;
              document.querySelectorAll("[data-monitor-edit]").forEach(btn => btn.onclick = () => {
                const card = btn.closest("[data-monitor-json]");
                const m = JSON.parse(card.dataset.monitorJson || "{}");
                const form = $("monitorForm");
                $("monitorConfig").open = true;
                form.elements.id.value = m.id || "";
                form.elements.domain_id.value = m.domain_id || "";
                form.elements.name.value = m.name || "";
                form.elements.start_url.value = m.start_url || "";
                form.elements.auth_type.value = m.auth_type || "none";
                form.elements.interval_hours.value = m.interval_hours || 24;
                const metadata = parseMaybeJson(m.metadata, {});
                form.elements.max_seconds.value = metadata.max_seconds || 60;
                form.elements.alert_min_risk.value = m.alert_min_risk || "medium";
                form.elements.login_url.value = m.login_url || "";
                form.elements.login_email.value = m.login_email || "";
                form.elements.password.value = "";
                form.elements.username_selector.value = m.username_selector || "";
                form.elements.password_selector.value = m.password_selector || "";
                form.elements.submit_selector.value = m.submit_selector || "";
                form.elements.auth_check_url.value = m.auth_check_url || "";
                form.elements.auth_check_selector.value = m.auth_check_selector || "";
                form.elements.auth_check_text.value = m.auth_check_text || "";
                form.elements.auth_failure_text.value = m.auth_failure_text || "";
                form.elements.cookie.value = "";
                const extraRoutes = parseMaybeJson(m.extra_routes, []);
                form.elements.extra_routes.value = Array.isArray(extraRoutes) ? extraRoutes.join("\\n") : "";
                form.elements.enabled.value = m.enabled ? "true" : "false";
                $("saveMonitor").textContent = "Update Monitor";
                form.scrollIntoView({behavior:"smooth", block:"start"});
              });
              $("monitorForm").onsubmit = async (e) => {
                e.preventDefault();
                const form = new FormData(e.currentTarget);
                const body = Object.fromEntries(form.entries());
                body.enabled = body.enabled === "true";
                const btn = $("saveMonitor");
                btn.disabled = true; btn.textContent = "Saving...";
                const resp = await fetch("/api/monitors", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
                const payload = await resp.json();
                btn.disabled = false; btn.textContent = "Save Monitor";
                if (!resp.ok) {
                  $("sourceTabs").insertAdjacentHTML("afterbegin", `<div class="badge red">${esc(payload.error || "Unable to save monitor")}</div>`);
                  return;
                }
                $("sourceTabs").insertAdjacentHTML("afterbegin", `<div class="badge green">Saved monitor ${esc(payload.id)}</div>`);
                setTimeout(loadMonitors, 600);
              };
              document.querySelectorAll("[data-monitor-run]").forEach(btn => btn.onclick = async () => {
                btn.disabled = true; btn.textContent = "Running...";
                const resp = await fetch(`/api/monitors/${btn.dataset.monitorRun}/run`, { method: "POST" });
                const payload = await resp.json();
                btn.disabled = false; btn.textContent = "Run now";
                if (!resp.ok) {
                  $("sourceTabs").insertAdjacentHTML("afterbegin", `<div class="badge red">${esc(payload.error || "Monitor run failed")}</div>`);
                  return;
                }
                $("sourceTabs").insertAdjacentHTML("afterbegin", `<div class="badge green">Run complete: ${esc(payload.new_events || 0)} new changes, ${esc(payload.scripts || 0)} JS files</div>`);
                state.monitorRunId = payload.run_id ? String(payload.run_id) : state.monitorRunId;
                state.monitorView = "events";
                setTimeout(loadMonitors, 600);
              });
              state.rows = data.rows || [];
              renderTable(state.rows, data.total || state.rows.length);
            }
            function formatBytes(value) {
              const size = Number(value || 0);
              if (size < 1024) return `${size} B`;
              if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
              return `${(size / (1024 * 1024)).toFixed(1)} MB`;
            }
            function rememberFfufDraft() {
              const form = $("ffufWorkbenchForm");
              if (!form) return;
              state.ffufDraft = {
                target_url: form.elements.target_url?.value || "",
                threads: form.elements.threads?.value || "10",
                rate: form.elements.rate?.value || "30",
                timeout: form.elements.timeout?.value || "10",
                max_runtime: form.elements.max_runtime?.value || "1800",
                match_codes: form.elements.match_codes?.value || "200,204,301,302,307,308,401,403",
                recursion: Boolean(form.elements.recursion?.checked),
                recursion_depth: form.elements.recursion_depth?.value || "1"
              };
            }
            function selectFfufWordlist(item) {
              state.ffufWordlist = item;
              document.querySelectorAll(".ffuf-entry").forEach(entry => entry.classList.toggle("selected", entry.dataset.wordlistPath === item.wordlist_path));
              const selected = $("ffufSelectedWordlist");
              if (selected) selected.innerHTML = `<strong>${esc(item.path)}</strong><br><span>${esc(formatBytes(item.size))}</span>`;
            }
            async function loadFfufWordlistDirectory(path = "") {
              state.ffufPath = path;
              const tree = $("ffufTree");
              if (!tree) return;
              tree.innerHTML = `<div class="loading">Loading folder...</div>`;
              const resp = await fetch(`/api/ffuf/workbench/wordlists?path=${encodeURIComponent(path)}`);
              const data = await resp.json();
              if (!resp.ok) {
                tree.innerHTML = `<div class="empty">${esc(data.error || "Unable to load wordlists")}</div>`;
                return;
              }
              const segments = (data.path || "").split("/").filter(Boolean);
              const crumbs = [{name: "SecLists", path: ""}];
              segments.forEach((segment, index) => crumbs.push({name: segment, path: segments.slice(0, index + 1).join("/")}));
              $("ffufBreadcrumbs").innerHTML = crumbs.map((crumb, index) => `${index ? `<span>/</span>` : ""}<button type="button" class="ffuf-crumb" data-ffuf-path="${esc(crumb.path)}">${esc(crumb.name)}</button>`).join("");
              const items = data.items || [];
              tree.innerHTML = items.length ? items.map(item => `
                <button type="button" class="ffuf-entry ${state.ffufWordlist?.wordlist_path === item.wordlist_path ? "selected" : ""}" data-kind="${esc(item.type)}" data-path="${esc(item.path)}" ${item.wordlist_path ? `data-wordlist-path="${esc(item.wordlist_path)}" data-size="${esc(item.size || 0)}"` : ""}>
                  <span class="kind">${item.type === "directory" ? "[+]" : "[w]"}</span>
                  <span class="entry-name" title="${esc(item.path)}">${esc(item.name)}</span>
                  <span class="entry-size">${item.type === "file" ? esc(formatBytes(item.size)) : ""}</span>
                </button>`).join("") : `<div class="empty">This folder contains no selectable wordlists.</div>`;
              document.querySelectorAll("[data-ffuf-path]").forEach(button => button.onclick = () => loadFfufWordlistDirectory(button.dataset.ffufPath || ""));
              document.querySelectorAll(".ffuf-entry").forEach(entry => entry.onclick = () => {
                if (entry.dataset.kind === "directory") return loadFfufWordlistDirectory(entry.dataset.path || "");
                selectFfufWordlist({
                  name: entry.querySelector(".entry-name")?.textContent || "",
                  path: entry.dataset.path || "",
                  wordlist_path: entry.dataset.wordlistPath || "",
                  size: Number(entry.dataset.size || 0)
                });
              });
            }
            async function searchFfufWordlists(query) {
              const q = query.trim();
              if (q.length < 2) return loadFfufWordlistDirectory(state.ffufPath || "");
              const tree = $("ffufTree");
              tree.innerHTML = `<div class="loading">Searching SecLists...</div>`;
              const resp = await fetch(`/api/ffuf/workbench/wordlists/search?q=${encodeURIComponent(q)}`);
              const data = await resp.json();
              const items = data.items || [];
              $("ffufBreadcrumbs").innerHTML = `<span>Search results for <strong>${esc(q)}</strong></span>`;
              tree.innerHTML = items.length ? items.map(item => `
                <button type="button" class="ffuf-entry ${state.ffufWordlist?.wordlist_path === item.wordlist_path ? "selected" : ""}" data-kind="file" data-path="${esc(item.path)}" data-wordlist-path="${esc(item.wordlist_path)}" data-size="${esc(item.size || 0)}">
                  <span class="kind">[w]</span>
                  <span class="entry-name" title="${esc(item.path)}">${esc(item.path)}</span>
                  <span class="entry-size">${esc(formatBytes(item.size))}</span>
                </button>`).join("") : `<div class="empty">No wordlists matched that name or path.</div>`;
              document.querySelectorAll(".ffuf-entry").forEach(entry => entry.onclick = () => selectFfufWordlist({
                name: entry.querySelector(".entry-name")?.textContent || "",
                path: entry.dataset.path || "",
                wordlist_path: entry.dataset.wordlistPath || "",
                size: Number(entry.dataset.size || 0)
              }));
            }
            async function loadFfufWorkbench() {
              clearTimeout(window.ffufWorkbenchPoll);
              $("columnsBtn").hidden = true;
              $("downloadLink").hidden = true;
              $("gridTitle").textContent = "FFUF Workbench";
              $("sourceTabs").hidden = false;
              const draft = state.ffufDraft || {};
              $("sourceTabs").innerHTML = `
                <div class="ffuf-workbench">
                  <section class="ffuf-browser">
                    <div class="ffuf-section-head"><strong>SecLists</strong><span class="meta">Pinned wordlist library</span></div>
                    <div class="ffuf-browser-tools">
                      <input id="ffufWordlistSearch" autocomplete="off" placeholder="Search filenames and folders">
                      <button type="button" class="btn" id="ffufClearSearch">Clear</button>
                    </div>
                    <div class="ffuf-breadcrumbs" id="ffufBreadcrumbs"></div>
                    <div class="ffuf-tree" id="ffufTree"><div class="loading">Loading SecLists...</div></div>
                  </section>
                  <section class="ffuf-launcher">
                    <div class="ffuf-section-head"><strong>New Run</strong><span class="meta">FUZZ is appended when omitted</span></div>
                    <form class="ffuf-form" id="ffufWorkbenchForm">
                      <label class="full">Target URL<input name="target_url" required value="${esc(draft.target_url || "")}" placeholder="https://target.example/FUZZ"></label>
                      <div class="ffuf-selected" id="ffufSelectedWordlist">${state.ffufWordlist ? `<strong>${esc(state.ffufWordlist.path)}</strong><br><span>${esc(formatBytes(state.ffufWordlist.size))}</span>` : "Choose a wordlist from the SecLists browser."}</div>
                      <details class="ffuf-advanced">
                        <summary>Advanced controls</summary>
                        <div class="ffuf-options">
                          <label>Threads<input name="threads" type="number" min="1" max="100" value="${esc(draft.threads || 10)}"></label>
                          <label>Rate / second<input name="rate" type="number" min="1" max="1000" value="${esc(draft.rate || 30)}"></label>
                          <label>Request timeout<input name="timeout" type="number" min="1" max="60" value="${esc(draft.timeout || 10)}"></label>
                          <label>Max runtime seconds<input name="max_runtime" type="number" min="60" max="7200" value="${esc(draft.max_runtime || 1800)}"></label>
                          <label>Match status<input name="match_codes" value="${esc(draft.match_codes || "200,204,301,302,307,308,401,403")}"></label>
                          <label>Recursion depth<input name="recursion_depth" type="number" min="1" max="5" value="${esc(draft.recursion_depth || 1)}"></label>
                          <label class="ffuf-recursion"><input name="recursion" type="checkbox" ${draft.recursion ? "checked" : ""}> Enable recursion</label>
                        </div>
                      </details>
                      <div class="ffuf-message" id="ffufMessage"></div>
                      <button type="submit" class="btn primary" id="startWorkbenchFfuf">Start FFUF</button>
                    </form>
                  </section>
                </div>`;
              const search = $("ffufWordlistSearch");
              search.addEventListener("input", () => {
                clearTimeout(window.ffufWordlistSearchTimer);
                window.ffufWordlistSearchTimer = setTimeout(() => searchFfufWordlists(search.value), 250);
              });
              $("ffufClearSearch").onclick = () => { search.value = ""; loadFfufWordlistDirectory(state.ffufPath || ""); };
              $("ffufWorkbenchForm").addEventListener("input", rememberFfufDraft);
              $("ffufWorkbenchForm").onsubmit = async event => {
                event.preventDefault();
                rememberFfufDraft();
                const message = $("ffufMessage");
                if (!state.ffufWordlist?.wordlist_path) {
                  message.innerHTML = `<span class="badge orange">Select a SecLists wordlist first.</span>`;
                  return;
                }
                const button = $("startWorkbenchFfuf");
                button.disabled = true;
                button.textContent = "Starting...";
                const body = {
                  target_url: state.ffufDraft.target_url,
                  wordlist_path: state.ffufWordlist.wordlist_path,
                  options: {
                    threads: state.ffufDraft.threads,
                    rate: state.ffufDraft.rate,
                    timeout: state.ffufDraft.timeout,
                    max_runtime: state.ffufDraft.max_runtime,
                    match_codes: state.ffufDraft.match_codes,
                    recursion: state.ffufDraft.recursion,
                    recursion_depth: state.ffufDraft.recursion_depth
                  }
                };
                const resp = await fetch("/api/ffuf/workbench/runs", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body)});
                const payload = await resp.json();
                button.disabled = false;
                button.textContent = "Start FFUF";
                if (!resp.ok) {
                  message.innerHTML = `<span class="badge red">${esc(payload.error || "Unable to start FFUF")}</span>`;
                  return;
                }
                message.innerHTML = `<span class="badge green">Run ${esc(payload.id)} ${payload.already_running ? "is already running" : "started"}</span>`;
                state.offset = 0;
                setTimeout(loadFfufWorkbench, 700);
              };
              await loadFfufWordlistDirectory(state.ffufPath || "");
              const resp = await fetch(globalPageParams("/api/ffuf/workbench/runs"));
              const data = await resp.json();
              state.rows = data.rows || [];
              renderTable(state.rows, data.total || 0);
              if (state.rows.some(row => row.status === "running")) window.ffufWorkbenchPoll = setTimeout(() => {
                if (state.tab === "ffuf_workbench") loadFfufWorkbench();
              }, 4000);
            }
            async function deleteFfufWorkbenchRun(runId, target = "") {
              if (!runId) return;
              const label = target ? `run ${runId} for ${target}` : `run ${runId}`;
              if (!confirm(`Delete FFUF ${label}? Stored hits for this run will also be removed.`)) return;
              const resp = await fetch(`/api/ffuf/workbench/runs/${runId}`, {method: "DELETE"});
              const payload = await resp.json().catch(() => ({}));
              if (!resp.ok) {
                alert(payload.error || "Unable to delete FFUF run");
                return;
              }
              if ($("drawer").classList.contains("open") && $("drawerTitle").textContent === `FFUF run ${runId}`) {
                $("drawer").classList.remove("open");
              }
              state.rows = state.rows.filter(row => Number(row.id) !== Number(runId));
              renderTable(state.rows, Math.max(0, state.rows.length + state.offset));
              loadFfufWorkbench();
            }
            async function openFfufWorkbenchRun(runId, offset = 0, filters = {}) {
              const limit = 100;
              const query = new URLSearchParams({limit, offset});
              for (const [key, value] of Object.entries(filters)) if (String(value || "").trim()) query.set(key, String(value).trim());
              const resp = await fetch(`/api/ffuf/workbench/runs/${runId}?${query}`);
              const data = await resp.json();
              if (!resp.ok) {
                $("drawerTitle").textContent = `FFUF run ${runId}`;
                $("drawerPosition").textContent = "Filter error";
                $("drawerBody").innerHTML = `<div class="empty"><span class="badge red">Invalid filter</span> ${esc(data.error || "Unable to load FFUF results")}</div>`;
                $("drawer").classList.add("open");
                return;
              }
              const hits = (data.hits || []).map(hit => `<tr><td>${badge(hit.status_code ?? "")}</td><td class="mono clip">${esc(hit.url)}</td><td>${esc(hit.content_length ?? "")}</td><td>${esc(hit.words ?? "")}</td></tr>`).join("");
              const downloadQuery = new URLSearchParams();
              for (const [key, value] of Object.entries(filters)) if (String(value || "").trim()) downloadQuery.set(key, String(value).trim());
              const downloadSearch = downloadQuery.toString();
              const downloadUrl = `/download/ffuf/workbench/runs/${runId}${downloadSearch ? `?${downloadSearch}` : ""}`;
              const filtered = data.hits_total !== data.hits_unfiltered_total;
              selectRowForAI({ ...data, id: runId, domain: data.domain, host_url: data.host_url, status: data.status, hits_count: data.hits_unfiltered_total });
              const rangeLabel = data.hits_total ? `${offset + 1}-${Math.min(offset + data.hits.length, data.hits_total)} of ${data.hits_total}` : "0 of 0";
              $("drawerTitle").textContent = `FFUF run ${runId}`;
              $("drawerPosition").textContent = filtered ? `${rangeLabel} filtered hits` : (data.hits_total ? `${rangeLabel} hits` : "No hits");
              $("drawerPrev").disabled = true;
              $("drawerNext").disabled = true;
              $("drawerBody").innerHTML = `
                <div class="panel" style="box-shadow:none">
                  <div class="panel-head">
                    <div class="panel-title"><h2>FFUF Results</h2><span class="meta">${esc(data.status)} · ${esc(data.hits_unfiltered_total || 0)} stored${filtered ? ` · ${esc(data.hits_total)} matched` : ""}</span></div>
                    <span class="row-actions"><button class="btn primary" id="askFfufRun">Ask AI</button><a class="btn" href="${esc(downloadUrl)}">Download CSV</a></span>
                  </div>
                  <div class="toolbar"><span class="badge blue mono">${esc(data.host_url)}</span><span class="badge">${esc(String(data.wordlist_path || "").replace("/app/wordlists/SecLists/", ""))}</span></div>
                  <div class="toolbar">
                    <input id="ffufHitStatus" inputmode="numeric" placeholder="Status: 200,302" value="${esc(filters.status || "")}">
                    <input id="ffufHitSizeMin" inputmode="numeric" placeholder="Size min" value="${esc(filters.size_min || "")}">
                    <input id="ffufHitSizeMax" inputmode="numeric" placeholder="Size max" value="${esc(filters.size_max || "")}">
                    <input id="ffufHitWordsMin" inputmode="numeric" placeholder="Words min" value="${esc(filters.words_min || "")}">
                    <input id="ffufHitWordsMax" inputmode="numeric" placeholder="Words max" value="${esc(filters.words_max || "")}">
                    <button class="btn" id="ffufApplyFilters">Apply</button>
                    <button class="btn" id="ffufClearFilters">Clear</button>
                  </div>
                  ${data.error ? `<div class="empty"><span class="badge red">Error</span> ${esc(data.error)}</div>` : ""}
                  <div class="data-shell" style="height:420px"><table><thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Words</th></tr></thead><tbody>${hits || `<tr><td colspan="4" class="empty">No hits stored yet.</td></tr>`}</tbody></table></div>
                  <div class="pager">
                    <span>${rangeLabel}${filtered ? ` filtered from ${data.hits_unfiltered_total}` : ""}</span>
                    <span><button class="btn" id="ffufHitsPrev" ${offset <= 0 ? "disabled" : ""}>Previous</button> <button class="btn" id="ffufHitsNext" ${offset + data.hits.length >= data.hits_total ? "disabled" : ""}>Next</button></span>
                  </div>
                </div>`;
              $("drawer").classList.add("open");
              $("askFfufRun").onclick = () => window.ReconAI?.open();
              const readFilters = () => ({
                status: $("ffufHitStatus").value,
                size_min: $("ffufHitSizeMin").value,
                size_max: $("ffufHitSizeMax").value,
                words_min: $("ffufHitWordsMin").value,
                words_max: $("ffufHitWordsMax").value
              });
              $("ffufApplyFilters").onclick = () => openFfufWorkbenchRun(runId, 0, readFilters());
              $("ffufClearFilters").onclick = () => openFfufWorkbenchRun(runId, 0, {});
              for (const id of ["ffufHitStatus", "ffufHitSizeMin", "ffufHitSizeMax", "ffufHitWordsMin", "ffufHitWordsMax"]) {
                $(id).onkeydown = event => { if (event.key === "Enter") openFfufWorkbenchRun(runId, 0, readFilters()); };
              }
              $("ffufHitsPrev").onclick = () => openFfufWorkbenchRun(runId, Math.max(0, offset - limit), filters);
              $("ffufHitsNext").onclick = () => openFfufWorkbenchRun(runId, offset + limit, filters);
              if (data.status === "running") setTimeout(() => {
                if ($("drawer").classList.contains("open")) openFfufWorkbenchRun(runId, offset, filters);
              }, 3000);
            }
            function openDrawer(row) {
              if (!row) return;
              selectRowForAI(row);
              const rowIndex = state.rows.indexOf(row);
              if (rowIndex >= 0) state.selected = rowIndex;
              $("drawerTitle").textContent = row.full_url || row.url || row.location || row.subdomain || row.asset_url || "Asset details";
              updateDrawerNav();
              const screenshot = row.screenshot_path ? `<div class="shot"><a href="/screenshots/${esc(row.screenshot_path)}" target="_blank"><img loading="lazy" src="/screenshots/${esc(row.screenshot_path)}"></a><div>${esc(row.url || row.screenshot_path)}</div></div>` : "";
	              const ffufPanel = state.tab === "live_hosts" && row.live_host_id ? `
	                <div class="panel" style="box-shadow:none">
	                  <div class="panel-head">
	                    <div class="panel-title"><h2>Manual FFUF</h2><span class="meta">run against this live host</span></div>
	                    <button class="btn" id="reloadFfuf">Reload</button>
	                  </div>
	                  <div class="toolbar">
	                    <span class="badge blue mono">${esc(row.url || "")}</span>
	                    <select id="ffufWordlist"><option value="">Loading wordlists...</option></select>
	                    <button class="btn primary" id="startFfuf">Run FFUF</button>
	                  </div>
                  <div class="cards" id="ffufRuns"><div class="loading">Loading FFUF runs...</div></div>
                </div>` : "";
              const validationControls = row.validation_steps && state.tab === "validation" ? `
                <div class="panel" style="box-shadow:none">
                  <div class="toolbar">
                    <select id="validationStatus">
                      <option value="needs_validation">needs_validation</option><option value="validating">validating</option><option value="validated">validated</option><option value="false_positive">false_positive</option><option value="accepted_risk">accepted_risk</option>
                    </select>
                    <input id="validationNotes" placeholder="validation notes">
                    <button class="btn primary" id="saveValidation">Update validation</button>
                  </div>
                </div>` : "";
              $("drawerBody").innerHTML = `${screenshot}
                <div class="panel" style="box-shadow:none">
                  <div class="toolbar">
                    <button class="btn primary" id="askDrawerAsset">Ask AI</button>
                    <button class="btn primary" id="bookmarkAsset">Bookmark</button>
                    <select id="assetStatus">
                      <option value="new">new</option><option value="interesting">interesting</option><option value="reviewing">reviewing</option><option value="reported">reported</option><option value="ignored">ignored</option>
                    </select>
                    <input id="assetTags" placeholder="tags: graphql, idor">
                    <input id="assetNotes" placeholder="notes">
                    <button class="btn" id="saveAnnotation">Save</button>
                  </div>
                </div>
                ${ffufPanel}
                ${validationControls}
                <pre>${esc(JSON.stringify(detailRow(row), null, 2))}</pre>`;
              $("drawer").classList.add("open");
              $("askDrawerAsset").onclick = () => window.ReconAI?.open();
              $("bookmarkAsset").onclick = () => saveAnnotation(row, { bookmarked: true, status: "interesting" });
              $("saveAnnotation").onclick = () => saveAnnotation(row, {
                status: $("assetStatus").value,
                tags: $("assetTags").value,
                notes: $("assetNotes").value
              });
              if (row.validation_steps && $("saveValidation")) {
                $("saveValidation").onclick = () => updateValidation(row.id, $("validationStatus").value, $("validationNotes").value);
              }
	              if (state.tab === "live_hosts" && row.live_host_id) loadFfufPanel(row.live_host_id);
	            }
	            async function loadFfufPanel(liveHostId) {
	              const [ctxResp, wlResp] = await Promise.all([
	                fetch(`/api/ffuf/live-hosts/${liveHostId}${DOMAIN_ID ? `?domain_id=${DOMAIN_ID}` : ""}`),
	                fetch("/api/ffuf/wordlists")
	              ]);
	              const ctx = await ctxResp.json();
	              const wl = await wlResp.json();
	              const wordlist = $("ffufWordlist");
	              const runs = $("ffufRuns");
	              if (!ctxResp.ok) {
	                runs.innerHTML = `<div class="empty">${esc(ctx.error || "Unable to load FFUF context")}</div>`;
	                return;
	              }
	              wordlist.innerHTML = (wl.wordlists || []).map(w => `<option value="${esc(w.path)}">${esc(w.name)} · ${Math.ceil((w.size || 0) / 1024)} KB</option>`).join("") || `<option value="">No wordlists found</option>`;
	              runs.innerHTML = (ctx.runs || []).length ? ctx.runs.map(r => `
	                <div class="intel-card" data-ffuf-run="${esc(r.id)}">
                  <div>${badge(r.status)} ${badge(`${r.hits_count || 0} hits`)}</div>
                  <div class="mono clip">${esc(r.host_url)}</div>
	                  <div class="meta">${esc((r.wordlist_path || "").replace("/app/wordlists/", ""))}</div>
	                  <div class="meta">${esc(r.started_at || "")}</div>
	                </div>`).join("") : `<div class="empty">No FFUF runs recorded for this live host yet.</div>`;
	              document.querySelectorAll("[data-ffuf-run]").forEach(el => el.onclick = () => openFfufRun(el.dataset.ffufRun));
	              $("reloadFfuf").onclick = () => loadFfufPanel(liveHostId);
	              $("startFfuf").onclick = async () => {
	                const body = { wordlist_path: wordlist.value };
	                $("startFfuf").disabled = true;
	                $("startFfuf").textContent = "Starting...";
	                const resp = await fetch(`/api/ffuf/live-hosts/${liveHostId}/run${DOMAIN_ID ? `?domain_id=${DOMAIN_ID}` : ""}`, {
	                  method: "POST",
	                  headers: { "Content-Type": "application/json" },
	                  body: JSON.stringify(body)
                });
                const payload = await resp.json();
                $("startFfuf").disabled = false;
                $("startFfuf").textContent = "Run FFUF";
                if (!resp.ok) {
                  runs.insertAdjacentHTML("afterbegin", `<div class="badge red">${esc(payload.error || "FFUF failed to start")}</div>`);
	                  return;
	                }
	                runs.insertAdjacentHTML("afterbegin", `<div class="badge green">FFUF run ${esc(payload.id)} started</div>`);
	                setTimeout(() => loadFfufPanel(liveHostId), 1200);
	              };
	            }
            async function openFfufRun(runId) {
              const resp = await fetch(`/api/ffuf/runs/${runId}${DOMAIN_ID ? `?domain_id=${DOMAIN_ID}` : ""}`);
              const data = await resp.json();
              if (!resp.ok) return;
              const hits = (data.hits || []).slice(0, 80).map(h => `<tr><td>${badge(h.status_code || "")}</td><td class="mono clip">${esc(h.url)}</td><td>${esc(h.content_length || "")}</td></tr>`).join("");
              $("drawerTitle").textContent = `FFUF run ${runId}`;
              $("drawerBody").innerHTML = `
                <div class="panel" style="box-shadow:none">
                  <div class="panel-head"><div class="panel-title"><h2>FFUF Results</h2><span class="meta">${esc(data.status)} · ${esc(data.hits_count || 0)} hits</span></div></div>
                  <div class="toolbar"><span class="badge blue">${esc(data.host_url)}</span><span class="badge">${esc((data.wordlist_path || "").replace("/app/wordlists/", ""))}</span></div>
                  <div class="data-shell" style="height:360px"><table><thead><tr><th>Status</th><th>URL</th><th>Size</th></tr></thead><tbody>${hits || `<tr><td colspan="3" class="empty">No hits stored yet.</td></tr>`}</tbody></table></div>
                </div>
                <pre>${esc(JSON.stringify(data, null, 2))}</pre>`;
            }
            function entityFromRow(row) {
              const location = row.full_url || row.url || row.location || row.asset_url || row.subdomain || row.title || "";
              let type = row.entity_type || row.result_type || (row.subdomain_id ? "subdomain" : row.live_host_id ? "live_host" : row.asset_url ? "js_asset" : row.full_url ? "endpoint" : row.url ? "live_host" : row.finding_type ? "finding" : "asset");
              let id = row.entity_id || null;
              if (!id && type === "subdomain") id = row.subdomain_id || row.id || null;
              if (!id && type === "live_host") id = row.live_host_id || row.id || null;
              if (!id && type === "endpoint") id = row.endpoint_id || row.id || null;
              if (!id && type === "js_asset") id = row.js_asset_id || row.id || null;
              if (!id && type === "finding") id = row.finding_id || row.id || null;
              if (!id) id = row.evidence_pack_id || null;
              return { entity_type: String(type), entity_id: id, entity_key: id ? `${type}:${id}` : "", location };
            }
            async function saveAnnotation(row, patch) {
              const payload = { ...entityFromRow(row), ...patch };
              const r = await fetch("/api/analyst/annotation" + (DOMAIN_ID ? `?domain_id=${DOMAIN_ID}` : ""), {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
              });
              if (r.ok) {
                $("drawerBody").insertAdjacentHTML("afterbegin", `<div class="badge green">Saved analyst annotation</div>`);
              }
            }
            async function updateValidation(id, status, notes) {
              const r = await fetch(`/api/validation/${id}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ status, notes })
              });
              if (r.ok) {
                $("drawerBody").insertAdjacentHTML("afterbegin", `<div class="badge green">Updated validation status</div>`);
                loadGrid();
              }
            }
            function switchTab(tab, resetFilters = true) {
              if (!tabs[tab]) return;
              state.tab = tab; state.offset = 0; state.selected = 0; state.sort = tabs[tab].sort || "last_seen";
              if (resetFilters) state.filters = defaultFiltersFor(tab);
              else if (tab === "findings" && !state.filters.finding_view) state.filters = { ...defaultFiltersFor(tab), ...state.filters };
              if (tab === "monitors" && !state.monitorView) state.monitorView = "runs";
              const nextUrl = new URL(location.href);
              nextUrl.searchParams.set("tab", tab);
              if (tab === "monitors" && state.monitorView) nextUrl.searchParams.set("monitor_view", state.monitorView);
              else nextUrl.searchParams.delete("monitor_view");
              if (tab === "monitors" && state.monitorRunId) nextUrl.searchParams.set("run_id", state.monitorRunId);
              else nextUrl.searchParams.delete("run_id");
              history.replaceState(null, "", nextUrl);
              $("askSelectedRow").disabled = true;
              window.ReconAI?.setSection(tab);
              filterOptions = emptyFilterOptions();
              renderNav();
              loadGrid().finally(loadFilterOptions);
            }
            async function loadFeed() {
              try {
                const separator = withDomain("/api/scans").includes("?") ? "&" : "?";
                const r = await fetch(`${withDomain("/api/scans")}${separator}limit=10`);
                const rows = await r.json();
                if (!r.ok) throw new Error(rows.error || `Scan feed failed (${r.status})`);
                $("liveFeed").innerHTML = (rows || []).slice(0, 6).map(s => `<div class="intel-card"><div>${badge(s.first_run ? "first run" : "delta")} ${badge(s.domain)}</div><div class="mono">${esc(s.scan_finished_at || "running")}</div><div class="meta">${esc(JSON.stringify(s.new_counts || {})).slice(0, 220)}</div></div>`).join("") || `<div class="empty">No scan snapshots yet.</div>`;
              } catch (error) {
                $("liveFeed").innerHTML = `<div class="empty">Scan feed unavailable. Use Refresh to retry.</div>`;
              }
            }
            $("quickFilter").addEventListener("input", e => { state.filters.contains = e.target.value; state.offset = 0; clearTimeout(window.filterTimer); window.filterTimer = setTimeout(loadGrid, 280); });
            $("statusFilter").addEventListener("change", e => { state.filters.status_code = e.target.value; state.offset = 0; loadGrid(); });
            $("jsResponseFilter").addEventListener("change", e => { state.filters.js_response = e.target.value; state.offset = 0; loadGrid(); });
            $("paramFilter").addEventListener("change", e => { state.filters.has_parameters = e.target.value; state.offset = 0; loadGrid(); });
            $("techFilter").addEventListener("change", e => { state.filters.tech = e.target.value; state.offset = 0; loadGrid(); });
            $("confidenceFilter").addEventListener("change", e => { state.filters.confidence = e.target.value; state.offset = 0; loadGrid(); });
            $("responseSizeFilter").addEventListener("input", e => { state.filters.response_size_gt = e.target.value; state.offset = 0; clearTimeout(window.sizeFilterTimer); window.sizeFilterTimer = setTimeout(loadGrid, 350); });
            $("findingViewFilter").addEventListener("change", e => { state.filters.finding_view = e.target.value || "leads"; state.offset = 0; loadGrid(); });
            $("findingSeverityFilter").addEventListener("change", e => { state.filters.severity = e.target.value; state.offset = 0; loadGrid(); });
            $("findingTypeFilter").addEventListener("input", e => { state.filters.finding_type = e.target.value; state.offset = 0; clearTimeout(window.findingTypeTimer); window.findingTypeTimer = setTimeout(loadGrid, 280); });
            $("findingResolutionFilter").addEventListener("change", e => { state.filters.resolution = e.target.value || "active"; state.offset = 0; loadGrid(); });
            $("findingRecentFilter").addEventListener("change", e => { state.filters.recent_days = e.target.value; state.offset = 0; loadGrid(); });
            $("scanScope").addEventListener("change", e => { state.scanId = e.target.value; state.offset = 0; filterOptions = emptyFilterOptions(); loadGrid().finally(loadFilterOptions); });
            $("pageSize").addEventListener("change", e => { state.limit = Number(e.target.value); state.offset = 0; loadGrid(); });
            $("prevPage").onclick = () => { state.offset = Math.max(0, state.offset - state.limit); loadGrid(); };
            $("nextPage").onclick = () => { state.offset += state.limit; loadGrid(); };
            $("refreshBtn").onclick = async () => {
              await loadGrid();
              await Promise.allSettled([loadFilterOptions(), loadMetrics(), loadFocus(), loadFeed()]);
            };
            $("closeDrawer").onclick = () => $("drawer").classList.remove("open");
            $("drawerPrev").onclick = () => openDrawerAt(state.selected - 1);
            $("drawerNext").onclick = () => openDrawerAt(state.selected + 1);
            $("askSelectedRow").onclick = () => {
              const row = state.rows[state.selected];
              if (!row) return;
              selectRowForAI(row);
              window.ReconAI?.open();
            };
            $("globalSearch").addEventListener("keydown", e => { if (e.key === "Enter") switchTab("search"); });
            $("columnsBtn").onclick = () => {
              const cols = columns[state.tab] || [];
              const choices = cols.map(([key,label]) => `${visible[state.tab]?.[key] ? "[ ]" : "[x]"} ${label}`).join("\\n");
              const pick = prompt(`Toggle a column by exact name:\\n${choices}`);
              const found = cols.find(([, label]) => label.toLowerCase() === String(pick || "").toLowerCase());
              if (found) { visible[state.tab] ||= {}; visible[state.tab][found[0]] = !visible[state.tab][found[0]]; localStorage.setItem("recon-visible-columns", JSON.stringify(visible)); renderTable(state.rows, state.rows.length + state.offset); }
            };
            document.querySelectorAll("[data-open-tab]").forEach(btn => btn.onclick = () => switchTab(btn.dataset.openTab));
            $("manageDomainsBtn").onclick = async () => {
              resetDomainForm();
              $("domainManagerDialog").showModal();
              try { await loadManagedDomains(); }
              catch (error) { $("domainMessage").textContent = error.message; }
            };
            $("closeDomainManager").onclick = () => $("domainManagerDialog").close();
            $("domainManagerDialog").addEventListener("close", () => { if (domainManagerDirty) location.reload(); });
            $("domainManagerSearch").addEventListener("input", renderManagedDomains);
            $("domainManagerStatus").addEventListener("change", renderManagedDomains);
            $("domainForm").elements.preset.addEventListener("change", event => applyDomainPreset(event.target.value));
            $("cancelDomainEdit").onclick = resetDomainForm;
            $("domainForm").onsubmit = async event => {
              event.preventDefault();
              const form = event.currentTarget;
              const editId = Number(form.elements.domain_id.value) || null;
              const options = {
                scan_interval_hours: Number(form.elements.scan_interval_hours.value),
                max_live_hosts: nullableNumber(form.elements.max_live_hosts.value),
                max_wayback_urls: nullableNumber(form.elements.max_wayback_urls.value),
                max_js_assets: nullableNumber(form.elements.max_js_assets.value)
              };
              for (const option of domainOptionNames) options[option] = Boolean(form.elements[option].checked);
              const payload = {
                preset: form.elements.preset.value,
                organization: form.elements.organization.value,
                options,
                active: Boolean(form.elements.active.checked)
              };
              if (!editId) {
                payload.domains = form.elements.domains.value;
                payload.start_now = Boolean(form.elements.start_now.checked);
              }
              const button = $("saveDomainButton");
              button.disabled = true;
              button.textContent = editId ? "Saving..." : "Adding...";
              try {
                const result = await domainApi(editId ? `/api/domains/${editId}` : "/api/domains", {method:editId ? "PATCH" : "POST", headers:domainApiHeaders(), body:JSON.stringify(payload)});
                domainManagerDirty = true;
                await loadManagedDomains();
                if (editId) {
                  const savedDomain = result.domain;
                  resetDomainForm();
                  $("domainMessage").textContent = `${savedDomain} settings saved.`;
                } else {
                  const created = result.created?.length || 0;
                  const existing = result.existing?.length || 0;
                  resetDomainForm();
                  $("domainMessage").textContent = `${created} domain${created === 1 ? "" : "s"} added${result.start_now && created ? " and queued for recon" : ""}.${existing ? ` ${existing} already existed and was unchanged.` : ""}`;
                }
              } catch (error) {
                $("domainMessage").textContent = error.message;
              } finally {
                button.disabled = false;
                button.textContent = form.elements.domain_id.value ? "Save settings" : "Add domains";
              }
            };
            $("domainManagerRows").addEventListener("click", event => {
              const button = event.target.closest("[data-domain-action]");
              if (!button) return;
              const domainId = Number(button.dataset.domainId);
              const action = button.dataset.domainAction;
              if (action === "edit") editManagedDomain(domainId);
              else if (action === "delete") openDomainDelete(domainId);
              else mutateManagedDomain(domainId, action);
            });
            $("closeDomainDelete").onclick = () => $("domainDeleteDialog").close();
            $("cancelDomainDelete").onclick = () => $("domainDeleteDialog").close();
            $("domainDeleteConfirmation").addEventListener("input", event => {
              const blockers = Object.keys(deleteDomainCandidate?.blockers || {}).length;
              $("confirmDomainDelete").disabled = !deleteDomainCandidate || blockers > 0 || event.target.value.trim().toLowerCase().replace(/[.]$/, "") !== deleteDomainCandidate.domain;
            });
            $("confirmDomainDelete").onclick = submitDomainDelete;
            document.addEventListener("keydown", e => {
              const typing = isTypingTarget(e.target);
              if (e.key === "/" && !typing) { e.preventDefault(); $("globalSearch").focus(); }
              if (typing && e.key !== "Escape") return;
              if (e.key === "j") { state.selected = Math.min(state.rows.length - 1, state.selected + 1); renderSelected(); }
              if (e.key === "k") { state.selected = Math.max(0, state.selected - 1); renderSelected(); }
              if (e.key === "Enter" && state.rows[state.selected]) openDrawer(state.rows[state.selected]);
              if ($("drawer").classList.contains("open") && e.key === "ArrowLeft") openDrawerAt(state.selected - 1);
              if ($("drawer").classList.contains("open") && e.key === "ArrowRight") openDrawerAt(state.selected + 1);
              if (e.key === "f" && state.rows[state.selected]) saveAnnotation(state.rows[state.selected], { bookmarked: true, status: "interesting" });
              if (e.key === "t" && state.rows[state.selected]) openDrawer(state.rows[state.selected]);
              if (e.key === "Escape") $("drawer").classList.remove("open");
            });
            if (tabs[initialTab]) {
              state.tab = initialTab;
              state.sort = tabs[initialTab].sort || "last_seen";
              state.filters = defaultFiltersFor(initialTab);
              if (initialTab === "monitors" && !state.monitorView) state.monitorView = "runs";
            }
            async function loadInitialDashboard() {
              renderNav();
              renderFilterControls();
              await loadGrid();
              if (!['codex_worker', 'ffuf_workbench'].includes(state.tab)) {
                await Promise.allSettled([loadFilterOptions(), loadMetrics(), loadFocus(), loadFeed()]);
              }
            }
            loadInitialDashboard();
            setInterval(() => { if (!['codex_worker', 'ffuf_workbench'].includes(state.tab)) loadFeed(); }, 30000);
            setInterval(() => { if (state.tab === "codex_worker") loadCodexWorker(); }, 15000);
          </script>
          <script src="{{ url_for('static', filename='ai_assistant.js') }}"></script>
        </body>
        </html>
        """,
        domains=domains,
        js_domains=[{"id": item["id"], "domain": item["domain"]} for item in domains],
        domain_id=domain_id,
        selected_domain=selected_domain,
        scan_options=scan_options,
        initial_scan_id=initial_scan_id,
        csrf_token=dashboard_csrf_token(),
    )
    scan_id = selected_scan_id()
    search_query = selected_search_query()
    row_limit = selected_row_limit()
    endpoint_filters = selected_endpoint_filters()
    # Keep scan selection lightweight. Per-scan rows are available through the
    # paginated /api/scans/<id>/<table> endpoints; preloading every table here
    # makes large first scans time out before the page can render.
    full_dashboard = selected_full_dashboard()
    cache_prefix = f"domain={domain_id or 'all'}|scan={scan_id or 'latest'}|limit={row_limit}|q={search_query}|filters={json.dumps(endpoint_filters, sort_keys=True)}"
    domains = cached_value("domains", 15, lambda: run_async(dashboard.get_domains()))
    if domain_id and not any(item["id"] == domain_id for item in domains):
        domain_id = None
    selected_domain = next((item for item in domains if item["id"] == domain_id), None)
    stats = cached_value(f"stats|{domain_id or 'all'}", 15, lambda: run_async(dashboard.get_stats(domain_id)))
    totals = cached_value(f"totals|{domain_id or 'all'}", 15, lambda: run_async(dashboard.get_totals(domain_id)))
    tables = {key: [] for key in ("subdomains", "live_hosts", "urls", "js", "parameters", "findings", "screenshots", "snapshots")}
    if full_dashboard:
        tables = {
            "subdomains": cached_value(f"{cache_prefix}|table=subdomains", 20, lambda: run_async(dashboard.get_table("subdomains", domain_id, row_limit))),
            "live_hosts": cached_value(f"{cache_prefix}|table=live_hosts", 20, lambda: run_async(dashboard.get_table("live_hosts", domain_id, row_limit))),
            "urls": cached_value(f"{cache_prefix}|table=urls", 20, lambda: run_async(dashboard.get_table("urls", domain_id, row_limit, endpoint_filters))),
            "js": cached_value(f"{cache_prefix}|table=js", 20, lambda: run_async(dashboard.get_table("js", domain_id, row_limit))),
            "parameters": cached_value(f"{cache_prefix}|table=parameters", 20, lambda: run_async(dashboard.get_table("parameters", domain_id, row_limit))),
            "findings": cached_value(f"{cache_prefix}|table=findings", 20, lambda: run_async(dashboard.get_table("findings", domain_id, row_limit))),
            "screenshots": cached_value(f"{cache_prefix}|table=screenshots", 20, lambda: run_async(dashboard.get_table("screenshots", domain_id, row_limit))),
            "snapshots": cached_value(f"{cache_prefix}|table=snapshots", 20, lambda: run_async(dashboard.get_table("snapshots", domain_id, 25))),
        }
    else:
        tables["snapshots"] = cached_value(f"{cache_prefix}|table=snapshots", 20, lambda: run_async(dashboard.get_table("snapshots", domain_id, 10)))
    scan_options = cached_value(f"scan_options|{domain_id or 'all'}", 20, lambda: run_async(dashboard.get_scan_options(domain_id, limit=50)))
    selected_scan = run_async(dashboard.get_scan(scan_id, domain_id)) if scan_id else (scan_options[0] if scan_options else None)
    scan_tables = cached_value(f"{cache_prefix}|scan_bundle={selected_scan['id'] if selected_scan else 'none'}", 20, lambda: run_async(dashboard.get_scan_bundle(selected_scan["id"], limit=row_limit, filters=endpoint_filters))) if selected_scan and full_dashboard else {key: [] for key in SCAN_TABLES}
    scan_counts = cached_value(f"{cache_prefix}|scan_counts={selected_scan['id'] if selected_scan else 'none'}", 20, lambda: run_async(dashboard.get_scan_counts(selected_scan["id"], endpoint_filters))) if selected_scan else {key: 0 for key in SCAN_TABLES}
    search_results = run_async(dashboard.search_database(search_query, domain_id)) if search_query else []
    parameter_clusters = cached_value(f"parameter_clusters|{domain_id or 'all'}", 30, lambda: run_async(dashboard.get_parameter_clusters(domain_id))) if full_dashboard else []
    researcher_focus = cached_value(f"researcher_focus|{domain_id or 'all'}", 20, lambda: run_async(dashboard.get_researcher_focus(domain_id, limit=25)))
    ai_triage = cached_value(f"ai_triage|{domain_id or 'all'}", 15, lambda: run_async(dashboard.get_ai_triage(domain_id, limit=50)))
    filter_options = cached_value(f"filter_options|{domain_id or 'all'}", 30, lambda: run_async(dashboard.get_endpoint_filter_options(domain_id))) if full_dashboard else {"subdomains": [], "live_hosts": [], "sources": [], "statuses": [], "technologies": []}
    endpoint_query = query_with_filters(domain_id, endpoint_filters)
    filter_presets = {label: preset_query(domain_id, preset_filters) for label, preset_filters in FILTER_PRESETS.items()}
    return render_template_string(
        """
        <!doctype html>
        <html>
        <head>
          <title>Enhanced Recon Dashboard</title>
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <style>
            :root {
              color-scheme: light dark;
              --bg: #f4f6f8;
              --header: #ffffff;
              --panel: #ffffff;
              --line: #d9e0e7;
              --row-line: #edf1f4;
              --table-head: #fafbfc;
              --text: #17212b;
              --table-head-text: #33404c;
              --muted: #5f6d7a;
              --accent: #0f766e;
              --accent-soft: #dff5f1;
              --accent-soft-text: #0b5f59;
              --control-bg: #ffffff;
              --download-text: #17324d;
              --link: #075985;
              --risk: #b42318;
              --warn: #a15c00;
            }
            :root[data-theme="dark"] {
              --bg: #0f1419;
              --header: #151b22;
              --panel: #171e26;
              --line: #2a3440;
              --row-line: #222b35;
              --table-head: #121820;
              --text: #e5edf5;
              --table-head-text: #b8c4d0;
              --muted: #8c9baa;
              --accent: #2dd4bf;
              --accent-soft: #123b38;
              --accent-soft-text: #99f6e4;
              --control-bg: #10161d;
              --download-text: #d8e4ef;
              --link: #67e8f9;
              --risk: #f87171;
              --warn: #fbbf24;
            }
            @media (prefers-color-scheme: dark) {
              :root:not([data-theme="light"]) {
                --bg: #0f1419;
                --header: #151b22;
                --panel: #171e26;
                --line: #2a3440;
                --row-line: #222b35;
                --table-head: #121820;
                --text: #e5edf5;
                --table-head-text: #b8c4d0;
                --muted: #8c9baa;
                --accent: #2dd4bf;
                --accent-soft: #123b38;
                --accent-soft-text: #99f6e4;
                --control-bg: #10161d;
                --download-text: #d8e4ef;
                --link: #67e8f9;
                --risk: #f87171;
                --warn: #fbbf24;
              }
            }
            * { box-sizing: border-box; }
            body { margin: 0; font-family: Inter, Arial, sans-serif; background: var(--bg); color: var(--text); }
            header { position: sticky; top: 0; z-index: 5; background: var(--header); border-bottom: 1px solid var(--line); }
            .bar { max-width: 1600px; margin: 0 auto; padding: 1rem 1.25rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
            h1 { margin: 0; font-size: 1.25rem; letter-spacing: 0; }
            h2 { margin: 0 0 .75rem; font-size: 1rem; letter-spacing: 0; }
            h3 { margin: 0; font-size: .95rem; letter-spacing: 0; }
            main { max-width: 1600px; margin: 0 auto; padding: 1.25rem; }
            .filter { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
            select, button { height: 2.25rem; border: 1px solid var(--line); background: var(--control-bg); color: var(--text); border-radius: 6px; padding: 0 .65rem; }
            button { cursor: pointer; background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
            .theme-toggle { min-width: 2.5rem; color: var(--text); background: var(--control-bg); border-color: var(--line); }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: .75rem; margin-bottom: 1rem; }
            .metric, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
            .metric { padding: .85rem; min-height: 5.2rem; }
            .metric .label { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
            .metric .value { margin-top: .45rem; font-size: 1.75rem; font-weight: 700; }
            .panel { margin-bottom: 1rem; overflow: hidden; }
            .panel-head { padding: .9rem 1rem; border-bottom: 1px solid var(--line); display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
            .panel-meta { color: var(--muted); font-size: .85rem; white-space: nowrap; }
            .table-wrap { overflow-x: auto; }
            table { width: 100%; border-collapse: collapse; font-size: .88rem; }
            th, td { text-align: left; padding: .68rem .75rem; border-bottom: 1px solid var(--row-line); vertical-align: top; }
            th { color: var(--table-head-text); font-size: .76rem; text-transform: uppercase; letter-spacing: .04em; background: var(--table-head); }
            tr:last-child td { border-bottom: 0; }
            a { color: var(--link); text-decoration: none; }
            a:hover { text-decoration: underline; }
            .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; max-width: 44rem; }
            .muted { color: var(--muted); }
            .tag { display: inline-block; padding: .12rem .45rem; border-radius: 999px; background: var(--accent-soft); color: var(--accent-soft-text); margin: 0 .25rem .2rem 0; font-size: .78rem; font-weight: 600; }
            .sev-critical, .sev-high { color: var(--risk); font-weight: 700; }
            .sev-medium { color: var(--warn); font-weight: 700; }
            .downloads { display: flex; flex-wrap: wrap; gap: .5rem; }
            .download { display: inline-flex; align-items: center; height: 2rem; padding: 0 .6rem; border: 1px solid var(--line); border-radius: 6px; background: var(--control-bg); color: var(--download-text); font-size: .85rem; }
            .search-input { min-width: min(36rem, 100%); height: 2.25rem; border: 1px solid var(--line); background: var(--control-bg); color: var(--text); border-radius: 6px; padding: 0 .65rem; }
            .filter-input { width: 12rem; height: 2.25rem; border: 1px solid var(--line); background: var(--control-bg); color: var(--text); border-radius: 6px; padding: 0 .65rem; }
            .scan-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: .5rem; padding: 1rem; border-bottom: 1px solid var(--line); }
            .scan-box { border: 1px solid var(--row-line); border-radius: 6px; padding: .65rem; background: var(--table-head); }
            .scan-box .label { color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; }
            .scan-box .value { margin-top: .25rem; font-weight: 700; }
            .domains-table td, .domains-table th { white-space: nowrap; }
            .empty { padding: 1rem; color: var(--muted); }
            .two-column { display: grid; grid-template-columns: repeat(auto-fit, minmax(430px, 1fr)); gap: 1rem; }
            .compact td, .compact th { padding: .52rem .6rem; }
            .reasons { min-width: 10rem; }
            .preset-row { display: flex; flex-wrap: wrap; gap: .5rem; padding: 0 1rem 1rem; }
            @media (max-width: 720px) {
              .bar { align-items: flex-start; flex-direction: column; }
              main { padding: .75rem; }
              .panel-head { align-items: flex-start; flex-direction: column; }
              .panel-meta { white-space: normal; }
              .two-column { grid-template-columns: 1fr; }
            }
          </style>
        </head>
        <body>
          <script>
            const savedTheme = localStorage.getItem("recon-theme");
            if (savedTheme) {
              document.documentElement.dataset.theme = savedTheme;
            }
          </script>
          <header>
            <div class="bar">
              <div>
                <h1>Enhanced Recon Dashboard</h1>
                <div class="muted">{{ selected_domain.domain if selected_domain else "All domains" }}</div>
              </div>
              <div class="filter">
                <form class="filter" method="get" action="/">
                  <label for="domain_id" class="muted">Domain</label>
                  <select id="domain_id" name="domain_id">
                    <option value="">All domains</option>
                    {% for domain in domains %}
                    <option value="{{ domain.id }}" {% if domain.id == domain_id %}selected{% endif %}>{{ domain.domain }}</option>
                    {% endfor %}
                  </select>
                  <button type="submit">View</button>
                </form>
                <button class="theme-toggle" type="button" id="themeToggle" aria-label="Toggle dark mode">◐</button>
              </div>
            </div>
          </header>

          <main>
            <section class="grid">
              {% for key, value in stats.items() %}
              <div class="metric">
                <div class="label">{{ key.replace("_", " ") }}</div>
                <div class="value">{{ value }}</div>
              </div>
              {% endfor %}
            </section>

            <section class="grid">
              {% for key, value in totals.items() %}
              <div class="metric">
                <div class="label">Total {{ key.replace("_", " ") }}</div>
                <div class="value">{{ value }}</div>
              </div>
              {% endfor %}
            </section>

            {% macro render_tags(tags) -%}
              {% for tag in tags or [] %}<span class="tag">{{ tag }}</span>{% endfor %}
            {%- endmacro %}

            <section class="panel">
              <div class="panel-head">
                <h2>Researcher Focus</h2>
                <span class="panel-meta">High-signal queues for fast triage <a href="/download/focus{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download JSON</a></span>
              </div>
              <div class="table-wrap">
                <table class="compact">
                  <tr><th>Domain</th><th>Subdomain</th><th>URL</th><th>Status</th><th>Size</th><th>Reasons</th><th>Risk</th><th>Seen</th></tr>
                  {% for item in researcher_focus.high_signal_endpoints %}
                  <tr>
                    <td>{{ item.domain }}</td>
                    <td class="mono">{{ item.subdomain }}</td>
                    <td class="mono">{{ item.full_url }}</td>
                    <td>{{ item.status_code or "" }}</td>
                    <td>{{ item.response_size or "" }}</td>
                    <td class="reasons">{{ render_tags(item.reasons) }}</td>
                    <td>{{ render_tags(item.risk_tags) }}</td>
                    <td>{{ item.last_seen }}</td>
                  </tr>
                  {% endfor %}
                </table>
                {% if not researcher_focus.high_signal_endpoints %}<div class="empty">No high-signal endpoints found for the current scope.</div>{% endif %}
              </div>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>AI Triage Queue</h2>
                <span class="panel-meta">Ranked new or changed assets <a href="/download/ai-triage{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download JSON</a></span>
              </div>
              <div class="table-wrap">
                <table class="compact">
                  <tr><th>Priority</th><th>Score</th><th>Domain</th><th>Type</th><th>Location</th><th>Reasons</th><th>Actions</th><th>Profiles</th><th>Seen</th></tr>
                  {% for item in ai_triage %}
                  <tr>
                    <td class="sev-{{ item.priority }}">{{ item.priority }}</td>
                    <td>{{ item.score }}</td>
                    <td>{{ item.domain or "" }}</td>
                    <td>{{ item.item_type }}</td>
                    <td class="mono">{{ item.location }}</td>
                    <td>{{ render_tags(item.reasons) }}</td>
                    <td>{{ render_tags(item.recommended_actions) }}</td>
                    <td>{{ render_tags(item.run_profiles) }}</td>
                    <td>{{ item.last_seen }}</td>
                  </tr>
                  {% endfor %}
                </table>
                {% if not ai_triage %}<div class="empty">No AI triage items yet. New high-signal assets will appear here after the scanner writes triage decisions.</div>{% endif %}
              </div>
            </section>

            <div class="two-column">
              <section class="panel">
                <div class="panel-head"><h2>Admin / Sensitive Surfaces</h2><span class="panel-meta">{{ researcher_focus.exposed_admin|length }} shown</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Domain</th><th>URL</th><th>Status</th><th>Source</th><th>Seen</th></tr>
                    {% for item in researcher_focus.exposed_admin %}
                    <tr><td>{{ item.domain }}</td><td class="mono">{{ item.full_url }}</td><td>{{ item.status_code or "" }}</td><td>{{ item.source }}</td><td>{{ item.last_seen }}</td></tr>
                    {% endfor %}
                  </table>
                  {% if not researcher_focus.exposed_admin %}<div class="empty">No matching admin or sensitive surfaces.</div>{% endif %}
                </div>
              </section>

              <section class="panel">
                <div class="panel-head"><h2>JS Intelligence</h2><span class="panel-meta">{{ researcher_focus.js_intel|length }} assets with useful signals</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Domain</th><th>Asset</th><th>Status</th><th>Size</th><th>Risk Summary</th><th>Analyzed</th></tr>
                    {% for item in researcher_focus.js_intel %}
                    <tr><td>{{ item.domain }}</td><td class="mono">{{ item.asset_url }}</td><td>{{ item.http_status or "" }}</td><td>{{ item.size_bytes or "" }}</td><td class="mono">{{ item.risk_summary|fmt }}</td><td>{{ item.analyzed_at }}</td></tr>
                    {% endfor %}
                  </table>
                  {% if not researcher_focus.js_intel %}<div class="empty">No JS assets with extracted secrets, DOM sinks, GraphQL hints, or API URLs.</div>{% endif %}
                </div>
              </section>
            </div>

            <div class="two-column">
              <section class="panel">
                <div class="panel-head"><h2>Status Breakdown</h2><span class="panel-meta">Endpoint status distribution</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Status</th><th>Count</th><th>Filter</th></tr>
                    {% for item in researcher_focus.status_breakdown %}
                    <tr><td>{{ item.status_code }}</td><td>{{ item.count }}</td><td><a href="/?{% if domain_id %}domain_id={{ domain_id }}&{% endif %}status_code={{ item.status_code }}">Show only {{ item.status_code }}</a></td></tr>
                    {% endfor %}
                  </table>
                </div>
              </section>

              <section class="panel">
                <div class="panel-head"><h2>Tech Inventory</h2><span class="panel-meta">Most common detected technologies</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Technology</th><th>Hosts</th><th>Last Seen</th><th>Filter</th></tr>
                    {% for item in researcher_focus.tech_breakdown %}
                    <tr><td>{{ item.technology }}</td><td>{{ item.host_count }}</td><td>{{ item.last_seen }}</td><td><a href="/?{% if domain_id %}domain_id={{ domain_id }}&{% endif %}tech={{ item.technology|urlencode }}">Endpoints</a></td></tr>
                    {% endfor %}
                  </table>
                </div>
              </section>
            </div>

            <div class="two-column">
              <section class="panel">
                <div class="panel-head"><h2>Notable Findings</h2><span class="panel-meta">Medium and above, plus nuclei findings</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Domain</th><th>Severity</th><th>Type</th><th>Location</th><th>Seen</th></tr>
                    {% for item in researcher_focus.notable_findings %}
                    <tr><td>{{ item.domain or "" }}</td><td class="sev-{{ item.severity }}">{{ item.severity }}</td><td>{{ item.finding_type }}</td><td class="mono">{{ item.location }}</td><td>{{ item.last_seen }}</td></tr>
                    {% endfor %}
                  </table>
                  {% if not researcher_focus.notable_findings %}<div class="empty">No notable findings in the current scope.</div>{% endif %}
                </div>
              </section>

              <section class="panel">
                <div class="panel-head"><h2>24h Growth</h2><span class="panel-meta">Domains with new data in the last day</span></div>
                <div class="table-wrap">
                  <table class="compact">
                    <tr><th>Domain</th><th>Subdomains</th><th>Live</th><th>Endpoints</th><th>JS</th></tr>
                    {% for item in researcher_focus.growth_24h %}
                    <tr><td>{{ item.domain }}</td><td>{{ item.new_subdomains }}</td><td>{{ item.new_live_hosts }}</td><td>{{ item.new_endpoints }}</td><td>{{ item.new_js_assets }}</td></tr>
                    {% endfor %}
                  </table>
                  {% if not researcher_focus.growth_24h %}<div class="empty">No new data in the last 24 hours for the current scope.</div>{% endif %}
                </div>
              </section>
            </div>

            <section class="panel">
              <div class="panel-head">
                <h2>Dashboard Rows</h2>
                <span class="panel-meta">Controls how many rows each main data table renders in the browser</span>
              </div>
              <form class="filter" style="padding: 1rem;" method="get" action="/">
                {% if domain_id %}<input type="hidden" name="domain_id" value="{{ domain_id }}">{% endif %}
                {% if scan_id %}<input type="hidden" name="scan_id" value="{{ scan_id }}">{% endif %}
                {% if search_query %}<input type="hidden" name="q" value="{{ search_query }}">{% endif %}
                <label class="muted" for="limit">Rows per table</label>
                <select id="limit" name="limit">
                  {% for item in [50, 100, 250, 500, 1000, 2500, 5000] %}
                  <option value="{{ item }}" {% if row_limit == item %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <button type="submit">Apply</button>
                {% if full_dashboard %}<input type="hidden" name="full" value="1">{% endif %}
              </form>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Data Mode</h2>
                <span class="panel-meta">Overview mode keeps the dashboard responsive; full mode loads historical tables.</span>
              </div>
              <div style="padding: 1rem;" class="downloads">
                {% if full_dashboard %}
                <a class="download" href="/{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Fast overview</a>
                {% else %}
                <a class="download" href="/?{% if domain_id %}domain_id={{ domain_id }}&{% endif %}{% if scan_id %}scan_id={{ scan_id }}&{% endif %}limit={{ row_limit }}&full=1">Load full tables</a>
                {% endif %}
                <a class="download" href="/api/ai-triage{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">AI triage API</a>
                <a class="download" href="/api/focus{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Focus API</a>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Domains</h2>
                <span class="panel-meta">{{ domains|length }} configured</span>
              </div>
              <div class="table-wrap">
                <table class="domains-table">
                  <tr>
                    <th>Domain</th><th>Active</th><th>Last scan</th><th>Next scan</th>
                    <th>Subdomains</th><th>Live</th><th>Endpoints/URLs</th><th>JS</th><th>Findings</th><th>Screenshots</th>
                  </tr>
                  {% for item in domains %}
                  <tr>
                    <td><a href="/?domain_id={{ item.id }}">{{ item.domain }}</a></td>
                    <td>{{ item.active }}</td>
                    <td>{{ item.last_scan or "" }}</td>
                    <td>{{ item.next_scan or "" }}</td>
                    <td>{{ item.subdomains }}</td>
                    <td>{{ item.live_hosts }}</td>
                    <td>{{ item.endpoints }}</td>
                    <td>{{ item.js_assets }}</td>
                    <td>{{ item.findings }}</td>
                    <td>{{ item.screenshots }}</td>
                  </tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Endpoint Filters</h2>
                <span class="panel-meta">Filters apply to Endpoints / URLs and its CSV export</span>
              </div>
              <form class="filter" style="padding: 1rem;" method="get" action="/">
                {% if domain_id %}<input type="hidden" name="domain_id" value="{{ domain_id }}">{% endif %}
                <label class="muted" for="subdomain">Subdomain</label>
                <select id="subdomain" name="subdomain">
                  <option value="">All</option>
                  {% for item in filter_options.subdomains %}
                  <option value="{{ item }}" {% if endpoint_filters.subdomain == item %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <label class="muted" for="live_host">Live host</label>
                <select id="live_host" name="live_host">
                  <option value="">All</option>
                  {% for item in filter_options.live_hosts %}
                  <option value="{{ item }}" {% if endpoint_filters.live_host == item %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <label class="muted" for="source">Source</label>
                <select id="source" name="source">
                  <option value="">All</option>
                  {% for item in filter_options.sources %}
                  <option value="{{ item }}" {% if endpoint_filters.source == item %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <label class="muted" for="status_code">Status</label>
                <select id="status_code" name="status_code">
                  <option value="">All</option>
                  {% for item in filter_options.statuses %}
                  <option value="{{ item }}" {% if endpoint_filters.status_code == item|string %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <label class="muted" for="has_parameters">Parameters</label>
                <select id="has_parameters" name="has_parameters">
                  <option value="">All</option>
                  <option value="true" {% if endpoint_filters.has_parameters == "true" %}selected{% endif %}>Has parameters</option>
                  <option value="false" {% if endpoint_filters.has_parameters == "false" %}selected{% endif %}>No parameters</option>
                </select>
                <label class="muted" for="tech">Tech</label>
                <select id="tech" name="tech">
                  <option value="">All</option>
                  {% for item in filter_options.technologies %}
                  <option value="{{ item }}" {% if endpoint_filters.tech == item %}selected{% endif %}>{{ item }}</option>
                  {% endfor %}
                </select>
                <label class="muted" for="contains">Contains</label>
                <input class="filter-input" id="contains" name="contains" value="{{ endpoint_filters.contains or '' }}" placeholder="admin">
                <label class="muted" for="response_size_gt">Response size &gt;</label>
                <input class="filter-input" id="response_size_gt" name="response_size_gt" value="{{ endpoint_filters.response_size_gt or '' }}" inputmode="numeric" placeholder="1024">
                <button type="submit">Filter</button>
                <a class="download" href="/">Clear</a>
              </form>
              <div class="preset-row">
                {% for label, href in filter_presets.items() %}
                <a class="download" href="{{ href }}">{{ label }}</a>
                {% endfor %}
              </div>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Downloads</h2>
                <span class="panel-meta">CSV exports use the selected domain filter</span>
              </div>
              <div style="padding: 1rem;" class="downloads">
                {% for key, label in [("subdomains", "Subdomains"), ("live_hosts", "Live hosts"), ("urls", "Endpoints / URLs"), ("js", "JS URLs"), ("parameters", "Parameters"), ("findings", "Findings"), ("screenshots", "Screenshots"), ("snapshots", "Snapshots")] %}
                <a class="download" href="/download/{{ key }}{% if key == 'urls' %}{{ endpoint_query }}{% elif domain_id %}?domain_id={{ domain_id }}{% endif %}">{{ label }}</a>
                {% endfor %}
              </div>
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Global Database Search</h2>
                <span class="panel-meta">Searches subdomains, hosts, endpoints, JS, parameters, findings, and screenshots</span>
              </div>
              <form class="filter" style="padding: 1rem;" method="get" action="/">
                {% if domain_id %}<input type="hidden" name="domain_id" value="{{ domain_id }}">{% endif %}
                {% if scan_id %}<input type="hidden" name="scan_id" value="{{ scan_id }}">{% endif %}
                <input class="search-input" type="search" name="q" value="{{ search_query }}" placeholder="Search all database records">
                <button type="submit">Search</button>
                {% if search_query %}
                <a class="download" href="/download/search?{% if domain_id %}domain_id={{ domain_id }}&{% endif %}q={{ search_query|urlencode }}">Download search</a>
                <a class="download" href="/{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Clear</a>
                {% endif %}
              </form>
              {% if search_query %}
              <div class="table-wrap">
                <table>
                  <tr><th>Type</th><th>Domain</th><th>Title</th><th>Location</th><th>Severity</th><th>Details</th><th>Seen</th></tr>
                  {% for item in search_results %}
                  <tr>
                    <td>{{ item.result_type }}</td>
                    <td>{{ item.domain or "" }}</td>
                    <td class="mono">{{ item.title }}</td>
                    <td class="mono">{{ item.location }}</td>
                    <td class="sev-{{ item.severity }}">{{ item.severity or "" }}</td>
                    <td class="mono">{{ item.details|fmt }}</td>
                    <td>{{ item.last_seen }}</td>
                  </tr>
                  {% endfor %}
                </table>
                {% if not search_results %}<div class="empty">No database records matched "{{ search_query }}".</div>{% endif %}
              </div>
              {% endif %}
            </section>

            <section class="panel">
              <div class="panel-head">
                <h2>Per-Scan New Results</h2>
                <span class="panel-meta">Shows only records first seen during the selected scan window</span>
              </div>
              <form class="filter" style="padding: 1rem;" method="get" action="/">
                {% if domain_id %}<input type="hidden" name="domain_id" value="{{ domain_id }}">{% endif %}
                {% if search_query %}<input type="hidden" name="q" value="{{ search_query }}">{% endif %}
                {% for key, value in endpoint_filters.items() %}
                <input type="hidden" name="{{ key }}" value="{{ value }}">
                {% endfor %}
                <label class="muted" for="scan_id">Scan</label>
                <select id="scan_id" name="scan_id">
                  {% for scan in scan_options %}
                  <option value="{{ scan.id }}" {% if scan.id == scan_id %}selected{% endif %}>{{ scan.domain }} | {{ scan.scan_finished_at }} | {{ "first" if scan.first_run else "delta" }}</option>
                  {% endfor %}
                </select>
                <button type="submit">View Scan</button>
                {% if selected_scan %}
                <a class="download" href="/download/scan/{{ selected_scan.id }}{{ endpoint_query }}">Download scan bundle</a>
                {% endif %}
              </form>
              {% if selected_scan %}
              <div class="scan-summary">
                <div class="scan-box"><div class="label">Domain</div><div class="value">{{ selected_scan.domain }}</div></div>
                <div class="scan-box"><div class="label">Started</div><div class="value">{{ selected_scan.scan_started_at }}</div></div>
                <div class="scan-box"><div class="label">Finished</div><div class="value">{{ selected_scan.scan_finished_at }}</div></div>
                <div class="scan-box"><div class="label">Duration</div><div class="value">{{ "%.1fs"|format(selected_scan.duration_seconds) }}</div></div>
                <div class="scan-box"><div class="label">Type</div><div class="value">{{ "first run" if selected_scan.first_run else "delta scan" }}</div></div>
                <div class="scan-box"><div class="label">New Counts</div><div class="value mono">{{ selected_scan.new_counts|fmt }}</div></div>
              </div>

              {% for key, label in [("subdomains", "New Subdomains"), ("live_hosts", "New Live Hosts"), ("urls", "New Endpoints / URLs"), ("js", "New JS Assets"), ("parameters", "New Parameters"), ("findings", "New Findings"), ("screenshots", "New Screenshots")] %}
              <div class="panel-head">
                <h3>{{ label }}</h3>
                <span class="panel-meta">{{ scan_tables[key]|length }} of {{ scan_counts[key] }} shown <a href="/download/scan/{{ selected_scan.id }}/{{ key }}{% if key == 'urls' %}{{ endpoint_query }}{% endif %}">Download all</a></span>
              </div>
              <div class="table-wrap">
                <table>
                  {% if key == "subdomains" %}
                  <tr><th>Domain</th><th>Subdomain</th><th>Resolved</th><th>IPs</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.subdomain }}</td><td>{{ item.is_resolved }}</td><td class="mono">{{ item.ip_addresses|fmt }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "live_hosts" %}
                  <tr><th>Domain</th><th>Subdomain</th><th>URL</th><th>Status</th><th>Title</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.subdomain }}</td><td class="mono">{{ item.url }}</td><td>{{ item.status_code or "" }}</td><td>{{ item.title or "" }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "urls" %}
                  <tr><th>Domain</th><th>Subdomain</th><th>URL</th><th>Status</th><th>Size</th><th>Tech</th><th>Source</th><th>JS Ref</th><th>Risk</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.subdomain }}</td><td class="mono">{{ item.full_url }}</td><td>{{ item.status_code or "" }}</td><td>{{ item.response_size or "" }}</td><td>{{ render_tags(item.technologies) }}</td><td>{{ item.source }}</td><td class="mono">{% if item.js_references %}{{ item.js_references|length }} file(s): {{ item.js_references[0] }}{% endif %}</td><td>{{ render_tags(item.risk_tags) }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "js" %}
                  <tr><th>Domain</th><th>Asset URL</th><th>Status</th><th>Source</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.asset_url }}</td><td>{{ item.http_status or "" }}</td><td>{{ item.source }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "parameters" %}
                  <tr><th>Domain</th><th>URL</th><th>Parameter</th><th>Example</th><th>Risk</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.base_url }}{{ item.path }}</td><td>{{ item.param_name }}</td><td class="mono">{{ item.example_value or "" }}</td><td>{{ render_tags(item.risk_tags) }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "findings" %}
                  <tr><th>Domain</th><th>Severity</th><th>Type</th><th>Location</th><th>Details</th><th>First Seen</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="sev-{{ item.severity }}">{{ item.severity }}</td><td>{{ item.finding_type }}</td><td class="mono">{{ item.location }}</td><td class="mono">{{ item.details|fmt }}</td><td>{{ item.first_seen }}</td></tr>{% endfor %}
                  {% elif key == "screenshots" %}
                  <tr><th>Domain</th><th>URL</th><th>Reason</th><th>Captured</th><th>File</th></tr>
                  {% for item in scan_tables[key] %}<tr><td>{{ item.domain }}</td><td class="mono">{{ item.url }}</td><td>{{ item.capture_reason }}</td><td>{{ item.captured_at }}</td><td class="mono"><a href="/screenshots/{{ item.screenshot_path }}" target="_blank">{{ item.screenshot_path }}</a></td></tr>{% endfor %}
                  {% endif %}
                </table>
                {% if not scan_tables[key] %}<div class="empty">No {{ label|lower }} in this scan.</div>{% endif %}
              </div>
              {% endfor %}
              {% else %}
              <div class="empty">No scan snapshots available yet.</div>
              {% endif %}
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Endpoints / URLs</h2><span class="panel-meta">Rows from the endpoints table. Showing {{ tables.urls|length }} filtered rows. <a href="/download/urls{{ endpoint_query }}">Download filtered</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>Subdomain</th><th>URL</th><th>Status</th><th>Size</th><th>Tech</th><th>Source</th><th>JS Ref</th><th>Risk</th><th>Probed</th><th>Seen</th></tr>
                  {% for item in tables.urls %}
                  <tr><td>{{ item.domain }}</td><td class="mono">{{ item.subdomain }}</td><td class="mono">{{ item.full_url }}</td><td>{{ item.status_code or "" }}</td><td>{{ item.response_size or "" }}</td><td>{{ render_tags(item.technologies) }}</td><td>{{ item.source }}</td><td class="mono">{% if item.js_references %}{{ item.js_references|length }} file(s): {{ item.js_references[0] }}{% endif %}</td><td>{{ render_tags(item.risk_tags) }}</td><td>{{ item.probed_at or "" }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
                {% if not tables.urls %}<div class="empty">No endpoints or URLs found.</div>{% endif %}
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>JS URLs</h2><span class="panel-meta">Showing {{ tables.js|length }} of {{ totals.js_urls }}. <a href="/download/js{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download all</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>Asset URL</th><th>Status</th><th>Size</th><th>Source</th><th>Seen</th></tr>
                  {% for item in tables.js %}
                  <tr><td>{{ item.domain }}</td><td class="mono">{{ item.asset_url }}</td><td>{{ item.http_status or "" }}</td><td>{{ item.size_bytes or "" }}</td><td>{{ item.source }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
                {% if not tables.js %}<div class="empty">No JS URLs found.</div>{% endif %}
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Live Hosts</h2><span class="panel-meta">Showing {{ tables.live_hosts|length }} of {{ totals.live_hosts }}. <a href="/download/live_hosts{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download all</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Seen</th></tr>
                  {% for item in tables.live_hosts %}
                  <tr><td>{{ item.domain }}</td><td class="mono"><a href="{{ item.url }}" target="_blank">{{ item.url }}</a></td><td>{{ item.status_code or "" }}</td><td>{{ item.title or "" }}</td><td>{{ item.webserver or "" }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Subdomains</h2><span class="panel-meta">Showing {{ tables.subdomains|length }} of {{ totals.subdomains }}. <a href="/download/subdomains{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download all</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>Subdomain</th><th>Resolved</th><th>IPs</th><th>Seen</th></tr>
                  {% for item in tables.subdomains %}
                  <tr><td>{{ item.domain }}</td><td class="mono">{{ item.subdomain }}</td><td>{{ item.is_resolved }}</td><td class="mono">{{ item.ip_addresses|fmt }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Risky Parameters</h2><span class="panel-meta">Showing {{ tables.parameters|length }} of {{ totals.parameters }}. <a href="/download/parameters{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download all</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>URL</th><th>Parameter</th><th>Example</th><th>Risk</th><th>Seen</th></tr>
                  {% for item in tables.parameters %}
                  <tr><td>{{ item.domain }}</td><td class="mono">{{ item.base_url }}{{ item.path }}</td><td>{{ item.param_name }}</td><td class="mono">{{ item.example_value or "" }}</td><td>{{ render_tags(item.risk_tags) }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Findings</h2><span class="panel-meta">Showing {{ tables.findings|length }} of {{ totals.findings }}. <a href="/download/findings{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download all</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>Severity</th><th>Type</th><th>Location</th><th>Details</th><th>Seen</th></tr>
                  {% for item in tables.findings %}
                  <tr><td>{{ item.domain or "" }}</td><td class="sev-{{ item.severity }}">{{ item.severity }}</td><td>{{ item.finding_type }}</td><td class="mono">{{ item.location }}</td><td class="mono">{{ item.details|fmt }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Parameter Clusters</h2><span class="panel-meta">Top clusters for current filter</span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Parameter</th><th>Risk</th><th>Occurrences</th><th>Domains</th><th>Seen</th></tr>
                  {% for item in parameter_clusters %}
                  <tr><td>{{ item.param_name }}</td><td>{{ render_tags(item.risk_tags) }}</td><td>{{ item.occurrence_count }}</td><td>{{ item.domains|fmt }}</td><td>{{ item.last_seen }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Screenshots</h2><span class="panel-meta">Showing {{ tables.screenshots|length }} of {{ totals.screenshots }}. <a href="/download/screenshots{% if domain_id %}?domain_id={{ domain_id }}{% endif %}">Download index</a></span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>URL</th><th>Reason</th><th>Captured</th><th>File</th></tr>
                  {% for item in tables.screenshots %}
                  <tr><td>{{ item.domain }}</td><td class="mono">{{ item.url }}</td><td>{{ item.capture_reason }}</td><td>{{ item.captured_at }}</td><td class="mono"><a href="/screenshots/{{ item.screenshot_path }}" target="_blank">{{ item.screenshot_path }}</a></td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>

            <section class="panel">
              <div class="panel-head"><h2>Scan Snapshots</h2><span class="panel-meta">Recent scan history</span></div>
              <div class="table-wrap">
                <table>
                  <tr><th>Domain</th><th>Finished</th><th>Duration</th><th>Type</th><th>Totals</th><th>New Counts</th></tr>
                  {% for item in tables.snapshots %}
                  <tr><td>{{ item.domain }}</td><td>{{ item.scan_finished_at }}</td><td>{{ "%.1fs"|format(item.duration_seconds) }}</td><td>{{ "first" if item.first_run else "delta" }}</td><td class="mono">{{ item.totals|fmt }}</td><td class="mono">{{ item.new_counts|fmt }}</td></tr>
                  {% endfor %}
                </table>
              </div>
            </section>
          </main>
          <script>
            const themeToggle = document.getElementById("themeToggle");
            const preferredDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
            function currentTheme() {
              return document.documentElement.dataset.theme || (preferredDark ? "dark" : "light");
            }
            function syncThemeButton() {
              themeToggle.textContent = currentTheme() === "dark" ? "☾" : "☼";
            }
            themeToggle.addEventListener("click", () => {
              const next = currentTheme() === "dark" ? "light" : "dark";
              document.documentElement.dataset.theme = next;
              localStorage.setItem("recon-theme", next);
              syncThemeButton();
            });
            syncThemeButton();
          </script>
        </body>
        </html>
        """,
        domains=domains,
        domain_id=domain_id,
        row_limit=row_limit,
        scan_id=selected_scan["id"] if selected_scan else None,
        scan_options=scan_options,
        selected_scan=selected_scan,
        scan_tables=scan_tables,
        scan_counts=scan_counts,
        search_query=search_query,
        search_results=search_results,
        selected_domain=selected_domain,
        endpoint_filters=endpoint_filters,
        endpoint_query=endpoint_query,
        filter_presets=filter_presets,
        filter_options=filter_options,
        researcher_focus=researcher_focus,
        ai_triage=ai_triage,
        full_dashboard=full_dashboard,
        stats=stats,
        totals=totals,
        tables=tables,
        parameter_clusters=parameter_clusters,
    )


@app.route("/download/<name>")
def download_table(name: str):
    domain_id = selected_domain_id()
    if name == "urls":
        filters = selected_endpoint_filters()
        fieldnames = [
            "domain", "subdomain", "base_url", "path", "full_url", "status_code",
            "probed_at", "source", "js_references", "js_reference_count",
            "risk_tags", "parameters", "response_size", "technologies",
            "first_seen", "last_seen",
        ]

        def stream_endpoint_csv():
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            yield output.getvalue()
            last_id = None
            while True:
                rows = run_async(
                    dashboard.get_endpoint_export_page(
                        domain_id,
                        filters=filters,
                        page_size=2000,
                        before_id=last_id,
                    ),
                    timeout=30,
                    lock_timeout=30,
                )
                if not rows:
                    break
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                for row in rows[:2000]:
                    writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
                yield output.getvalue()
                if len(rows) <= 2000:
                    break
                cursor = rows[1999]
                last_id = cursor.get("endpoint_id")

        filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
        return Response(
            stream_with_context(stream_endpoint_csv()),
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=urls-{filename_domain}.csv",
                "X-Export-Mode": "keyset-stream",
            },
        )
    rows = run_async(dashboard.get_table(name, domain_id, limit=None, filters=selected_endpoint_filters()))
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}-{filename_domain}.csv"},
    )


@app.route("/download/search")
def download_search():
    domain_id = selected_domain_id()
    query = selected_search_query()
    rows = run_async(dashboard.search_database(query, domain_id, limit=5000)) if query else []
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=search-{filename_domain}.csv"},
    )


@app.route("/download/search-intelligence")
def download_search_intelligence():
    domain_id = selected_domain_id()
    run_id = selected_int_arg("run_id")
    payload = run_async(
        dashboard.get_search_intel_results(
            domain_id,
            limit=5000,
            offset=0,
            run_id=run_id,
            category=request.args.get("category", "").strip(),
            scope=request.args.get("scope", "").strip(),
            contains=request.args.get("contains", "").strip(),
        )
    )
    rows = payload["rows"]
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    filename_run = f"-run-{run_id}" if run_id else ""
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=search-intelligence-{filename_domain}{filename_run}.csv"
            )
        },
    )


@app.route("/download/focus")
def download_focus():
    domain_id = selected_domain_id()
    payload = run_async(dashboard.get_researcher_focus(domain_id, limit=500))
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        json.dumps(payload, default=str, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=researcher-focus-{filename_domain}.json"},
    )


@app.route("/download/ai-triage")
def download_ai_triage():
    domain_id = selected_domain_id()
    payload = run_async(dashboard.get_ai_triage(domain_id, limit=5000))
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        json.dumps(payload, default=str, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=ai-triage-{filename_domain}.json"},
    )


@app.route("/download/report.md")
def download_report_markdown():
    domain_id = selected_domain_id()
    body = run_async(
        dashboard.build_report_markdown(
            domain_id,
            limit=selected_report_limit(),
            sections=selected_report_sections(),
            validation_status=request.args.get("status", "").strip() or None,
        )
    )
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        body,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=recon-report-{filename_domain}.md"},
    )


@app.route("/download/report.json")
def download_report_json():
    domain_id = selected_domain_id()
    bundle = run_async(
        dashboard.build_report_bundle(
            domain_id,
            limit=selected_report_limit(),
            sections=selected_report_sections(),
            validation_status=request.args.get("status", "").strip() or None,
        )
    )
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        json.dumps(bundle, default=str, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=recon-report-{filename_domain}.json"},
    )


@app.route("/download/active-hunt")
def download_active_hunt():
    domain_id = selected_domain_id()
    rows = run_async(dashboard.get_active_hunt_results(domain_id, limit=None, offset=0))["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "run_id",
        "scope",
        "check_type",
        "target_url",
        "source_url",
        "parameter_name",
        "http_status",
        "finding",
        "confidence",
        "severity",
        "request",
        "response",
        "evidence",
        "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=active-hunt-{filename_domain}.csv"},
    )


@app.route("/download/bookmarks")
def download_bookmarks():
    domain_id = selected_domain_id()
    rows = run_async(dashboard.get_bookmarks(domain_id, limit=5000, offset=0))["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "entity_type",
        "entity_id",
        "location",
        "priority",
        "score",
        "status",
        "tags",
        "notes",
        "assigned_to",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=bookmarks-{filename_domain}.csv"},
    )


@app.route("/download/monitor-events")
def download_monitor_events():
    domain_id = selected_monitor_domain_id()
    rows = run_async(
        dashboard.get_monitor_events(
            domain_id,
            monitor_id=selected_int_arg("monitor_id"),
            run_id=selected_int_arg("run_id"),
            limit=5000,
            offset=0,
        )
    )["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "monitor",
        "event_type",
        "item_type",
        "value",
        "severity",
        "summary",
        "payload",
        "first_seen",
        "last_seen",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=monitor-events-{filename_domain}.csv"},
    )


@app.route("/download/monitor-runs")
def download_monitor_runs():
    domain_id = selected_monitor_domain_id()
    rows = run_async(
        dashboard.get_monitor_runs(
            domain_id,
            monitor_id=selected_int_arg("monitor_id"),
            status=request.args.get("status", "").strip() or None,
            limit=5000,
            offset=0,
        )
    )["rows"]
    output = io.StringIO()
    fieldnames = [
        "id",
        "domain",
        "monitor",
        "status",
        "started_at",
        "finished_at",
        "duration_seconds",
        "auth_status",
        "new_items_count",
        "new_events_count",
        "scripts_count",
        "requests_count",
        "error",
        "summary",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=monitor-runs.csv"},
    )


@app.route("/download/monitor-intel")
def download_monitor_intel():
    domain_id = selected_monitor_domain_id()
    rows = run_async(
        dashboard.get_monitor_intel(
            domain_id,
            monitor_id=selected_int_arg("monitor_id"),
            limit=5000,
            offset=0,
        )
    )["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "monitor",
        "item_type",
        "value",
        "risk",
        "source_url",
        "metadata",
        "first_seen",
        "last_seen",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=monitor-intel.csv"},
    )


@app.route("/download/playbooks")
def download_playbooks():
    domain_id = selected_domain_id()
    rows = run_async(dashboard.get_attack_playbooks(domain_id, limit=250, offset=0))["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "status",
        "priority",
        "confidence",
        "check_type",
        "owasp_category",
        "target_url",
        "reasons",
        "validation_steps",
        "stop_conditions",
        "safety_notes",
        "source_table",
        "source_id",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=attack-playbooks-{filename_domain}.csv"},
    )


@app.route("/download/bug-jobs")
def download_bug_jobs():
    domain_id = selected_domain_id()
    rows = run_async(dashboard.get_bug_jobs(domain_id, limit=5000, offset=0))["rows"]
    output = io.StringIO()
    fieldnames = [
        "domain",
        "status",
        "priority",
        "scope_ok",
        "asset_type",
        "asset_value",
        "job_type",
        "hypothesis",
        "finding_status",
        "confidence",
        "attempt_count",
        "max_attempts",
        "source_table",
        "source_id",
        "prompt_path",
        "codex_output_path",
        "result_summary",
        "error",
        "created_at",
        "started_at",
        "finished_at",
        "updated_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
    filename_domain = f"domain-{domain_id}" if domain_id else "all-domains"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=bug-jobs-{filename_domain}.csv"},
    )


@app.route("/download/scan/<int:scan_id>")
def download_scan_bundle(scan_id: int):
    scan = run_async(dashboard.get_scan(scan_id, selected_domain_id()))
    if not scan:
        return Response("scan not found\n", status=404, mimetype="text/plain")
    bundle = {
        "scan": {key: normalize_json(value) for key, value in scan.items()},
        "results": run_async(dashboard.get_scan_bundle(scan_id, limit=None, filters=selected_endpoint_filters())),
    }
    return Response(
        json.dumps(bundle, default=str, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}-new-results.json"},
    )


@app.route("/download/scan/<int:scan_id>/<name>")
def download_scan_table(scan_id: int, name: str):
    scan = run_async(dashboard.get_scan(scan_id, selected_domain_id()))
    if not scan:
        return Response("scan not found\n", status=404, mimetype="text/plain")
    rows = run_async(dashboard.get_scan_table(name, scan_id, limit=None, filters=selected_endpoint_filters() if name in {"urls", "js", "parameters"} else None))
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(value) for key, value in row.items()})
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}-{name}.csv"},
    )


@app.route("/api/stats")
def api_stats():
    domain_id = selected_domain_id()
    return jsonify(
        shared_json_cache(
            f"api_stats|{domain_id or 'all'}",
            30,
            lambda: run_async(dashboard.get_stats(domain_id)),
            stale_seconds=300,
        )
    )


@app.route("/api/command-center")
def api_command_center():
    domain_id = selected_domain_id()
    return jsonify(
        shared_json_cache(
            f"api_command_center_v2|{domain_id or 'all'}",
            60,
            lambda: run_async(dashboard.get_command_center(domain_id)),
            stale_seconds=600,
        )
    )


@app.route("/api/domains", methods=["GET", "POST"])
def api_domains():
    if request.method == "GET":
        return jsonify(run_async(dashboard.get_domains()))
    require_dashboard_csrf()
    payload = request.get_json(silent=True) or {}
    try:
        result = run_async(dashboard.create_domains(payload), timeout=45)
    except (DomainValidationError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    invalidate_domain_caches()
    status = 201 if result["created"] else 200
    return jsonify(result), status


@app.route("/api/domains/<int:domain_id>", methods=["PATCH", "DELETE"])
def api_domain(domain_id: int):
    require_dashboard_csrf()
    payload = request.get_json(silent=True) or {}
    try:
        if request.method == "PATCH":
            row = run_async(dashboard.update_domain(domain_id, payload), timeout=30)
            if not row:
                return jsonify({"error": "domain not found"}), 404
            invalidate_domain_caches()
            return jsonify(row)
        if payload.get("delete_data") is not True:
            return jsonify({"error": "delete_data=true is required"}), 400
        row = run_async(
            dashboard.delete_domain(domain_id, str(payload.get("confirm_domain") or "")),
            timeout=120,
        )
        if not row:
            return jsonify({"error": "domain not found"}), 404
        invalidate_domain_caches()
        return jsonify(row)
    except DomainValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409


@app.get("/api/domains/<int:domain_id>/deletion-impact")
def api_domain_deletion_impact(domain_id: int):
    row = run_async(dashboard.get_domain_delete_preview(domain_id), timeout=60)
    if not row:
        return jsonify({"error": "domain not found"}), 404
    return jsonify(row)


@app.post("/api/domains/<int:domain_id>/scan")
def api_queue_domain_scan(domain_id: int):
    require_dashboard_csrf()
    try:
        row = run_async(dashboard.queue_domain_scan(domain_id), timeout=30)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409
    if not row:
        return jsonify({"error": "domain not found"}), 404
    invalidate_domain_caches()
    return jsonify(row), 202


@app.route("/api/filter-options")
def api_filter_options():
    domain_id = selected_domain_id()
    tab = request.args.get("tab", "").strip()
    if tab == "parameters" and request.args.get("scan_id", "").isdigit():
        scan_id = int(request.args["scan_id"])
        scan = run_async(dashboard.get_scan(scan_id, domain_id))
        if not scan:
            return jsonify({"error": "scan not found"}), 404
        return jsonify(shared_json_cache(
            f"scan_parameter_status_options|{scan_id}",
            900,
            lambda: run_async(dashboard.get_scan_parameter_status_options(scan_id)),
            stale_seconds=86400,
        ))
    if domain_id is None:
        return jsonify(
            {
                "subdomains": [],
                "live_hosts": [],
                "sources": [],
                "source_counts": [],
                "js_sources": [],
                "js_source_counts": [],
                "statuses": [200, 301, 302, 401, 403, 404, 500],
                "status_counts": [],
                "endpoint_status_counts": [],
                "live_host_status_counts": [],
                "js_status_counts": [],
                "parameter_status_counts": [],
                "technologies": [],
            }
        )
    if tab:
        return jsonify(
            shared_json_cache(
                f"api_filter_options_v2|{domain_id}|{tab}",
                900,
                lambda: run_async(dashboard.get_tab_filter_options(domain_id, tab)),
                stale_seconds=86400,
            )
        )
    return jsonify(shared_json_cache(f"api_filter_options_all_v2|{domain_id or 'all'}", 900, lambda: run_async(dashboard.get_endpoint_filter_options(domain_id)), stale_seconds=86400))


@app.route("/api/results/<name>")
def api_results(name: str):
    return jsonify(
        run_async(
            dashboard.get_table_page(
                name,
                selected_domain_id(),
                limit=selected_api_limit(),
                offset=selected_offset(),
                sort=selected_sort(),
                direction=selected_direction(),
                filters=selected_endpoint_filters(),
            )
        )
    )


@app.route("/api/snapshots")
def api_snapshots():
    return jsonify(run_async(dashboard.get_table("snapshots", selected_domain_id(), 25)))


@app.route("/api/search")
def api_search():
    query = selected_search_query()
    if query.startswith("/") or request.args.get("type", "").strip().lower() == "endpoints":
        return jsonify(
            run_async(
                dashboard.search_endpoint_paths(
                    query,
                    selected_domain_id(),
                    limit=selected_api_limit(),
                    offset=selected_offset(),
                )
            )
        )
    return jsonify(run_async(dashboard.search_database(query, selected_domain_id(), limit=selected_api_limit())))


@app.route("/api/search-intelligence/results")
def api_search_intelligence_results():
    return jsonify(
        run_async(
            dashboard.get_search_intel_results(
                selected_domain_id(),
                limit=selected_api_limit(),
                offset=selected_offset(),
                sort=selected_sort(),
                direction=selected_direction(),
                run_id=selected_int_arg("run_id"),
                category=request.args.get("category", "").strip(),
                scope=request.args.get("scope", "").strip(),
                contains=request.args.get("contains", "").strip(),
            )
        )
    )


@app.route("/api/search-intelligence/runs")
def api_search_intelligence_runs():
    return jsonify(
        {
            "rows": run_async(
                dashboard.get_search_intel_runs(
                    selected_domain_id(),
                    limit=min(selected_api_limit(), 100),
                )
            ),
            "status": dashboard.search_intelligence_status(),
        }
    )


@app.route("/api/search-intelligence/run", methods=["POST"])
def api_search_intelligence_run():
    payload = request.get_json(silent=True) or {}
    domain_id = payload.get("domain_id") or selected_domain_id()
    try:
        domain_id = int(domain_id)
    except (TypeError, ValueError):
        return jsonify({"error": "select a domain before starting search intelligence"}), 400
    try:
        return jsonify(run_async(dashboard.queue_search_intel_run(domain_id)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/focus")
def api_focus():
    domain_id = selected_domain_id()
    limit = min(selected_api_limit(), 50)
    compact = request.args.get("compact", "").strip().lower() in {"1", "true", "yes", "on"}
    if compact:
        return jsonify(
            shared_json_cache(
                f"api_focus_cards_v2|{domain_id or 'all'}|{limit}",
                60,
                lambda: run_async(dashboard.get_focus_cards(domain_id, limit=limit)),
                stale_seconds=600,
            )
        )
    return jsonify(cached_value_stale_ok(f"api_focus|{domain_id or 'all'}|{limit}", 60, lambda: run_async(dashboard.get_researcher_focus(domain_id, limit=limit)), stale_seconds=600))


@app.route("/api/ai-triage")
def api_ai_triage():
    domain_id = selected_domain_id()
    return jsonify(cached_value_stale_ok(f"api_ai_triage|{domain_id or 'all'}", 15, lambda: run_async(dashboard.get_ai_triage(domain_id))))


@app.route("/api/events")
def api_events():
    domain_id = selected_domain_id()
    limit = selected_api_limit()
    offset = selected_offset()
    return jsonify(cached_value_stale_ok(f"api_events|{domain_id or 'all'}|limit={limit}|offset={offset}", 10, lambda: run_async(dashboard.get_asset_events(domain_id, limit=limit, offset=offset))))


@app.route("/api/risk")
def api_risk():
    domain_id = selected_domain_id()
    limit = selected_api_limit()
    offset = selected_offset()
    return jsonify(
        shared_json_cache(
            f"api_risk_v2|{domain_id or 'all'}|limit={limit}|offset={offset}",
            10,
            lambda: run_async(dashboard.get_risk_scores(domain_id, limit=limit, offset=offset)),
            stale_seconds=300,
        )
    )


@app.route("/api/bookmarks")
def api_bookmarks():
    return jsonify(run_async(dashboard.get_bookmarks(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/cloud")
def api_cloud():
    return jsonify(run_async(dashboard.get_cloud_assets(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/api-surfaces")
def api_api_surfaces():
    return jsonify(
        run_async(
            dashboard.get_api_surfaces(
                selected_domain_id(),
                limit=selected_api_limit(),
                offset=selected_offset(),
                confidence=request.args.get("confidence"),
            )
        )
    )


@app.route("/api/evidence")
def api_evidence():
    return jsonify(run_async(dashboard.get_evidence_packs(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/validation")
def api_validation():
    return jsonify(run_async(dashboard.get_validation_queue(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/playbooks")
def api_playbooks():
    return jsonify(run_async(dashboard.get_attack_playbooks(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/bug-jobs")
def api_bug_jobs():
    return jsonify(run_async(dashboard.get_bug_jobs(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/agentic/runs", methods=["GET", "POST"])
def api_agentic_runs():
    assert dashboard.agentic is not None
    if request.method == "GET":
        return jsonify(run_async(dashboard.agentic.list_runs(selected_domain_id())))
    require_dashboard_csrf()
    payload = request.get_json(silent=True) or {}
    if payload.get("scope_confirmed") is not True:
        return jsonify({"error": "Confirm current program scope before queuing a run."}), 400
    try:
        domain_id = int(payload.get("domain_id"))
        action = str(payload.get("action") or "hunt")
        if action not in {"hunt", "validate"}:
            raise ValueError("Use the separate recon action for a new scan")
        parent = int(payload["lead_id"]) if action == "validate" else None
        row = run_async(dashboard.agentic.create_run(
            domain_id, action, str(payload.get("data_source") or "recent_delta"),
            str(payload.get("focus") or ""), parent,
            payload.get("credential_ids") or [],
            int(payload.get("max_passes") or 4),
            payload.get("target_host"),
            int(payload.get("request_budget") or 300)), timeout=30)
        return jsonify(row), 201
    except (TypeError, ValueError, KeyError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/agentic/runs/<int:run_id>")
def api_agentic_run(run_id: int):
    assert dashboard.agentic is not None
    try:
        return jsonify(run_async(dashboard.agentic.get_run(run_id)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.get("/api/agentic/leads/<int:lead_id>")
def api_agentic_lead_detail(lead_id: int):
    assert dashboard.agentic is not None
    try:
        return jsonify(run_async(dashboard.agentic.get_lead_detail(lead_id)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.post("/api/agentic/runs/<int:run_id>/pause")
def api_agentic_pause(run_id: int):
    require_dashboard_csrf()
    assert dashboard.agentic is not None
    try:
        return jsonify(run_async(dashboard.agentic.pause_run(run_id)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409


@app.post("/api/agentic/runs/<int:run_id>/login/<int:credential_id>/complete")
def api_agentic_login_complete(run_id: int, credential_id: int):
    require_dashboard_csrf()

    async def selected_login():
        async with dashboard.pool.acquire() as conn:
            return await conn.fetchrow("""
                SELECT r.id FROM agentic_runs r JOIN hunt_credentials c
                  ON c.id=$2 AND c.domain_id=r.domain_id
                WHERE r.id=$1 AND r.status='waiting_login'
                  AND c.credential_type IN ('login_file', 'manual_login')
                  AND c.id=ANY(r.credential_ids)
            """, run_id, credential_id)

    if not run_async(selected_login()):
        return jsonify({"error": "This run is not waiting for the selected owned login"}), 409
    if not HUNT_LOGIN_SIGNAL_DIR.is_dir() or HUNT_LOGIN_SIGNAL_DIR.is_symlink():
        return jsonify({"error": "Human-login handoff is unavailable"}), 503
    marker = HUNT_LOGIN_SIGNAL_DIR / f"run_{1_000_000_000 + run_id}_account_{credential_id}.complete"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    except OSError:
        return jsonify({"error": "Could not signal login completion"}), 503
    return jsonify({"status": "verifying", "account_id": credential_id})


@app.post("/api/agentic/recon")
def api_agentic_recon():
    require_dashboard_csrf()
    assert dashboard.agentic is not None
    payload = request.get_json(silent=True) or {}
    if payload.get("scope_confirmed") is not True:
        return jsonify({"error": "Confirm current program scope before queuing recon."}), 400
    try:
        domain_id = int(payload.get("domain_id"))
        row = run_async(dashboard.agentic.create_run(domain_id, "recon", "all"), timeout=25)
        try:
            scan = run_async(dashboard.queue_domain_scan(domain_id), timeout=30)
        except Exception as exc:
            async def mark_failed():
                async with dashboard.pool.acquire() as conn:
                    await conn.execute("UPDATE agentic_runs SET status='failed', finished_at=NOW(), error=$2 WHERE id=$1",
                                       row["id"], str(exc)[:300])
            run_async(mark_failed())
            raise
        async def mark_queued():
            async with dashboard.pool.acquire() as conn:
                await conn.execute("UPDATE agentic_runs SET status='done', finished_at=NOW(), summary=$2::jsonb WHERE id=$1",
                                   row["id"], json.dumps({"scan_queue": scan, "note": "Queued in existing recon framework"}))
        run_async(mark_queued())
        return jsonify({"run": row, "recon": scan}), 201
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/hunts", methods=["GET", "POST"])
def api_hunts():
    assert dashboard.hunts is not None
    if request.method == "GET":
        return jsonify(run_async(dashboard.hunts.list_runs(selected_domain_id())))
    require_dashboard_csrf()
    payload = request.get_json(silent=True) or {}
    if payload.get("scope_confirmed") is not True:
        return jsonify({"error": "Confirm program scope before starting a hunt."}), 400
    if "autonomous_validation_enabled" in payload and not isinstance(payload["autonomous_validation_enabled"], bool):
        return jsonify({"error": "autonomous_validation_enabled must be a boolean"}), 400
    if "target_signup_enabled" in payload and not isinstance(payload["target_signup_enabled"], bool):
        return jsonify({"error": "target_signup_enabled must be a boolean"}), 400
    try:
        domain_id = int(payload.get("domain_id"))
        records_per_pass = int(payload.get("records_per_pass", 5000))
        row = run_async(
            dashboard.hunts.start_run(domain_id, str(payload.get("mode") or "one_time"), records_per_pass,
                                      payload.get("application_context", ""), payload.get("credential_ids") or [],
                                      str(payload.get("data_scope") or "all"),
                                      str(payload.get("data_source") or "all"),
                                      payload.get("delta_scan_ids") or [],
                                      payload.get("autonomous_validation_enabled") is True,
                                      payload.get("target_signup_enabled") is True),
            timeout=40,
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(row), 201


@app.get("/api/hunts/delta-scans")
def api_hunt_delta_scans():
    assert dashboard.hunts is not None
    try:
        domain_id = int(request.args.get("domain_id"))
        return jsonify(run_async(dashboard.hunts.list_delta_scans(domain_id), timeout=25))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/api/hunts/<int:run_id>")
def api_hunt(run_id: int):
    assert dashboard.hunts is not None
    try:
        return jsonify(run_async(dashboard.hunts.get_run(run_id), timeout=25))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.post("/api/hunts/<int:run_id>/refresh")
def api_hunt_refresh(run_id: int):
    require_dashboard_csrf()
    assert dashboard.hunts is not None
    try:
        result = run_async(dashboard.hunts.refresh_run(run_id), timeout=40)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify(result)


@app.post("/api/hunts/<int:run_id>/actions/<int:action_id>/reconcile")
def api_hunt_action_reconcile(run_id: int, action_id: int):
    require_dashboard_csrf()
    assert dashboard.hunts is not None
    payload = request.get_json(silent=True) or {}
    try:
        detail = run_async(dashboard.hunts.reconcile_action(
            run_id, action_id, str(payload.get("disposition") or ""), str(payload.get("note") or "")
        ), timeout=30)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(detail)


@app.post("/api/hunts/<int:run_id>/login/<int:credential_id>/complete")
def api_hunt_login_complete(run_id: int, credential_id: int):
    require_dashboard_csrf()
    assert dashboard.hunts is not None
    try:
        detail = run_async(dashboard.hunts.get_run(run_id), timeout=25)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    account = next((item for item in detail["credentials"] if item["id"] == credential_id), None)
    if not account or account["credential_type"] != "login_file":
        return jsonify({"error": "Owned login account not found in this hunt"}), 404
    if account.get("login_status") != "manual_login_pending":
        return jsonify({"error": "This account is not waiting for manual login"}), 409
    if not HUNT_LOGIN_SIGNAL_DIR.is_dir() or HUNT_LOGIN_SIGNAL_DIR.is_symlink():
        return jsonify({"error": "Human-login handoff is unavailable"}), 503
    marker = HUNT_LOGIN_SIGNAL_DIR / f"run_{run_id}_account_{credential_id}.complete"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    except OSError:
        return jsonify({"error": "Could not signal login completion"}), 503
    return jsonify({"status": "verifying", "account_id": credential_id})


@app.patch("/api/hunts/<int:run_id>")
def api_hunt_status(run_id: int):
    require_dashboard_csrf()
    assert dashboard.hunts is not None
    payload = request.get_json(silent=True) or {}
    if "autonomous_validation_enabled" in payload and not isinstance(payload["autonomous_validation_enabled"], bool):
        return jsonify({"error": "autonomous_validation_enabled must be a boolean"}), 400
    if "target_signup_enabled" in payload and not isinstance(payload["target_signup_enabled"], bool):
        return jsonify({"error": "target_signup_enabled must be a boolean"}), 400
    try:
        if any(key in payload for key in ("application_context", "credential_ids", "data_scope",
                                          "data_source", "delta_scan_ids", "autonomous_validation_enabled",
                                          "target_signup_enabled")):
            current = run_async(dashboard.hunts.get_run(run_id))
            return jsonify(run_async(dashboard.hunts.update_context(
                run_id, payload.get("application_context", current["run"]["application_context"]),
                payload.get("credential_ids", [item["id"] for item in current["credentials"]]),
                payload.get("data_scope", current["run"]["data_scope"]),
                payload.get("data_source", current["run"]["data_source"]),
                payload.get("delta_scan_ids", current["run"]["delta_scan_ids"]),
                payload.get("autonomous_validation_enabled", current["run"]["autonomous_validation_enabled"]),
                payload.get("target_signup_enabled", current["run"]["target_signup_enabled"]),
            ), timeout=30))
        return jsonify(run_async(dashboard.hunts.set_status(run_id, str(payload.get("status") or "")), timeout=30))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/hunt-credentials", methods=["GET", "POST"])
def api_hunt_credentials():
    assert dashboard.hunts is not None
    try:
        domain_id = int(request.args.get("domain_id") or (request.get_json(silent=True) or {}).get("domain_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Select a root domain"}), 400
    if request.method == "GET":
        return jsonify(run_async(dashboard.hunts.list_credentials(domain_id)))
    require_dashboard_csrf()
    payload = request.get_json(silent=True) or {}
    if payload.get("authorized") is not True:
        return jsonify({"error": "Confirm that this is an authorized owned account"}), 400
    secret_file = None
    try:
        async def get_domain():
            async with dashboard.pool.acquire() as conn:
                return await conn.fetchval("SELECT domain FROM domains WHERE id = $1 AND active = TRUE", domain_id)
        domain = run_async(get_domain())
        if not domain:
            raise ValueError("Select an active root domain")
        fields = validate_credential(domain, payload)
        secret_file = write_secret(fields.pop("secret"))
        row = run_async(dashboard.hunts.add_credential(domain_id, fields, secret_file))
        return jsonify(row), 201
    except (ValueError, RuntimeError, asyncpg.UniqueViolationError) as exc:
        if secret_file:
            remove_secret(secret_file)
        return jsonify({"error": "Account alias already exists" if isinstance(exc, asyncpg.UniqueViolationError) else str(exc)}), 400


@app.delete("/api/hunt-credentials/<int:credential_id>")
def api_hunt_credential_delete(credential_id: int):
    require_dashboard_csrf()
    assert dashboard.hunts is not None
    try:
        secret_file = run_async(dashboard.hunts.delete_credential(credential_id))
        remove_secret(secret_file)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"deleted": True})


@app.route("/api/codex-worker")
def api_codex_worker():
    domain_id = selected_domain_id()
    status = request.args.get("status", "").strip().lower()
    outcome = request.args.get("outcome", "").strip().lower()
    limit = selected_api_limit()
    cache_key = f"codex_worker|{domain_id or 'all'}|{status}|{outcome}|{limit}"
    return jsonify(
        shared_json_cache(
            cache_key,
            60,
            lambda: run_async(
                dashboard.get_codex_worker_overview(domain_id, limit, status, outcome),
                timeout=12,
                lock_timeout=5,
            ),
            stale_seconds=3600,
            timeout_fallback=lambda: degraded_codex_worker_overview(config),
        )
    )


@app.route("/api/codex-worker/jobs/<int:job_id>")
def api_codex_worker_job(job_id: int):
    row = run_async(dashboard.get_codex_worker_job(job_id, selected_domain_id()))
    if row is None:
        return jsonify({"error": "Codex worker job not found in this scope"}), 404
    return jsonify(row)


@app.route("/api/research/leads")
def api_research_leads():
    return jsonify(
        run_async(
            dashboard.get_research_leads(
                selected_domain_id(),
                limit=selected_api_limit(),
                outcome=request.args.get("outcome", "attention"),
                search=request.args.get("q", ""),
                analyst_status=request.args.get("analyst_status", ""),
            )
        )
    )


@app.route("/api/research/leads/<int:job_id>")
def api_research_lead(job_id: int):
    row = run_async(dashboard.get_research_lead_context(job_id, selected_domain_id()), timeout=20)
    if row is None:
        return jsonify({"error": "Research lead not found in this scope"}), 404
    return jsonify(row)


@app.route("/api/research/leads/<int:job_id>/validation", methods=["POST"])
def api_research_lead_validation(job_id: int):
    row = run_async(dashboard.queue_research_validation(job_id, selected_domain_id()), timeout=20)
    if row is None:
        return jsonify({"error": "Research lead not found in this scope"}), 404
    return jsonify(row), 201


@app.route("/api/research/evidence")
def api_research_evidence():
    return jsonify(run_async(dashboard.get_research_evidence_feed(selected_domain_id(), selected_api_limit())))


@app.route("/api/research/validation")
def api_research_validation():
    return jsonify(run_async(dashboard.get_research_validation_feed(selected_domain_id(), selected_api_limit())))


@app.route("/api/ai-assistant/questions", methods=["POST"])
def api_ai_assistant_create():
    payload = request.get_json(silent=True) or {}
    try:
        row = run_async(dashboard.create_ai_assistant_query(payload, selected_domain_id()))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(row), 202


@app.route("/api/ai-assistant/questions/<int:query_id>")
def api_ai_assistant_query(query_id: int):
    row = run_async(dashboard.get_ai_assistant_query(query_id))
    if not row:
        return jsonify({"error": "assistant question not found"}), 404
    return jsonify(row)


@app.route("/api/ai-assistant/history", methods=["GET", "DELETE"])
def api_ai_assistant_history():
    if request.method == "DELETE":
        return jsonify(run_async(dashboard.clear_ai_assistant_history(selected_domain_id())))
    thread_id = request.args.get("thread_id", "").strip()
    if not thread_id:
        return jsonify({"rows": [], "total": 0, "thread_id": None})
    try:
        return jsonify(run_async(dashboard.get_ai_assistant_history(thread_id, selected_api_limit())))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ai-assistant/conversations")
def api_ai_assistant_conversations():
    return jsonify(run_async(dashboard.get_ai_assistant_conversations(selected_domain_id(), selected_api_limit())))


@app.route("/api/ai-assistant/threads/<thread_id>", methods=["DELETE"])
def api_ai_assistant_delete_thread(thread_id: str):
    try:
        return jsonify(run_async(dashboard.delete_ai_assistant_thread(thread_id)))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 409


@app.route("/api/ai-assistant/status")
def api_ai_assistant_status():
    return jsonify(run_async(dashboard.get_ai_assistant_status()))


@app.route("/api/active-hunt")
def api_active_hunt():
    return jsonify(run_async(dashboard.get_active_hunt_results(selected_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/monitors", methods=["GET", "POST"])
def api_monitors():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        try:
            row = run_async(dashboard.upsert_monitor_target(payload, None))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": repr(exc)}), 500
        return jsonify(row), 201
    return jsonify(run_async(dashboard.get_monitor_targets(selected_monitor_domain_id(), limit=selected_api_limit(), offset=selected_offset())))


@app.route("/api/monitor-events")
def api_monitor_events():
    return jsonify(
        run_async(
            dashboard.get_monitor_events(
                selected_monitor_domain_id(),
                selected_int_arg("monitor_id"),
                selected_int_arg("run_id"),
                limit=selected_api_limit(),
                offset=selected_offset(),
            )
        )
    )


@app.route("/api/monitor-runs")
def api_monitor_runs():
    return jsonify(
        run_async(
            dashboard.get_monitor_runs(
                selected_monitor_domain_id(),
                selected_int_arg("monitor_id"),
                status=request.args.get("status", "").strip() or None,
                limit=selected_api_limit(),
                offset=selected_offset(),
            )
        )
    )


@app.route("/api/monitor-intel")
def api_monitor_intel():
    return jsonify(
        run_async(
            dashboard.get_monitor_intel(
                selected_monitor_domain_id(),
                selected_int_arg("monitor_id"),
                limit=selected_api_limit(),
                offset=selected_offset(),
            )
        )
    )


@app.route("/api/monitors/<int:monitor_id>/run", methods=["POST"])
def api_monitor_run(monitor_id: int):
    try:
        row = run_async(dashboard.run_monitor_now(monitor_id, selected_monitor_domain_id()))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": repr(exc)}), 500
    return jsonify(row)


@app.route("/api/ffuf/wordlists")
def api_ffuf_wordlists():
    return jsonify({"wordlists": dashboard.list_ffuf_wordlists()})


@app.route("/api/ffuf/workbench/wordlists")
def api_ffuf_workbench_wordlists():
    try:
        return jsonify(dashboard.browse_ffuf_wordlists(request.args.get("path", "")))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/ffuf/workbench/wordlists/search")
def api_ffuf_workbench_wordlist_search():
    return jsonify({"items": dashboard.search_ffuf_wordlists(request.args.get("q", ""), limit=200)})


@app.route("/api/ffuf/workbench/runs", methods=["GET", "POST"])
def api_ffuf_workbench_runs():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        try:
            row = run_async(
                dashboard.start_ffuf_workbench_run(
                    str(payload.get("target_url") or ""),
                    str(payload.get("wordlist_path") or ""),
                    payload.get("options") if isinstance(payload.get("options"), dict) else {},
                )
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify(row), 202
    return jsonify(
        run_async(
            dashboard.get_ffuf_workbench_runs(
                limit=selected_api_limit(),
                offset=selected_offset(),
            )
        )
    )


@app.route("/api/ffuf/workbench/runs/<int:run_id>", methods=["GET", "DELETE"])
def api_ffuf_workbench_run(run_id: int):
    if request.method == "DELETE":
        try:
            row = run_async(dashboard.delete_ffuf_workbench_run(run_id))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        if not row:
            return jsonify({"error": "FFUF workbench run not found"}), 404
        return jsonify(row)
    try:
        row = run_async(
            dashboard.get_ffuf_workbench_run(
                run_id,
                limit=selected_api_limit(),
                offset=selected_offset(),
                **selected_ffuf_hit_filters(),
            )
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not row:
        return jsonify({"error": "FFUF workbench run not found"}), 404
    return jsonify(row)


@app.route("/download/ffuf/workbench/runs/<int:run_id>")
def download_ffuf_workbench_run(run_id: int):
    try:
        filters = selected_ffuf_hit_filters()
    except ValueError as exc:
        return Response(f"{exc}\n", status=400, mimetype="text/plain")
    row = run_async(dashboard.get_ffuf_workbench_run(run_id, limit=250, offset=0, **filters))
    if not row:
        return Response("FFUF workbench run not found\n", status=404, mimetype="text/plain")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["status_code", "url", "path", "content_length", "words", "lines", "redirect_location", "created_at"])
    offset = 0
    while True:
        page = run_async(
            dashboard.get_ffuf_workbench_run(
                run_id,
                limit=250,
                offset=offset,
                **filters,
            )
        )
        hits = page["hits"] if page else []
        for hit in hits:
            writer.writerow(
                [
                    hit.get("status_code"),
                    hit.get("url"),
                    hit.get("path"),
                    hit.get("content_length"),
                    hit.get("words"),
                    hit.get("lines"),
                    hit.get("redirect_location"),
                    hit.get("created_at"),
                ]
            )
        if len(hits) < 250:
            break
        offset += 250
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="ffuf-workbench-run-{run_id}.csv"'},
    )


@app.route("/api/ffuf/subdomains/<int:subdomain_id>")
def api_ffuf_subdomain(subdomain_id: int):
    row = run_async(dashboard.get_subdomain_ffuf_context(subdomain_id, selected_domain_id()))
    if not row:
        return jsonify({"error": "subdomain not found"}), 404
    return jsonify(row)


@app.route("/api/ffuf/live-hosts/<int:live_host_id>")
def api_ffuf_live_host(live_host_id: int):
    row = run_async(dashboard.get_live_host_ffuf_context(live_host_id, selected_domain_id()))
    if not row:
        return jsonify({"error": "live host not found"}), 404
    return jsonify(row)


@app.route("/api/ffuf/subdomains/<int:subdomain_id>/run", methods=["POST"])
def api_ffuf_subdomain_run(subdomain_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        row = run_async(
            dashboard.start_manual_ffuf_run(
                subdomain_id,
                str(payload.get("wordlist_path") or ""),
                int(payload["live_host_id"]) if payload.get("live_host_id") else None,
                selected_domain_id(),
            )
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(row), 202


@app.route("/api/ffuf/live-hosts/<int:live_host_id>/run", methods=["POST"])
def api_ffuf_live_host_run(live_host_id: int):
    payload = request.get_json(silent=True) or {}
    try:
        row = run_async(
            dashboard.start_manual_ffuf_run_for_live_host(
                live_host_id,
                str(payload.get("wordlist_path") or ""),
                selected_domain_id(),
            )
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(row), 202


@app.route("/api/ffuf/runs/<int:run_id>")
def api_ffuf_run(run_id: int):
    row = run_async(dashboard.get_ffuf_run(run_id, selected_domain_id()))
    if not row:
        return jsonify({"error": "ffuf run not found"}), 404
    return jsonify(row)


@app.route("/api/analyst/annotation", methods=["POST"])
def api_upsert_annotation():
    payload = request.get_json(silent=True) or {}
    return jsonify(run_async(dashboard.upsert_annotation(payload, selected_domain_id())))


@app.route("/api/validation/<int:validation_id>", methods=["POST"])
def api_update_validation(validation_id: int):
    payload = request.get_json(silent=True) or {}
    row = run_async(dashboard.update_validation_status(validation_id, str(payload.get("status") or "needs_validation"), payload.get("notes")))
    if not row:
        return jsonify({"error": "validation item not found"}), 404
    return jsonify(row)


@app.route("/api/scans")
def api_scans():
    domain_id = selected_domain_id()
    limit = selected_api_limit()
    return jsonify(
        cached_value_stale_ok(
            f"api_scans|{domain_id or 'all'}|{limit}",
            15,
            lambda: run_async(dashboard.get_scan_options(domain_id, limit=limit)),
            stale_seconds=120,
        )
    )


@app.route("/api/scans/<int:scan_id>")
def api_scan(scan_id: int):
    scan = run_async(dashboard.get_scan(scan_id, selected_domain_id()))
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({"scan": scan, "results": run_async(dashboard.get_scan_bundle(scan_id, filters=selected_endpoint_filters()))})


@app.route("/api/scans/<int:scan_id>/<name>")
def api_scan_table(scan_id: int, name: str):
    scan = run_async(dashboard.get_scan(scan_id, selected_domain_id()))
    if not scan:
        return jsonify({"error": "scan not found"}), 404
    if name == "triage":
        return jsonify(run_async(dashboard.get_scan_ai_triage_page(scan_id, limit=selected_api_limit(), offset=selected_offset())))
    if name == "search":
        return jsonify(run_async(dashboard.search_scan_database(scan_id, selected_search_query(), limit=SEARCH_LIMIT)))
    return jsonify(
        run_async(
            dashboard.get_scan_table_page(
                name,
                scan_id,
                limit=selected_api_limit(),
                offset=selected_offset(),
                filters=selected_endpoint_filters() if name in {"urls", "js", "parameters"} else None,
            )
        )
    )


@app.route("/api/clusters/parameters")
def api_parameter_clusters():
    return jsonify(run_async(dashboard.get_parameter_clusters(selected_domain_id())))


@app.route("/api/review/endpoints")
def api_review_endpoints():
    return jsonify(run_async(dashboard.get_review_queue("ai_review_endpoint_queue")))


@app.route("/api/review/js")
def api_review_js():
    return jsonify(run_async(dashboard.get_review_queue("ai_review_js_queue")))


@app.route("/api/review/findings")
def api_review_findings():
    return jsonify(run_async(dashboard.get_review_queue("ai_review_findings_queue")))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=False)
