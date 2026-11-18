#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import asyncpg

from continuous_recon import load_config


LOG_DIR = Path("/app/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "delta_intelligence_worker.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("delta-intelligence-worker")


def utcnow() -> datetime:
    return datetime.utcnow()


def json_value(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def numeric_new_counts(value: Any) -> dict[str, int]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    if not isinstance(value, dict):
        return {}
    result: dict[str, int] = {}
    for key, raw in value.items():
        if isinstance(raw, bool):
            continue
        try:
            count = int(raw)
        except (TypeError, ValueError):
            continue
        if count > 0:
            result[str(key)] = count
    return result


def signal_score(new_counts: dict[str, int], event_types: Counter[str], severities: Counter[str]) -> int:
    """Rank deltas for queue ordering, not vulnerability severity."""
    score = 90
    high_value_counts = {
        "findings",
        "endpoints",
        "url_parameters",
        "js_assets",
        "js_analysis_results",
        "api_surfaces",
        "ffuf_hits",
        "port_scan_results",
        "service_fingerprints",
        "cloud_assets",
    }
    score += min(4, sum(1 for key in high_value_counts if new_counts.get(key, 0) > 0))
    score += min(3, severities.get("critical", 0) * 2 + severities.get("high", 0))
    high_value_event_terms = (
        "admin",
        "api",
        "auth",
        "cloud",
        "endpoint",
        "finding",
        "graphql",
        "js",
        "port",
        "secret",
        "service",
        "source_map",
        "swagger",
        "takeover",
    )
    score += min(
        3,
        sum(count for name, count in event_types.items() if any(term in name.lower() for term in high_value_event_terms)),
    )
    return min(100, score)


class DeltaIntelligenceWorker:
    def __init__(self) -> None:
        self.config = load_config()
        scan = self.config.scan
        self.enabled = bool(scan.get("delta_intelligence_enabled", True))
        self.interval_seconds = max(900, int(scan.get("delta_intelligence_interval_seconds", 43200) or 43200))
        self.bootstrap_hours = max(1, int(scan.get("delta_intelligence_bootstrap_hours", 12) or 12))
        self.max_domains = max(1, int(scan.get("delta_intelligence_max_domains_per_run", 500) or 500))
        self.state_path = Path(
            str(
                scan.get("delta_intelligence_state_path")
                or "/root/codex_artifacts/bug-jobs/results/.delta_intelligence_state.json"
            )
        )
        self.pool: asyncpg.Pool | None = None
        self.lock_conn: asyncpg.Connection | None = None

    async def init(self) -> None:
        db = self.config.database
        self.pool = await asyncpg.create_pool(
            host=db["host"],
            port=db["port"],
            database=db["name"],
            user=db["user"],
            password=db["password"],
            min_size=1,
            max_size=2,
        )
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delta_intelligence_runs (
                    id BIGSERIAL PRIMARY KEY,
                    window_started_at TIMESTAMP NOT NULL,
                    window_finished_at TIMESTAMP NOT NULL,
                    status VARCHAR(30) NOT NULL DEFAULT 'running',
                    domains_considered INTEGER NOT NULL DEFAULT 0,
                    jobs_enqueued INTEGER NOT NULL DEFAULT 0,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TIMESTAMP
                )
                """
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_delta_intelligence_runs_window "
                "ON delta_intelligence_runs(status, window_finished_at DESC)"
            )
        self.lock_conn = await self.pool.acquire()
        acquired = await self.lock_conn.fetchval(
            "SELECT pg_try_advisory_lock(hashtext('recon_delta_intelligence_worker_v1'))"
        )
        if not acquired:
            await self.pool.release(self.lock_conn)
            self.lock_conn = None
            raise RuntimeError("Another delta intelligence worker holds the singleton lock")
        self.state_path.parent.mkdir(parents=True, exist_ok=True)

    async def close(self) -> None:
        if self.lock_conn is not None and self.pool is not None:
            await self.lock_conn.execute(
                "SELECT pg_advisory_unlock(hashtext('recon_delta_intelligence_worker_v1'))"
            )
            await self.pool.release(self.lock_conn)
            self.lock_conn = None
        if self.pool is not None:
            await self.pool.close()
            self.pool = None

    def write_state(self, **values: Any) -> None:
        state = {
            "worker": "delta-intelligence-worker",
            "updated_at": utcnow().isoformat() + "Z",
            "interval_seconds": self.interval_seconds,
            **values,
        }
        temp = self.state_path.with_suffix(".tmp")
        temp.write_text(json.dumps(state, indent=2, sort_keys=True, default=str), encoding="utf-8")
        with contextlib.suppress(OSError):
            temp.chmod(0o600)
        temp.replace(self.state_path)

    async def window_start(self, conn: asyncpg.Connection, window_end: datetime) -> datetime:
        previous = await conn.fetchval(
            """
            SELECT MAX(window_finished_at)
            FROM delta_intelligence_runs
            WHERE status = 'done'
            """
        )
        if isinstance(previous, datetime):
            return min(previous, window_end)
        return window_end - timedelta(hours=self.bootstrap_hours)

    async def collect_domains(
        self,
        conn: asyncpg.Connection,
        window_start: datetime,
        window_end: datetime,
    ) -> list[asyncpg.Record]:
        return await conn.fetch(
            """
            SELECT
                d.id AS domain_id,
                d.domain,
                array_agg(ss.id ORDER BY ss.scan_finished_at) AS snapshot_ids,
                max(ss.id) AS latest_snapshot_id,
                min(ss.scan_started_at) AS delta_started_at,
                max(ss.scan_finished_at) AS delta_finished_at,
                jsonb_agg(ss.new_counts ORDER BY ss.scan_finished_at) AS snapshot_new_counts
            FROM scan_snapshots ss
            JOIN domains d ON d.id = ss.domain_id
            WHERE ss.scan_finished_at > $1
              AND ss.scan_finished_at <= $2
              AND ss.first_run = FALSE
              AND ss.new_counts <> '{}'::jsonb
            GROUP BY d.id, d.domain
            ORDER BY max(ss.scan_finished_at), d.id
            LIMIT $3
            """,
            window_start,
            window_end,
            self.max_domains,
        )

    async def enqueue_domain_job(
        self,
        conn: asyncpg.Connection,
        row: asyncpg.Record,
        window_start: datetime,
        window_end: datetime,
    ) -> bool:
        domain_id = int(row["domain_id"])
        snapshot_ids = [int(item) for item in row["snapshot_ids"]]
        latest_snapshot_id = int(row["latest_snapshot_id"])
        aggregated_counts: Counter[str] = Counter()
        for item in row["snapshot_new_counts"] or []:
            aggregated_counts.update(numeric_new_counts(item))

        event_rows = await conn.fetch(
            """
            SELECT event_type, severity, COUNT(*)::int AS count
            FROM asset_events
            WHERE domain_id = $1
              AND first_seen > $2
              AND first_seen <= $3
            GROUP BY event_type, severity
            ORDER BY count DESC, event_type
            LIMIT 40
            """,
            domain_id,
            window_start,
            window_end,
        )
        event_types: Counter[str] = Counter()
        severities: Counter[str] = Counter()
        event_summary: list[dict[str, Any]] = []
        for event in event_rows:
            count = int(event["count"])
            event_types[str(event["event_type"])] += count
            severities[str(event["severity"]).lower()] += count
            event_summary.append(
                {
                    "event_type": str(event["event_type"]),
                    "severity": str(event["severity"]),
                    "count": count,
                }
            )

        counts = dict(sorted(aggregated_counts.items()))
        if not counts and not event_summary:
            return False
        priority = signal_score(counts, event_types, severities)
        job_key = hashlib.sha256(
            f"delta_intelligence_review|{domain_id}|{latest_snapshot_id}".encode("utf-8")
        ).hexdigest()
        asset_value = (
            f"recon-delta://{row['domain']}?snapshot={latest_snapshot_id}"
            f"&from={window_start.isoformat()}Z&to={window_end.isoformat()}Z"
        )
        context = {
            "delta_intelligence": True,
            "window_start": window_start.isoformat() + "Z",
            "window_end": window_end.isoformat() + "Z",
            "snapshot_ids": snapshot_ids,
            "latest_snapshot_id": latest_snapshot_id,
            "new_counts": counts,
            "asset_event_summary": event_summary,
            "pentesterland_corpus": {
                "summary": "/root/bug_hunt_prompt_library/SOURCE_ANALYSIS.md",
                "manifest": "/root/bug_hunt_prompt_library/fulltext_corpus/manifest.jsonl",
                "family_analyses": "/root/bug_hunt_prompt_library/fulltext_analysis",
            },
            "hackerone_pattern_skill": "user-hackerone-patterns",
        }
        initial_status = (
            "curation_pending"
            if self.config.scan.get("bug_job_curator_enabled", True)
            and self.config.scan.get("bug_job_curator_gate_new_jobs", True)
            else "queued"
        )
        result = await conn.execute(
            """
            INSERT INTO bug_jobs (
                domain_id, target, asset_type, asset_value, job_type, priority,
                status, scope_ok, source_table, source_id, source_observed_at,
                job_key, hypothesis, safety_notes, required_context
            ) VALUES (
                $1, $2, 'domain_delta', $3, 'delta_intelligence_review', $4,
                $5, TRUE, 'scan_snapshots', $6, $7,
                $8, $9, $10, $11::jsonb
            )
            ON CONFLICT (job_key) DO NOTHING
            """,
            domain_id,
            str(row["domain"]),
            asset_value,
            priority,
            initial_status,
            latest_snapshot_id,
            row["delta_finished_at"],
            job_key,
            "Correlate only newly observed delta-scan data across the recon database, match it to evidence-backed writeup patterns, and validate the highest-value current exposure safely.",
            [
                "Delta window only; do not inventory or rescan the whole domain.",
                "Use writeup patterns to generate hypotheses, never as proof.",
                "No brute force, broad fuzzing, credential use, destructive actions, or out-of-scope requests.",
            ],
            json_value(context),
        )
        return result.endswith("1")

    async def run_once(self) -> tuple[int, int]:
        assert self.pool is not None
        window_end = utcnow()
        async with self.pool.acquire() as conn:
            window_start = await self.window_start(conn, window_end)
            run_id = await conn.fetchval(
                """
                INSERT INTO delta_intelligence_runs (window_started_at, window_finished_at)
                VALUES ($1, $2)
                RETURNING id
                """,
                window_start,
                window_end,
            )
            try:
                domains = await self.collect_domains(conn, window_start, window_end)
                enqueued = 0
                for row in domains:
                    if await self.enqueue_domain_job(conn, row, window_start, window_end):
                        enqueued += 1
                summary = {
                    "domain_ids": [int(row["domain_id"]) for row in domains],
                    "latest_snapshot_ids": [int(row["latest_snapshot_id"]) for row in domains],
                }
                await conn.execute(
                    """
                    UPDATE delta_intelligence_runs
                    SET status = 'done', domains_considered = $2, jobs_enqueued = $3,
                        summary = $4::jsonb, finished_at = NOW()
                    WHERE id = $1
                    """,
                    run_id,
                    len(domains),
                    enqueued,
                    json_value(summary),
                )
            except Exception as exc:
                await conn.execute(
                    """
                    UPDATE delta_intelligence_runs
                    SET status = 'failed', error = $2, finished_at = NOW()
                    WHERE id = $1
                    """,
                    run_id,
                    repr(exc)[:4000],
                )
                raise
        self.write_state(
            status="idle",
            last_window_start=window_start,
            last_window_end=window_end,
            domains_considered=len(domains),
            jobs_enqueued=enqueued,
            next_run_at=window_end + timedelta(seconds=self.interval_seconds),
        )
        logger.info(
            "Delta intelligence pass complete window=%s..%s domains=%s jobs=%s",
            window_start.isoformat(),
            window_end.isoformat(),
            len(domains),
            enqueued,
        )
        return len(domains), enqueued

    async def run(self) -> None:
        if not self.enabled:
            self.write_state(status="disabled")
            logger.info("Delta intelligence worker disabled")
            while True:
                await asyncio.sleep(3600)
        while True:
            try:
                self.write_state(status="running")
                await self.run_once()
            except Exception as exc:
                logger.exception("Delta intelligence pass failed")
                self.write_state(status="error", error=repr(exc)[:1000])
            await asyncio.sleep(self.interval_seconds)


async def amain(once: bool = False) -> None:
    worker = DeltaIntelligenceWorker()
    await worker.init()
    try:
        if once:
            await worker.run_once()
        else:
            await worker.run()
    finally:
        await worker.close()


def healthcheck() -> int:
    worker = DeltaIntelligenceWorker()
    try:
        state = json.loads(worker.state_path.read_text(encoding="utf-8"))
        updated_raw = str(state.get("updated_at") or "").replace("Z", "+00:00")
        updated = datetime.fromisoformat(updated_raw).replace(tzinfo=None)
        age = (utcnow() - updated).total_seconds()
    except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
        return 1
    if str(state.get("status") or "") not in {"idle", "running", "disabled"}:
        return 1
    return 0 if age <= worker.interval_seconds + 900 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        raise SystemExit(healthcheck())
    asyncio.run(amain(args.once))
