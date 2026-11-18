"""Independent domain hunts; no bug-job queue ownership or job linking."""

from __future__ import annotations

import json
import argparse
import hashlib
import os
import time
from datetime import datetime
from pathlib import Path

from hunt_coordinator import HuntCoordinator, iso, normalize_application_context
from hunt_research import (
    STATE_PRIORITY,
    extract_research_observations,
    merge_evidence_level,
    owasp_top10_2025_coverage,
    reconcile_validation_state,
    research_completion,
)


DATA_SCOPES = {"all", "context"}
DATA_SOURCES = {"all", "delta"}
SESSION_ROOT = Path("/root/codex_artifacts/domain_hunts")
LOGIN_SIGNALS = Path("/root/codex_artifacts/hunt_login_signals")
LOGIN_STATES = {"manual_login_pending", "ready_for_identity_verification", "blocked_host"}


def json_object(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def format_report_draft(hypothesis: dict) -> str:
    """Render a reviewable disclosure draft from E3 fields without copying raw traffic."""
    observation = json_object(hypothesis.get("latest_observation"))

    def value(name: str, fallback: str = "") -> str:
        raw = observation.get(name, fallback)
        if isinstance(raw, (dict, list)):
            raw = json.dumps(raw, ensure_ascii=False, indent=2, default=str)
        return str(raw or fallback).strip()[:6000]

    severity = value("severity", "Needs program triage")
    return "\n".join((
        f"# {value('title', str(hypothesis.get('title') or 'Security finding'))}",
        "",
        f"**Severity:** {severity}",
        f"**Affected asset:** {value('affected_asset', str(hypothesis.get('affected_asset') or ''))}",
        f"**Vulnerability class:** {value('bug_class', str(hypothesis.get('bug_family') or ''))}",
        "",
        "## Summary",
        value("summary", str(hypothesis.get("latest_summary") or "")),
        "",
        "## Impact",
        value("impact", "Impact needs analyst review."),
        "",
        "## Reproduction",
        value("reproduction", "Reproduction steps need analyst review."),
        "",
        "## Baseline and negative control",
        f"Baseline: {value('baseline', 'Not recorded')}",
        f"Negative control: {value('negative_control', 'Not recorded')}",
        "",
        "## Evidence",
        *[f"- {path}" for path in (hypothesis.get("evidence_paths") or [])],
        "",
        "## Remediation",
        value("remediation", "Recommend enforcing the relevant authorization and state checks server side, then review the specific affected trust boundary."),
        "",
        "_Draft generated from the confirmed evidence record. Review scope, redactions, severity, impact, and reproduction before submission._",
    ))


class IndependentHuntCoordinator(HuntCoordinator):
    async def ensure_schema(self) -> None:
        await super().ensure_schema()
        async with self.pool.acquire() as conn:
            await conn.execute("""
                ALTER TABLE hunt_runs
                    ADD COLUMN IF NOT EXISTS data_scope VARCHAR(12) NOT NULL DEFAULT 'all',
                    ADD COLUMN IF NOT EXISTS data_source VARCHAR(12) NOT NULL DEFAULT 'all',
                    ADD COLUMN IF NOT EXISTS delta_scan_ids BIGINT[] NOT NULL DEFAULT '{}'::bigint[],
                    ADD COLUMN IF NOT EXISTS records_per_pass INTEGER NOT NULL DEFAULT 5000,
                    ADD COLUMN IF NOT EXISTS cursor JSONB NOT NULL DEFAULT '{}'::jsonb,
                    ADD COLUMN IF NOT EXISTS coverage JSONB NOT NULL DEFAULT '{}'::jsonb,
                    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP,
                    ADD COLUMN IF NOT EXISTS next_pass_at TIMESTAMP,
                    ADD COLUMN IF NOT EXISTS autonomous_validation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS target_signup_enabled BOOLEAN NOT NULL DEFAULT FALSE
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_passes (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    status VARCHAR(12) NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued', 'running', 'done', 'failed')),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMP,
                    finished_at TIMESTAMP,
                    prompt_path TEXT,
                    packet_path TEXT,
                    output_path TEXT,
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    processed_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
                    cursor_before JSONB NOT NULL DEFAULT '{}'::jsonb,
                    cursor_after JSONB NOT NULL DEFAULT '{}'::jsonb,
                    error TEXT,
                    UNIQUE(run_id, sequence)
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_passes_queue ON hunt_passes(status, created_at) WHERE status = 'queued'")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_passes_run ON hunt_passes(run_id, sequence DESC)")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_hypotheses (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    dedup_key CHAR(64) NOT NULL,
                    bug_family VARCHAR(48) NOT NULL,
                    title TEXT NOT NULL,
                    affected_asset TEXT NOT NULL,
                    feature TEXT NOT NULL DEFAULT '',
                    controlled_input VARCHAR(80) NOT NULL DEFAULT 'route',
                    boundary_class VARCHAR(80) NOT NULL DEFAULT 'feature_boundary',
                    actor_context VARCHAR(160) NOT NULL DEFAULT 'unspecified',
                    state VARCHAR(32) NOT NULL CHECK (state IN (
                        'hypothesis', 'candidate', 'supported', 'confirmed', 'rejected',
                        'duplicate', 'out_of_scope', 'blocked_missing_fixture',
                        'blocked_human_login', 'killed', 'needs_reconciliation'
                    )),
                    evidence_level VARCHAR(2) NOT NULL CHECK (evidence_level IN ('E0', 'E1', 'E2', 'E3')),
                    priority INTEGER NOT NULL DEFAULT 50 CHECK (priority BETWEEN 0 AND 100),
                    first_pass_id BIGINT REFERENCES hunt_passes(id) ON DELETE SET NULL,
                    last_pass_id BIGINT REFERENCES hunt_passes(id) ON DELETE SET NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 0 CHECK (occurrence_count >= 0),
                    next_action TEXT NOT NULL DEFAULT '',
                    missing_proof TEXT NOT NULL DEFAULT '',
                    latest_summary TEXT NOT NULL DEFAULT '',
                    latest_observation JSONB NOT NULL DEFAULT '{}'::jsonb,
                    report_ready BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(run_id, dedup_key),
                    CHECK (NOT report_ready OR (state = 'confirmed' AND evidence_level = 'E3'))
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_hypothesis_events (
                    id BIGSERIAL PRIMARY KEY,
                    hypothesis_id BIGINT NOT NULL REFERENCES hunt_hypotheses(id) ON DELETE CASCADE,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    pass_id BIGINT REFERENCES hunt_passes(id) ON DELETE SET NULL,
                    event_type VARCHAR(32) NOT NULL,
                    from_state VARCHAR(32),
                    to_state VARCHAR(32) NOT NULL,
                    evidence_level VARCHAR(2) NOT NULL CHECK (evidence_level IN ('E0', 'E1', 'E2', 'E3')),
                    source_hash CHAR(64) NOT NULL,
                    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(hypothesis_id, pass_id, source_hash)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_evidence_refs (
                    id BIGSERIAL PRIMARY KEY,
                    hypothesis_id BIGINT NOT NULL REFERENCES hunt_hypotheses(id) ON DELETE CASCADE,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    pass_id BIGINT REFERENCES hunt_passes(id) ON DELETE SET NULL,
                    evidence_path TEXT NOT NULL,
                    source_hash CHAR(64) NOT NULL,
                    redaction_class VARCHAR(24) NOT NULL DEFAULT 'redacted',
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(hypothesis_id, pass_id, evidence_path)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_actions (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    hypothesis_id BIGINT REFERENCES hunt_hypotheses(id) ON DELETE CASCADE,
                    action_key VARCHAR(96) NOT NULL,
                    state VARCHAR(20) NOT NULL DEFAULT 'proposed' CHECK (state IN (
                        'proposed', 'ready', 'started', 'completed', 'aborted',
                        'uncertain', 'reconciliation', 'blocked', 'failed'
                    )),
                    purpose TEXT NOT NULL DEFAULT '',
                    baseline_ref TEXT NOT NULL DEFAULT '',
                    negative_control_ref TEXT NOT NULL DEFAULT '',
                    mutation_dimension VARCHAR(120) NOT NULL DEFAULT '',
                    stop_conditions TEXT NOT NULL DEFAULT '',
                    cleanup_plan TEXT NOT NULL DEFAULT '',
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(run_id, action_key)
                )
            """)
            await conn.execute("ALTER TABLE hunt_passes ADD COLUMN IF NOT EXISTS action_id BIGINT")
            await conn.execute("""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conrelid='hunt_passes'::regclass
                          AND conname='hunt_passes_action_id_fkey'
                    ) THEN
                        ALTER TABLE hunt_passes ADD CONSTRAINT hunt_passes_action_id_fkey
                        FOREIGN KEY (action_id) REFERENCES hunt_actions(id) ON DELETE SET NULL;
                    END IF;
                END $$
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_sessions (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    credential_id BIGINT NOT NULL REFERENCES hunt_credentials(id) ON DELETE CASCADE,
                    exact_host VARCHAR(255) NOT NULL,
                    verification_state VARCHAR(32) NOT NULL DEFAULT 'unverified' CHECK (verification_state IN (
                        'unverified', 'manual_login_pending', 'ready_for_identity_verification',
                        'verified', 'expired', 'wrong_identity', 'blocked_host'
                    )),
                    identity_label TEXT NOT NULL DEFAULT '',
                    role_label TEXT NOT NULL DEFAULT '',
                    tenant_label TEXT NOT NULL DEFAULT '',
                    verified_at TIMESTAMP,
                    expires_at TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(run_id, credential_id, exact_host)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_fixtures (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    hypothesis_id BIGINT REFERENCES hunt_hypotheses(id) ON DELETE SET NULL,
                    fixture_key VARCHAR(96) NOT NULL,
                    object_type VARCHAR(100) NOT NULL,
                    owner_label TEXT NOT NULL,
                    tenant_label TEXT NOT NULL DEFAULT '',
                    exact_host VARCHAR(255) NOT NULL,
                    state VARCHAR(24) NOT NULL DEFAULT 'planned' CHECK (state IN (
                        'planned', 'created', 'verified', 'cleanup_pending', 'cleaned',
                        'uncertain', 'reconciliation'
                    )),
                    create_action_id BIGINT REFERENCES hunt_actions(id) ON DELETE SET NULL,
                    cleanup_action_id BIGINT REFERENCES hunt_actions(id) ON DELETE SET NULL,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(run_id, fixture_key)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_skill_runs (
                    id BIGSERIAL PRIMARY KEY,
                    run_id BIGINT NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    pass_id BIGINT REFERENCES hunt_passes(id) ON DELETE SET NULL,
                    hypothesis_id BIGINT REFERENCES hunt_hypotheses(id) ON DELETE SET NULL,
                    skill_id VARCHAR(160) NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    outcome TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    UNIQUE(pass_id, skill_id)
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_hypotheses_queue ON hunt_hypotheses(run_id, state, priority DESC, updated_at)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_hypothesis_events_run ON hunt_hypothesis_events(run_id, created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_actions_queue ON hunt_actions(run_id, state, updated_at)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_passes_action ON hunt_passes(action_id) WHERE action_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_hunt_sessions_run ON hunt_sessions(run_id, exact_host, verification_state)")
            async with conn.transaction():
                await conn.execute("SELECT pg_advisory_xact_lock(45123, 31881)")
                definition = await conn.fetchval("""
                    SELECT pg_get_constraintdef(oid) FROM pg_constraint
                    WHERE conrelid = 'hunt_credentials'::regclass
                      AND conname = 'hunt_credentials_credential_type_check'
                """)
                if not definition or "login_file" not in definition or "manual_login" not in definition:
                    await conn.execute("ALTER TABLE hunt_credentials DROP CONSTRAINT IF EXISTS hunt_credentials_credential_type_check")
                    await conn.execute("""
                        ALTER TABLE hunt_credentials ADD CONSTRAINT hunt_credentials_credential_type_check
                        CHECK (credential_type IN ('cookie', 'bearer', 'header', 'login_file', 'manual_login'))
                    """)

    async def record_pass_research(self, conn, run_id: int, pass_id: int, result: dict) -> int:
        """Idempotently reconcile one pass result into the durable research ledger."""
        observations = extract_research_observations(result)
        pass_info = await conn.fetchrow(
            "SELECT action_id, sequence FROM hunt_passes WHERE id=$1 AND run_id=$2", pass_id, run_id
        )
        if not pass_info:
            raise RuntimeError("Research pass is unavailable")
        action_pass = bool(pass_info["action_id"])
        accepted = 0
        # inv: every earlier observation has either been ignored as an exact replay or has one event and a reconciled hypothesis.
        # term: one finite observation is consumed per iteration.
        for observation in observations:
            row = observation.to_dict()
            hypothesis_id = await conn.fetchval("""
                INSERT INTO hunt_hypotheses (
                    run_id, dedup_key, bug_family, title, affected_asset, feature,
                    controlled_input, boundary_class, actor_context, state,
                    evidence_level, priority, first_pass_id, last_pass_id,
                    next_action, missing_proof, latest_summary, latest_observation
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    $13, $13, $14, $15, $16, $17::jsonb
                ) ON CONFLICT (run_id, dedup_key) DO NOTHING RETURNING id
            """, run_id, row["dedup_key"], row["bug_family"], row["title"], row["affected_asset"],
                 row["feature"], row["controlled_input"], row["boundary_class"], row["actor_context"],
                 row["state"], row["evidence_level"], row["priority"], pass_id, row["next_action"],
                 row["missing_proof"], row["summary"], json.dumps(row["source_item"], default=str))
            current = await conn.fetchrow("""
                SELECT id, state, evidence_level, priority, next_action, missing_proof
                FROM hunt_hypotheses WHERE run_id=$1 AND dedup_key=$2 FOR UPDATE
            """, run_id, row["dedup_key"])
            if not current:
                raise RuntimeError("Research hypothesis upsert did not produce a row")
            hypothesis_id = int(current["id"])
            merged_state = reconcile_validation_state(
                str(current["state"]), row["state"], action_pass,
                row["source_item"], row["evidence_path"],
            )
            merged_level = merge_evidence_level(str(current["evidence_level"]), row["evidence_level"])
            source_item = row["source_item"]
            report_complete = (
                row["source_kind"] == "confirmed_findings" and
                all(source_item.get(key) for key in (
                    "title", "bug_class", "affected_asset", "evidence_path", "baseline",
                    "negative_control", "impact", "reproduction",
                )) and self._confirmed_evidence_exists(run_id, int(pass_info["sequence"]), row["evidence_path"])
            )
            report_ready = bool(merged_state == "confirmed" and merged_level == "E3" and report_complete)
            event_id = await conn.fetchval("""
                INSERT INTO hunt_hypothesis_events (
                    hypothesis_id, run_id, pass_id, event_type, from_state,
                    to_state, evidence_level, source_hash, payload
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                ON CONFLICT (hypothesis_id, pass_id, source_hash) DO NOTHING
                RETURNING id
            """, hypothesis_id, run_id, pass_id, row["source_kind"], current["state"],
                 merged_state, row["evidence_level"], row["source_hash"],
                 json.dumps(row["source_item"], default=str))
            next_action = row["next_action"] or str(current["next_action"] or "")
            missing_proof = row["missing_proof"] or str(current["missing_proof"] or "")
            if not next_action and merged_state == "needs_reconciliation":
                next_action = (
                    "Reconcile contradictory pass outcomes with a fresh owned baseline, "
                    "negative control, and one-variable differential test."
                )
            elif not next_action and merged_state.startswith("blocked_") and missing_proof:
                next_action = f"Satisfy the recorded proof prerequisite: {missing_proof[:1200]}"
            if event_id:
                accepted += 1
                await conn.execute("""
                    UPDATE hunt_hypotheses SET
                        bug_family=$2, title=$3, affected_asset=$4, feature=$5,
                        controlled_input=$6, boundary_class=$7, actor_context=$8,
                        state=$9, evidence_level=$10, priority=$11,
                        last_pass_id=$12, occurrence_count=occurrence_count + 1,
                        next_action=$13, missing_proof=$14, latest_summary=$15,
                        latest_observation=$16::jsonb, report_ready=$17, updated_at=NOW()
                    WHERE id=$1
                """, hypothesis_id, row["bug_family"], row["title"], row["affected_asset"],
                     row["feature"], row["controlled_input"], row["boundary_class"], row["actor_context"],
                     merged_state, merged_level, STATE_PRIORITY[merged_state], pass_id,
                     next_action, missing_proof, row["summary"], json.dumps(row["source_item"], default=str),
                     report_ready)
                if row["evidence_path"]:
                    await conn.execute("""
                        INSERT INTO hunt_evidence_refs (
                            hypothesis_id, run_id, pass_id, evidence_path, source_hash
                        ) VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (hypothesis_id, pass_id, evidence_path) DO NOTHING
                    """, hypothesis_id, run_id, pass_id, row["evidence_path"], row["source_hash"])
            elif next_action and not current["next_action"]:
                await conn.execute("""
                    UPDATE hunt_hypotheses SET next_action=$2, missing_proof=$3,
                        updated_at=NOW() WHERE id=$1
                """, hypothesis_id, next_action, missing_proof)
            if next_action:
                action_state = (
                    "completed" if merged_state == "confirmed" else
                    "reconciliation" if merged_state == "needs_reconciliation" else
                    "blocked" if merged_state.startswith("blocked_") else
                    "aborted" if merged_state in {"killed", "rejected", "duplicate", "out_of_scope"} else
                    "proposed"
                )
                action_hash = hashlib.sha256(next_action.encode()).hexdigest()[:24]
                action_key = f"hypothesis:{hypothesis_id}:{action_hash}"
                await conn.execute("""
                    UPDATE hunt_actions SET state='aborted', updated_at=NOW()
                    WHERE hypothesis_id=$1 AND action_key LIKE $2 AND action_key<>$3
                      AND state NOT IN ('completed', 'aborted')
                """, hypothesis_id, f"hypothesis:{hypothesis_id}:%", action_key)
                await conn.execute("""
                    INSERT INTO hunt_actions (
                        run_id, hypothesis_id, action_key, state, purpose,
                        mutation_dimension, stop_conditions
                    ) VALUES ($1, $2, $3, $4, $5, $6,
                              'Stop on scope ambiguity, unexpected side effects, or evidence of non-owned data.')
                    ON CONFLICT (run_id, action_key) DO UPDATE SET
                        hypothesis_id=EXCLUDED.hypothesis_id,
                        state=CASE
                            WHEN hunt_actions.state IN ('completed','blocked','failed','uncertain')
                            THEN hunt_actions.state ELSE EXCLUDED.state END,
                        purpose=EXCLUDED.purpose,
                        mutation_dimension=EXCLUDED.mutation_dimension,
                        updated_at=NOW()
                """, run_id, hypothesis_id, action_key, action_state, next_action,
                     row["controlled_input"])
        skills = result.get("skills_used") if isinstance(result, dict) else []
        if isinstance(skills, list):
            # inv: every earlier valid skill identifier has one idempotent pass record.
            # term: one finite skill item is consumed per iteration.
            for skill in skills[:8]:
                skill_id = str(skill).strip()[:160]
                if not skill_id:
                    continue
                await conn.execute("""
                    INSERT INTO hunt_skill_runs (run_id, pass_id, skill_id)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (pass_id, skill_id) DO NOTHING
                """, run_id, pass_id, skill_id)
        return accepted

    @staticmethod
    def _confirmed_evidence_exists(run_id: int, sequence: int, evidence_path: str) -> bool:
        if not evidence_path:
            return False
        root = (SESSION_ROOT / f"run_{run_id}" / f"pass_{sequence}").resolve()
        supplied = Path(evidence_path)
        resolved = (supplied if supplied.is_absolute() else root / supplied).resolve()
        try:
            resolved.relative_to(root)
        except ValueError:
            return False
        return resolved.is_file()

    async def backfill_research_ledger(self, run_id: int | None = None, limit: int = 5000) -> int:
        """Idempotently import historical completed passes into the durable ledger."""
        if limit < 1 or limit > 50000:
            raise ValueError("Backfill limit must be between 1 and 50000")
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT p.id, p.run_id, p.result FROM hunt_passes p
                WHERE p.status='done' AND ($1::bigint IS NULL OR p.run_id=$1)
                ORDER BY p.id ASC LIMIT $2
            """, run_id, limit)
        accepted = 0
        # inv: all earlier passes were committed independently and exact replays were ignored.
        # term: one finite pass row is consumed per iteration.
        for pass_row in rows:
            async with self.pool.acquire() as conn:
                async with conn.transaction():
                    accepted += await self.record_pass_research(
                        conn, int(pass_row["run_id"]), int(pass_row["id"]), json_object(pass_row["result"])
                    )
        return accepted

    async def sync_pending_job_context(self, conn, run_id: int) -> None:
        # Hunt credentials never mutate or ride along with ordinary bug jobs.
        return None

    async def list_delta_scans(self, domain_id: int, limit: int = 80) -> list[dict]:
        async with self.pool.acquire() as conn:
            domain = await conn.fetchval("SELECT id FROM domains WHERE id=$1 AND active=TRUE", domain_id)
            if not domain:
                raise ValueError("Select an active root domain")
            rows = await conn.fetch("""
                SELECT id, scan_started_at, scan_finished_at,
                       COALESCE(metadata->>'scan_lane', 'delta') AS scan_lane, new_counts
                FROM scan_snapshots
                WHERE domain_id=$1 AND first_run=FALSE AND scan_finished_at IS NOT NULL
                ORDER BY scan_finished_at DESC, id DESC LIMIT $2
            """, domain_id, min(max(int(limit), 1), 100))
        return [{"id": row["id"], "scan_started_at": iso(row["scan_started_at"]),
                 "scan_finished_at": iso(row["scan_finished_at"]), "scan_lane": row["scan_lane"],
                 "new_counts": json_object(row["new_counts"])} for row in rows]

    async def validate_data_source(self, conn, domain_id: int, mode: str,
                                   data_source: str, delta_scan_ids: list[int]) -> list[int]:
        if data_source not in DATA_SOURCES:
            raise ValueError("data_source must be all or delta")
        if data_source == "all":
            return []
        if mode != "one_time":
            raise ValueError("Selected delta scans require a one-time hunt")
        if not isinstance(delta_scan_ids, list) or not 1 <= len(delta_scan_ids) <= 20:
            raise ValueError("Select 1 to 20 delta scans")
        try:
            selected = list(dict.fromkeys(int(value) for value in delta_scan_ids))
        except (TypeError, ValueError) as exc:
            raise ValueError("Delta scan IDs must be integers") from exc
        if len(selected) != len(delta_scan_ids) or any(value <= 0 for value in selected):
            raise ValueError("Select unique valid delta scans")
        rows = await conn.fetch("""
            SELECT id FROM scan_snapshots WHERE domain_id=$1 AND first_run=FALSE
              AND scan_finished_at IS NOT NULL AND id=ANY($2::bigint[])
        """, domain_id, selected)
        if len(rows) != len(selected):
            raise ValueError("Selected scans must be completed delta scans for this domain")
        return selected

    async def start_run(self, domain_id: int, mode: str, records_per_pass: int,
                        application_context: str = "", credential_ids: list[int] | None = None,
                        data_scope: str = "all", data_source: str = "all",
                        delta_scan_ids: list[int] | None = None,
                        autonomous_validation_enabled: bool = False,
                        target_signup_enabled: bool = False) -> dict:
        if not isinstance(autonomous_validation_enabled, bool) or not isinstance(target_signup_enabled, bool):
            raise ValueError("Autonomous validation and target signup settings must be booleans")
        if mode not in {"one_time", "continuous"}:
            raise ValueError("mode must be one_time or continuous")
        if data_scope not in DATA_SCOPES:
            raise ValueError("data_scope must be all or context")
        if not 100 <= records_per_pass <= 10000:
            raise ValueError("records_per_pass must be between 100 and 10000")
        application_context = normalize_application_context(application_context)
        if data_scope == "context" and not application_context:
            raise ValueError("Describe the data to inspect in application context")
        if target_signup_enabled and not autonomous_validation_enabled:
            raise ValueError("Enable autonomous validation before allowing target-account signup")
        credential_ids = credential_ids or []
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                domain = await conn.fetchrow("SELECT id, active FROM domains WHERE id = $1", domain_id)
                if not domain or not domain["active"]:
                    raise ValueError("Select an active root domain from the recon database")
                await self.validate_credentials(conn, domain_id, credential_ids)
                selected_scans = await self.validate_data_source(
                    conn, domain_id, mode, data_source, delta_scan_ids or [])
                run_id = await conn.fetchval("""
                    INSERT INTO hunt_runs (
                        domain_id, mode, scope_confirmed_at, max_jobs_per_cycle,
                        application_context, data_scope, data_source, delta_scan_ids,
                        records_per_pass, next_pass_at, autonomous_validation_enabled,
                        target_signup_enabled
                    ) VALUES ($1, $2, NOW(), 24, $3, $4, $5, $6::bigint[], $7, NOW(), $8, $9) RETURNING id
                """, domain_id, mode, application_context, data_scope, data_source,
                     selected_scans, records_per_pass, bool(autonomous_validation_enabled),
                     bool(target_signup_enabled))
                for credential_id in credential_ids:
                    await conn.execute("INSERT INTO hunt_run_credentials (run_id, credential_id) VALUES ($1, $2)",
                                       run_id, credential_id)
        await self.refresh_run(run_id)
        return await self.get_run(run_id)

    async def refresh_run(self, run_id: int) -> dict:
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow("""
                    SELECT h.id, h.status, h.mode, h.completed_at,
                           h.autonomous_validation_enabled,
                           h.max_jobs_per_cycle, d.active AS domain_active
                    FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                    WHERE h.id = $1 FOR UPDATE OF h
                """, run_id)
                if not run:
                    raise ValueError("Hunt run not found")
                if run["status"] != "active" or not run["domain_active"]:
                    return {"run_id": run_id, "queued": False, "paused": True}
                pending = await conn.fetchval("""
                    SELECT id FROM hunt_passes WHERE run_id = $1 AND status IN ('queued', 'running')
                    ORDER BY id DESC LIMIT 1
                """, run_id)
                if pending:
                    return {"run_id": run_id, "queued": False, "pending_pass_id": pending}
                action_id = None
                if run["autonomous_validation_enabled"]:
                    action_id = await conn.fetchval("""
                    SELECT id FROM hunt_actions
                    WHERE run_id=$1 AND state IN ('proposed', 'ready')
                      AND (SELECT COUNT(*) FROM hunt_passes
                           WHERE run_id=$1 AND action_id IS NOT NULL) < $2
                    ORDER BY CASE state WHEN 'ready' THEN 0 ELSE 1 END, updated_at, id
                    LIMIT 1 FOR UPDATE SKIP LOCKED
                """, run_id, int(run["max_jobs_per_cycle"]))
                if run["mode"] == "one_time" and run["completed_at"] and not action_id:
                    return {"run_id": run_id, "queued": False, "complete": True}
                sequence = await conn.fetchval("SELECT COALESCE(MAX(sequence), 0) + 1 FROM hunt_passes WHERE run_id = $1", run_id)
                pass_id = await conn.fetchval("""
                    INSERT INTO hunt_passes (run_id, sequence, status, action_id)
                    VALUES ($1, $2, 'queued', $3) RETURNING id
                """, run_id, sequence, action_id)
                if action_id:
                    await conn.execute("""
                        UPDATE hunt_actions SET state='ready', updated_at=NOW() WHERE id=$1
                    """, action_id)
                await conn.execute("UPDATE hunt_runs SET last_refresh_at = NOW(), next_pass_at = NULL WHERE id = $1", run_id)
                return {"run_id": run_id, "queued": True, "pass_id": pass_id,
                        "action_id": action_id}

    async def set_status(self, run_id: int, status: str) -> dict:
        if status not in {"active", "paused"}:
            raise ValueError("status must be active or paused")
        async with self.pool.acquire() as conn:
            found = await conn.fetchval("UPDATE hunt_runs SET status = $2 WHERE id = $1 RETURNING id", run_id, status)
        if not found:
            raise ValueError("Hunt run not found")
        if status == "active":
            await self.refresh_run(run_id)
        return await self.get_run(run_id)

    async def update_context(self, run_id: int, application_context: str, credential_ids: list[int],
                             data_scope: str | None = None, data_source: str | None = None,
                             delta_scan_ids: list[int] | None = None,
                             autonomous_validation_enabled: bool | None = None,
                             target_signup_enabled: bool | None = None) -> dict:
        if autonomous_validation_enabled is not None and not isinstance(autonomous_validation_enabled, bool):
            raise ValueError("autonomous_validation_enabled must be a boolean")
        if target_signup_enabled is not None and not isinstance(target_signup_enabled, bool):
            raise ValueError("target_signup_enabled must be a boolean")
        application_context = normalize_application_context(application_context)
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow("""
                    SELECT domain_id, mode, data_scope, data_source, delta_scan_ids,
                           application_context,
                           autonomous_validation_enabled, target_signup_enabled
                    FROM hunt_runs WHERE id = $1 FOR UPDATE
                """, run_id)
                if not run:
                    raise ValueError("Hunt run not found")
                scope = data_scope or run["data_scope"]
                if scope not in DATA_SCOPES:
                    raise ValueError("data_scope must be all or context")
                if scope == "context" and not application_context:
                    raise ValueError("Describe the data to inspect in application context")
                autonomous = (run["autonomous_validation_enabled"] if autonomous_validation_enabled is None
                              else autonomous_validation_enabled)
                signup = run["target_signup_enabled"] if target_signup_enabled is None else target_signup_enabled
                if signup and not autonomous:
                    raise ValueError("Enable autonomous validation before allowing target-account signup")
                source = data_source or run["data_source"]
                selected_scans = await self.validate_data_source(
                    conn, run["domain_id"], run["mode"], source,
                    delta_scan_ids if delta_scan_ids is not None else list(run["delta_scan_ids"] or []))
                reset_inventory = (
                    application_context != run["application_context"] or
                    scope != run["data_scope"] or source != run["data_source"] or
                    selected_scans != list(run["delta_scan_ids"] or [])
                )
                await self.validate_credentials(conn, run["domain_id"], credential_ids)
                running = await conn.fetchval("""
                    SELECT EXISTS(SELECT 1 FROM hunt_passes WHERE run_id = $1 AND status = 'running')
                """, run_id)
                if running:
                    raise ValueError("Wait for the current hunt pass to finish before changing its context")
                await conn.execute("""
                    UPDATE hunt_runs SET application_context = $2, data_scope = $3,
                        data_source = $4, delta_scan_ids = $5::bigint[],
                        autonomous_validation_enabled = $6,
                        target_signup_enabled = $7,
                        cursor = CASE WHEN $8 THEN '{}'::jsonb ELSE cursor END,
                        coverage = CASE WHEN $8 THEN '{}'::jsonb ELSE coverage END,
                        completed_at = CASE WHEN $8 THEN NULL ELSE completed_at END,
                        next_pass_at = NOW()
                    WHERE id = $1
                """, run_id, application_context, scope, source, selected_scans,
                     bool(autonomous), bool(signup), reset_inventory)
                await conn.execute("DELETE FROM hunt_run_credentials WHERE run_id = $1", run_id)
                for credential_id in credential_ids:
                    await conn.execute("INSERT INTO hunt_run_credentials (run_id, credential_id) VALUES ($1, $2)",
                                       run_id, credential_id)
        await self.refresh_run(run_id)
        return await self.get_run(run_id)

    async def reconcile_action(self, run_id: int, action_id: int, disposition: str, note: str) -> dict:
        """Resolve an interrupted action or explicitly authorize one retry after review."""
        if disposition not in {"resolved", "retry"}:
            raise ValueError("Choose resolved or retry")
        note = " ".join(str(note or "").split())[:2000]
        if len(note) < 20:
            raise ValueError("Record what you checked, including side effects and cleanup, in at least 20 characters")
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    "SELECT status, autonomous_validation_enabled FROM hunt_runs WHERE id=$1 FOR UPDATE",
                    run_id,
                )
                action = await conn.fetchrow(
                    "SELECT state, hypothesis_id, result FROM hunt_actions WHERE id=$1 AND run_id=$2 FOR UPDATE",
                    action_id, run_id,
                )
                if not run or not action:
                    raise ValueError("Hunt action not found")
                if run["status"] != "paused":
                    raise ValueError("Pause the campaign before reconciling an uncertain action")
                if action["state"] != "uncertain":
                    raise ValueError("Only an uncertain action can be reconciled here")
                if disposition == "retry" and not run["autonomous_validation_enabled"]:
                    raise ValueError("Enable validation for this campaign before authorizing a retry")
                new_state = "ready" if disposition == "retry" else "completed"
                await conn.execute("""
                    UPDATE hunt_actions SET state=$3,
                        result=result || jsonb_build_object('operator_reconciliation',
                          jsonb_build_object('disposition',$4::text,'note',$5::text,'at',NOW())),
                        updated_at=NOW() WHERE id=$1 AND run_id=$2
                """, action_id, run_id, new_state, disposition, note)
                if action["hypothesis_id"]:
                    await conn.execute("""
                        UPDATE hunt_hypotheses SET
                          next_action=CASE WHEN $3='retry' THEN 'Retry explicitly authorized after operator reconciliation'
                                           ELSE 'Interrupted action reconciled by operator; review evidence before reporting' END,
                          updated_at=NOW() WHERE id=$1 AND run_id=$2
                    """, action["hypothesis_id"], run_id, disposition)
                if disposition == "retry":
                    await conn.execute("""
                        UPDATE hunt_runs SET status='active', completed_at=NULL, next_pass_at=NOW(),
                            last_error=NULL WHERE id=$1
                    """, run_id)
        if disposition == "retry":
            await self.refresh_run(run_id)
        return await self.get_run(run_id)

    async def list_runs(self, domain_id: int | None = None, limit: int = 40) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT h.id, h.domain_id, d.domain, h.mode, h.status, h.data_scope,
                       h.data_source, h.autonomous_validation_enabled, h.target_signup_enabled,
                       cardinality(h.delta_scan_ids) AS delta_scan_count,
                       h.created_at, h.completed_at, h.last_refresh_at, h.coverage,
                       COUNT(p.id)::int AS pass_count,
                       COUNT(p.id) FILTER (WHERE p.status = 'running')::int AS running_count,
                       COUNT(p.id) FILTER (WHERE p.status = 'done')::int AS done_count,
                       COALESCE((SELECT COUNT(*)::int FROM hunt_hypotheses hh
                                 WHERE hh.run_id=h.id AND hh.state IN
                                 ('candidate','supported','needs_reconciliation')),
                                0) AS lead_count,
                       COALESCE((SELECT COUNT(*)::int FROM hunt_hypotheses hh
                                 WHERE hh.run_id=h.id AND hh.state='confirmed'),
                                0) AS confirmed_count,
                       COALESCE((SELECT COUNT(*)::int FROM hunt_hypotheses hh
                                 WHERE hh.run_id=h.id AND hh.state='needs_reconciliation'),
                                0) AS reconciliation_count
                FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                LEFT JOIN hunt_passes p ON p.run_id = h.id
                WHERE ($1::int IS NULL OR h.domain_id = $1)
                GROUP BY h.id, d.domain ORDER BY h.created_at DESC LIMIT $2
            """, domain_id, limit)
        output = []
        # inv: output contains every earlier run with JSON coverage and independent completion labels.
        # term: one finite database row is consumed per iteration.
        for row in rows:
            item = {key: iso(value) for key, value in dict(row).items()}
            coverage = json_object(row["coverage"])
            item["coverage"] = coverage
            counts = {
                "candidate": int(row["lead_count"]),
                "confirmed": int(row["confirmed_count"]),
                "needs_reconciliation": int(row["reconciliation_count"]),
            }
            item.update(research_completion(bool(coverage.get("last_packet_exhausted")), counts))
            output.append(item)
        return output

    async def get_run(self, run_id: int) -> dict:
        async with self.pool.acquire() as conn:
            run = await conn.fetchrow("""
                SELECT h.*, d.domain FROM hunt_runs h JOIN domains d ON d.id = h.domain_id
                WHERE h.id = $1
            """, run_id)
            if not run:
                raise ValueError("Hunt run not found")
            passes = await conn.fetch("""
                SELECT id, sequence, action_id, status, created_at, started_at, finished_at,
                       prompt_path, packet_path, output_path, result, processed_counts, error
                FROM hunt_passes WHERE run_id = $1 ORDER BY sequence DESC LIMIT 100
            """, run_id)
            totals = await conn.fetchrow("""
                SELECT COUNT(*)::int AS passes,
                       COUNT(*) FILTER (WHERE status = 'running')::int AS running
                FROM hunt_passes WHERE run_id = $1
            """, run_id)
            credentials = await conn.fetch("""
                SELECT hc.id, hc.alias, hc.role, hc.tenant, hc.host, hc.credential_type
                FROM hunt_run_credentials hrc JOIN hunt_credentials hc ON hc.id = hrc.credential_id
                WHERE hrc.run_id = $1 ORDER BY hc.alias
            """, run_id)
            hypotheses = await conn.fetch("""
                SELECT h.id, h.dedup_key, h.bug_family, h.title, h.affected_asset,
                       h.feature, h.controlled_input, h.boundary_class, h.actor_context,
                       h.state, h.evidence_level, h.priority, h.first_pass_id,
                       h.last_pass_id, h.occurrence_count, h.next_action,
                       h.missing_proof, h.latest_summary, h.latest_observation,
                       h.report_ready, h.created_at, h.updated_at,
                       COALESCE(array_remove(array_agg(DISTINCT e.evidence_path), NULL),
                                ARRAY[]::text[]) AS evidence_paths
                FROM hunt_hypotheses h
                LEFT JOIN hunt_evidence_refs e ON e.hypothesis_id=h.id
                WHERE h.run_id=$1
                GROUP BY h.id
                ORDER BY h.priority DESC, h.updated_at DESC LIMIT 200
            """, run_id)
            owasp_family_counts = await conn.fetch("""
                SELECT bug_family, COUNT(*)::int AS hypothesis_count
                FROM hunt_hypotheses WHERE run_id=$1 GROUP BY bug_family
            """, run_id)
            state_rows = await conn.fetch("""
                SELECT state, COUNT(*)::int AS count FROM hunt_hypotheses
                WHERE run_id=$1 GROUP BY state
            """, run_id)
            skill_rows = await conn.fetch("""
                SELECT skill_id, COUNT(*)::int AS use_count, MAX(created_at) AS last_used_at
                FROM hunt_skill_runs WHERE run_id=$1
                GROUP BY skill_id ORDER BY use_count DESC, skill_id LIMIT 50
            """, run_id)
            action_rows = await conn.fetch("""
                SELECT id, hypothesis_id, action_key, state, purpose, baseline_ref,
                       negative_control_ref, mutation_dimension, stop_conditions,
                       cleanup_plan, result, created_at, updated_at
                FROM hunt_actions WHERE run_id=$1
                ORDER BY CASE state
                    WHEN 'reconciliation' THEN 0 WHEN 'ready' THEN 1
                    WHEN 'proposed' THEN 2 WHEN 'blocked' THEN 3 ELSE 4 END,
                    updated_at DESC LIMIT 200
            """, run_id)
        serialized = [{key: iso(value) for key, value in dict(item).items()} for item in passes]
        for item in serialized:
            item["result"] = json_object(item.get("result"))
            item["processed_counts"] = json_object(item.get("processed_counts"))
        coverage = json_object(run["coverage"])
        run_data = {key: iso(value) for key, value in dict(run).items()}
        run_data["cursor"] = json_object(run["cursor"])
        run_data["coverage"] = coverage
        scan_config = self.config.get("scan", {})
        run_data["worker_model"] = str(
            scan_config.get("hunt_worker_model") or scan_config.get("codex_worker_model") or "cli_default"
        )
        run_data["worker_reasoning_effort"] = str(
            scan_config.get("hunt_worker_reasoning_effort") or "medium"
        )
        hypothesis_data = []
        # inv: hypothesis_data contains every earlier durable hypothesis with parsed JSON and timestamps.
        # term: one finite hypothesis row is consumed per iteration.
        for row in hypotheses:
            item = {key: iso(value) for key, value in dict(row).items()}
            item["latest_observation"] = json_object(item.get("latest_observation"))
            hypothesis_data.append(item)
        state_counts = {str(item["state"]): int(item["count"]) for item in state_rows}
        completion = research_completion(bool(coverage.get("last_packet_exhausted")), state_counts)
        run_data.update(completion)
        action_data = [{key: iso(value) for key, value in dict(item).items()} for item in action_rows]
        # inv: every earlier action has a parsed result object suitable for API serialization.
        # term: one finite action record is consumed per iteration.
        for item in action_data:
            item["result"] = json_object(item.get("result"))
        report_drafts = []
        for item in hypothesis_data:
            if item.get("report_ready") and item.get("state") == "confirmed":
                report_drafts.append({
                    "hypothesis_id": item["id"],
                    "title": item["title"],
                    "bug_family": item["bug_family"],
                    "affected_asset": item["affected_asset"],
                    "evidence_paths": item["evidence_paths"],
                    "draft": format_report_draft(item),
                })
        leads = sum(state_counts.get(state, 0) for state in (
            "candidate", "supported", "needs_reconciliation",
            "blocked_missing_fixture", "blocked_human_login",
        ))
        confirmed = state_counts.get("confirmed", 0)
        account_data = []
        for item in credentials:
            account = dict(item)
            if account["credential_type"] == "login_file":
                status_path = SESSION_ROOT / f"run_{run_id}" / "sessions" / f"account_{account['id']}.status.json"
                try:
                    status = json_object(status_path.read_text(encoding="utf-8")).get("status")
                except OSError:
                    status = None
                account["login_status"] = status if status in LOGIN_STATES else "waiting_to_start"
            account_data.append(account)
        return {
            "run": run_data,
            "credentials": account_data,
            "passes": serialized,
            "hypotheses": hypothesis_data,
            "research_summary": state_counts,
            "completion": completion,
            "actions": action_data,
            "report_drafts": report_drafts,
            "owasp_coverage": owasp_top10_2025_coverage([dict(item) for item in owasp_family_counts]),
            "skill_runs": [{key: iso(value) for key, value in dict(item).items()} for item in skill_rows],
            "coverage": coverage,
            "summary": {
                "passes": totals["passes"],
                "running": totals["running"],
                "leads": leads,
                "confirmed": confirmed,
                "records_examined": sum(coverage.get("scanned", {}).values()),
            },
        }


def request_owned_relogin(run_id: int, account_id: int, wait_seconds: int = 1500) -> bool:
    if run_id < 1 or account_id < 1 or not 0 <= wait_seconds <= 1800:
        raise ValueError("Invalid run, account, or wait window")
    run_dir = SESSION_ROOT / f"run_{run_id}"
    request = json.loads((run_dir / "login_request.json").read_text(encoding="utf-8"))
    if request.get("run_id") != run_id or not any(
        item.get("id") == account_id for item in request.get("accounts", [])
    ):
        raise ValueError("Account is not selected for this hunt")
    LOGIN_SIGNALS.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = run_dir / "sessions" / f"account_{account_id}.json"
    old_mtime = state.stat().st_mtime_ns if state.exists() else 0
    marker = LOGIN_SIGNALS / f"run_{run_id}_account_{account_id}.retry"
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
    except FileExistsError:
        pass
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if state.exists() and state.stat().st_mtime_ns > old_mtime:
            return True
        time.sleep(5)
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Request a fresh isolated VNC login for an owned hunt account")
    parser.add_argument("--request-relogin", action="store_true", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--account-id", type=int, required=True)
    parser.add_argument("--wait-seconds", type=int, default=1500)
    args = parser.parse_args()
    if request_owned_relogin(args.run_id, args.account_id, args.wait_seconds):
        print("New session captured; verify account identity before testing.")
    else:
        print("Login still pending; stop authenticated testing until a new session is captured.")
        raise SystemExit(1)
