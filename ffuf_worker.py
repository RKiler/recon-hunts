#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import socket
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import asyncpg

from continuous_recon import ContinuousReconFramework, load_config, postgres_json


logger = logging.getLogger("recon-ffuf-worker")


class FfufQueueWorker:
    def __init__(self, framework: ContinuousReconFramework) -> None:
        self.framework = framework
        self.config = framework.config

    async def recover_interrupted_runs(self) -> None:
        assert self.framework.db_pool is not None
        async with self.framework.db_pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE ffuf_runs
                SET status = 'queued',
                    error = 'recovered after FFUF worker restart',
                    options = options - 'worker_id'
                WHERE status = 'running'
                  AND options->>'queue_worker' = 'ffuf'
                """
            )
        logger.info("FFUF queue recovery: %s", result)

    async def claim_run(self, worker_id: str) -> dict[str, Any] | None:
        assert self.framework.db_pool is not None
        async with self.framework.db_pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT id
                    FROM ffuf_runs
                    WHERE status = 'queued'
                      AND options->>'queue_worker' = 'ffuf'
                    ORDER BY started_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                    """
                )
                if not row:
                    return None
                claimed = await conn.fetchrow(
                    """
                    UPDATE ffuf_runs
                    SET status = 'running',
                        started_at = NOW(),
                        completed_at = NULL,
                        error = NULL,
                        options = options || jsonb_build_object('worker_id', $2::text)
                    WHERE id = $1
                    RETURNING *
                    """,
                    row["id"],
                    worker_id,
                )
                return dict(claimed)

    @staticmethod
    def normalize_wordlist(source: Path) -> str:
        seen: set[str] = set()
        normalized: list[str] = []
        with source.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                value = raw_line.strip()
                if not value or value.startswith("#"):
                    continue
                value = value.lstrip("/")
                if not value or value in seen:
                    continue
                seen.add(value)
                normalized.append(value)
        temp = tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            prefix="ffuf-normalized-",
            suffix=".txt",
            delete=False,
        )
        try:
            temp.write("\n".join(normalized))
            temp.write("\n")
            return temp.name
        finally:
            temp.close()

    @staticmethod
    def safe_int(value: Any) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def json_object(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else {}
        return {}

    @staticmethod
    def endpoint_path(url: str) -> str:
        parsed = urlsplit(url)
        path = parsed.path or "/"
        return f"{path}?{parsed.query}" if parsed.query else path

    @classmethod
    def hit_fingerprint(cls, hit: dict[str, Any]) -> tuple[Any, ...]:
        """Group likely fallback responses without trusting a single metric."""
        return (
            cls.safe_int(hit.get("status")),
            cls.safe_int(hit.get("length")),
            cls.safe_int(hit.get("words")),
            cls.safe_int(hit.get("lines")),
            str(hit.get("redirectlocation") or ""),
        )

    @classmethod
    def match_statuses(cls, options: dict[str, Any], scan_cfg: dict[str, Any]) -> list[int]:
        if options.get("profile") == "bug_jobs_auto":
            configured = options.get("match_status") or scan_cfg.get(
                "bug_jobs_auto_ffuf_match_status",
                [200, 204, 301, 302, 307, 308, 401, 403, 405, 500],
            )
        else:
            configured = options.get("match_status") or scan_cfg.get(
                "ffuf_match_status",
                [200, 204, 301, 302, 307, 308, 401, 403],
            )
        if not isinstance(configured, (list, tuple, set)):
            configured = [configured]
        values: list[int] = []
        for value in configured:
            parsed = cls.safe_int(value)
            if parsed is not None and 100 <= parsed <= 599 and parsed not in values:
                values.append(parsed)
        return values or [200, 204, 301, 302, 307, 308, 401, 403]

    @staticmethod
    def effective_wordlist(run: dict[str, Any], options: dict[str, Any], scan_cfg: dict[str, Any]) -> Path:
        configured = None
        if options.get("profile") == "bug_jobs_auto":
            configured = scan_cfg.get("bug_jobs_auto_ffuf_wordlist")
        return Path(str(configured or run["wordlist_path"]))

    @staticmethod
    def max_hits_per_fingerprint(options: dict[str, Any], scan_cfg: dict[str, Any]) -> int:
        if options.get("profile") == "bug_jobs_auto":
            return max(1, int(scan_cfg.get("bug_jobs_auto_ffuf_max_hits_per_fingerprint", 1)))
        return max(5, int(scan_cfg.get("ffuf_max_hits_per_fingerprint", 25)))

    async def load_context(self, run: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        assert self.framework.db_pool is not None
        async with self.framework.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT fr.id, fr.domain_id, fr.live_host_id, fr.host_url,
                       d.domain, lh.status_code, lh.title, lh.webserver
                FROM ffuf_runs fr
                JOIN domains d ON d.id = fr.domain_id
                JOIN live_hosts lh ON lh.id = fr.live_host_id
                WHERE fr.id = $1
                """,
                run["id"],
            )
        if not row:
            raise RuntimeError("FFUF run context disappeared")
        context = dict(row)
        domain_info = {
            "id": int(context["domain_id"]),
            "domain": context["domain"],
            "_scope_rules": await self.framework.load_scope_rules(int(context["domain_id"])),
            "_auth_profiles": await self.framework.load_auth_profiles(int(context["domain_id"])),
        }
        return context, domain_info

    async def save_hit(
        self,
        run_id: int,
        context: dict[str, Any],
        hit: dict[str, Any],
    ) -> bool:
        url = str(hit.get("url") or "").strip()
        if not url:
            return False
        status = hit.get("status")
        status_code = int(status) if status is not None else None
        endpoint_id = await self.framework.save_endpoint(
            int(context["domain_id"]),
            int(context["live_host_id"]),
            url,
            "ffuf",
            status_code=status_code,
        )
        path = self.endpoint_path(url)
        assert self.framework.db_pool is not None
        async with self.framework.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO ffuf_run_hits (
                  ffuf_run_id, endpoint_id, url, path, status_code,
                  content_length, words, lines, redirect_location, result
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
                status_code,
                self.safe_int(hit.get("length")),
                self.safe_int(hit.get("words")),
                self.safe_int(hit.get("lines")),
                hit.get("redirectlocation"),
                postgres_json(hit),
            )
        return True

    async def execute_run(self, run: dict[str, Any]) -> None:
        context, domain_info = await self.load_context(run)
        options = self.json_object(run.get("options"))
        scan_cfg = self.config.scan
        wordlist = self.effective_wordlist(run, options, scan_cfg)
        if not wordlist.is_file():
            raise FileNotFoundError(f"wordlist not found: {wordlist}")
        normalized_path = self.normalize_wordlist(wordlist)
        command = [
            self.config.tools.get("ffuf", "ffuf"),
            "-w",
            normalized_path,
            "-u",
            f"{str(context['host_url']).rstrip('/')}/FUZZ",
            "-mc",
            ",".join(str(status) for status in self.match_statuses(options, scan_cfg)),
            "-t",
            str(scan_cfg.get("ffuf_batch_threads", 5)),
            "-rate",
            str(scan_cfg.get("ffuf_batch_rate", 8)),
            "-timeout",
            str(scan_cfg.get("ffuf_timeout_seconds", 10)),
            "-maxtime",
            str(scan_cfg.get("ffuf_batch_max_time_seconds", 1200)),
            "-ac",
            "-noninteractive",
            "-json",
        ]
        for header in self.framework.authenticated_header_lines(
            domain_info,
            str(context["host_url"]),
        ):
            command.extend(["-H", header])

        hits_count = 0
        parsed_hits = 0
        suppressed_hits = 0
        max_hits = max(100, int(scan_cfg.get("ffuf_max_hits_per_run", 2000)))
        max_per_fingerprint = self.max_hits_per_fingerprint(options, scan_cfg)
        fingerprint_counts: dict[tuple[Any, ...], int] = {}
        try:
            rc, stdout, stderr = await self.framework.run_port_command(
                command,
                float(scan_cfg.get("ffuf_batch_max_time_seconds", 1200)) + 30,
            )
            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    hit = json.loads(line)
                except json.JSONDecodeError:
                    continue
                parsed_hits += 1
                fingerprint = self.hit_fingerprint(hit)
                fingerprint_counts[fingerprint] = fingerprint_counts.get(fingerprint, 0) + 1
                if fingerprint_counts[fingerprint] > max_per_fingerprint:
                    suppressed_hits += 1
                    continue
                if hits_count >= max_hits:
                    suppressed_hits += 1
                    continue
                if await self.save_hit(int(run["id"]), context, hit):
                    hits_count += 1
            status = "completed" if rc in {0, 1} else "failed"
            error = None if status == "completed" else (stderr or stdout)[-4000:]
            if status == "completed" and suppressed_hits:
                error = (
                    "bounded noisy FFUF results: "
                    f"parsed={parsed_hits}, stored={hits_count}, suppressed={suppressed_hits}, "
                    f"max_per_run={max_hits}, max_per_fingerprint={max_per_fingerprint}"
                )
        finally:
            Path(normalized_path).unlink(missing_ok=True)

        assert self.framework.db_pool is not None
        async with self.framework.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE ffuf_runs
                SET completed_at = NOW(),
                    status = $2,
                    hits_count = $3,
                    error = $4,
                    options = options - 'worker_id'
                WHERE id = $1
                """,
                run["id"],
                status,
                hits_count,
                error,
            )
        logger.info(
            "Completed FFUF run=%s host=%s profile=%s hits=%s parsed=%s suppressed=%s status=%s",
            run["id"],
            context["host_url"],
            options.get("profile"),
            hits_count,
            parsed_hits,
            suppressed_hits,
            status,
        )

    async def worker_loop(self, worker_id: str) -> None:
        idle_sleep = max(2.0, float(self.config.scan.get("ffuf_batch_idle_seconds", 5)))
        while True:
            run = await self.claim_run(worker_id)
            if not run:
                await asyncio.sleep(idle_sleep)
                continue
            try:
                await self.execute_run(run)
            except Exception as exc:
                logger.exception("FFUF run %s failed: %s", run["id"], exc)
                assert self.framework.db_pool is not None
                async with self.framework.db_pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE ffuf_runs
                        SET completed_at = NOW(),
                            status = 'failed',
                            error = $2,
                            options = options - 'worker_id'
                        WHERE id = $1
                        """,
                        run["id"],
                        repr(exc)[:4000],
                    )


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config()
    framework = ContinuousReconFramework(config)
    framework.db_pool = await asyncpg.create_pool(
        host=config.database["host"],
        port=config.database["port"],
        database=config.database["name"],
        user=config.database["user"],
        password=config.database["password"],
        min_size=1,
        max_size=max(5, int(config.scan.get("ffuf_batch_workers", 3)) + 2),
    )
    worker = FfufQueueWorker(framework)
    await worker.recover_interrupted_runs()
    concurrency = max(1, int(config.scan.get("ffuf_batch_workers", 3)))
    instance = os.getenv("HOSTNAME") or socket.gethostname()
    logger.info(
        "FFUF queue worker started concurrency=%s rate_per_worker=%s",
        concurrency,
        config.scan.get("ffuf_batch_rate", 8),
    )
    await asyncio.gather(
        *(worker.worker_loop(f"{instance}:{index}") for index in range(1, concurrency + 1))
    )


if __name__ == "__main__":
    asyncio.run(main())
