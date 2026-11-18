#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import aiohttp
import asyncpg


logger = logging.getLogger("recon-search-intelligence")


QUERY_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("inventory", "site:{domain}"),
    ("auth", 'site:{domain} (inurl:login OR inurl:signin OR inurl:register OR inurl:signup)'),
    ("admin", 'site:{domain} (inurl:admin OR inurl:dashboard OR inurl:console OR inurl:portal)'),
    ("api", 'site:{domain} (inurl:api OR inurl:swagger OR inurl:openapi OR inurl:graphql OR inurl:graphiql)'),
    ("redirect", 'site:{domain} (inurl:redirect OR inurl:return OR inurl:callback OR inurl:next=)'),
    ("upload", 'site:{domain} (inurl:upload OR inurl:import OR inurl:attachment OR inurl:file)'),
    ("documents", "site:{domain} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:csv)"),
    ("javascript", "site:{domain} (filetype:js OR filetype:map)"),
    ("configuration", 'site:{domain} (filetype:env OR filetype:yaml OR filetype:yml OR filetype:json OR filetype:xml)'),
    ("errors", 'site:{domain} ("stack trace" OR "exception" OR "debug" OR "Index of /")'),
    ("cloud", 'site:{domain} ("amazonaws.com" OR "storage.googleapis.com" OR "blob.core.windows.net")'),
    ("staging", 'site:{domain} (inurl:dev OR inurl:staging OR inurl:test OR inurl:sandbox OR inurl:beta)'),
)


CATEGORY_RISK_TAGS = {
    "auth": ["auth"],
    "admin": ["admin"],
    "api": ["api"],
    "redirect": ["redirect"],
    "upload": ["upload"],
    "documents": ["document"],
    "javascript": ["javascript"],
    "configuration": ["configuration"],
    "errors": ["debug"],
    "cloud": ["cloud"],
    "staging": ["nonproduction"],
}


@dataclass(frozen=True)
class SearchProvider:
    name: str
    api_key: str
    engine_id: str = ""


def provider_from_config(config: dict[str, Any]) -> SearchProvider | None:
    requested = str(config.get("provider") or "auto").strip().lower()
    candidates = {
        "google_cse": (
            str(config.get("google_api_key") or os.getenv("GOOGLE_CSE_API_KEY") or ""),
            str(config.get("google_engine_id") or os.getenv("GOOGLE_CSE_ENGINE_ID") or ""),
        ),
        "serper": (str(config.get("serper_api_key") or os.getenv("SERPER_API_KEY") or ""), ""),
        "serpapi": (str(config.get("serpapi_api_key") or os.getenv("SERPAPI_API_KEY") or ""), ""),
    }
    order = ("google_cse", "serper", "serpapi") if requested == "auto" else (requested,)
    for name in order:
        api_key, engine_id = candidates.get(name, ("", ""))
        if api_key and (name != "google_cse" or engine_id):
            return SearchProvider(name=name, api_key=api_key, engine_id=engine_id)
    return None


def canonical_url(value: str) -> str | None:
    value = str(value or "").strip()
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower().rstrip(".")
    port = f":{parsed.port}" if parsed.port and parsed.port not in {80, 443} else ""
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    query = "&".join(
        f"{name}={val}"
        for name, val in sorted(parse_qsl(parsed.query, keep_blank_values=True))
    )
    return f"{scheme}://{hostname}{port}{path}{'?' + query if query else ''}"


def is_in_scope(hostname: str, root_domain: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    root_domain = root_domain.lower().rstrip(".")
    return hostname == root_domain or hostname.endswith(f".{root_domain}")


class SearchIntelligence:
    def __init__(self, pool: asyncpg.Pool, config: dict[str, Any]) -> None:
        self.pool = pool
        self.config = config
        self.provider = provider_from_config(config)

    async def ensure_schema(self) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                ALTER TABLE domains
                    ADD COLUMN IF NOT EXISTS enable_search_intelligence BOOLEAN;
                CREATE TABLE IF NOT EXISTS search_intel_jobs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    status VARCHAR(20) NOT NULL DEFAULT 'queued',
                    priority INTEGER NOT NULL DEFAULT 50,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    available_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMP,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error TEXT,
                    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS search_intel_runs (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    provider VARCHAR(30) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'running',
                    query_count INTEGER NOT NULL DEFAULT 0,
                    result_count INTEGER NOT NULL DEFAULT 0,
                    new_result_count INTEGER NOT NULL DEFAULT 0,
                    in_scope_count INTEGER NOT NULL DEFAULT 0,
                    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    error TEXT,
                    summary JSONB NOT NULL DEFAULT '{}'::jsonb
                );
                CREATE TABLE IF NOT EXISTS search_intel_results (
                    id BIGSERIAL PRIMARY KEY,
                    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
                    first_run_id BIGINT REFERENCES search_intel_runs(id) ON DELETE SET NULL,
                    last_run_id BIGINT REFERENCES search_intel_runs(id) ON DELETE SET NULL,
                    endpoint_id INTEGER REFERENCES endpoints(id) ON DELETE SET NULL,
                    provider VARCHAR(30) NOT NULL,
                    category VARCHAR(40) NOT NULL,
                    query TEXT NOT NULL,
                    query_hash VARCHAR(64) NOT NULL,
                    url TEXT NOT NULL,
                    url_hash VARCHAR(64) NOT NULL,
                    hostname VARCHAR(255),
                    title TEXT,
                    snippet TEXT,
                    display_link TEXT,
                    is_in_scope BOOLEAN NOT NULL DEFAULT FALSE,
                    status_code INTEGER,
                    risk_tags TEXT[] NOT NULL DEFAULT '{}',
                    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    first_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, query_hash, url_hash)
                );
                CREATE TABLE IF NOT EXISTS search_intel_run_results (
                    run_id BIGINT NOT NULL REFERENCES search_intel_runs(id) ON DELETE CASCADE,
                    result_id BIGINT NOT NULL REFERENCES search_intel_results(id) ON DELETE CASCADE,
                    rank INTEGER,
                    PRIMARY KEY(run_id, result_id)
                );
                CREATE INDEX IF NOT EXISTS idx_search_intel_jobs_claim
                    ON search_intel_jobs(status, available_at, priority DESC, created_at);
                CREATE INDEX IF NOT EXISTS idx_search_intel_runs_domain
                    ON search_intel_runs(domain_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_search_intel_results_domain_seen
                    ON search_intel_results(domain_id, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_search_intel_results_category
                    ON search_intel_results(category, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_search_intel_results_scope
                    ON search_intel_results(is_in_scope, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_search_intel_run_results_run
                    ON search_intel_run_results(run_id, rank);
                """
            )
            await conn.execute(
                """
                UPDATE search_intel_jobs
                SET status = 'queued',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    error = COALESCE(error, 'worker lease expired'),
                    updated_at = NOW()
                WHERE status = 'running'
                  AND lease_expires_at < NOW()
                """
            )

    async def seed_jobs(self) -> str:
        interval = max(24, int(self.config.get("interval_hours", 168)))
        max_attempts = max(1, int(self.config.get("max_attempts", 3)))
        async with self.pool.acquire() as conn:
            return await conn.execute(
                """
                INSERT INTO search_intel_jobs (
                    domain_id, dedupe_key, priority, max_attempts
                )
                SELECT id, 'domain:' || id::text, 50, $1
                FROM domains
                WHERE active = TRUE
                  AND COALESCE(enable_search_intelligence, TRUE) = TRUE
                ON CONFLICT (dedupe_key)
                DO UPDATE SET
                    status = 'queued',
                    attempts = 0,
                    available_at = NOW(),
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    error = NULL,
                    updated_at = NOW()
                WHERE search_intel_jobs.status IN ('completed', 'failed')
                  AND search_intel_jobs.updated_at <= NOW() - ($2 * INTERVAL '1 hour')
                """,
                max_attempts,
                interval,
            )

    async def claim_job(self, worker_id: str) -> dict[str, Any] | None:
        lease_seconds = max(120, int(self.config.get("lease_seconds", 900)))
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT sij.id, sij.domain_id, d.domain
                    FROM search_intel_jobs sij
                    JOIN domains d ON d.id = sij.domain_id
                    WHERE sij.status = 'queued'
                      AND sij.available_at <= NOW()
                    ORDER BY sij.priority DESC, sij.created_at
                    FOR UPDATE OF sij SKIP LOCKED
                    LIMIT 1
                    """
                )
                if not row:
                    return None
                state = await conn.fetchrow(
                    """
                    UPDATE search_intel_jobs
                    SET status = 'running',
                        attempts = attempts + 1,
                        lease_owner = $2,
                        lease_expires_at = NOW() + ($3 * INTERVAL '1 second'),
                        started_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1
                    RETURNING attempts, max_attempts
                    """,
                    row["id"],
                    worker_id,
                    lease_seconds,
                )
        result = dict(row)
        result.update(dict(state))
        return result

    async def search(self, query: str, limit: int) -> list[dict[str, Any]]:
        if not self.provider:
            raise RuntimeError("no search provider credentials configured")
        timeout = aiohttp.ClientTimeout(total=max(10, int(self.config.get("request_timeout_seconds", 30))))
        limit = max(1, min(limit, 100))
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if self.provider.name == "google_cse":
                params = {
                    "key": self.provider.api_key,
                    "cx": self.provider.engine_id,
                    "q": query,
                    "num": min(limit, 10),
                }
                async with session.get("https://www.googleapis.com/customsearch/v1", params=params) as response:
                    payload = await response.json(content_type=None)
                    if response.status != 200:
                        raise RuntimeError(f"Google CSE HTTP {response.status}: {payload}")
                    items = payload.get("items") or []
            elif self.provider.name == "serper":
                headers = {"X-API-KEY": self.provider.api_key, "Content-Type": "application/json"}
                async with session.post(
                    "https://google.serper.dev/search",
                    headers=headers,
                    json={"q": query, "num": min(limit, 100)},
                ) as response:
                    payload = await response.json(content_type=None)
                    if response.status != 200:
                        raise RuntimeError(f"Serper HTTP {response.status}: {payload}")
                    items = payload.get("organic") or []
            else:
                params = {
                    "engine": "google",
                    "api_key": self.provider.api_key,
                    "q": query,
                    "num": min(limit, 100),
                }
                async with session.get("https://serpapi.com/search.json", params=params) as response:
                    payload = await response.json(content_type=None)
                    if response.status != 200:
                        raise RuntimeError(f"SerpAPI HTTP {response.status}: {payload}")
                    items = payload.get("organic_results") or []
        return [item for item in items if isinstance(item, dict)][:limit]

    async def probe_url(self, session: aiohttp.ClientSession, url: str) -> int | None:
        try:
            async with session.get(
                url,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 recon-search-intelligence/1.0"},
            ) as response:
                await response.content.read(8192)
                return response.status
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    async def ingest_endpoint(
        self,
        conn: asyncpg.Connection,
        domain_id: int,
        root_domain: str,
        url: str,
        status_code: int | None,
        category: str,
    ) -> int | None:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not is_in_scope(hostname, root_domain):
            return None
        subdomain_id = await conn.fetchval(
            """
            INSERT INTO subdomains (domain_id, subdomain, is_resolved)
            VALUES ($1, $2, FALSE)
            ON CONFLICT (domain_id, subdomain)
            DO UPDATE SET last_seen = NOW()
            RETURNING id
            """,
            domain_id,
            hostname,
        )
        await conn.execute(
            """
            INSERT INTO subdomain_sources (subdomain_id, source, metadata)
            VALUES ($1, 'google_dork', jsonb_build_object('category', $2::text))
            ON CONFLICT (subdomain_id, source)
            DO UPDATE SET last_seen = NOW(),
                          metadata = subdomain_sources.metadata || EXCLUDED.metadata
            """,
            subdomain_id,
            category,
        )
        if status_code is None:
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        origin = f"{parsed.scheme}://{hostname}"
        if parsed.port and parsed.port not in {80, 443}:
            origin = f"{origin}:{parsed.port}"
        live_host_id = await conn.fetchval(
            """
            INSERT INTO live_hosts (
                subdomain_id, url, port, protocol, status_code
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (url)
            DO UPDATE SET status_code = EXCLUDED.status_code, last_seen = NOW()
            RETURNING id
            """,
            subdomain_id,
            origin,
            port,
            parsed.scheme,
            status_code,
        )
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        path_hash = hashlib.sha256(path.encode()).hexdigest()
        risk_tags = CATEGORY_RISK_TAGS.get(category, [])
        endpoint_id = await conn.fetchval(
            """
            INSERT INTO endpoints (
                live_host_id, path, path_hash, method, status_code,
                probed_at, parameters, risk_tags, source
            )
            VALUES ($1, $2, $3, 'GET', $4, NOW(), $5::jsonb, $6, 'google_dork')
            ON CONFLICT (live_host_id, path_hash, method, source)
            DO UPDATE SET status_code = EXCLUDED.status_code,
                          probed_at = NOW(),
                          last_seen = NOW(),
                          risk_tags = ARRAY(
                            SELECT DISTINCT tag
                            FROM unnest(endpoints.risk_tags || EXCLUDED.risk_tags) AS tag
                          )
            RETURNING id
            """,
            live_host_id,
            path,
            path_hash,
            status_code,
            json.dumps(
                [
                    {"name": name, "example_value": value}
                    for name, value in parse_qsl(parsed.query, keep_blank_values=True)
                ]
            ),
            risk_tags,
        )
        return int(endpoint_id)

    async def run_job(self, job: dict[str, Any]) -> dict[str, Any]:
        if not self.provider:
            raise RuntimeError("no search provider credentials configured")
        templates = QUERY_TEMPLATES[: max(1, int(self.config.get("max_queries_per_domain", 12)))]
        per_query = max(1, int(self.config.get("max_results_per_query", 20)))
        verify_limit = max(0, int(self.config.get("max_url_probes_per_run", 50)))
        request_interval = max(0.5, float(self.config.get("request_interval_seconds", 1.2)))
        async with self.pool.acquire() as conn:
            run_id = await conn.fetchval(
                """
                INSERT INTO search_intel_runs (domain_id, provider, query_count)
                VALUES ($1, $2, $3)
                RETURNING id
                """,
                job["domain_id"],
                self.provider.name,
                len(templates),
            )

        collected: list[dict[str, Any]] = []
        for index, (category, template) in enumerate(templates):
            query = template.format(domain=job["domain"])
            items = await self.search(query, per_query)
            for rank, item in enumerate(items, start=1):
                url = canonical_url(item.get("link") or item.get("url"))
                if not url:
                    continue
                collected.append(
                    {
                        "category": category,
                        "query": query,
                        "rank": int(item.get("position") or rank),
                        "url": url,
                        "title": item.get("title"),
                        "snippet": item.get("snippet"),
                        "display_link": item.get("displayLink") or item.get("displayed_link"),
                        "raw": item,
                    }
                )
            if index + 1 < len(templates):
                await asyncio.sleep(request_interval)

        unique_urls = list(dict.fromkeys(item["url"] for item in collected))
        statuses: dict[str, int | None] = {}
        in_scope_urls = [
            url
            for url in unique_urls
            if is_in_scope(urlsplit(url).hostname or "", job["domain"])
        ][:verify_limit]
        timeout = aiohttp.ClientTimeout(total=max(5, int(self.config.get("url_probe_timeout_seconds", 10))))
        connector = aiohttp.TCPConnector(limit=max(1, int(self.config.get("url_probe_concurrency", 3))))
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            values = await asyncio.gather(*(self.probe_url(session, url) for url in in_scope_urls))
        statuses.update(zip(in_scope_urls, values))

        new_count = 0
        in_scope_count = 0
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                for item in collected:
                    parsed = urlsplit(item["url"])
                    hostname = (parsed.hostname or "").lower().rstrip(".")
                    scoped = is_in_scope(hostname, job["domain"])
                    in_scope_count += int(scoped)
                    query_hash = hashlib.sha256(item["query"].encode()).hexdigest()
                    url_hash = hashlib.sha256(item["url"].encode()).hexdigest()
                    endpoint_id = await self.ingest_endpoint(
                        conn,
                        int(job["domain_id"]),
                        job["domain"],
                        item["url"],
                        statuses.get(item["url"]),
                        item["category"],
                    )
                    row = await conn.fetchrow(
                        """
                        INSERT INTO search_intel_results (
                            domain_id, first_run_id, last_run_id, endpoint_id,
                            provider, category, query, query_hash, url, url_hash,
                            hostname, title, snippet, display_link, is_in_scope,
                            status_code, risk_tags, raw_result
                        )
                        VALUES (
                            $1, $2, $2, $3, $4, $5, $6, $7, $8, $9,
                            $10, $11, $12, $13, $14, $15, $16, $17::jsonb
                        )
                        ON CONFLICT (domain_id, query_hash, url_hash)
                        DO UPDATE SET
                            last_run_id = EXCLUDED.last_run_id,
                            endpoint_id = COALESCE(EXCLUDED.endpoint_id, search_intel_results.endpoint_id),
                            title = EXCLUDED.title,
                            snippet = EXCLUDED.snippet,
                            display_link = EXCLUDED.display_link,
                            is_in_scope = EXCLUDED.is_in_scope,
                            status_code = COALESCE(EXCLUDED.status_code, search_intel_results.status_code),
                            raw_result = EXCLUDED.raw_result,
                            last_seen = NOW()
                        RETURNING id, (xmax = 0) AS inserted
                        """,
                        job["domain_id"],
                        run_id,
                        endpoint_id,
                        self.provider.name,
                        item["category"],
                        item["query"],
                        query_hash,
                        item["url"],
                        url_hash,
                        hostname,
                        item["title"],
                        item["snippet"],
                        item["display_link"],
                        scoped,
                        statuses.get(item["url"]),
                        CATEGORY_RISK_TAGS.get(item["category"], []),
                        json.dumps(item["raw"], default=str),
                    )
                    new_count += int(row["inserted"])
                    await conn.execute(
                        """
                        INSERT INTO search_intel_run_results (run_id, result_id, rank)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (run_id, result_id)
                        DO UPDATE SET rank = LEAST(search_intel_run_results.rank, EXCLUDED.rank)
                        """,
                        run_id,
                        row["id"],
                        item["rank"],
                    )
                summary = {
                    "provider": self.provider.name,
                    "queries": len(templates),
                    "results": len(collected),
                    "unique_urls": len(unique_urls),
                    "new_results": new_count,
                    "in_scope_results": in_scope_count,
                    "probed_urls": len(in_scope_urls),
                }
                await conn.execute(
                    """
                    UPDATE search_intel_runs
                    SET status = 'completed',
                        result_count = $2,
                        new_result_count = $3,
                        in_scope_count = $4,
                        completed_at = NOW(),
                        summary = $5::jsonb
                    WHERE id = $1
                    """,
                    run_id,
                    len(collected),
                    new_count,
                    in_scope_count,
                    json.dumps(summary),
                )
        return summary

    async def finish_job(self, job: dict[str, Any], result: dict[str, Any] | None, error: Exception | None) -> None:
        async with self.pool.acquire() as conn:
            if error is None:
                await conn.execute(
                    """
                    UPDATE search_intel_jobs
                    SET status = 'completed',
                        completed_at = NOW(),
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        error = NULL,
                        result_summary = $2::jsonb,
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    job["id"],
                    json.dumps(result or {}),
                )
                return
            await conn.execute(
                """
                UPDATE search_intel_jobs
                SET status = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
                    available_at = CASE
                      WHEN attempts < max_attempts THEN NOW() + INTERVAL '30 minutes'
                      ELSE available_at
                    END,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    error = $2,
                    updated_at = NOW()
                WHERE id = $1
                """,
                job["id"],
                repr(error)[:2000],
            )

    async def run_once(self, worker_id: str) -> bool:
        job = await self.claim_job(worker_id)
        if not job:
            return False
        try:
            result = await self.run_job(job)
        except Exception as exc:
            logger.exception("Search intelligence job %s failed: %s", job["id"], exc)
            async with self.pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE search_intel_runs
                    SET status = 'failed',
                        completed_at = NOW(),
                        error = $2
                    WHERE id = (
                      SELECT id
                      FROM search_intel_runs
                      WHERE domain_id = $1 AND status = 'running'
                      ORDER BY started_at DESC
                      LIMIT 1
                    )
                    """,
                    job["domain_id"],
                    repr(exc)[:2000],
                )
            await self.finish_job(job, None, exc)
        else:
            await self.finish_job(job, result, None)
            logger.info("Completed search intelligence for %s: %s", job["domain"], result)
        return True
