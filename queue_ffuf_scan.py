#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import asyncpg

from continuous_recon import load_config


WORDLISTS = {
    "baseline": "/app/wordlists/SecLists/Discovery/Web-Content/common.txt",
    "api": "/app/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
    "graphql": "/app/wordlists/SecLists/Discovery/Web-Content/graphql.txt",
    "admin": "/app/wordlists/SecLists/Discovery/Web-Content/quickhits.txt",
    "spring": "/app/wordlists/SecLists/Discovery/Web-Content/Programming-Language-Specific/Java-Spring-Boot.txt",
    "apache": "/app/wordlists/SecLists/Discovery/Web-Content/Web-Servers/Apache.txt",
    "nginx": "/app/wordlists/SecLists/Discovery/Web-Content/Web-Servers/nginx.txt",
    "wordpress": "/app/wordlists/SecLists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
    "kubernetes": "/app/wordlists/SecLists/Discovery/Web-Content/Service-Specific/Kubernetes.txt",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def profiles_for_host(host: dict[str, Any]) -> list[str]:
    hostname = (urlsplit(str(host["url"])).hostname or "").lower()
    text = " ".join(
        [
            hostname,
            str(host.get("title") or ""),
            str(host.get("webserver") or ""),
            " ".join(str(item) for item in host.get("technologies") or []),
        ]
    ).lower()
    profiles = ["baseline"]
    if re.search(r"(^|[-.])(api|webapi|graphql|gateway|proxy)([-.]|$)", hostname) or any(
        token in text for token in ("swagger", "openapi", "api docs", "backend")
    ):
        profiles.append("api")
    if "graphql" in text or "graphiql" in text:
        profiles.append("graphql")
    if any(
        token in text
        for token in (
            "admin",
            "backoffice",
            "dashboard",
            "portal",
            "control",
            "manage",
            "akhq",
            "vault",
            "unleash",
            "login",
        )
    ):
        profiles.append("admin")
    if any(token in text for token in ("spring", "java", "actuator")):
        profiles.append("spring")
    if "apache" in text:
        profiles.append("apache")
    if "nginx" in text:
        profiles.append("nginx")
    if any(token in text for token in ("wordpress", "wp.", "blogs.")):
        profiles.append("wordpress")
    if any(token in hostname for token in (".svc.", ".ctrl.", ".nmp.")):
        profiles.append("kubernetes")
    return list(dict.fromkeys(profiles))


async def queue(domain: str, scan_id: int | None, dry_run: bool) -> None:
    config = load_config()
    db = config.database
    conn = await asyncpg.connect(
        host=db["host"],
        port=db["port"],
        database=db["name"],
        user=db["user"],
        password=db["password"],
    )
    try:
        domain_row = await conn.fetchrow(
            "SELECT id, domain FROM domains WHERE lower(domain) = lower($1)",
            domain,
        )
        if not domain_row:
            raise RuntimeError(f"domain not found: {domain}")
        if scan_id is None:
            scan_id = await conn.fetchval(
                "SELECT id FROM scan_snapshots WHERE domain_id = $1 ORDER BY scan_finished_at DESC LIMIT 1",
                domain_row["id"],
            )
        scan = await conn.fetchrow(
            """
            SELECT id, scan_started_at, scan_finished_at
            FROM scan_snapshots
            WHERE id = $1 AND domain_id = $2
            """,
            scan_id,
            domain_row["id"],
        )
        if not scan:
            raise RuntimeError(f"scan {scan_id} not found for {domain}")
        rows = await conn.fetch(
            """
            SELECT lh.id AS live_host_id, lh.url, lh.status_code, lh.title, lh.webserver,
                   COALESCE(
                     ARRAY_AGG(DISTINCT t.technology)
                       FILTER (WHERE t.technology IS NOT NULL),
                     ARRAY[]::varchar[]
                   ) AS technologies
            FROM live_hosts lh
            JOIN subdomains s ON s.id = lh.subdomain_id
            LEFT JOIN technologies t ON t.live_host_id = lh.id
            WHERE s.domain_id = $1
              AND lh.last_seen BETWEEN $2 AND $3
            GROUP BY lh.id
            ORDER BY lh.url
            """,
            domain_row["id"],
            scan["scan_started_at"],
            scan["scan_finished_at"],
        )
        lane = f"batch_{domain.replace('.', '_')}_scan_{scan_id}"
        wordlist_paths = {profile: Path(path) for profile, path in WORDLISTS.items()}
        for wordlist in wordlist_paths.values():
            if not wordlist.is_file():
                raise FileNotFoundError(wordlist)
        wordlist_hashes = {
            profile: file_sha256(wordlist)
            for profile, wordlist in wordlist_paths.items()
        }

        profile_counts: dict[str, int] = {}
        jobs: list[tuple[int, str, dict[str, Any]]] = []
        profile_order = {
            "nginx": 10,
            "kubernetes": 20,
            "graphql": 30,
            "api": 40,
            "spring": 50,
            "wordpress": 60,
            "admin": 70,
            "apache": 80,
            "baseline": 90,
        }
        for row in rows:
            host = dict(row)
            for profile in profiles_for_host(host):
                profile_counts[profile] = profile_counts.get(profile, 0) + 1
                jobs.append((profile_order[profile], profile, host))
        jobs.sort(key=lambda item: (item[0], item[2]["url"]))

        queued = 0
        for _, profile, host in jobs:
            if dry_run:
                continue
            result = await conn.execute(
                """
                INSERT INTO ffuf_runs (
                  domain_id, live_host_id, host_url, scan_lane,
                  wordlist_path, wordlist_sha256, status, options
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7::jsonb)
                ON CONFLICT (live_host_id, scan_lane, wordlist_sha256)
                DO NOTHING
                """,
                domain_row["id"],
                host["live_host_id"],
                host["url"],
                lane,
                str(wordlist_paths[profile]),
                wordlist_hashes[profile],
                json.dumps(
                    {
                        "queue_worker": "ffuf",
                        "profile": profile,
                        "source_scan_id": scan_id,
                        "technology_aware": True,
                    }
                ),
            )
            if result.endswith(" 1"):
                queued += 1
        print(
            json.dumps(
                {
                    "domain": domain,
                    "scan_id": scan_id,
                    "hosts": len(rows),
                    "planned_runs": sum(profile_counts.values()),
                    "queued_runs": queued,
                    "profiles": profile_counts,
                    "dry_run": dry_run,
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        await conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("domain")
    parser.add_argument("--scan-id", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    asyncio.run(queue(args.domain, args.scan_id, args.dry_run))


if __name__ == "__main__":
    main()
