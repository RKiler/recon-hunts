#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read matching callback evidence from Interaction Hub")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--wait-seconds", type=int, default=0)
    parser.add_argument("--limit", type=int, default=25)
    return parser.parse_args()


def query(db_path: Path, marker: str, limit: int) -> list[dict[str, object]]:
    uri = f"file:{db_path}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT i.id, i.received_at, i.kind, i.method, i.path,
                   i.query_string, i.source_ip, i.user_agent,
                   i.body_sha256, t.label, t.token
            FROM interactions i
            JOIN callback_tokens t ON t.id = i.token_id
            WHERE i.path LIKE ? OR i.query_string LIKE ? OR i.body_preview LIKE ?
            ORDER BY i.id DESC
            LIMIT ?
            """,
            (f"%{marker}%", f"%{marker}%", f"%{marker}%", max(1, min(limit, 100))),
        ).fetchall()
    results: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        token = str(item.pop("token", ""))
        if token:
            for key in ("path", "query_string", "user_agent"):
                item[key] = str(item.get(key, "")).replace(token, "[CALLBACK_TOKEN]")
        results.append(item)
    return results


def main() -> int:
    args = parse_args()
    marker = str(args.marker).strip()
    if not marker or len(marker) > 160:
        raise SystemExit("marker must be 1-160 characters")

    deadline = time.monotonic() + max(0, min(args.wait_seconds, 300))
    rows: list[dict[str, object]] = []
    while True:
        rows = query(args.db, marker, args.limit)
        if rows or time.monotonic() >= deadline:
            break
        time.sleep(2)

    print(json.dumps({"marker": marker, "count": len(rows), "interactions": rows}, indent=2))
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
