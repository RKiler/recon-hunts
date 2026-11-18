#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import logging
import os
import socket

import asyncpg

from continuous_recon import load_config
from search_intelligence import SearchIntelligence


logger = logging.getLogger("recon-search-intel-worker")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    app_config = load_config()
    config = app_config.data.get("search_intelligence", {})
    if not config.get("enabled", False):
        logger.warning("Search intelligence worker disabled in configuration")
        return
    pool = await asyncpg.create_pool(
        host=app_config.database["host"],
        port=app_config.database["port"],
        database=app_config.database["name"],
        user=app_config.database["user"],
        password=app_config.database["password"],
        min_size=1,
        max_size=3,
    )
    intelligence = SearchIntelligence(pool, config)
    await intelligence.ensure_schema()
    if not intelligence.provider:
        logger.warning(
            "No search provider credentials configured; set GOOGLE_CSE_API_KEY and "
            "GOOGLE_CSE_ENGINE_ID, SERPER_API_KEY, or SERPAPI_API_KEY"
        )
    worker_id = f"{os.getenv('HOSTNAME') or socket.gethostname()}:1"
    idle = max(10.0, float(config.get("worker_idle_seconds", 60)))
    seed_interval = max(300.0, float(config.get("seed_interval_seconds", 3600)))
    last_seed = 0.0
    loop = asyncio.get_running_loop()
    while True:
        now = loop.time()
        if intelligence.provider and now - last_seed >= seed_interval:
            logger.info("Search intelligence queue seed: %s", await intelligence.seed_jobs())
            last_seed = now
        claimed = await intelligence.run_once(worker_id) if intelligence.provider else False
        await asyncio.sleep(1.0 if claimed else idle)


if __name__ == "__main__":
    asyncio.run(main())
