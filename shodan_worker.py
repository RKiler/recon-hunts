#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import logging
import os
import socket

from continuous_recon import ContinuousReconFramework, load_config


logger = logging.getLogger("recon-shodan-worker")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config()
    framework = ContinuousReconFramework(config)
    await framework.init()
    if not config.shodan.get("enabled", False):
        logger.warning("Shodan worker disabled in configuration")
        return
    if not config.shodan.get("api_key"):
        logger.error("SHODAN_API_KEY is not configured")
        return
    await framework.seed_shodan_jobs()

    worker_id = f"{os.getenv('HOSTNAME') or socket.gethostname()}:1"
    idle_sleep = max(2.0, float(config.shodan.get("worker_idle_seconds", 10)))
    request_interval = max(1.0, float(config.shodan.get("request_interval_seconds", 1.05)))
    logger.info(
        "Shodan worker started request_interval=%.2fs idle_sleep=%.2fs",
        request_interval,
        idle_sleep,
    )
    while True:
        try:
            claimed = await framework.run_shodan_worker_once(worker_id)
        except Exception as exc:
            logger.exception("Shodan worker cycle failed: %s", exc)
            claimed = False
        await asyncio.sleep(request_interval if claimed else idle_sleep)


if __name__ == "__main__":
    asyncio.run(main())
