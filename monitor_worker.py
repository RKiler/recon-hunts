#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import logging
import os

from continuous_recon import ContinuousReconFramework, load_config


logger = logging.getLogger("recon-monitor-worker")


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config()
    framework = ContinuousReconFramework(config)
    await framework.init()
    sleep_seconds = max(15, int(os.getenv("RECON_MONITOR_WORKER_SLEEP", config.scan.get("idle_sleep_seconds", 60))))
    logger.info("Monitor worker started; polling every %ss", sleep_seconds)
    while True:
        try:
            await framework.run_due_monitors()
        except Exception as exc:
            logger.exception("Monitor worker cycle failed: %s", exc)
        await asyncio.sleep(sleep_seconds)


if __name__ == "__main__":
    asyncio.run(main())
