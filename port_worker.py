#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import logging
import os
import socket

from continuous_recon import ContinuousReconFramework, load_config


logger = logging.getLogger("recon-port-worker")


async def worker_loop(framework: ContinuousReconFramework, worker_id: str, idle_sleep: float) -> None:
    while True:
        try:
            claimed = await framework.run_port_worker_once(worker_id)
        except Exception as exc:
            logger.exception("Port worker %s cycle failed: %s", worker_id, exc)
            claimed = False
        if not claimed:
            await asyncio.sleep(idle_sleep)


async def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = load_config()
    framework = ContinuousReconFramework(config)
    await framework.init()
    concurrency = max(1, int(config.scan.get("port_scan_workers", 5)))
    idle_sleep = max(2.0, float(config.scan.get("port_scan_worker_idle_seconds", 10)))
    instance = os.getenv("HOSTNAME") or socket.gethostname()
    logger.info(
        "Port worker started with concurrency=%s per_ip_timeout=%ss",
        concurrency,
        config.scan.get("port_scan_per_ip_timeout_seconds", 480),
    )
    await asyncio.gather(
        *(
            worker_loop(framework, f"{instance}:{index}", idle_sleep)
            for index in range(1, concurrency + 1)
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
