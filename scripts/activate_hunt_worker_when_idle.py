#!/usr/bin/env python3
"""Recreate the worker only after its daily budget has drained active jobs."""

import json
import subprocess
import time
from pathlib import Path


STATE = Path("/root/codex_artifacts/bug-jobs/results/.worker_state.json")
WORKDIR = "/root/enhanced_recon_framework"


def ready_to_restart(state: dict) -> bool:
    return state.get("status") == "paused" and state.get("pause_reason") == "daily_budget" and not state.get("active_jobs")


def main() -> int:
    deadline = time.monotonic() + 36 * 3600
    while time.monotonic() < deadline:
        try:
            state = json.loads(STATE.read_text(encoding="utf-8"))
            if ready_to_restart(state):
                subprocess.run(["docker", "compose", "--profile", "codex", "restart", "bug-job-worker"],
                               cwd=WORKDIR, check=True, timeout=90)
                return 0
        except (OSError, json.JSONDecodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        time.sleep(15)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
