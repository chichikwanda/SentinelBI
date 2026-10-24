"""File heartbeat so container health checks can tell a stuck worker from a live one.

The worker touches the file on every loop iteration; the Docker health check passes only
if the file was modified recently (see ``check``; used by compose healthchecks).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

DEFAULT_PATH = "/tmp/healthy"  # noqa: S108 - container-local marker file


def beat(path: str = DEFAULT_PATH) -> None:
    Path(path).touch()


def check(path: str = DEFAULT_PATH, max_age_s: float = 30.0) -> int:
    try:
        age = time.time() - os.path.getmtime(path)
    except OSError:
        return 1
    return 0 if age <= max_age_s else 1


if __name__ == "__main__":
    sys.exit(check(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH))
