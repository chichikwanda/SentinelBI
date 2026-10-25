"""The sensor script that users download from their own SentinelBI server.

It is a single standard-library Python file kept in ``sensor/`` and mounted read-only into the
API container, so the server always hands out the version it was deployed with, and shows its
SHA-256 so the download can be checked.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SensorScript:
    content: bytes
    sha256: str


_cache: dict[str, tuple[tuple[int, int], SensorScript]] = {}


def load_sensor_script(path: str) -> SensorScript | None:
    """The script's bytes and hash, or None when it is not available on this server."""
    file = Path(path)
    try:
        stat = file.stat()
    except OSError:
        return None
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _cache.get(path)
    if cached and cached[0] == stamp:
        return cached[1]
    try:
        content = file.read_bytes()
    except OSError:
        return None
    script = SensorScript(content, hashlib.sha256(content).hexdigest())
    _cache[path] = (stamp, script)
    return script
