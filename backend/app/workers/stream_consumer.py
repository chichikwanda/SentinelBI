"""Stream consumer worker (skeleton: heartbeat only; real consumer lands in the vertical slice)."""

from __future__ import annotations

import asyncio
import logging

from app.core.config import get_settings
from app.core.heartbeat import beat
from app.core.logging import configure_logging

log = logging.getLogger("worker")


async def main() -> None:
    configure_logging(get_settings().log_level)
    log.info("worker started")
    while True:
        beat()
        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
