"""NetFlow collector (skeleton: heartbeat only; real listener lands in the vertical slice)."""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

log = logging.getLogger("collector")


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    log.info("collector started")
    while True:
        await asyncio.to_thread(Path("/tmp/healthy").touch)  # noqa: S108
        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
