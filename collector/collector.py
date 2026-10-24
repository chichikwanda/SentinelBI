"""NetFlow v5/v9/IPFIX collector.

UDP listener -> exporter allow-list (unknown/ambiguous exporters are dropped and logged BEFORE
any parsing) -> parse -> normalise -> Redis Stream ``flows.raw`` (same message shape as the
HTTP ingest API, so the worker handles both identically).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import netflow
import redis.asyncio as aioredis

from allowlist import ExporterAllowlist, load_sources
from normalize import normalize_packet

log = logging.getLogger("collector")

STREAM = os.environ.get("STREAM_FLOWS", "flows.raw")
STREAM_MAXLEN = int(os.environ.get("STREAM_MAXLEN", "500000"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "2055"))
QUEUE_SIZE = int(os.environ.get("QUEUE_SIZE", "10000"))
REFRESH_S = float(os.environ.get("ALLOWLIST_REFRESH_S", "30"))
HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/tmp/healthy")  # noqa: S108
UNKNOWN_LOG_EVERY_S = 60.0


class Stats:
    def __init__(self) -> None:
        self.received = self.dropped_unknown = self.dropped_queue_full = 0
        self.parse_errors = self.flows_out = self.redis_errors = 0


class Collector(asyncio.DatagramProtocol):
    def __init__(self, allowlist: ExporterAllowlist, redis: aioredis.Redis | None) -> None:
        self.allowlist = allowlist
        self.redis = redis
        self.queue: asyncio.Queue[tuple[bytes, str]] = asyncio.Queue(maxsize=QUEUE_SIZE)
        self.stats = Stats()
        self.last_progress = time.monotonic()
        self._templates: dict[str, dict[str, dict[Any, Any]]] = defaultdict(
            lambda: {"netflow": {}, "ipfix": {}}
        )
        self._last_unknown_log: dict[str, float] = {}

    # --- asyncio protocol (must never block) ---------------------------------------------
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        sock = transport.get_extra_info("socket")
        if sock is not None:  # absorb bursts: the kernel buffer is our first queue
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.stats.received += 1
        try:
            self.queue.put_nowait((data, addr[0]))
        except asyncio.QueueFull:
            self.stats.dropped_queue_full += 1

    # --- processing --------------------------------------------------------------------------
    def _log_unknown(self, exporter: str, reason: str) -> None:
        now = time.monotonic()
        if now - self._last_unknown_log.get(exporter, -UNKNOWN_LOG_EVERY_S) >= UNKNOWN_LOG_EVERY_S:
            self._last_unknown_log[exporter] = now
            log.warning("dropping NetFlow from %s exporter %s", reason, exporter)

    async def handle(self, data: bytes, exporter_ip: str) -> int:
        """Process one datagram; return the number of flows pushed to the stream."""
        resolution = self.allowlist.resolve(exporter_ip)
        if resolution.source is None:  # drop BEFORE parsing untrusted input
            self.stats.dropped_unknown += 1
            self._log_unknown(exporter_ip, resolution.reason)
            return 0
        try:
            packet = netflow.parse_packet(data, self._templates[exporter_ip])
            records = normalize_packet(packet)
        except Exception as exc:  # incl. templates not yet seen: they arrive periodically
            self.stats.parse_errors += 1
            log.debug("unparseable packet from %s: %s", exporter_ip, type(exc).__name__)
            return 0
        if not records or self.redis is None:
            return 0
        source = resolution.source
        try:
            pipe = self.redis.pipeline(transaction=False)
            for rec in records:
                pipe.xadd(
                    STREAM,
                    {"org": source.org_id, "src": source.source_id, "data": json.dumps(rec)},
                    maxlen=STREAM_MAXLEN,
                    approximate=True,
                )
            await pipe.execute()
        except Exception:
            self.stats.redis_errors += 1
            log.exception("could not queue %d flows", len(records))
            return 0
        self.stats.flows_out += len(records)
        return len(records)

    async def run_consumer(self) -> None:
        while True:
            self.last_progress = time.monotonic()
            try:
                data, exporter = await asyncio.wait_for(self.queue.get(), timeout=5)
            except TimeoutError:
                continue  # idle tick keeps the heartbeat alive
            await self.handle(data, exporter)


async def refresh_allowlist(allowlist: ExporterAllowlist, dsn: str) -> None:
    while True:
        try:
            sources = await asyncio.to_thread(load_sources, dsn)
            if len(sources) != len(allowlist):
                log.info("exporter allow-list: %d netflow source(s)", len(sources))
            allowlist.replace(sources)
        except Exception:
            log.exception("allow-list refresh failed; keeping the previous list")
        await asyncio.sleep(REFRESH_S)


async def heartbeat(collector: Collector) -> None:
    while True:
        if time.monotonic() - collector.last_progress < 20:
            await asyncio.to_thread(Path(HEARTBEAT_FILE).touch)
        await asyncio.sleep(5)


async def report(collector: Collector) -> None:
    while True:
        await asyncio.sleep(60)
        s = collector.stats
        log.info(
            "recv=%d flows=%d dropped_unknown=%d queue_full=%d parse_err=%d redis_err=%d",
            s.received,
            s.flows_out,
            s.dropped_unknown,
            s.dropped_queue_full,
            s.parse_errors,
            s.redis_errors,
        )


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    allowlist = ExporterAllowlist()
    redis = aioredis.Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)
    collector = Collector(allowlist, redis)
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: collector, local_addr=("0.0.0.0", LISTEN_PORT))  # noqa: S104
    log.info("collector listening on udp/%d", LISTEN_PORT)
    await asyncio.gather(
        refresh_allowlist(allowlist, os.environ["DATABASE_URL"]),
        collector.run_consumer(),
        heartbeat(collector),
        report(collector),
    )


if __name__ == "__main__":
    asyncio.run(main())
