"""Model registry helpers: which model is active, registering exported artifacts, hot-swap.

python -m app.services.inference.registry register <version> [--activate]
python -m app.services.inference.registry list
python -m app.services.inference.registry sync  # register exported models found on disk
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import get_settings
from app.db.models import ModelRegistry
from app.db.session import get_engine, get_sessionmaker
from app.services.inference.artifact import ModelLoadError, load_artifact_predictor, read_card
from app.services.inference.placeholder import PLACEHOLDER_VERSION, PlaceholderPredictor
from app.services.inference.predictor import Predictor

log = logging.getLogger("inference.registry")


def build_predictor(version: str) -> Predictor:
    if version == PLACEHOLDER_VERSION:
        return PlaceholderPredictor()
    return load_artifact_predictor(version)


async def active_version(session: AsyncSession) -> str:
    row = (await session.execute(select(ModelRegistry.version).where(ModelRegistry.active))).first()
    return str(row[0]) if row else PLACEHOLDER_VERSION


async def register_from_card(
    session: AsyncSession, version: str, activate: bool = False
) -> ModelRegistry:
    card = read_card(version)
    existing = await session.get(ModelRegistry, version)
    metrics: dict[str, Any] = {
        "test": card["metrics"]["test"],
        "validation": card["metrics"]["validation_selection"],
        "latency_ms_per_500_flows": card.get("latency_ms_per_500_flows"),
        "classes": card["classes"],
        "limitations": card["limitations"],
        "training": card["training"],
        "artifact_sha256": card["artifact_sha256"],
    }
    if existing is None:
        existing = ModelRegistry(
            version=version,
            algo=card["algo"],
            metrics=metrics,
            features=card["features"],
            dataset=(
                f"{card['dataset']['name']} (csv sha256 {card['dataset']['csv_sha256'][:16]}...)"
            ),
            active=False,
        )
        session.add(existing)
        await session.flush()
    else:  # re-registering refreshes the stored card data (limitations, metrics) but not 'active'
        existing.metrics = metrics
        existing.features = card["features"]
    if activate:
        await set_active(session, version)
    await session.commit()
    return existing


def _discover_models() -> list[tuple[str, str]]:
    """(trained_at, version) for every loadable model directory (blocking file IO)."""
    root = Path(get_settings().models_dir)
    found: list[tuple[str, str]] = []
    if root.is_dir():
        for card_path in sorted(root.glob("*/model_card.json")):
            version = card_path.parent.name
            try:
                found.append((read_card(version).get("trained_at", ""), version))
            except ModelLoadError as exc:
                log.warning("skipping %s: %s", version, exc)
    return found


async def sync_models(session: AsyncSession) -> dict[str, Any]:
    """Register every exported model found on disk. If only the placeholder is active, activate
    the newest real model (an administrator's explicit choice is never overridden)."""
    found = await asyncio.to_thread(_discover_models)
    for _, version in found:
        await register_from_card(session, version, activate=False)
    activated = None
    if found and await active_version(session) == PLACEHOLDER_VERSION:
        activated = max(found)[1]
        await set_active(session, activated)
        await session.commit()
    return {"registered": sorted(v for _, v in found), "activated": activated}


async def set_active(session: AsyncSession, version: str) -> None:
    """Make ``version`` the single active model (the partial unique index allows only one)."""
    await session.execute(update(ModelRegistry).where(ModelRegistry.active).values(active=False))
    await session.execute(
        update(ModelRegistry).where(ModelRegistry.version == version).values(active=True)
    )


class PredictorHolder:
    """The worker's current predictor; swaps to the registry's active model when it changes."""

    def __init__(self, refresh_seconds: int) -> None:
        self.predictor: Predictor = PlaceholderPredictor()
        self._refresh_seconds = refresh_seconds
        self._last_check = 0.0

    async def refresh(
        self, sessionmaker: async_sessionmaker[AsyncSession], force: bool = False
    ) -> None:
        if not force and time.monotonic() - self._last_check < self._refresh_seconds:
            return
        self._last_check = time.monotonic()
        try:
            async with sessionmaker() as session:
                wanted = await active_version(session)
            if wanted == self.predictor.version:
                return
            self.predictor = await asyncio.to_thread(build_predictor, wanted)
            log.info("active model is now %s", wanted)
        except ModelLoadError:
            log.exception("cannot load the active model; keeping %s", self.predictor.version)
        except Exception:
            log.exception("model refresh failed; keeping %s", self.predictor.version)


async def _cli(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "register":
        async with get_sessionmaker()() as session:
            row = await register_from_card(session, argv[1], activate="--activate" in argv)
            print(f"registered {row.version} (active={row.active})")
        await get_engine().dispose()
        return 0
    if argv[:1] == ["sync"]:
        async with get_sessionmaker()() as session:
            print(await sync_models(session))
        await get_engine().dispose()
        return 0
    if argv[:1] == ["list"]:
        async with get_sessionmaker()() as session:
            for r in (
                await session.execute(select(ModelRegistry).order_by(ModelRegistry.created_at))
            ).scalars():
                print(f"{'*' if r.active else ' '} {r.version}  {r.algo}")
        await get_engine().dispose()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    sys.exit(asyncio.run(_cli(sys.argv[1:])))
