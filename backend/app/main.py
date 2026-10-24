"""FastAPI application entrypoint."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.redis import get_redis
from app.db.session import get_engine


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(title="SentinelBI API", version="0.1.0")

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        """Liveness: the process is up."""
        return {"status": "ok"}

    @app.get("/health/ready", tags=["health"])
    async def ready() -> dict[str, str]:
        """Readiness: Postgres and Redis are reachable."""
        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            await get_redis().ping()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="dependency unavailable") from exc
        return {"status": "ready"}

    return app


app = create_app()
