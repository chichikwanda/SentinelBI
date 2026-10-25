"""Serves the sensor script (public: it is code, not data, and contains no secrets)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from app.core.config import get_settings
from app.services.ingestion.sensor_script import load_sensor_script

router = APIRouter(prefix="/sensor", tags=["sensor"])


@router.get("/sentinelbi_sensor.py")
async def sensor_script() -> Response:
    script = load_sensor_script(get_settings().sensor_script_path)
    if script is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "the sensor script is not available here")
    return Response(
        content=script.content,
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="sentinelbi_sensor.py"',
            "X-Content-SHA256": script.sha256,
        },
    )
