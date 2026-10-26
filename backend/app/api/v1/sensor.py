"""Serves the sensor script (public: it is code, not data, and contains no secrets)."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, HTTPException, Response, status

from app.core.config import get_settings
from app.core.deps import SessionDep, SourceDep
from app.core.enums import SourceMethod
from app.schemas.common import host_form
from app.schemas.sources import MAX_EXTRA_CIDRS, SensorAddresses, SourceAddresses
from app.services.ingestion.sensor_script import load_sensor_script

router = APIRouter(prefix="/sensor", tags=["sensor"])


@router.put("/addresses", response_model=SourceAddresses)
async def announce_addresses(
    body: SensorAddresses, source: SourceDep, session: SessionDep
) -> SourceAddresses:
    """A sensor reports the other addresses of its machine, so the traffic views count them as
    the same monitored host. Authenticated with the source's API key, limited to that source."""
    if source.method != SourceMethod.SENSOR.value:
        raise HTTPException(status.HTTP_409_CONFLICT, "only a sensor source can announce addresses")
    own = ipaddress.ip_network(str(source.cidr))  # the driver may hand back network objects
    known = [str(ipaddress.ip_network(str(c))) for c in source.extra_cidrs]
    for text in body.addresses:
        ip = ipaddress.ip_address(text)
        net = str(ipaddress.ip_network(ip))
        if (ip.version == own.version and ip in own) or net in known:
            continue  # already covered
        known.append(net)
    source.extra_cidrs = known[-MAX_EXTRA_CIDRS:]  # the newest are kept
    await session.commit()
    return SourceAddresses(
        cidr=host_form(str(own)), addresses=[host_form(c) for c in source.extra_cidrs]
    )


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
