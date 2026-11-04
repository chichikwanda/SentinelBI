"""Serves the sensor script (public: it is code, not data, and contains no secrets)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response, status

from app.core.config import get_settings
from app.core.deps import SessionDep, SourceDep
from app.core.enums import SourceMethod
from app.schemas.common import host_form
from app.schemas.inventory import DiscoveryAccepted, DiscoveryReport, SensorPolicy
from app.schemas.sources import MAX_EXTRA_CIDRS, SensorAddresses, SourceAddresses
from app.services.ingestion.sensor_script import load_sensor_script
from app.services.inventory import quarantined_targets, record_discovered

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


DISCOVER_INTERVAL_SECONDS = 300


@router.get("/policy", response_model=SensorPolicy)
async def policy(source: SourceDep, session: SessionDep) -> SensorPolicy:
    """What this sensor should do. A source registered as a network (not one host) is discovered:
    the sensor finds every device on it. The quarantine list is shown so it can be logged."""
    net = ipaddress.ip_network(str(source.cidr), strict=False)
    return SensorPolicy(
        cidr=host_form(str(net)),
        discover=net.num_addresses > 1,
        discover_interval_seconds=DISCOVER_INTERVAL_SECONDS,
        learning_until=source.baseline_until,
        quarantined=await quarantined_targets(session, source.id),
    )


@router.put("/devices", response_model=DiscoveryAccepted)
async def report_devices(
    body: DiscoveryReport, source: SourceDep, session: SessionDep
) -> DiscoveryAccepted:
    """A sensor reports the devices it found on its network (address, MAC, name). Only addresses
    inside the registered network are kept."""
    if source.method != SourceMethod.SENSOR.value:
        raise HTTPException(status.HTTP_409_CONFLICT, "only a sensor source can report devices")
    stored = await record_discovered(
        session,
        source,
        [(d.ip, d.mac, d.hostname) for d in body.devices],
        settings=get_settings(),
    )
    await session.commit()
    return DiscoveryAccepted(stored=stored)


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


@router.get("/install-service.ps1")
async def installer_script() -> Response:
    """The Windows installer that runs the sensor in the background (kept next to the sensor)."""
    script = load_sensor_script(
        str(Path(get_settings().sensor_script_path).with_name("install-service.ps1"))
    )
    if script is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "the installer is not available here")
    return Response(
        content=script.content,
        media_type="text/plain",
        headers={
            "Content-Disposition": 'attachment; filename="install-service.ps1"',
            "X-Content-SHA256": script.sha256,
        },
    )
