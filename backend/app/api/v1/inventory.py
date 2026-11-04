"""Devices on the monitored networks, the baseline of peer networks, and the quarantine queue."""

from __future__ import annotations

import ipaddress
import uuid
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Query, Response, status
from sqlalchemy import func, select

from app.core.deps import AdminDep, AnalystDep, PrincipalDep, SessionDep
from app.db.models import Device, PeerNetwork
from app.schemas.inventory import (
    Decision,
    DeviceOut,
    InventorySummary,
    NetworkOut,
    QuarantineItem,
)
from app.services.inventory import block_commands, decide

router = APIRouter(prefix="/inventory", tags=["inventory"])

DeviceState = Annotated[str | None, Query(pattern="^(known|new|trusted|quarantined)$")]
NetworkState = Annotated[str | None, Query(pattern="^(baseline|new|approved|quarantined)$")]


@router.get("/summary", response_model=InventorySummary)
async def summary(principal: PrincipalDep, session: SessionDep) -> InventorySummary:
    async def counts(table: type[Device] | type[PeerNetwork]) -> dict[str, int]:
        rows = await session.execute(
            select(table.state, func.count())
            .where(table.org_id == principal.org_id)
            .group_by(table.state)
        )
        return {str(state): int(n) for state, n in rows.all()}

    d, n = await counts(Device), await counts(PeerNetwork)
    return InventorySummary(
        devices_total=sum(d.values()),
        devices_new=d.get("new", 0),
        devices_quarantined=d.get("quarantined", 0),
        networks_total=sum(n.values()),
        networks_new=n.get("new", 0),
        networks_quarantined=n.get("quarantined", 0),
    )


@router.get("/devices", response_model=list[DeviceOut])
async def list_devices(
    principal: PrincipalDep,
    session: SessionDep,
    state: DeviceState = None,
    source_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Device]:
    q = select(Device).where(Device.org_id == principal.org_id)
    if state:
        q = q.where(Device.state == state)
    if source_id:
        q = q.where(Device.source_id == source_id)
    rows = await session.execute(
        q.order_by(Device.last_seen.desc(), Device.id).limit(limit).offset(offset)
    )
    return list(rows.scalars())


@router.get("/networks", response_model=list[NetworkOut])
async def list_networks(
    principal: PrincipalDep,
    session: SessionDep,
    state: NetworkState = None,
    source_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[PeerNetwork]:
    q = select(PeerNetwork).where(PeerNetwork.org_id == principal.org_id)
    if state:
        q = q.where(PeerNetwork.state == state)
    if source_id:
        q = q.where(PeerNetwork.source_id == source_id)
    rows = await session.execute(
        q.order_by(PeerNetwork.last_seen.desc(), PeerNetwork.id).limit(limit).offset(offset)
    )
    return list(rows.scalars())


async def _scoped(
    session: SessionDep,
    table: type[Device] | type[PeerNetwork],
    org_id: uuid.UUID,
    row_id: uuid.UUID,
) -> Device | PeerNetwork:
    row = cast(
        "Device | PeerNetwork | None",
        (
            await session.execute(select(table).where(table.id == row_id, table.org_id == org_id))
        ).scalar_one_or_none(),
    )
    if row is None:  # 404, not 403: do not reveal that another tenant's id exists
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return row


@router.post("/devices/{device_id}/decision", response_model=DeviceOut)
async def decide_device(
    device_id: uuid.UUID, body: Decision, analyst: AnalystDep, session: SessionDep
) -> Device:
    row = await _scoped(session, Device, analyst.org_id, device_id)
    await decide(session, row, body.action, by=analyst.email, note=body.note)
    await session.commit()
    assert isinstance(row, Device)  # noqa: S101 - _scoped returned the table asked for
    return row


@router.post("/networks/{network_id}/decision", response_model=NetworkOut)
async def decide_network(
    network_id: uuid.UUID, body: Decision, analyst: AnalystDep, session: SessionDep
) -> PeerNetwork:
    row = await _scoped(session, PeerNetwork, analyst.org_id, network_id)
    await decide(session, row, body.action, by=analyst.email, note=body.note)
    await session.commit()
    assert isinstance(row, PeerNetwork)  # noqa: S101
    return row


async def _forget(
    session: SessionDep,
    table: type[Device] | type[PeerNetwork],
    org_id: uuid.UUID,
    row_id: uuid.UUID,
) -> Response:
    row = await _scoped(session, table, org_id, row_id)
    if row.state == "quarantined":
        raise HTTPException(status.HTTP_409_CONFLICT, "Release it first: it is held in quarantine")
    await session.delete(row)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def forget_device(device_id: uuid.UUID, admin: AdminDep, session: SessionDep) -> Response:
    """Remove a device that is gone from the list. If it appears again it is listed again (as
    new, once the baseline is over)."""
    return await _forget(session, Device, admin.org_id, device_id)


@router.delete("/networks/{network_id}", status_code=status.HTTP_204_NO_CONTENT)
async def forget_network(network_id: uuid.UUID, admin: AdminDep, session: SessionDep) -> Response:
    return await _forget(session, PeerNetwork, admin.org_id, network_id)


@router.get("/quarantine", response_model=list[QuarantineItem])
async def quarantine_queue(principal: PrincipalDep, session: SessionDep) -> list[QuarantineItem]:
    """Everything held for a decision, with the commands a person may run to block it."""
    items: list[QuarantineItem] = []
    devices = await session.execute(
        select(Device).where(Device.org_id == principal.org_id, Device.state == "quarantined")
    )
    for d in devices.scalars():
        target = str(ipaddress.ip_address(str(d.ip)))
        items.append(
            QuarantineItem(
                kind="device",
                id=d.id,
                source_id=d.source_id,
                target=target,
                flagged_ips=[target],
                reason=d.state_reason,
                since=d.state_changed_at,
                alert_id=d.alert_id,
                commands=block_commands(target),
            )
        )
    nets = await session.execute(
        select(PeerNetwork).where(
            PeerNetwork.org_id == principal.org_id, PeerNetwork.state == "quarantined"
        )
    )
    for n in nets.scalars():
        flagged = [str(x) for x in n.flagged_ips]
        items.append(
            QuarantineItem(
                kind="network",
                id=n.id,
                source_id=n.source_id,
                target=str(n.network),
                flagged_ips=flagged,
                reason=n.state_reason,
                since=n.state_changed_at,
                alert_id=n.alert_id,
                commands=block_commands(str(n.network)),
            )
        )
    return sorted(items, key=lambda i: i.since, reverse=True)
