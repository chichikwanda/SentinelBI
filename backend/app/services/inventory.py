"""Devices on a registered network, the networks that talk to it, and the quarantine queue.

Three things feed it:

* the sensor's discovery (``record_discovered``): every device that answers on the network;
* the flows themselves (``observe_flows``): addresses and peer networks seen in traffic;
* alerts (``quarantine_for_alert``): a High or Critical alert flags the address it came from.

A source first *learns* (``Source.baseline_until``): everything seen then is ``known`` or
``baseline``. After that anything first seen is ``new`` and waits for a person. This module never
blocks anything on the network: quarantine means "flagged and held for a decision", and
``block_commands`` writes the commands a person may choose to run.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import and_, case, false, func, select, true
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.enums import DeviceState, NetworkState, Severity
from app.db.models import Alert, Device, PeerNetwork, Source
from app.services.privacy import pseudonymize_ip, pseudonymize_mac

_SEVERITY_RANK = {
    Severity.LOW.value: 0,
    Severity.MEDIUM.value: 1,
    Severity.HIGH.value: 2,
    Severity.CRITICAL.value: 3,
}
# where pseudonymised internal addresses land (see privacy.py)
_PSEUDONYM_RANGES = (ipaddress.ip_network("240.0.0.0/4"), ipaddress.ip_network("fd00::/8"))
# one discovery report is capped, so a misbehaving sensor cannot flood the table
MAX_DISCOVERED = 1024


@dataclass(frozen=True)
class SourceInfo:
    id: uuid.UUID
    org_id: uuid.UUID
    nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    baseline_until: datetime | None
    # flows store internal addresses as pseudonyms: those then count as inside the network
    pseudonymized: bool = False

    def contains(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if any(ip.version == n.version and ip in n for n in self.nets):
            return True
        return self.pseudonymized and any(
            ip.version == n.version and ip in n for n in _PSEUDONYM_RANGES
        )

    def learning(self, when: datetime) -> bool:
        return self.baseline_until is None or when < self.baseline_until


def source_info(source: Source, *, pseudonymized: bool = False) -> SourceInfo:
    nets = [ipaddress.ip_network(str(c), strict=False) for c in [source.cidr, *source.extra_cidrs]]
    return SourceInfo(source.id, source.org_id, tuple(nets), source.baseline_until, pseudonymized)


async def load_sources(
    session: AsyncSession, ids: Iterable[uuid.UUID], *, pseudonymized: bool = False
) -> dict[uuid.UUID, SourceInfo]:
    rows = await session.execute(select(Source).where(Source.id.in_(set(ids))))
    return {s.id: source_info(s, pseudonymized=pseudonymized) for s in rows.scalars()}


def _addr(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


def _is_ordinary(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local) and (
        ip != ipaddress.IPv4Address("255.255.255.255")
    )


def peer_network_of(text: str) -> str | None:
    """The network an address belongs to for baselining: a /24 (IPv4) or a /48 (IPv6)."""
    ip = _addr(text)
    if ip is None or not _is_ordinary(ip):
        return None
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


# ----------------------------------------------------------------------------------------------
# devices
# ----------------------------------------------------------------------------------------------
async def _upsert_device(
    session: AsyncSession,
    src: SourceInfo,
    ip: str,
    *,
    mac: str | None,
    hostname: str | None,
    when: datetime,
    now: datetime,
) -> None:
    learning = src.learning(now)
    state = DeviceState.KNOWN.value if learning else DeviceState.NEW.value
    reason = None if learning else "first seen after the baseline was learned"
    stmt = insert(Device).values(
        org_id=src.org_id,
        source_id=src.id,
        ip=ip,
        mac=mac,
        hostname=hostname,
        state=state,
        first_seen=when,
        last_seen=when,
        state_reason=reason,
        state_changed_at=now,
        state_by="system",
    )
    ex = stmt.excluded
    # a known address that now answers from a different MAC is the classic sign of spoofing or of a
    # swapped device: after the baseline, hold it for a decision (unless it is already flagged)
    changed = and_(
        ex.mac.is_not(None),
        Device.mac.is_not(None),
        ex.mac != Device.mac,
        Device.state.in_([DeviceState.KNOWN.value, DeviceState.TRUSTED.value]),
        false() if learning else true(),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_devices_org_source_ip",
        set_={
            "last_seen": func.greatest(Device.last_seen, ex.last_seen),
            "mac": func.coalesce(ex.mac, Device.mac),
            "hostname": func.coalesce(ex.hostname, Device.hostname),
            "state": case((changed, DeviceState.NEW.value), else_=Device.state),
            "state_reason": case(
                (changed, "its MAC address changed (was " + func.coalesce(Device.mac, "?") + ")"),
                else_=Device.state_reason,
            ),
            "state_changed_at": case((changed, now), else_=Device.state_changed_at),
            "state_by": case((changed, "system"), else_=Device.state_by),
        },
    )
    await session.execute(stmt)


def _clean_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(digits) != 12 or digits in ("0" * 12, "f" * 12):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


async def record_discovered(
    session: AsyncSession,
    source: Source,
    found: Sequence[tuple[str, str | None, str | None]],
    *,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> int:
    """Store the devices a sensor found on its network: (ip, mac, hostname). Addresses outside the
    registered network are ignored, so a sensor cannot add devices to a network it does not own.

    With ``pseudonymize_ips`` on, the address and MAC are stored as pseudonyms and the host name
    is dropped, the same promise the flows make."""
    now = now or datetime.now(UTC)
    src = source_info(source)
    stored = 0
    key = settings.pseudonym_key.get_secret_value().encode() if settings else b""
    hide = bool(settings and settings.pseudonymize_ips)
    for raw_ip, mac, hostname in found[:MAX_DISCOVERED]:
        ip = _addr(raw_ip)
        if ip is None or not _is_ordinary(ip) or not src.contains(ip):
            continue
        clean_mac = _clean_mac(mac)
        name = (hostname or "").strip()[:253] or None
        shown = str(ip)
        if hide:
            shown = pseudonymize_ip(shown, src.org_id, key)
            clean_mac = pseudonymize_mac(clean_mac, src.org_id, key) if clean_mac else None
            name = None
        await _upsert_device(
            session,
            src,
            shown,
            mac=clean_mac,
            hostname=name,
            when=now,
            now=now,
        )
        stored += 1
    return stored


# ----------------------------------------------------------------------------------------------
# what the traffic shows
# ----------------------------------------------------------------------------------------------
async def observe_flows(
    session: AsyncSession,
    rows: Iterable[dict[str, Any]],
    sources: dict[uuid.UUID, SourceInfo],
    *,
    now: datetime,
) -> None:
    """Record, from new flows, the devices inside each source and the networks outside it.

    ``rows`` need ``org_id, source_id, src_ip, dst_ip, ts, in_bytes, out_bytes``.
    """
    devices: dict[tuple[uuid.UUID, str], datetime] = {}
    peers: dict[tuple[uuid.UUID, str], list[Any]] = {}
    for r in rows:
        src = sources.get(r["source_id"])
        if src is None:
            continue
        a, b = _addr(str(r["src_ip"])), _addr(str(r["dst_ip"]))
        if a is None or b is None:
            continue
        ts: datetime = r["ts"]
        size = int(r["in_bytes"] or 0) + int(r["out_bytes"] or 0)
        a_in, b_in = src.contains(a), src.contains(b)
        for ip, inside in ((a, a_in), (b, b_in)):
            if inside and _is_ordinary(ip):
                key = (src.id, str(ip))
                devices[key] = max(devices.get(key, ts), ts)
        remote = b if a_in and not b_in else a if b_in and not a_in else None
        if remote is None:
            continue
        net = peer_network_of(str(remote))
        if net is None:
            continue
        entry = peers.setdefault((src.id, net), [ts, ts, 0, 0])
        entry[0], entry[1] = min(entry[0], ts), max(entry[1], ts)
        entry[2] += 1
        entry[3] += size

    for (source_id, device_ip), ts in devices.items():
        await _upsert_device(
            session, sources[source_id], device_ip, mac=None, hostname=None, when=ts, now=now
        )
    for (source_id, net), (first, last, n, size) in peers.items():
        src = sources[source_id]
        learning = src.learning(now)
        stmt = insert(PeerNetwork).values(
            org_id=src.org_id,
            source_id=src.id,
            network=net,
            flows=n,
            bytes=size,
            state=NetworkState.BASELINE.value if learning else NetworkState.NEW.value,
            state_reason=None if learning else "first seen after the baseline was learned",
            first_seen=first,
            last_seen=last,
            state_changed_at=now,
            state_by="system",
        )
        await session.execute(
            stmt.on_conflict_do_update(
                constraint="uq_peer_networks_org_source_net",
                set_={
                    "flows": PeerNetwork.flows + stmt.excluded.flows,
                    "bytes": PeerNetwork.bytes + stmt.excluded.bytes,
                    "last_seen": func.greatest(PeerNetwork.last_seen, stmt.excluded.last_seen),
                    "first_seen": func.least(PeerNetwork.first_seen, stmt.excluded.first_seen),
                },
            )
        )


# ----------------------------------------------------------------------------------------------
# quarantine
# ----------------------------------------------------------------------------------------------
def _meets(alert_severity: str, minimum: str) -> bool:
    return _SEVERITY_RANK.get(alert_severity, 0) >= _SEVERITY_RANK.get(minimum, 2)


async def quarantine_for_alert(
    session: AsyncSession,
    alert: Alert,
    src: SourceInfo,
    settings: Settings,
    *,
    now: datetime,
) -> str | None:
    """Flag the address a serious alert came from and hold it for a decision.

    A device on the registered network is marked ``quarantined``; an outside address marks its
    network (and remembers the address). A person's later decision wins: once someone approved
    it, only an alert that began after that decision flags it again. Returns what was flagged.
    """
    if not settings.auto_quarantine or alert.src_ip is None:
        return None
    if not _meets(alert.severity, settings.quarantine_min_severity):
        return None
    ip = _addr(str(alert.src_ip))
    if ip is None or not _is_ordinary(ip):
        return None
    reason = f"{alert.attack_class} alert ({alert.severity}, {alert.count} flows)"

    if src.contains(ip):
        table: type[Device] | type[PeerNetwork] = Device
        where = and_(Device.org_id == src.org_id, Device.source_id == src.id, Device.ip == str(ip))
        label = str(ip)
    else:
        net = peer_network_of(str(ip))
        if net is None:
            return None
        table = PeerNetwork
        where = and_(
            PeerNetwork.org_id == src.org_id,
            PeerNetwork.source_id == src.id,
            PeerNetwork.network == net,
        )
        label = net

    row = cast(
        "Device | PeerNetwork | None",
        (await session.execute(select(table).where(where).with_for_update())).scalar_one_or_none(),
    )
    if row is None:
        common: dict[str, Any] = {
            "org_id": src.org_id,
            "source_id": src.id,
            "first_seen": alert.first_seen,
            "last_seen": alert.last_seen,
            "state": "quarantined",
            "state_reason": reason,
            "state_changed_at": now,
            "state_by": "system",
            "alert_id": alert.id,
        }
        if table is Device:
            session.add(Device(ip=str(ip), **common))
        else:
            session.add(PeerNetwork(network=label, flagged_ips=[str(ip)], **common))
        await session.flush()
        return label

    if row.state == "quarantined":
        if isinstance(row, PeerNetwork) and str(ip) not in {str(x) for x in row.flagged_ips}:
            row.flagged_ips = [*row.flagged_ips, str(ip)][-64:]
        row.last_seen = max(row.last_seen, alert.last_seen)
        return None  # already held
    if row.state_by != "system" and row.state_changed_at >= alert.first_seen:
        return None  # a person decided after this alert began: their decision stands
    row.state, row.state_reason, row.state_changed_at = "quarantined", reason, now
    row.state_by, row.alert_id = "system", alert.id
    if isinstance(row, PeerNetwork) and str(ip) not in {str(x) for x in row.flagged_ips}:
        row.flagged_ips = [*row.flagged_ips, str(ip)][-64:]
    await session.flush()
    return label


async def decide(
    session: AsyncSession,
    row: Device | PeerNetwork,
    action: str,
    *,
    by: str,
    note: str | None,
    now: datetime | None = None,
) -> None:
    """A person's decision. ``approve`` releases and trusts; ``quarantine`` holds."""
    now = now or datetime.now(UTC)
    if isinstance(row, Device):
        row.state = (
            DeviceState.TRUSTED.value if action == "approve" else DeviceState.QUARANTINED.value
        )
    else:
        row.state = (
            NetworkState.APPROVED.value if action == "approve" else NetworkState.QUARANTINED.value
        )
    verb = "approved" if action == "approve" else "quarantined"
    row.state_reason = f"{verb} by {by}" + (f": {note.strip()}" if note and note.strip() else "")
    row.state_changed_at, row.state_by = now, by
    await session.flush()


def block_commands(target: str) -> dict[str, list[str]]:
    """Commands a person may run to cut an address or network off. Nothing here is executed by the
    app. ``target`` always comes from a stored address, but is parsed again so it cannot carry
    anything but an address."""
    net = ipaddress.ip_network(target, strict=False)
    t = str(net.network_address) if net.num_addresses == 1 else str(net)
    tables = "iptables" if net.version == 4 else "ip6tables"
    name = f"SentinelBI quarantine {t}"
    return {
        "windows": [
            f'New-NetFirewallRule -DisplayName "{name} (out)" -Direction Outbound '
            f"-RemoteAddress {t} -Action Block",
            f'New-NetFirewallRule -DisplayName "{name} (in)" -Direction Inbound '
            f"-RemoteAddress {t} -Action Block",
            f'# undo: Remove-NetFirewallRule -DisplayName "{name}*"',
        ],
        "linux": [
            f"sudo {tables} -I INPUT -s {t} -j DROP",
            f"sudo {tables} -I OUTPUT -d {t} -j DROP",
            f"# undo: sudo {tables} -D INPUT -s {t} -j DROP; "
            f"sudo {tables} -D OUTPUT -d {t} -j DROP",
        ],
        "gateway": [
            f"sudo {tables} -I FORWARD -s {t} -j DROP",
            f"sudo {tables} -I FORWARD -d {t} -j DROP",
            f"# undo: sudo {tables} -D FORWARD -s {t} -j DROP; "
            f"sudo {tables} -D FORWARD -d {t} -j DROP",
        ],
    }


async def quarantined_targets(session: AsyncSession, source_id: uuid.UUID) -> list[str]:
    """Everything a source currently holds in quarantine, as addresses or networks."""
    devs = (
        await session.execute(
            select(Device.ip).where(
                Device.source_id == source_id, Device.state == DeviceState.QUARANTINED.value
            )
        )
    ).scalars()
    nets = (
        await session.execute(
            select(PeerNetwork.network).where(
                PeerNetwork.source_id == source_id,
                PeerNetwork.state == NetworkState.QUARANTINED.value,
            )
        )
    ).scalars()
    return [str(x) for x in (*devs, *nets)]
