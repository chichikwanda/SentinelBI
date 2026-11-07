"""Settings an administrator can change from the web interface (no .env edit, no restart).

The environment value (``app.core.config.Settings``) is the default. A row in ``app_settings``
overrides it. ``effective_settings(session)`` returns the environment settings with the
overrides applied; the worker and the API use it wherever a value is meant to be adjustable.

Only the keys in ``CATALOGUE`` can be stored, each with a type and a range that is checked
on every write, so a typo or an absurd value is refused instead of silently breaking alerting.
Secrets (SECRET_KEY, database password, pseudonym key) are deliberately not in the catalogue.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.models import AppSetting

Kind = Literal["int", "float", "bool", "choice", "emails"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]
RETENTION_KEY = "retention_days"
RETENTION_DEFAULT = 30


@dataclass(frozen=True)
class Item:
    key: str
    group: str
    label: str
    help: str
    kind: Kind
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()
    unit: str = ""


CATALOGUE: tuple[Item, ...] = (
    Item(
        "alert_min_probability",
        "Alerting",
        "Minimum probability to flag a flow",
        "A flow counts as flagged only above this probability (or the model's own calibrated "
        "threshold, if that is higher).",
        "float",
        0.5,
        0.99,
    ),
    Item(
        "alert_min_flows",
        "Alerting",
        "Minimum flagged flows per alert",
        "At least this many flagged flows from one source inside the window.",
        "int",
        1,
        1000,
        unit="flows",
    ),
    Item(
        "alert_min_share",
        "Alerting",
        "Minimum flagged share",
        "Flagged flows must also be at least this share of all the source's flows in the window, "
        "so a busy benign host does not raise alerts (0.2 = 20%).",
        "float",
        0.0,
        1.0,
    ),
    Item(
        "alert_window_seconds",
        "Alerting",
        "Alert window",
        "The period over which flagged flows are counted.",
        "int",
        10,
        3600,
        unit="seconds",
    ),
    Item(
        "alert_merge_seconds",
        "Alerting",
        "Merge window",
        "Alerts of the same kind from the same source within this time become one alert.",
        "int",
        60,
        86400,
        unit="seconds",
    ),
    Item(
        "baseline_days",
        "Baseline and quarantine",
        "Baseline learning period",
        "A new source learns which devices and networks are normal for this long. Applies to "
        "sources added from now on.",
        "int",
        1,
        90,
        unit="days",
    ),
    Item(
        "auto_quarantine",
        "Baseline and quarantine",
        "Hold addresses behind serious alerts",
        "When on, the address behind a serious alert is held for a person's decision. Nothing "
        "on the network is blocked by SentinelBI.",
        "bool",
    ),
    Item(
        "quarantine_min_severity",
        "Baseline and quarantine",
        "Lowest severity that holds an address",
        "Alerts at or above this severity hold the address that caused them.",
        "choice",
        choices=tuple(SEVERITIES),
    ),
    Item(
        "risk_decay_half_life_hours",
        "Risk",
        "Risk half-life",
        "How quickly an alert's contribution to the risk score fades.",
        "float",
        0.5,
        168,
        unit="hours",
    ),
    Item(
        "pseudonymize_ips",
        "Privacy and retention",
        "Pseudonymise internal addresses",
        "Replace internal addresses with keyed hashes before storage. Changing it mid-way "
        "leaves older flows under the old form.",
        "bool",
    ),
    Item(
        RETENTION_KEY,
        "Privacy and retention",
        "Keep flows and predictions for",
        "Older data is dropped automatically by TimescaleDB.",
        "int",
        1,
        365,
        unit="days",
    ),
    Item(
        "allow_registration",
        "Access",
        "Allow new organisations to register",
        "Turn off on a public deployment once your organisation exists.",
        "bool",
    ),
    Item(
        "register_max_per_hour",
        "Access",
        "Sign-ups allowed per hour",
        "Across the whole deployment.",
        "int",
        1,
        1000,
    ),
    Item(
        "login_max_failures",
        "Access",
        "Failed sign-ins before an account is locked",
        "The account stays locked for the lockout period, whatever password is tried.",
        "int",
        1,
        100,
    ),
    Item(
        "platform_admin_emails",
        "Access",
        "Additional platform administrators",
        "Comma-separated emails that may change these settings and switch or train models, in "
        "addition to PLATFORM_ADMIN_EMAILS in the environment.",
        "emails",
    ),
)
BY_KEY = {i.key: i for i in CATALOGUE}


class SettingError(ValueError):
    """A submitted value is not allowed."""


def clean(item: Item, raw: Any) -> Any:
    """Validate and normalise one value; raise ``SettingError`` with an actionable message."""
    if item.kind == "bool":
        if not isinstance(raw, bool):
            raise SettingError(f"{item.label}: must be on or off")
        return raw
    if item.kind in ("int", "float"):
        if isinstance(raw, bool) or not isinstance(raw, int | float):
            raise SettingError(f"{item.label}: must be a number")
        value: float = int(raw) if item.kind == "int" else float(raw)
        if item.kind == "int" and float(raw) != int(raw):
            raise SettingError(f"{item.label}: must be a whole number")
        if item.minimum is not None and value < item.minimum:
            raise SettingError(f"{item.label}: must be at least {item.minimum:g}")
        if item.maximum is not None and value > item.maximum:
            raise SettingError(f"{item.label}: must be at most {item.maximum:g}")
        return value
    if item.kind == "choice":
        if raw not in item.choices:
            raise SettingError(f"{item.label}: must be one of {', '.join(item.choices)}")
        return raw
    if item.kind == "emails":
        if not isinstance(raw, str):
            raise SettingError(f"{item.label}: must be text")
        emails = [e.strip().lower() for e in raw.split(",") if e.strip()]
        if any("@" not in e or " " in e for e in emails):
            raise SettingError(f"{item.label}: each entry must be an email address")
        return ", ".join(emails)
    raise SettingError(f"unknown setting kind {item.kind}")  # pragma: no cover


async def stored_overrides(session: AsyncSession) -> dict[str, Any]:
    rows = (await session.execute(select(AppSetting))).scalars().all()
    return {r.key: r.value for r in rows if r.key in BY_KEY}


def apply(base: Settings, overrides: dict[str, Any]) -> Settings:
    update = {
        k: v
        for k, v in overrides.items()
        if k in Settings.model_fields and k != "platform_admin_emails"
    }
    if "platform_admin_emails" in overrides:
        merged = [
            e
            for e in (base.platform_admin_emails + "," + overrides["platform_admin_emails"]).split(
                ","
            )
            if e.strip()
        ]
        update["platform_admin_emails"] = ",".join(e.strip() for e in merged)
    return base.model_copy(update=update)


async def effective_settings(session: AsyncSession) -> Settings:
    return apply(get_settings(), await stored_overrides(session))


async def platform_admins(session: AsyncSession) -> set[str]:
    s = await effective_settings(session)
    return {e.strip().lower() for e in s.platform_admin_emails.split(",") if e.strip()}


async def effective_retention(session: AsyncSession) -> int:
    return int((await stored_overrides(session)).get(RETENTION_KEY, RETENTION_DEFAULT))


def default_for(item: Item) -> Any:
    if item.key == RETENTION_KEY:
        return RETENTION_DEFAULT
    if item.key == "platform_admin_emails":
        return get_settings().platform_admin_emails
    return getattr(get_settings(), item.key)


async def set_retention(session: AsyncSession, days: int) -> None:
    """Change the TimescaleDB retention policy of both hypertables."""
    for table in ("flows", "predictions"):
        await session.execute(text(f"SELECT remove_retention_policy('{table}', if_exists => true)"))
        await session.execute(
            text(f"SELECT add_retention_policy('{table}', make_interval(days => :d))"), {"d": days}
        )


async def describe(session: AsyncSession) -> list[dict[str, Any]]:
    over = await stored_overrides(session)
    out = []
    for it in CATALOGUE:
        default = default_for(it)
        out.append(
            {
                "key": it.key,
                "group": it.group,
                "label": it.label,
                "help": it.help,
                "kind": it.kind,
                "min": it.minimum,
                "max": it.maximum,
                "choices": list(it.choices),
                "unit": it.unit,
                "default": default,
                "value": over.get(it.key, default),
                "overridden": it.key in over,
            }
        )
    return out
