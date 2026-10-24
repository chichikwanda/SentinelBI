"""Prescriptive engine: alert + context -> ranked, de-duplicated recommendations.

Rules are DATA (``rules/*.yaml``), not code (design rule 5), so a supervisor or security
expert can review them without reading Python. Every rule file is validated against the
schema below at load time, so a typo fails fast with a clear message instead of silently
producing no advice.

Ranking follows plan section 8:  ``rank = (1 / priority) x severity_weight x criticality``
(priority 1 is most urgent). Identical actions proposed by several rules are collapsed to the
highest-ranked one.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.enums import Severity

log = logging.getLogger("prescriptive")

RULES_DIR = Path(__file__).parent / "rules"
MAPPINGS_DIR = Path(__file__).parent / "mappings"

SEVERITY_WEIGHT: dict[str, int] = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


# --- rule file schema ---------------------------------------------------------------------------
class Refs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mitre: list[str] = Field(default_factory=list)  # ATT&CK mitigation ids, e.g. M1036
    cis: list[str] = Field(default_factory=list)  # CIS Controls v8 safeguard ids, e.g. "5.2"
    nist: list[str] = Field(default_factory=list)  # NIST CSF 2.0 categories, e.g. PR.AA


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=10)
    priority: int = Field(ge=1, le=5)
    effort: Literal["low", "medium", "high"]
    refs: Refs = Field(default_factory=Refs)


class When(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_class: str | list[str]
    min_severity: Severity = Severity.LOW
    min_criticality: int = Field(default=1, ge=1, le=3)
    dst_port_in: list[int] | None = None  # match only if the alert touched one of these ports


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^RULE-[A-Z]+-\d{3}$")
    when: When
    recommend: list[Action] = Field(min_length=1)
    compliance_note: str | None = None


# --- runtime types -------------------------------------------------------------------------------
@dataclass(frozen=True)
class AlertContext:
    attack_class: str
    severity: str
    criticality: int = 2  # 1 low .. 3 high
    dst_ports: frozenset[int] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Recommendation:
    rule_id: str
    rec_key: str  # stable per (rule, action index): makes persistence idempotent
    action: str
    priority: int
    effort: str
    refs: dict[str, list[str]]
    compliance_note: str | None
    rank: float


def rank_score(priority: int, severity: str, criticality: int) -> float:
    return (1.0 / priority) * SEVERITY_WEIGHT.get(severity, 1) * max(1, criticality)


# --- loading -------------------------------------------------------------------------------------
def load_rules(directory: Path = RULES_DIR) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            for item in raw:
                rule = Rule.model_validate(item)
                if rule.id in seen:
                    raise ValueError(f"duplicate rule id {rule.id}")
                seen.add(rule.id)
                rules.append(rule)
        except (ValidationError, ValueError, yaml.YAMLError) as exc:
            raise ValueError(f"invalid rule file {path.name}: {exc}") from exc
    return rules


@lru_cache
def default_rules() -> tuple[Rule, ...]:
    return tuple(load_rules())


# --- matching ------------------------------------------------------------------------------------
def _matches(rule: Rule, ctx: AlertContext) -> bool:
    w = rule.when
    classes = [w.attack_class] if isinstance(w.attack_class, str) else w.attack_class
    if ctx.attack_class not in classes and "*" not in classes:
        return False
    if SEVERITY_WEIGHT.get(ctx.severity, 0) < SEVERITY_WEIGHT[w.min_severity.value]:
        return False
    if ctx.criticality < w.min_criticality:
        return False
    return not (w.dst_port_in is not None and not (set(w.dst_port_in) & ctx.dst_ports))


def recommend(ctx: AlertContext, rules: Iterable[Rule] | None = None) -> list[Recommendation]:
    """Return the ranked, de-duplicated recommendations for one alert."""
    best: dict[str, Recommendation] = {}
    for rule in rules if rules is not None else default_rules():
        if not _matches(rule, ctx):
            continue
        for idx, act in enumerate(rule.recommend):
            rec = Recommendation(
                rule_id=rule.id,
                rec_key=f"{rule.id}:{idx}",
                action=act.action,
                priority=act.priority,
                effort=act.effort,
                refs=act.refs.model_dump(),
                compliance_note=rule.compliance_note,
                rank=rank_score(act.priority, ctx.severity, ctx.criticality),
            )
            key = " ".join(act.action.lower().split())
            if key not in best or rec.rank > best[key].rank:
                best[key] = rec
    return sorted(best.values(), key=lambda r: (-r.rank, r.priority, r.rec_key))


# --- reference mappings (id -> title/url), for display and validation ---------------------
@lru_cache
def reference_index() -> dict[str, dict[str, dict[str, str]]]:
    """``{"mitre": {"M1036": {"title": ..., "url": ...}}, "cis": {...}, "nist": {...}}``."""
    out: dict[str, dict[str, dict[str, str]]] = {}
    for name in ("mitre", "cis", "nist"):
        path = MAPPINGS_DIR / f"{name}.yaml"
        items: dict[str, dict[str, str]] = {}
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for key, value in (data.get("items") or {}).items():
                items[str(key)] = (
                    {k: str(v) for k, v in value.items()}
                    if isinstance(value, dict)
                    else {"title": str(value)}
                )
        out[name] = items
    return out


def reference_titles() -> dict[str, dict[str, str]]:
    return {
        fw: {k: v["title"] for k, v in items.items()} for fw, items in reference_index().items()
    }
