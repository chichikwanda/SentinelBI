"""Event risk (plan section 7). Weights are PROVISIONAL (ADR-014), to be expert-elicited.

    event_risk = P(attack) x impact_weight[class] x criticality_factor x exposure_factor

Only the pieces available in this phase are implemented: asset/org aggregation, KEV and
threat-intel exposure terms arrive with the risk phase (exposure_factor defaults to 1.0).
"""

from __future__ import annotations

from app.core.enums import Severity

IMPACT_WEIGHTS: dict[str, float] = {
    "DoS/DDoS": 0.6,
    "BruteForce": 0.7,
    "Botnet/Backdoor": 0.9,
    "Exploit/Other": 0.9,
    # not given in the plan; provisional values
    "Recon/Scan": 0.3,
    "WebAttack": 0.7,
}
DEFAULT_IMPACT = 0.5

# Source/asset criticality 1 (low) .. 3 (high) -> multiplier
CRITICALITY_FACTOR: dict[int, float] = {1: 0.75, 2: 1.0, 3: 1.25}


def event_risk(
    probability: float,
    attack_class: str,
    criticality: int = 2,
    exposure_factor: float = 1.0,
) -> float:
    """Return a 0..1 risk for one flagged event."""
    impact = IMPACT_WEIGHTS.get(attack_class, DEFAULT_IMPACT)
    crit = CRITICALITY_FACTOR.get(criticality, 1.0)
    return max(0.0, min(1.0, probability * impact * crit * exposure_factor))


def severity_for(score_0_100: float) -> Severity:
    """0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical."""
    if score_0_100 < 25:
        return Severity.LOW
    if score_0_100 < 50:
        return Severity.MEDIUM
    if score_0_100 < 75:
        return Severity.HIGH
    return Severity.CRITICAL
