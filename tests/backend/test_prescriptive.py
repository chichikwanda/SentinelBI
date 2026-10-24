"""Prescriptive engine: rule files are valid, references resolve, ranking is as specified."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.services.prescriptive.engine import (
    AlertContext,
    load_rules,
    rank_score,
    recommend,
    reference_titles,
)
from sentinelbi_ml.features import CLASSES

ATTACK_CLASSES = [c for c in CLASSES if c != "Benign"]


def test_all_rule_files_load_and_ids_are_unique() -> None:
    rules = load_rules()
    assert len(rules) >= 8
    assert len({r.id for r in rules}) == len(rules)


def test_every_reference_resolves_to_a_known_title() -> None:
    titles = reference_titles()
    for rule in load_rules():
        for act in rule.recommend:
            for m in act.refs.mitre:
                assert m in titles["mitre"], f"{rule.id}: unknown ATT&CK mitigation {m}"
            for c in act.refs.cis:
                assert c in titles["cis"], f"{rule.id}: CIS safeguard {c} missing from cis.yaml"
            for n in act.refs.nist:
                assert n in titles["nist"], f"{rule.id}: NIST category {n} missing from nist.yaml"


def test_mitre_mapping_is_generated_from_stix_not_hand_written() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "backend/app/services/prescriptive/mappings/mitre.yaml"
    )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["status"] == "verified-against-stix"
    assert len(data["stix_file_sha256"]) == 64


def test_cis_and_nist_mappings_are_honestly_flagged_unverified() -> None:
    base = Path(__file__).resolve().parents[2] / "backend/app/services/prescriptive/mappings"
    for name in ("cis.yaml", "nist.yaml"):
        assert yaml.safe_load((base / name).read_text(encoding="utf-8"))["status"].startswith(
            "unverified"
        )


@pytest.mark.parametrize("attack_class", ATTACK_CLASSES)
def test_every_attack_class_gets_ranked_recommendations(attack_class: str) -> None:
    # BruteForce's port-specific rule needs a port; the generic one covers the rest
    recs = recommend(AlertContext(attack_class, "Medium", 2, frozenset({22})))
    assert recs, f"no recommendations for {attack_class}"
    ranks = [r.rank for r in recs]
    assert ranks == sorted(ranks, reverse=True)
    assert len({r.action for r in recs}) == len(recs)  # de-duplicated


def test_benign_gets_nothing() -> None:
    assert recommend(AlertContext("Benign", "Low", 2)) == []


def test_rank_formula_matches_the_plan() -> None:
    assert rank_score(priority=1, severity="High", criticality=3) == 9.0
    assert rank_score(priority=2, severity="High", criticality=3) == 4.5
    assert rank_score(priority=1, severity="Low", criticality=1) == 1.0


def test_severity_and_criticality_gate_rules() -> None:
    low = {r.rule_id for r in recommend(AlertContext("DoS/DDoS", "Low", 1))}
    high = {r.rule_id for r in recommend(AlertContext("DoS/DDoS", "High", 3))}
    assert "RULE-DOS-002" not in low and "RULE-DOS-002" in high  # min_severity High
    assert "RULE-GEN-002" not in low and "RULE-GEN-002" in high  # min_criticality 3


def test_port_specific_rule_needs_a_matching_port() -> None:
    with_ssh = {
        r.rule_id for r in recommend(AlertContext("BruteForce", "Medium", 2, frozenset({22})))
    }
    without = {
        r.rule_id for r in recommend(AlertContext("BruteForce", "Medium", 2, frozenset({8080})))
    }
    assert "RULE-BF-001" in with_ssh
    assert "RULE-BF-001" not in without
    assert "RULE-BF-002" in without  # the generic rule still applies


def test_compliance_note_never_cites_section_numbers_or_deadlines() -> None:
    """The legal wording must stay generic until a lawyer has confirmed the interpretation."""
    for rule in load_rules():
        if rule.compliance_note:
            assert "Chapter 12:07" in rule.compliance_note
            assert "confirm" in rule.compliance_note.lower()
            assert "section" not in rule.compliance_note.lower()
            assert "hours" not in rule.compliance_note.lower()


def test_invalid_rule_file_fails_loudly(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text(
        "- id: RULE-X-001\n  when: {attack_class: DoS/DDoS}\n  recommend:\n    - {action: 'too short', priority: 9, effort: low}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"bad\.yaml"):
        load_rules(tmp_path)
