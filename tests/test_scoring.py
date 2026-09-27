"""Tests for lag.scoring: weighting, unknown source errors, merging, and ordering."""

from __future__ import annotations

import logging

import pytest

from lag.errors import LagError
from lag.models import AttackData, Citation, Config, Procedure, Technique, TechniqueEntry
from lag.scoring import order_entries, score_techniques


def make_technique(attack_id: str, parent_id: str | None = None, name: str | None = None) -> Technique:
    return Technique(
        attack_id=attack_id,
        name=name or attack_id,
        full_name=name or attack_id,
        description="",
        citations={},
        tactics=["execution"],
        platforms=[],
        url=f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}",
        parent_id=parent_id,
    )


def make_procedure(source_id: str, source_name: str, technique_id: str, description: str = "") -> Procedure:
    return Procedure(
        source_id=source_id,
        source_name=source_name,
        technique_id=technique_id,
        description=description,
        citations=[],
    )


def make_attack(techniques: dict[str, Technique], sources: dict[str, str], procedures: dict) -> AttackData:
    return AttackData(
        version="19.2",
        domain="enterprise-attack",
        techniques=techniques,
        tactics=[],
        sources=sources,
        procedures=procedures,
    )


def make_config(sources: dict[str, int]) -> Config:
    return Config(sources=sources)


def test_unknown_source_ids_raise_listing_all() -> None:
    attack = make_attack({}, {"G0128": "ZIRCONIUM"}, {})
    config = make_config({"G0128": 1, "S9999": 2, "C8888": 3})
    with pytest.raises(LagError) as exc_info:
        score_techniques(attack, config)
    message = str(exc_info.value)
    assert "S9999" in message
    assert "C8888" in message
    assert "G0128" not in message


def test_known_source_with_no_procedures_warns(caplog: pytest.LogCaptureFixture) -> None:
    attack = make_attack({}, {"G0128": "ZIRCONIUM"}, {})
    config = make_config({"G0128": 1})
    with caplog.at_level(logging.WARNING):
        entries = score_techniques(attack, config)
    assert entries == []
    assert any("G0128" in record.message for record in caplog.records)


def test_source_weight_applied_once_per_technique_regardless_of_procedure_count() -> None:
    techniques = {
        "T1059": make_technique("T1059"),
        "T1059.003": make_technique("T1059.003", parent_id="T1059"),
    }
    procedures = {
        "G0001": [
            make_procedure("G0001", "TestGroup", "T1059.003", "first use"),
            make_procedure("G0001", "TestGroup", "T1059.003", "second use"),
        ]
    }
    attack = make_attack(techniques, {"G0001": "TestGroup"}, procedures)
    config = make_config({"G0001": 3})

    entries = score_techniques(attack, config)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.technique_id == "T1059.003"
    assert entry.score == 3
    assert len(entry.procedures) == 2
    assert [p.description for p in entry.procedures] == ["first use", "second use"]


def test_imported_entries_merge_score_procedures_and_links() -> None:
    techniques = {"T1027": make_technique("T1027")}
    procedures = {"S0001": [make_procedure("S0001", "TestSoftware", "T1027", "software use")]}
    attack = make_attack(techniques, {"S0001": "TestSoftware"}, procedures)
    config = make_config({"S0001": 1})

    imported_procedure = make_procedure("Observed Activity", "Observed Activity", "T1027", "seen in the wild")
    shared_link = Citation(label="Report", url="https://example.com/report")
    imported = [
        TechniqueEntry(
            technique_id="T1027",
            score=2,
            procedures=[imported_procedure],
            links=[shared_link, Citation(label="Other", url="https://example.com/other")],
        )
    ]

    entries = score_techniques(attack, config, imported=imported)

    assert len(entries) == 1
    entry = entries[0]
    assert entry.score == 3
    assert len(entry.procedures) == 2
    assert entry.procedures[0].source_id == "S0001"
    assert entry.procedures[1].source_id == "Observed Activity"
    assert len(entry.links) == 2


def test_imported_entry_links_deduplicated_against_existing() -> None:
    techniques = {"T1027": make_technique("T1027")}
    attack = make_attack(techniques, {}, {})
    config = Config(sources={}, custom_layers=[])

    link = Citation(label="Report", url="https://example.com/report")
    imported = [
        TechniqueEntry(technique_id="T1027", score=1, procedures=[], links=[link]),
        TechniqueEntry(technique_id="T1027", score=1, procedures=[], links=[link]),
    ]

    entries = score_techniques(attack, config, imported=imported)

    assert len(entries) == 1
    assert entries[0].score == 2
    assert entries[0].links == [link]


def test_order_by_parent_group_total_then_score() -> None:
    techniques = {
        "T1059": make_technique("T1059"),
        "T1059.001": make_technique("T1059.001", parent_id="T1059"),
        "T1059.003": make_technique("T1059.003", parent_id="T1059"),
        "T1027": make_technique("T1027"),
    }
    entries = [
        TechniqueEntry(technique_id="T1027", score=5, procedures=[], links=[]),
        TechniqueEntry(technique_id="T1059.001", score=1, procedures=[], links=[]),
        TechniqueEntry(technique_id="T1059.003", score=4, procedures=[], links=[]),
    ]
    attack = make_attack(techniques, {}, {})

    ordered = order_entries(entries, attack)

    # T1059 group total = 1 + 4 = 5, ties with T1027's group total of 5;
    # tie broken by technique_sort_key of the parent ascending: T1027 (1027) before T1059 (1059).
    assert [e.technique_id for e in ordered] == ["T1027", "T1059.003", "T1059.001"]


def test_order_group_total_takes_priority_over_individual_score() -> None:
    techniques = {
        "T1059": make_technique("T1059"),
        "T1059.001": make_technique("T1059.001", parent_id="T1059"),
        "T1059.002": make_technique("T1059.002", parent_id="T1059"),
        "T1027": make_technique("T1027"),
    }
    entries = [
        TechniqueEntry(technique_id="T1027", score=10, procedures=[], links=[]),
        TechniqueEntry(technique_id="T1059.001", score=6, procedures=[], links=[]),
        TechniqueEntry(technique_id="T1059.002", score=6, procedures=[], links=[]),
    ]
    attack = make_attack(techniques, {}, {})

    ordered = order_entries(entries, attack)

    # T1059 group total = 12 > T1027 group total = 10, so the whole T1059 group comes first
    # even though no single T1059 entry outscores T1027 alone.
    assert [e.technique_id for e in ordered] == ["T1059.001", "T1059.002", "T1027"]


def test_order_falls_back_to_prefix_for_unknown_technique_id() -> None:
    entries = [
        TechniqueEntry(technique_id="T9999.001", score=1, procedures=[], links=[]),
        TechniqueEntry(technique_id="T9999.002", score=2, procedures=[], links=[]),
    ]
    attack = make_attack({}, {}, {})

    ordered = order_entries(entries, attack)

    assert [e.technique_id for e in ordered] == ["T9999.002", "T9999.001"]
