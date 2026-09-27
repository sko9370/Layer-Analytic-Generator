"""Tests for lag.layers: build_layer, write_layer, read_custom_layer."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from lag.errors import LagError
from lag.layers import build_layer, read_custom_layer, write_layer
from lag.models import (
    AttackData,
    Citation,
    Config,
    CustomLayer,
    Procedure,
    Technique,
    TechniqueEntry,
)


def make_technique(attack_id: str) -> Technique:
    return Technique(
        attack_id=attack_id,
        name=attack_id,
        full_name=attack_id,
        description="",
        citations={},
        tactics=["execution"],
        platforms=[],
        url=f"https://attack.mitre.org/techniques/{attack_id}",
        parent_id=None,
    )


def make_attack(version: str = "19.2", techniques: dict | None = None) -> AttackData:
    return AttackData(
        version=version,
        domain="enterprise-attack",
        techniques=techniques or {},
        tactics=[],
        sources={"G0128": "ZIRCONIUM", "S0596": "ShadowPad"},
        procedures={},
    )


# --------------------------------------------------------------------------- build_layer


def test_build_layer_has_no_tactic_keys() -> None:
    entries = [TechniqueEntry(technique_id="T1059.003", score=2, procedures=[], links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 2}))
    for technique in layer["techniques"]:
        assert "tactic" not in technique


def test_build_layer_versions() -> None:
    layer = build_layer([], make_attack("19.2"), Config(sources={"G0128": 1}))
    assert layer["versions"]["attack"] == "19"
    assert layer["versions"]["navigator"] == "5.3.2"
    assert layer["versions"]["layer"] == "4.5"


def test_build_layer_name_domain_and_sources_metadata() -> None:
    config = Config(name="My Plan", domain="enterprise-attack", sources={"G0128": 2, "S0596": 1})
    layer = build_layer([], make_attack(), config)
    assert layer["name"] == "My Plan"
    assert layer["domain"] == "enterprise-attack"
    sources_meta = next(m for m in layer["metadata"] if m["name"] == "Sources")
    assert sources_meta["value"] == "G0128 x2, S0596 x1"
    version_meta = next(m for m in layer["metadata"] if m["name"] == "ATT&CK version")
    assert version_meta["value"] == "19.2"
    assert "G0128" in layer["description"] or "19.2" in layer["description"]


def test_build_layer_metadata_dividers_between_procedures_only() -> None:
    procedures = [
        Procedure("G0128", "ZIRCONIUM", "T1059.003", "used it", []),
        Procedure("S0596", "ShadowPad", "T1059.003", "also used it", []),
    ]
    entries = [TechniqueEntry(technique_id="T1059.003", score=3, procedures=procedures, links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 2, "S0596": 1}))
    metadata = layer["techniques"][0]["metadata"]

    assert metadata[0] != {"divider": True}
    assert metadata[-1] != {"divider": True}
    dividers = [i for i, item in enumerate(metadata) if item == {"divider": True}]
    assert dividers == [1]
    assert metadata[0]["name"] == "G0128 ZIRCONIUM"
    assert metadata[2]["name"] == "S0596 ShadowPad"


def test_build_layer_metadata_single_procedure_no_divider() -> None:
    procedures = [Procedure("G0128", "ZIRCONIUM", "T1059.003", "used it", [])]
    entries = [TechniqueEntry(technique_id="T1059.003", score=2, procedures=procedures, links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 2}))
    metadata = layer["techniques"][0]["metadata"]
    assert len(metadata) == 1
    assert {"divider": True} not in metadata


def test_build_layer_links_no_leading_trailing_or_consecutive_dividers() -> None:
    procedures = [
        Procedure("G0128", "ZIRCONIUM", "T1059.003", "d1", [Citation("Ref1", "https://example.com/1")]),
        Procedure("S0596", "ShadowPad", "T1059.003", "d2", []),  # no url -> empty group, skipped
    ]
    entry = TechniqueEntry(
        technique_id="T1059.003",
        score=3,
        procedures=procedures,
        links=[Citation("Extra", "https://example.com/extra")],
    )
    layer = build_layer([entry], make_attack(), Config(sources={"G0128": 2, "S0596": 1}))
    links = layer["techniques"][0]["links"]

    assert links[0] != {"divider": True}
    assert links[-1] != {"divider": True}
    dividers = [i for i, item in enumerate(links) if item == {"divider": True}]
    assert dividers == [1]
    assert links[0] == {"label": "Ref1", "url": "https://example.com/1"}
    assert links[2] == {"label": "Extra", "url": "https://example.com/extra"}


def test_build_layer_links_skip_citations_without_url() -> None:
    procedures = [Procedure("G0128", "ZIRCONIUM", "T1059.003", "d1", [Citation("NoUrl", None)])]
    entry = TechniqueEntry(technique_id="T1059.003", score=2, procedures=procedures, links=[])
    layer = build_layer([entry], make_attack(), Config(sources={"G0128": 2}))
    assert layer["techniques"][0]["links"] == []


def test_build_layer_gradient_max_value_at_least_3() -> None:
    entries = [TechniqueEntry(technique_id="T1059.003", score=1, procedures=[], links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 1}))
    assert layer["gradient"]["maxValue"] == 3
    assert layer["gradient"]["minValue"] == 1
    assert layer["gradient"]["colors"] == Config().layer_gradient


def test_build_layer_gradient_max_value_above_3() -> None:
    entries = [TechniqueEntry(technique_id="T1059.003", score=7, procedures=[], links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 7}))
    assert layer["gradient"]["maxValue"] == 7


def test_build_layer_score_and_settings() -> None:
    entries = [TechniqueEntry(technique_id="T1059.003", score=4, procedures=[], links=[])]
    layer = build_layer(entries, make_attack(), Config(sources={"G0128": 4}))
    technique = layer["techniques"][0]
    assert technique["techniqueID"] == "T1059.003"
    assert technique["score"] == 4
    assert technique["enabled"] is True
    assert technique["showSubtechniques"] is False
    assert layer["sorting"] == 3
    assert layer["layout"]["layout"] == "flat"
    assert layer["hideDisabled"] is False


# --------------------------------------------------------------------------- write_layer


def test_write_layer_creates_parent_dirs_and_valid_json(tmp_path: Path) -> None:
    layer = {"name": "x", "techniques": []}
    path = tmp_path / "nested" / "dir" / "layer.json"
    write_layer(layer, path)
    assert path.is_file()
    with path.open(encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded == layer
    text = path.read_text(encoding="utf-8")
    assert text.startswith("{\n  ")  # indent=2


# --------------------------------------------------------------------------- read_custom_layer


def test_read_custom_layer_missing_file_raises(tmp_path: Path) -> None:
    custom = CustomLayer(path=tmp_path / "missing.json", label="Observed")
    with pytest.raises(LagError, match="not found"):
        read_custom_layer(custom, make_attack())


def test_read_custom_layer_not_a_layer_raises(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    custom = CustomLayer(path=path, label="Observed")
    with pytest.raises(LagError, match="not a Navigator layer"):
        read_custom_layer(custom, make_attack())


def _write_layer_file(path: Path, techniques: list[dict]) -> None:
    path.write_text(json.dumps({"name": "x", "techniques": techniques}), encoding="utf-8")


def test_read_custom_layer_score_gt_0_included(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(path, [{"techniqueID": "T1059.003", "score": 5}])
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert len(entries) == 1
    assert entries[0].score == 5


def test_read_custom_layer_no_score_but_has_comment_gets_score_1(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(path, [{"techniqueID": "T1059.003", "comment": "seen"}])
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert len(entries) == 1
    assert entries[0].score == 1
    assert entries[0].procedures[0].description == "seen"


def test_read_custom_layer_no_score_no_content_skipped(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(path, [{"techniqueID": "T1059.003"}])
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert entries == []


def test_read_custom_layer_zero_score_but_has_metadata_gets_score_1(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(
        path,
        [
            {
                "techniqueID": "T1059.003",
                "score": 0,
                "metadata": [{"name": "note", "value": "hello"}],
            }
        ],
    )
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert len(entries) == 1
    assert entries[0].score == 1
    assert "note: hello" in entries[0].procedures[0].description


def test_read_custom_layer_duplicate_technique_merges(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(
        path,
        [
            {"techniqueID": "T1059.003", "score": 2, "comment": "seen once"},
            {"techniqueID": "T1059.003", "score": 5, "comment": "seen again"},
        ],
    )
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert len(entries) == 1
    assert entries[0].score == 5  # max
    description = entries[0].procedures[0].description
    assert "seen once" in description and "seen again" in description


def test_read_custom_layer_duplicate_merges_links_union(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(
        path,
        [
            {
                "techniqueID": "T1059.003",
                "score": 3,
                "links": [{"label": "A", "url": "https://example.com/a"}],
            },
            {
                "techniqueID": "T1059.003",
                "score": 3,
                "links": [
                    {"label": "A", "url": "https://example.com/a"},
                    {"label": "B", "url": "https://example.com/b"},
                ],
            },
        ],
    )
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert len(entries) == 1
    labels = {c.label for c in entries[0].links}
    assert labels == {"A", "B"}


def test_read_custom_layer_unknown_technique_skipped_with_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(
        path,
        [
            {"techniqueID": "T9999", "score": 3},
            {"techniqueID": "T1059.003", "score": 2},
        ],
    )
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    with caplog.at_level(logging.WARNING):
        entries = read_custom_layer(custom, attack)
    assert [e.technique_id for e in entries] == ["T1059.003"]
    assert any("T9999" in record.message for record in caplog.records)


def test_read_custom_layer_float_score_rounded(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(path, [{"techniqueID": "T1059.003", "score": 2.6}])
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert entries[0].score == 3
    assert isinstance(entries[0].score, int)


def test_read_custom_layer_links_skip_dividers(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(
        path,
        [
            {
                "techniqueID": "T1059.003",
                "score": 2,
                "links": [
                    {"label": "A", "url": "https://example.com/a"},
                    {"divider": True},
                    {"label": "B", "url": "https://example.com/b"},
                ],
            }
        ],
    )
    custom = CustomLayer(path=path, label="Observed")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    assert [c.label for c in entries[0].links] == ["A", "B"]


def test_read_custom_layer_procedure_uses_label_as_source(tmp_path: Path) -> None:
    path = tmp_path / "custom.json"
    _write_layer_file(path, [{"techniqueID": "T1059.003", "score": 2}])
    custom = CustomLayer(path=path, label="Observed Activity")
    attack = make_attack(techniques={"T1059.003": make_technique("T1059.003")})
    entries = read_custom_layer(custom, attack)
    procedure = entries[0].procedures[0]
    assert procedure.source_id == "Observed Activity"
    assert procedure.source_name == "Observed Activity"
    assert procedure.citations == []


def test_read_custom_layer_maps_revoked_ids(tmp_path, caplog):
    import json as _json

    from lag.models import CustomLayer

    attack = make_attack(techniques={"T1685": make_technique("T1685")})
    attack.revoked_techniques["T9003"] = "T1685"
    path = tmp_path / "old.json"
    path.write_text(_json.dumps({"techniques": [{"techniqueID": "T9003", "score": 2, "comment": "old"}]}))
    entries = read_custom_layer(CustomLayer(path=path, label="Old"), attack)
    assert [e.technique_id for e in entries] == [attack.revoked_techniques["T9003"]]
    assert "revoked" in caplog.text
