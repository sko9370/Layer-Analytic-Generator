"""Tests for lag.attack: STIX parsing against the mini enterprise fixture."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lag.attack import load_attack, parse_bundle, stix_url, technique_sort_key
from lag.errors import LagError
from lag.models import Config

MATRIX_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "stealth",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


@pytest.fixture()
def bundle(mini_bundle_path: Path) -> dict:
    return json.loads(mini_bundle_path.read_text(encoding="utf-8"))


@pytest.fixture()
def data(bundle: dict):
    return parse_bundle(bundle)


# ---------------------------------------------------------------------------
# stix_url
# ---------------------------------------------------------------------------


def test_stix_url_latest() -> None:
    assert stix_url("enterprise-attack") == (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )


def test_stix_url_versioned() -> None:
    assert stix_url("enterprise-attack", "19.2") == (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack-19.2.json"
    )


# ---------------------------------------------------------------------------
# technique_sort_key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("technique_id", "expected"),
    [
        ("T1059.003", (1059, 3)),
        ("T1059", (1059, 0)),
        ("T1003.001", (1003, 1)),
    ],
)
def test_technique_sort_key(technique_id: str, expected: tuple[int, int]) -> None:
    assert technique_sort_key(technique_id) == expected


def test_technique_sort_key_orders_parent_before_subs() -> None:
    ids = ["T1059.003", "T1059", "T1059.001"]
    assert sorted(ids, key=technique_sort_key) == ["T1059", "T1059.001", "T1059.003"]


# ---------------------------------------------------------------------------
# parse_bundle: version, tactics
# ---------------------------------------------------------------------------


def test_version(data) -> None:
    assert data.version == "19.2"


def test_domain(data) -> None:
    assert data.domain == "enterprise-attack"


def test_tactics_matrix_order(data) -> None:
    assert [t.shortname for t in data.tactics] == MATRIX_ORDER
    assert len(data.tactics) == 15


def test_tactics_stealth_and_defense_impairment_present(data) -> None:
    shortnames = {t.shortname for t in data.tactics}
    assert "stealth" in shortnames
    assert "defense-impairment" in shortnames
    assert "defense-evasion" not in shortnames


def test_tactic_fields(data) -> None:
    stealth = next(t for t in data.tactics if t.shortname == "stealth")
    assert stealth.name == "Stealth"
    assert stealth.attack_id.startswith("TA")


# ---------------------------------------------------------------------------
# parse_bundle: revoked / deprecated exclusion
# ---------------------------------------------------------------------------


def test_revoked_technique_excluded(data) -> None:
    assert "T1066" not in data.techniques


def test_deprecated_technique_excluded(data) -> None:
    assert "T1153" not in data.techniques


# ---------------------------------------------------------------------------
# parse_bundle: sources and procedures
# ---------------------------------------------------------------------------


def test_sources_present(data) -> None:
    assert data.sources["G0128"] == "ZIRCONIUM"
    assert data.sources["S0596"] == "ShadowPad"
    assert data.sources["C0041"] == "FrostyGoop Incident"


def test_sources_have_procedures(data) -> None:
    for source_id in ("G0128", "S0596", "C0041"):
        procs = data.procedures.get(source_id, [])
        assert len(procs) > 0
        for proc in procs:
            assert proc.source_id == source_id
            assert proc.source_name == data.sources[source_id]
            assert proc.technique_id in data.techniques


def test_procedures_sorted_by_technique_sort_key(data) -> None:
    for procs in data.procedures.values():
        keys = [technique_sort_key(p.technique_id) for p in procs]
        assert keys == sorted(keys)


def test_procedure_citations_resolved_with_urls(data) -> None:
    found_with_url = False
    for procs in data.procedures.values():
        for proc in procs:
            for citation in proc.citations:
                if citation.url:
                    found_with_url = True
    assert found_with_url


def test_procedure_citations_in_first_appearance_order(data) -> None:
    from lag import text as lag_text

    checked_any = False
    for procs in data.procedures.values():
        for proc in procs:
            labels_in_text = lag_text.citation_labels(proc.description)
            citation_labels = [c.label for c in proc.citations]
            # every label mentioned in the text appears, in the order it first appears
            leading = [label for label in citation_labels if label in labels_in_text]
            expected_leading = [label for label in dict.fromkeys(labels_in_text) if label in citation_labels]
            assert leading == expected_leading
            if labels_in_text:
                checked_any = True
    assert checked_any


# ---------------------------------------------------------------------------
# parse_bundle: sub-techniques
# ---------------------------------------------------------------------------


def test_subtechnique_full_name_and_parent_id(data) -> None:
    sub = data.techniques["T1027.011"]
    assert sub.parent_id == "T1027"
    parent = data.techniques["T1027"]
    assert sub.full_name == f"{parent.name}: {sub.name}"
    assert sub.full_name != sub.name


def test_non_subtechnique_full_name_equals_name(data) -> None:
    parent = data.techniques["T1027"]
    assert parent.parent_id is None
    assert parent.full_name == parent.name


def test_technique_tactics_sorted_in_matrix_order(data) -> None:
    order_index = {shortname: i for i, shortname in enumerate(MATRIX_ORDER)}
    for technique in data.techniques.values():
        indices = [order_index[t] for t in technique.tactics]
        assert indices == sorted(indices)


# ---------------------------------------------------------------------------
# parse_bundle: detection strategies / analytics / data components
# ---------------------------------------------------------------------------


def test_detection_strategies_present(data) -> None:
    with_detections = [t for t in data.techniques.values() if t.detection_strategies]
    assert with_detections


def test_detection_strategy_analytics_have_data_components(data) -> None:
    checked_any = False
    for technique in data.techniques.values():
        for strategy in technique.detection_strategies:
            assert strategy.attack_id
            assert strategy.name
            for analytic in strategy.analytics:
                assert analytic.attack_id
                for log_source in analytic.log_sources:
                    checked_any = True
                    assert log_source.name != "" or log_source.channel != ""
    assert checked_any


def test_detection_strategy_has_some_named_data_components(data) -> None:
    names = set()
    for technique in data.techniques.values():
        for strategy in technique.detection_strategies:
            for analytic in strategy.analytics:
                for log_source in analytic.log_sources:
                    if log_source.data_component:
                        names.add(log_source.data_component)
    assert names, "expected at least one resolved data component name"


def test_detection_strategies_sorted_by_attack_id(data) -> None:
    for technique in data.techniques.values():
        ids = [s.attack_id for s in technique.detection_strategies]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# load_attack
# ---------------------------------------------------------------------------


def test_load_attack_with_stix_file(mini_bundle_path: Path, tmp_path: Path) -> None:
    config = Config(sources={"G0128": 1}, stix_file=mini_bundle_path, cache_dir=tmp_path)
    result = load_attack(config)
    assert result.version == "19.2"
    assert "T1066" not in result.techniques


def test_load_attack_missing_stix_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.json"
    config = Config(sources={"G0128": 1}, stix_file=missing, cache_dir=tmp_path)
    with pytest.raises(LagError, match="does_not_exist.json"):
        load_attack(config)


def test_load_attack_downloads_when_no_stix_file(
    mini_bundle_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def fake_fetch_text(url, cache_dir, *, offline=False, max_age_hours=None, timeout=60):
        calls.append((url, offline, max_age_hours))
        return mini_bundle_path.read_text(encoding="utf-8")

    monkeypatch.setattr("lag.attack.fetch_text", fake_fetch_text)
    config = Config(sources={"G0128": 1}, cache_dir=tmp_path)
    result = load_attack(config)
    assert result.version == "19.2"
    assert len(calls) == 1
    url, offline, max_age_hours = calls[0]
    assert "enterprise-attack.json" in url
    assert offline is False
    assert max_age_hours == 24


def test_load_attack_versioned_never_expires(
    mini_bundle_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = []

    def fake_fetch_text(url, cache_dir, *, offline=False, max_age_hours=None, timeout=60):
        calls.append((url, max_age_hours))
        return mini_bundle_path.read_text(encoding="utf-8")

    monkeypatch.setattr("lag.attack.fetch_text", fake_fetch_text)
    config = Config(sources={"G0128": 1}, cache_dir=tmp_path, attack_version="19.2")
    load_attack(config)
    url, max_age_hours = calls[0]
    assert "enterprise-attack-19.2.json" in url
    assert max_age_hours is None


# ---------------------------------------------------------------------------
# live test against the real, current ATT&CK Enterprise bundle
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_load_attack_has_many_techniques(tmp_path: Path) -> None:
    config = Config(sources={}, cache_dir=tmp_path)
    result = load_attack(config)
    assert len(result.techniques) > 500
