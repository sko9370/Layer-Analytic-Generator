"""Tests for lag.analytics: CAR coverage, JPCERT tool list, and whole-word tool matching."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from lag.analytics import (
    CAR_URL,
    AnalyticSources,
    load_analytic_sources,
    matching_tools,
)
from lag.errors import LagError
from lag.models import Config

FIXTURES = Path(__file__).parent / "fixtures"
CAR_FIXTURE = (FIXTURES / "analytics_car.json").read_text(encoding="utf-8")
JPCERT_FIXTURE = (FIXTURES / "analytics_jpcert.html").read_text(encoding="utf-8")


def make_config(**overrides) -> Config:
    config = Config(sources={"G0128": 1})
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


# ---------------------------------------------------------------------------
# matching_tools: whole-word matching
# ---------------------------------------------------------------------------


def test_matching_tools_does_not_substring_match_rdp_in_wordpress():
    tools = [("rdp", "https://tool.example/rdp")]
    assert matching_tools("The site runs on wordpress.", tools) == []


def test_matching_tools_does_not_substring_match_bits_in_orbits():
    tools = [("bits", "https://tool.example/bits")]
    assert matching_tools("The satellite completed several orbits.", tools) == []


def test_matching_tools_matches_whole_word_case_insensitive():
    tools = [("bits", "https://tool.example/bits"), ("rdp", "https://tool.example/rdp")]
    text = "The actor used BITS to transfer files, then connected over Rdp."
    assert matching_tools(text, tools) == [
        ("bits", "https://tool.example/bits"),
        ("rdp", "https://tool.example/rdp"),
    ]


def test_matching_tools_hyphen_boundary_also_excluded():
    # "net" should not match inside "net-user" style hyphenated words.
    tools = [("net", "https://tool.example/net")]
    assert matching_tools("Uses a net-user style command.", tools) == []


def test_matching_tools_unique_and_list_order():
    tools = [
        ("psexec", "https://tool.example/psexec"),
        ("bits", "https://tool.example/bits"),
        ("psexec", "https://tool.example/psexec"),  # exact duplicate tuple
    ]
    text = "psexec and bits and psexec again"
    assert matching_tools(text, tools) == [
        ("psexec", "https://tool.example/psexec"),
        ("bits", "https://tool.example/bits"),
    ]


def test_matching_tools_empty_text():
    assert matching_tools("", [("bits", "url")]) == []


# ---------------------------------------------------------------------------
# load_analytic_sources
# ---------------------------------------------------------------------------


def test_car_coverage_collects_technique_ids(monkeypatch, tmp_path):
    monkeypatch.setattr("lag.analytics.fetch_text", lambda *a, **k: CAR_FIXTURE)
    config = make_config(cache_dir=tmp_path, jpcert_enabled=False)
    sources = load_analytic_sources(config)
    assert sources.car_techniques == {"T1059", "T1059.003", "T1055"}
    assert sources.jpcert_tools == []


def test_jpcert_tool_list_parsing(monkeypatch, tmp_path):
    monkeypatch.setattr("lag.analytics.fetch_text", lambda *a, **k: JPCERT_FIXTURE)
    config = make_config(cache_dir=tmp_path, car_enabled=False)
    sources = load_analytic_sources(config)
    names = [name for name, _ in sources.jpcert_tools]
    assert "psexec" in names
    assert "bits" in names
    assert "rdp" in names
    # trailing "(...)" removed and lowercased
    assert "mimikatz" in names
    assert names.count("mimikatz") == 2  # two distinct rows collapse to the same name
    tool_map = dict(sources.jpcert_tools)
    assert tool_map["rdp"] == "https://jpcertcc.github.io/ToolAnalysisResultSheet/details/mstsc.htm"
    assert sources.car_techniques == set()


def test_disabled_sources_are_empty(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise AssertionError("fetch_text should not be called for a disabled source")

    monkeypatch.setattr("lag.analytics.fetch_text", boom)
    config = make_config(cache_dir=tmp_path, car_enabled=False, jpcert_enabled=False)
    sources = load_analytic_sources(config)
    assert sources == AnalyticSources(car_techniques=set(), jpcert_tools=[])


def test_failed_car_fetch_leaves_source_empty_with_warning(monkeypatch, tmp_path, caplog):
    def raise_lag_error(*args, **kwargs):
        raise LagError("network is down")

    monkeypatch.setattr("lag.analytics.fetch_text", raise_lag_error)
    config = make_config(cache_dir=tmp_path, jpcert_enabled=False)
    with caplog.at_level(logging.WARNING):
        sources = load_analytic_sources(config)
    assert sources.car_techniques == set()
    assert any("car" in rec.message.lower() for rec in caplog.records)


def test_failed_jpcert_fetch_leaves_source_empty_with_warning(monkeypatch, tmp_path, caplog):
    def raise_lag_error(*args, **kwargs):
        raise LagError("network is down")

    monkeypatch.setattr("lag.analytics.fetch_text", raise_lag_error)
    config = make_config(cache_dir=tmp_path, car_enabled=False)
    with caplog.at_level(logging.WARNING):
        sources = load_analytic_sources(config)
    assert sources.jpcert_tools == []
    assert any("jpcert" in rec.message.lower() for rec in caplog.records)


def test_jpcert_fetch_returns_unparseable_html_leaves_source_empty_with_warning(
    monkeypatch, tmp_path, caplog
):
    monkeypatch.setattr("lag.analytics.fetch_text", lambda *a, **k: "<html><body>no table here</body></html>")
    config = make_config(cache_dir=tmp_path, car_enabled=False)
    with caplog.at_level(logging.WARNING):
        sources = load_analytic_sources(config)
    assert sources.jpcert_tools == []
    assert len(caplog.records) >= 1


def test_car_url_constant():
    assert CAR_URL == "https://car.mitre.org/analytics/by_technique"


def test_car_fetch_receives_expected_arguments(monkeypatch, tmp_path):
    calls = []

    def fake_fetch(url, cache_dir, *, offline=False, max_age_hours=None, timeout=60):
        calls.append((url, cache_dir, offline, max_age_hours))
        return CAR_FIXTURE

    monkeypatch.setattr("lag.analytics.fetch_text", fake_fetch)
    config = make_config(cache_dir=tmp_path, jpcert_enabled=False, offline=True)
    load_analytic_sources(config)
    assert len(calls) == 1
    url, cache_dir, offline, max_age_hours = calls[0]
    assert url == config.car_coverage_url
    assert cache_dir == tmp_path
    assert offline is True
    assert max_age_hours == pytest.approx(24 * 7)
