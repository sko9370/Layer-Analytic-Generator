"""End-to-end pipeline tests. The offline test uses only the bundled mini STIX fixture; the
`live` test downloads the real, current ATT&CK Enterprise bundle and enables the analytics
sources (network access required, deselected by default)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from lag import pipeline
from lag.models import Config


def _offline_config(tmp_path: Path, stix_file: Path) -> Config:
    return Config(
        name="Test Plan",
        output_dir=tmp_path / "output",
        sources={"G0128": 2, "S0596": 1},
        stix_file=stix_file,
        cache_dir=tmp_path / "cache",
        offline=True,
        car_enabled=False,
        jpcert_enabled=False,
        html_enabled=True,
    )


def test_run_end_to_end_offline(tmp_path: Path, mini_bundle_path: Path):
    config = _offline_config(tmp_path, mini_bundle_path)

    result = pipeline.run(config)

    assert result.attack_version
    assert result.technique_count > 0
    assert result.layer_path == config.output_dir / "layer.json"
    assert result.layer_path.exists()

    layer = json.loads(result.layer_path.read_text(encoding="utf-8"))
    assert layer["techniques"], "layer should have at least one technique"
    for technique in layer["techniques"]:
        assert "tactic" not in technique, "Navigator layer techniques must not carry a tactic key"

    assert result.csv_path == config.output_dir / "analytic_plan.csv"
    assert result.csv_path.exists()
    with result.csv_path.open(newline="", encoding="utf-8-sig") as handle:
        data_rows = list(csv.DictReader(handle))
    assert len(data_rows) > 0

    assert result.html_path == config.output_dir / "analytic_plan.html"
    assert result.html_path is not None
    assert result.html_path.exists()
    html_text = result.html_path.read_text(encoding="utf-8")
    assert "<html" in html_text.lower()
    assert "<script src=" not in html_text.lower()


def test_run_raises_lag_error_for_unknown_source(tmp_path: Path, mini_bundle_path: Path):
    from lag.errors import LagError

    config = _offline_config(tmp_path, mini_bundle_path)
    config.sources = {"G9999": 1}

    with pytest.raises(LagError):
        pipeline.run(config)


def test_run_skips_html_when_disabled(tmp_path: Path, mini_bundle_path: Path):
    config = _offline_config(tmp_path, mini_bundle_path)
    config.html_enabled = False

    result = pipeline.run(config)

    assert result.html_path is None
    assert not (config.output_dir / "analytic_plan.html").exists()


@pytest.mark.live
def test_run_end_to_end_live_with_analytics(tmp_path: Path):
    """Full run against the latest real ATT&CK Enterprise data, with CAR and JPCERT enabled."""
    config = Config(
        name="Live Test Plan",
        output_dir=tmp_path / "output",
        sources={"G0128": 2, "S0596": 1},
        cache_dir=tmp_path / "cache",
        offline=False,
        car_enabled=True,
        jpcert_enabled=True,
        html_enabled=True,
    )

    result = pipeline.run(config)

    assert result.attack_version
    assert result.technique_count > 0
    assert result.layer_path.exists()
    assert result.csv_path.exists()
    assert result.html_path is not None
    assert result.html_path.exists()

    layer = json.loads(result.layer_path.read_text(encoding="utf-8"))
    assert layer["techniques"]
    for technique in layer["techniques"]:
        assert "tactic" not in technique
