"""End-to-end run and step-reporting tests. The offline tests use only the bundled mini STIX
fixture; the `live` test downloads the real, current ATT&CK Enterprise bundle and enables the
analytics sources (network access required, deselected by default)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from lag import pipeline
from lag.errors import LagError
from lag.models import Config, CustomLayer, Procedure, ReportSource, TechniqueEntry


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

    assert result.extractions == []


def test_run_raises_lag_error_for_unknown_source(tmp_path: Path, mini_bundle_path: Path):
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


# ---------------------------------------------------------------------------
# Step numbering and progress reporting
# ---------------------------------------------------------------------------


def test_run_reports_progress_lines_for_each_applicable_step(tmp_path: Path, mini_bundle_path: Path):
    config = _offline_config(tmp_path, mini_bundle_path)
    lines: list[str] = []

    pipeline.run(config, progress=lines.append)

    # 5 mandatory steps (load, score, layer, analytics, plan) + html enabled = 6, 2 lines each.
    assert len(lines) == 12
    assert lines[0] == "[1/6] Load ATT&CK data..."
    assert lines[1].startswith("[1/6] Load ATT&CK data: ATT&CK ")
    assert lines[-2] == "[6/6] Write HTML plan..."
    assert lines[-1].startswith("[6/6] Write HTML plan: ")


def test_run_step_numbering_without_optional_steps(tmp_path: Path, mini_bundle_path: Path):
    config = _offline_config(tmp_path, mini_bundle_path)
    config.html_enabled = False
    lines: list[str] = []

    pipeline.run(config, progress=lines.append)

    assert len(lines) == 10
    assert lines[0] == "[1/5] Load ATT&CK data..."
    assert lines[-2] == "[5/5] Build analytic plan and write CSV..."


def test_run_step_numbering_with_custom_layer(tmp_path: Path, mini_bundle_path: Path):
    layer_path = tmp_path / "custom.json"
    layer_path.write_text(
        json.dumps({"techniques": [{"techniqueID": "T1547.001", "score": 3, "comment": "seen"}]}),
        encoding="utf-8",
    )
    config = Config(
        output_dir=tmp_path / "output",
        sources={},
        custom_layers=[CustomLayer(path=layer_path, label="Observed")],
        stix_file=mini_bundle_path,
        cache_dir=tmp_path / "cache",
        offline=True,
        car_enabled=False,
        jpcert_enabled=False,
        html_enabled=False,
    )
    lines: list[str] = []

    result = pipeline.run(config, progress=lines.append)

    assert result.technique_count > 0
    # load, custom layers, score, layer, analytics, plan = 6 steps.
    assert len(lines) == 12
    assert lines[0] == "[1/6] Load ATT&CK data..."
    assert lines[2] == "[2/6] Read custom layers..."
    assert lines[4] == "[3/6] Score techniques..."


def test_run_step_numbering_with_report(tmp_path: Path, mini_bundle_path: Path, monkeypatch):
    config = Config(
        output_dir=tmp_path / "output",
        sources={"G0128": 1},
        reports=[ReportSource(source="https://example.com/report.pdf")],
        stix_file=mini_bundle_path,
        cache_dir=tmp_path / "cache",
        offline=True,
        car_enabled=False,
        jpcert_enabled=False,
        html_enabled=False,
    )

    def fake_run_report(report, attack, cfg, client=None):
        extraction = _FakeExtraction(dropped=["T9999"])
        entry = TechniqueEntry(
            technique_id="T1547.001",
            score=report.weight,
            procedures=[
                Procedure(
                    source_id="Report: Example",
                    source_name="Report: Example",
                    technique_id="T1547.001",
                    description="Actor persisted via a boot script.",
                    citations=[],
                )
            ],
            links=[],
        )
        return extraction, [entry]

    monkeypatch.setattr("lag.extract.run_report", fake_run_report)

    lines: list[str] = []
    result = pipeline.run(config, progress=lines.append)

    # load, reports, score, layer, analytics, plan = 6 steps.
    assert len(lines) == 12
    assert lines[2] == "[2/6] Extract techniques from reports with claude-opus-5..."
    assert "1 kept, 1 dropped" in lines[3]
    assert result.extractions == [("Report: Example", 1, ["T9999"])]


class _FakeExtraction:
    def __init__(self, dropped: list[str]):
        self.source = "https://example.com/report.pdf"
        self.title = "Example Report"
        self.model = "claude-opus-5"
        self.techniques = []
        self.dropped = dropped


# ---------------------------------------------------------------------------
# StepError formatting
# ---------------------------------------------------------------------------


def test_step_error_message_format_for_lag_error(tmp_path: Path, mini_bundle_path: Path):
    config = _offline_config(tmp_path, mini_bundle_path)
    config.sources = {"G9999": 1}

    with pytest.raises(pipeline.StepError) as excinfo:
        pipeline.run(config)

    error = excinfo.value
    assert error.step_number == 2
    assert error.step_title == "Score techniques"
    assert "unknown source ID(s): G9999" in str(error.cause)
    assert str(error) == (
        "Step 2/6 (Score techniques) failed: unknown source ID(s): G9999\n"
        "  Hint: check source IDs at https://attack.mitre.org "
        "(groups G####, software S####, campaigns C####)"
    )


def test_step_error_wraps_unexpected_exception_with_type_and_traceback_hint(
    tmp_path: Path, mini_bundle_path: Path, monkeypatch
):
    config = _offline_config(tmp_path, mini_bundle_path)

    def _boom(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr("lag.scoring.score_techniques", _boom)

    with pytest.raises(pipeline.StepError) as excinfo:
        pipeline.run(config)

    error = excinfo.value
    assert isinstance(error.cause, ValueError)
    assert "ValueError: boom" in str(error)
    assert "rerun with -v for the full traceback" in str(error)


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
