"""Tests for lag.cli: init, build, extract, --source parsing, LagError handling, and
`python -m lag`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from lag import cli
from lag.errors import LagError


def test_parse_source_default_weight():
    assert cli._parse_source("G0128") == ("G0128", 1)


def test_parse_source_explicit_weight():
    assert cli._parse_source("G0128=2") == ("G0128", 2)


def test_parse_source_invalid_weight_raises_lag_error():
    with pytest.raises(LagError):
        cli._parse_source("G0128=abc")


def test_init_writes_file(tmp_path: Path):
    path = tmp_path / "plan.toml"
    rc = cli.main(["init", str(path)])
    assert rc == 0
    assert path.exists()
    assert path.read_text(encoding="utf-8").strip() != ""


def test_init_refuses_overwrite_without_force(tmp_path: Path, capsys):
    path = tmp_path / "plan.toml"
    path.write_text('name = "existing"\n', encoding="utf-8")

    rc = cli.main(["init", str(path)])

    assert rc == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert path.read_text(encoding="utf-8") == 'name = "existing"\n'


def test_init_force_overwrites(tmp_path: Path):
    path = tmp_path / "plan.toml"
    path.write_text('name = "existing"\n', encoding="utf-8")

    rc = cli.main(["init", str(path), "--force"])

    assert rc == 0
    assert path.read_text(encoding="utf-8") != 'name = "existing"\n'


def test_build_with_no_sources_and_no_config_is_lag_error(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["build"])
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error:")


def test_build_missing_config_file_is_lag_error(tmp_path: Path, capsys):
    missing = tmp_path / "does_not_exist.toml"
    rc = cli.main(["build", "-c", str(missing)])
    assert rc == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err


def test_python_dash_m_lag_help_works():
    result = subprocess.run(
        [sys.executable, "-m", "lag", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert "usage" in result.stdout.lower() or "usage" in result.stderr.lower()


def test_python_dash_m_lag_build_offline_end_to_end(tmp_path: Path, mini_bundle_path: Path):
    output_dir = tmp_path / "out"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "lag",
            "build",
            "--source",
            "G0128=2",
            "--source",
            "S0596=1",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
            "--no-html",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert (output_dir / "layer.json").exists()
    assert (output_dir / "analytic_plan.csv").exists()
    assert not (output_dir / "analytic_plan.html").exists()


# ---------------------------------------------------------------------------
# Progress output, -v / -q, and StepError formatting
# ---------------------------------------------------------------------------


def test_build_prints_progress_lines_to_stderr_by_default(tmp_path: Path, mini_bundle_path: Path, capsys):
    output_dir = tmp_path / "out"
    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=2",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "[1/6] Load ATT&CK data..." in captured.err
    assert "Layer:" in captured.out


def test_build_quiet_suppresses_progress_lines(tmp_path: Path, mini_bundle_path: Path, capsys):
    output_dir = tmp_path / "out"
    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=2",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
            "--quiet",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "[1/6]" not in captured.err
    assert "Load ATT&CK data" not in captured.err
    assert "Layer:" in captured.out


def test_build_unknown_source_prints_step_error_with_hint(tmp_path: Path, mini_bundle_path: Path, capsys):
    output_dir = tmp_path / "out"
    rc = cli.main(
        [
            "build",
            "--source",
            "G9999=1",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("[1/6]")
    assert "error: Step 2/6 (Score techniques) failed: unknown source ID(s): G9999" in captured.err
    assert "Hint: check source IDs at https://attack.mitre.org" in captured.err


def test_build_missing_stix_file_prints_step_error(tmp_path: Path, capsys):
    output_dir = tmp_path / "out"
    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=1",
            "--stix-file",
            str(tmp_path / "does_not_exist.json"),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert "error: Step 1/6 (Load ATT&CK data) failed: STIX file not found" in captured.err
    assert "Hint: check network access" in captured.err


def test_build_step_wraps_unexpected_exception_as_step_error(
    tmp_path: Path, mini_bundle_path: Path, capsys, monkeypatch
):
    # A failure inside a pipeline step, even one the step's own code did not anticipate, is still
    # a StepError (exit 2), not the generic "unexpected exception outside steps" path (exit 1).
    output_dir = tmp_path / "out"

    def _boom(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("lag.scoring.score_techniques", _boom)

    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=1",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert "RuntimeError: kaboom" in captured.err
    assert "rerun with -v for the full traceback" in captured.err


def test_build_unexpected_exception_outside_steps_gives_exit_code_1(tmp_path: Path, capsys, monkeypatch):
    def boom(config, progress=None):
        raise RuntimeError("kaboom")

    monkeypatch.setattr("lag.pipeline.run", boom)
    rc = cli.main(["build", "--source", "G0128=1", "--output-dir", str(tmp_path / "out")])
    assert rc == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error: unexpected RuntimeError: kaboom")
    assert "rerun with -v for details" in captured.err


def test_build_output_dir_that_is_a_file_fails_in_layer_step(tmp_path: Path, capsys):
    output_dir = tmp_path / "out"
    output_dir.write_text("not a directory", encoding="utf-8")
    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=1",
            "--stix-file",
            "tests/fixtures/mini_enterprise.json",
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "(Write Navigator layer) failed" in err
    assert "Hint: check that output_dir is writable" in err


def test_build_with_report_calls_run_report(tmp_path: Path, mini_bundle_path: Path, capsys, monkeypatch):
    from lag.models import Procedure, TechniqueEntry

    output_dir = tmp_path / "out"

    def fake_run_report(report, attack, config, client=None):
        class FakeExtraction:
            source = report.source
            title = "A Report"
            model = config.llm_model
            techniques = []
            dropped: list[str] = []

        entry = TechniqueEntry(
            technique_id="T1547.001",
            score=report.weight,
            procedures=[
                Procedure(
                    source_id="Report: A Report",
                    source_name="Report: A Report",
                    technique_id="T1547.001",
                    description="Actor persisted via a boot script.",
                    citations=[],
                )
            ],
            links=[],
        )
        return FakeExtraction(), [entry]

    monkeypatch.setattr("lag.extract.run_report", fake_run_report)

    rc = cli.main(
        [
            "build",
            "--source",
            "G0128=1",
            "--report",
            "https://example.com/report.pdf",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
            "--no-html",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "Report 'Report: A Report': 1 technique(s) kept" in captured.out


# ---------------------------------------------------------------------------
# `lag extract`
# ---------------------------------------------------------------------------


def test_extract_writes_layer_and_prints_table(tmp_path: Path, mini_bundle_path: Path, capsys, monkeypatch):
    from lag import extract

    output_dir = tmp_path / "out"

    def fake_run_report(report, attack, config, client=None):
        extraction = extract.Extraction(
            source=report.source,
            title="A Sample Report",
            model=config.llm_model,
            techniques=[
                extract.ExtractedTechnique(
                    technique_id="T1547.001",
                    evidence="The actor added a registry run key to persist.",
                    quote="added a run key",
                    confidence="high",
                ),
            ],
            dropped=["T9999"],
        )
        entries = extract.extraction_to_entries(extraction, report, report.label or "Report: A Sample Report")
        return extraction, entries

    monkeypatch.setattr(extract, "run_report", fake_run_report)

    rc = cli.main(
        [
            "extract",
            "https://example.com/report.pdf",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(output_dir),
        ]
    )

    assert rc == 0
    captured = capsys.readouterr()
    assert "T1547.001" in captured.out
    assert "high" in captured.out
    assert "Kept 1 technique(s); dropped 1 unknown ID(s): T9999" in captured.out
    assert "[[custom_layers]]" in captured.out
    assert "[[reports]]" in captured.out

    written = list(output_dir.glob("report_*.json"))
    assert len(written) == 1
    layer = json.loads(written[0].read_text(encoding="utf-8"))
    assert layer["techniques"][0]["techniqueID"] == "T1547.001"


def test_extract_works_without_a_config_file(tmp_path: Path, mini_bundle_path: Path, monkeypatch):
    from lag import extract

    def fake_run_report(report, attack, config, client=None):
        return extract.Extraction(
            source=report.source, title="T", model=config.llm_model, techniques=[], dropped=[]
        ), []

    monkeypatch.setattr(extract, "run_report", fake_run_report)

    rc = cli.main(
        [
            "extract",
            "report.txt",
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 0


def test_extract_propagates_step_error_when_extraction_fails(tmp_path: Path, mini_bundle_path: Path, capsys):
    rc = cli.main(
        [
            "extract",
            str(tmp_path / "report.txt"),
            "--stix-file",
            str(mini_bundle_path),
            "--offline",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert rc == 2
    captured = capsys.readouterr()
    assert "error: Step 2/2" in captured.err
