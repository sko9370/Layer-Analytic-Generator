"""Tests for lag.cli: init, --source parsing, LagError handling, and `python -m lag`."""

from __future__ import annotations

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
