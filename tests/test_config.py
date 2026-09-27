"""Tests for lag.config: TOML loading, validation, path resolution, EXAMPLE_CONFIG."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from lag.config import EXAMPLE_CONFIG, config_from_dict, load_config
from lag.errors import LagError
from lag.models import Config

MINIMAL = {"sources": {"G0128": 1}}


def test_minimal_config_ok(tmp_path: Path) -> None:
    config = config_from_dict(MINIMAL, tmp_path)
    assert config.sources == {"G0128": 1}
    assert config.name == "Analytic Plan"


def test_unknown_top_level_key_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "domian": "typo"}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_unknown_nested_key_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "site": {"enalbed": True}}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


@pytest.mark.parametrize("bad_id", ["X0128", "G012", "g012x", "G01288"])
def test_bad_source_id_raises(tmp_path: Path, bad_id: str) -> None:
    with pytest.raises(LagError, match="invalid source ID"):
        config_from_dict({"sources": {bad_id: 1}}, tmp_path)


def test_source_id_normalized_to_upper(tmp_path: Path) -> None:
    config = config_from_dict({"sources": {"g0128": 2}}, tmp_path)
    assert config.sources == {"G0128": 2}


def test_float_weight_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="positive integer"):
        config_from_dict({"sources": {"G0128": 1.5}}, tmp_path)


def test_bool_weight_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="positive integer"):
        config_from_dict({"sources": {"G0128": True}}, tmp_path)


def test_zero_or_negative_weight_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="positive integer"):
        config_from_dict({"sources": {"G0128": 0}}, tmp_path)
    with pytest.raises(LagError, match="positive integer"):
        config_from_dict({"sources": {"G0128": -1}}, tmp_path)


def test_site_table_is_unknown_key(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "site": {"mode": "local"}}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_html_enabled_default_true(tmp_path: Path) -> None:
    config = config_from_dict(MINIMAL, tmp_path)
    assert config.html_enabled is True


def test_html_enabled_can_be_disabled(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "html": {"enabled": False}}
    config = config_from_dict(data, tmp_path)
    assert config.html_enabled is False


def test_html_unknown_key_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "html": {"enabeld": True}}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_html_enabled_must_be_boolean(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "html": {"enabled": "yes"}}
    with pytest.raises(LagError, match="html.enabled"):
        config_from_dict(data, tmp_path)


@pytest.mark.parametrize(
    "gradient",
    [
        ["#8ec843ff"],  # only one color
        ["notacolor", "#ffe766ff"],
        ["#8ec843", "#ggg766"],
        "#8ec843ff",  # not a list at all
    ],
)
def test_bad_gradient_raises(tmp_path: Path, gradient: object) -> None:
    data = {"sources": {"G0128": 1}, "layer": {"gradient": gradient}}
    with pytest.raises(LagError, match="gradient"):
        config_from_dict(data, tmp_path)


def test_gradient_accepts_6_and_8_digit_hex(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "layer": {"gradient": ["#8ec843", "#ffe766ff"]}}
    config = config_from_dict(data, tmp_path)
    assert config.layer_gradient == ["#8ec843", "#ffe766ff"]


def test_no_sources_and_no_custom_layers_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="at least one source, custom layer, or report"):
        config_from_dict({}, tmp_path)


def test_custom_layer_alone_is_enough(tmp_path: Path) -> None:
    data = {"custom_layers": [{"path": "custom.json"}]}
    config = config_from_dict(data, tmp_path)
    assert config.sources == {}
    assert len(config.custom_layers) == 1
    assert config.custom_layers[0].label == "Observed Activity"


def test_custom_layer_unknown_key_raises(tmp_path: Path) -> None:
    data = {"custom_layers": [{"path": "custom.json", "lable": "typo"}]}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_custom_layer_missing_path_raises(tmp_path: Path) -> None:
    data = {"custom_layers": [{"label": "Observed"}]}
    with pytest.raises(LagError, match="path"):
        config_from_dict(data, tmp_path)


def test_relative_paths_resolved_against_base_dir(tmp_path: Path) -> None:
    base_dir = tmp_path / "configs"
    base_dir.mkdir()
    data = {
        "sources": {"G0128": 1},
        "output_dir": "out",
        "attack": {"stix_file": "bundle.json", "cache_dir": "cache"},
        "custom_layers": [{"path": "custom.json"}],
    }
    config = config_from_dict(data, base_dir)
    assert config.output_dir == base_dir / "out"
    assert config.stix_file == base_dir / "bundle.json"
    assert config.cache_dir == base_dir / "cache"
    assert config.custom_layers[0].path == base_dir / "custom.json"


def test_absolute_paths_kept_as_is(tmp_path: Path) -> None:
    absolute = tmp_path / "elsewhere" / "out"
    data = {"sources": {"G0128": 1}, "output_dir": str(absolute)}
    config = config_from_dict(data, tmp_path / "configs")
    assert config.output_dir == absolute


def test_empty_stix_file_means_none(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "attack": {"stix_file": ""}}
    config = config_from_dict(data, tmp_path)
    assert config.stix_file is None


def test_defaults_still_resolved_relative_to_base_dir(tmp_path: Path) -> None:
    base_dir = tmp_path / "configs"
    config = config_from_dict({"sources": {"G0128": 1}}, base_dir)
    assert config.output_dir == base_dir / "output"
    assert config.cache_dir == base_dir / ".lag_cache"


def test_load_config_reads_toml_file(tmp_path: Path) -> None:
    config_path = tmp_path / "plan.toml"
    config_path.write_text("[sources]\nG0128 = 2\n", encoding="utf-8")
    config = load_config(config_path)
    assert config.sources == {"G0128": 2}
    assert config.output_dir == tmp_path / "output"


def test_load_config_missing_file_raises() -> None:
    with pytest.raises(LagError, match="not found"):
        load_config(Path("/nonexistent/plan.toml"))


def test_load_config_invalid_toml_raises(tmp_path: Path) -> None:
    config_path = tmp_path / "plan.toml"
    config_path.write_text("this is not [valid toml", encoding="utf-8")
    with pytest.raises(LagError):
        load_config(config_path)


def test_example_config_round_trips(tmp_path: Path) -> None:
    data = tomllib.loads(EXAMPLE_CONFIG)
    config = config_from_dict(data, tmp_path)
    assert isinstance(config, Config)
    assert config.sources == {"G0128": 2, "S0596": 1}
    assert config.layer_gradient == ["#8ec843ff", "#ffe766ff", "#ff6666ff"]
    assert config.html_enabled is True
    assert len(config.custom_layers) == 1
    assert config.custom_layers[0].path == tmp_path / "custom.json"


def test_example_config_has_no_em_dash() -> None:
    assert "\u2014" not in EXAMPLE_CONFIG


# ---------------------------------------------------------------------------
# reports / llm (Agent G)
# ---------------------------------------------------------------------------


def test_report_minimal_ok(tmp_path: Path) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf"}]}
    config = config_from_dict(data, tmp_path)
    assert len(config.reports) == 1
    report = config.reports[0]
    assert report.source == "https://example.com/report.pdf"
    assert report.label == ""
    assert report.weight == 1
    assert report.min_confidence == "medium"


def test_reports_alone_satisfy_at_least_one_requirement(tmp_path: Path) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf"}]}
    config = config_from_dict(data, tmp_path)
    assert config.sources == {}
    assert config.custom_layers == []


def test_report_missing_source_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="source"):
        config_from_dict({"reports": [{"label": "Report"}]}, tmp_path)


def test_report_unknown_key_raises(tmp_path: Path) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf", "wieght": 2}]}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_report_local_path_resolved_against_base_dir(tmp_path: Path) -> None:
    base_dir = tmp_path / "configs"
    data = {"reports": [{"source": "report.pdf"}]}
    config = config_from_dict(data, base_dir)
    assert config.reports[0].source == str(base_dir / "report.pdf")


def test_report_url_source_kept_as_is(tmp_path: Path) -> None:
    data = {"reports": [{"source": "http://example.com/report.html"}]}
    config = config_from_dict(data, tmp_path)
    assert config.reports[0].source == "http://example.com/report.html"


@pytest.mark.parametrize("bad_weight", [0, -1, 1.5, True])
def test_report_bad_weight_raises(tmp_path: Path, bad_weight: object) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf", "weight": bad_weight}]}
    with pytest.raises(LagError, match="positive integer"):
        config_from_dict(data, tmp_path)


@pytest.mark.parametrize("confidence", ["low", "medium", "high"])
def test_report_valid_min_confidence(tmp_path: Path, confidence: str) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf", "min_confidence": confidence}]}
    config = config_from_dict(data, tmp_path)
    assert config.reports[0].min_confidence == confidence


def test_report_bad_min_confidence_raises(tmp_path: Path) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf", "min_confidence": "extreme"}]}
    with pytest.raises(LagError, match="min_confidence"):
        config_from_dict(data, tmp_path)


def test_report_label_and_weight_override(tmp_path: Path) -> None:
    data = {"reports": [{"source": "https://example.com/report.pdf", "label": "APT Report", "weight": 3}]}
    config = config_from_dict(data, tmp_path)
    assert config.reports[0].label == "APT Report"
    assert config.reports[0].weight == 3


def test_llm_defaults(tmp_path: Path) -> None:
    config = config_from_dict(MINIMAL, tmp_path)
    assert config.llm_provider == "anthropic"
    assert config.llm_model == ""
    assert config.llm_effort == ""
    assert config.llm_base_url == ""
    assert config.llm_api_key_env == ""
    assert config.llm_pdf_input == "auto"


def test_llm_model_and_effort_override(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"model": "claude-sonnet-5", "effort": "low"}}
    config = config_from_dict(data, tmp_path)
    assert config.llm_model == "claude-sonnet-5"
    assert config.llm_effort == "low"


def test_llm_unknown_key_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"modle": "x"}}
    with pytest.raises(LagError, match="unknown key"):
        config_from_dict(data, tmp_path)


def test_llm_bad_effort_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"effort": "ultra"}}
    with pytest.raises(LagError, match="llm.effort"):
        config_from_dict(data, tmp_path)


def test_llm_effort_valid_for_openai_but_invalid_for_anthropic(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"provider": "openai", "model": "gpt-5.5", "effort": "minimal"}}
    config = config_from_dict(data, tmp_path)
    assert config.llm_effort == "minimal"

    bad = {"sources": {"G0128": 1}, "llm": {"provider": "anthropic", "effort": "minimal"}}
    with pytest.raises(LagError, match="llm.effort"):
        config_from_dict(bad, tmp_path)


def test_llm_empty_model_is_valid_by_default(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"model": ""}}
    config = config_from_dict(data, tmp_path)
    assert config.llm_model == ""


def test_llm_bad_provider_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"provider": "azure"}}
    with pytest.raises(LagError, match="llm.provider"):
        config_from_dict(data, tmp_path)


def test_llm_base_url_requires_openai_provider(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"base_url": "http://localhost:11434/v1"}}
    with pytest.raises(LagError, match="llm.base_url"):
        config_from_dict(data, tmp_path)


def test_llm_base_url_allowed_with_openai_provider(tmp_path: Path) -> None:
    data = {
        "sources": {"G0128": 1},
        "llm": {"provider": "openai", "model": "gpt-5.5", "base_url": "http://localhost:11434/v1"},
    }
    config = config_from_dict(data, tmp_path)
    assert config.llm_base_url == "http://localhost:11434/v1"


def test_llm_bad_pdf_input_raises(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"pdf_input": "images"}}
    with pytest.raises(LagError, match="llm.pdf_input"):
        config_from_dict(data, tmp_path)


def test_llm_api_key_env_parses(tmp_path: Path) -> None:
    data = {"sources": {"G0128": 1}, "llm": {"api_key_env": "MY_KEY"}}
    config = config_from_dict(data, tmp_path)
    assert config.llm_api_key_env == "MY_KEY"


def test_reports_with_openai_provider_and_no_model_raises(tmp_path: Path) -> None:
    data = {
        "reports": [{"source": "https://example.com/report.pdf"}],
        "llm": {"provider": "openai"},
    }
    with pytest.raises(LagError, match='llm.model is required for provider "openai"'):
        config_from_dict(data, tmp_path)


def test_reports_with_openai_provider_and_model_ok(tmp_path: Path) -> None:
    data = {
        "reports": [{"source": "https://example.com/report.pdf"}],
        "llm": {"provider": "openai", "model": "gpt-5.5"},
    }
    config = config_from_dict(data, tmp_path)
    assert config.llm_model == "gpt-5.5"


def test_example_config_reports_are_commented_out(tmp_path: Path) -> None:
    data = tomllib.loads(EXAMPLE_CONFIG)
    config = config_from_dict(data, tmp_path)
    assert config.reports == []


def test_example_config_llm_table(tmp_path: Path) -> None:
    data = tomllib.loads(EXAMPLE_CONFIG)
    config = config_from_dict(data, tmp_path)
    assert config.llm_provider == "anthropic"
    assert config.llm_model == ""
    assert config.llm_effort == ""
    assert config.llm_pdf_input == "auto"


@pytest.mark.parametrize("value", [0, 1.5, -0.1, True, "0.3"])
def test_network_min_share_rejects_bad_values(tmp_path, value):
    with pytest.raises(LagError, match="network_min_share"):
        config_from_dict({"sources": {"G0128": 1}, "analytics": {"network_min_share": value}}, tmp_path)


def test_network_min_share_parses(tmp_path):
    config = config_from_dict({"sources": {"G0128": 1}, "analytics": {"network_min_share": 0.5}}, tmp_path)
    assert config.network_min_share == 0.5
