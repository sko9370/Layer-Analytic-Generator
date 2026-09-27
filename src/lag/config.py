"""Load and validate lag configuration from TOML."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from lag.errors import LagError
from lag.models import CONFIDENCE_LEVELS, Config, CustomLayer, ReportSource

SOURCE_ID_RE = re.compile(r"^[GSC]\d{4}$")
GRADIENT_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}([0-9a-fA-F]{2})?$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
LLM_EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")

_TOP_LEVEL_KEYS = {
    "name",
    "domain",
    "output_dir",
    "sources",
    "custom_layers",
    "reports",
    "attack",
    "analytics",
    "layer",
    "html",
    "llm",
}
_ATTACK_KEYS = {"version", "stix_file", "cache_dir", "offline"}
_ANALYTICS_KEYS = {
    "car",
    "car_coverage_url",
    "jpcert",
    "jpcert_tool_list_url",
    "network_data_components",
}
_LAYER_KEYS = {"gradient"}
_HTML_KEYS = {"enabled"}
_CUSTOM_LAYER_KEYS = {"path", "label"}
_REPORT_KEYS = {"source", "label", "weight", "min_confidence"}
_LLM_KEYS = {"model", "effort"}

_DEFAULTS = Config()

EXAMPLE_CONFIG = """\
name = "Analytic Plan"
domain = "enterprise-attack"
output_dir = "output"

[sources]            # ATT&CK Group (G####), Software (S####), Campaign (C####) ID = positive integer weight
G0128 = 2
S0596 = 1

[[custom_layers]]    # optional, repeatable
path = "custom.json"
label = "Observed Activity"

# [[reports]]          # optional, repeatable: a threat report read by an LLM (Claude) for its techniques
# source = "https://example.com/report.pdf"   # URL, or a local .pdf/.html/.htm/.txt/.md path
# label = ""           # "" = "Report: <title>"
# weight = 1
# min_confidence = "medium"    # low, medium, high

[llm]                 # only used when [[reports]] entries are present
model = "claude-opus-5"
effort = "high"       # low, medium, high, xhigh, max
# needs an API key: set ANTHROPIC_API_KEY, or run `ant auth login` once.
# results are cached under attack.cache_dir, so rebuilds do not re-bill the API.

[attack]
version = ""         # "" = latest
stix_file = ""        # "" = download
cache_dir = ".lag_cache"
offline = false

[analytics]
car = true
car_coverage_url = "https://raw.githubusercontent.com/mitre-attack/car/master/docs/coverage/splunk_analytic_coverage_01_08_2024.json"
jpcert = true
jpcert_tool_list_url = "https://raw.githubusercontent.com/JPCERTCC/ToolAnalysisResultSheet/master/tool-list.html"
network_data_components = ["Network Connection Creation", "Network Traffic Content", "Network Traffic Flow"]

[layer]
gradient = ["#8ec843ff", "#ffe766ff", "#ff6666ff"]

[html]
enabled = true       # writes a single self-contained analytic_plan.html that opens offline
"""


def _check_keys(table: dict, allowed: set[str], where: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise LagError(f"unknown key(s) in {where}: {', '.join(sorted(unknown))}")


def _resolve_path(value: str | Path, base_dir: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base_dir / path


def _validate_gradient(gradient: object) -> list[str]:
    if not isinstance(gradient, list) or len(gradient) < 2:
        raise LagError("layer.gradient must be a list of at least two colors")
    for color in gradient:
        if not isinstance(color, str) or not GRADIENT_COLOR_RE.fullmatch(color):
            raise LagError(f"invalid gradient color: {color!r}")
    return list(gradient)


def _parse_sources(raw: object) -> dict[str, int]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise LagError("sources must be a table of ID = weight")
    sources: dict[str, int] = {}
    for key, value in raw.items():
        source_id = str(key).upper()
        if not SOURCE_ID_RE.fullmatch(source_id):
            raise LagError(f"invalid source ID: {key!r} (expected G####, S#### or C####)")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise LagError(f"source {key!r} weight must be a positive integer, got {value!r}")
        sources[source_id] = value
    return sources


def _parse_custom_layers(raw: object, base_dir: Path) -> list[CustomLayer]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise LagError("custom_layers must be a list of tables")
    layers: list[CustomLayer] = []
    for i, table in enumerate(raw):
        if not isinstance(table, dict):
            raise LagError(f"custom_layers[{i}] must be a table")
        _check_keys(table, _CUSTOM_LAYER_KEYS, f"custom_layers[{i}]")
        if not table.get("path"):
            raise LagError(f"custom_layers[{i}] is missing path")
        path = _resolve_path(table["path"], base_dir)
        label = table.get("label", CustomLayer.label)
        layers.append(CustomLayer(path=path, label=label))
    return layers


def _parse_reports(raw: object, base_dir: Path) -> list[ReportSource]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise LagError("reports must be a list of tables")
    reports: list[ReportSource] = []
    for i, table in enumerate(raw):
        if not isinstance(table, dict):
            raise LagError(f"reports[{i}] must be a table")
        _check_keys(table, _REPORT_KEYS, f"reports[{i}]")

        source = table.get("source", "")
        if not isinstance(source, str) or not source:
            raise LagError(f"reports[{i}] is missing source")
        if not URL_RE.match(source):
            source = str(_resolve_path(source, base_dir))

        label = table.get("label", ReportSource.label)
        if not isinstance(label, str):
            raise LagError(f"reports[{i}].label must be a string")

        weight = table.get("weight", ReportSource.weight)
        if isinstance(weight, bool) or not isinstance(weight, int) or weight <= 0:
            raise LagError(f"reports[{i}].weight must be a positive integer, got {weight!r}")

        min_confidence = table.get("min_confidence", ReportSource.min_confidence)
        if min_confidence not in CONFIDENCE_LEVELS:
            raise LagError(
                f"reports[{i}].min_confidence must be one of {', '.join(CONFIDENCE_LEVELS)}, "
                f"got {min_confidence!r}"
            )

        reports.append(ReportSource(source=source, label=label, weight=weight, min_confidence=min_confidence))
    return reports


def config_from_dict(data: dict, base_dir: Path) -> Config:
    """Validate and build a Config from a parsed TOML dict. Relative paths resolve against base_dir."""
    _check_keys(data, _TOP_LEVEL_KEYS, "config")

    name = data.get("name", _DEFAULTS.name)
    domain = data.get("domain", _DEFAULTS.domain)
    output_dir = _resolve_path(data.get("output_dir", str(_DEFAULTS.output_dir)), base_dir)

    sources = _parse_sources(data.get("sources"))
    custom_layers = _parse_custom_layers(data.get("custom_layers"), base_dir)
    reports = _parse_reports(data.get("reports"), base_dir)
    if not sources and not custom_layers and not reports:
        raise LagError("config must define at least one source, custom layer, or report")

    attack_table = data.get("attack", {})
    if not isinstance(attack_table, dict):
        raise LagError("attack must be a table")
    _check_keys(attack_table, _ATTACK_KEYS, "attack")
    attack_version = attack_table.get("version", _DEFAULTS.attack_version)
    stix_file_raw = attack_table.get("stix_file", "")
    stix_file = _resolve_path(stix_file_raw, base_dir) if stix_file_raw else None
    cache_dir = _resolve_path(attack_table.get("cache_dir", str(_DEFAULTS.cache_dir)), base_dir)
    offline = attack_table.get("offline", _DEFAULTS.offline)
    if not isinstance(offline, bool):
        raise LagError("attack.offline must be a boolean")

    analytics_table = data.get("analytics", {})
    if not isinstance(analytics_table, dict):
        raise LagError("analytics must be a table")
    _check_keys(analytics_table, _ANALYTICS_KEYS, "analytics")
    car_enabled = analytics_table.get("car", _DEFAULTS.car_enabled)
    car_coverage_url = analytics_table.get("car_coverage_url", _DEFAULTS.car_coverage_url)
    jpcert_enabled = analytics_table.get("jpcert", _DEFAULTS.jpcert_enabled)
    jpcert_tool_list_url = analytics_table.get("jpcert_tool_list_url", _DEFAULTS.jpcert_tool_list_url)
    network_data_components = analytics_table.get(
        "network_data_components", list(_DEFAULTS.network_data_components)
    )
    if not isinstance(network_data_components, list):
        raise LagError("analytics.network_data_components must be a list")

    layer_table = data.get("layer", {})
    if not isinstance(layer_table, dict):
        raise LagError("layer must be a table")
    _check_keys(layer_table, _LAYER_KEYS, "layer")
    gradient = _validate_gradient(layer_table.get("gradient", list(_DEFAULTS.layer_gradient)))

    html_table = data.get("html", {})
    if not isinstance(html_table, dict):
        raise LagError("html must be a table")
    _check_keys(html_table, _HTML_KEYS, "html")
    html_enabled = html_table.get("enabled", _DEFAULTS.html_enabled)
    if not isinstance(html_enabled, bool):
        raise LagError("html.enabled must be a boolean")

    llm_table = data.get("llm", {})
    if not isinstance(llm_table, dict):
        raise LagError("llm must be a table")
    _check_keys(llm_table, _LLM_KEYS, "llm")
    llm_model = llm_table.get("model", _DEFAULTS.llm_model)
    if not isinstance(llm_model, str) or not llm_model:
        raise LagError("llm.model must be a non-empty string")
    llm_effort = llm_table.get("effort", _DEFAULTS.llm_effort)
    if llm_effort not in LLM_EFFORT_LEVELS:
        raise LagError(f"llm.effort must be one of {', '.join(LLM_EFFORT_LEVELS)}, got {llm_effort!r}")

    return Config(
        name=name,
        domain=domain,
        output_dir=output_dir,
        sources=sources,
        custom_layers=custom_layers,
        reports=reports,
        llm_model=llm_model,
        llm_effort=llm_effort,
        attack_version=attack_version,
        stix_file=stix_file,
        cache_dir=cache_dir,
        offline=offline,
        car_enabled=car_enabled,
        car_coverage_url=car_coverage_url,
        jpcert_enabled=jpcert_enabled,
        jpcert_tool_list_url=jpcert_tool_list_url,
        network_data_components=network_data_components,
        layer_gradient=gradient,
        html_enabled=html_enabled,
    )


def load_config(path: Path) -> Config:
    """Load and validate a TOML config file. Relative paths in it resolve against its directory."""
    path = Path(path)
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError as exc:
        raise LagError(f"config file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise LagError(f"invalid TOML in {path}: {exc}") from exc
    return config_from_dict(data, path.parent)
