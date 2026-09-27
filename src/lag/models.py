"""Shared data model. Every module reads and writes these types; keep them free of logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# ATT&CK knowledge base (populated by lag.attack)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Citation:
    label: str  # STIX external_reference source_name, e.g. "FireEye APT38 Oct 2018"
    url: str | None  # may be None when ATT&CK has no URL for the reference


@dataclass
class Tactic:
    attack_id: str  # "TA0011"
    shortname: str  # "command-and-control" (the kill_chain phase_name)
    name: str  # "Command and Control"


@dataclass
class LogSource:
    data_component: str  # data component name, e.g. "Process Creation"
    name: str  # log source name, e.g. "WinEventLog:Security"
    channel: str  # e.g. "EventCode=4688"


@dataclass
class Analytic:
    attack_id: str  # "AN0110"
    url: str
    description: str
    platforms: list[str]
    log_sources: list[LogSource]


@dataclass
class DetectionStrategy:
    attack_id: str  # "DET0103"
    name: str
    url: str
    analytics: list[Analytic]


@dataclass
class Technique:
    attack_id: str  # "T1055.011"
    name: str  # own name, e.g. "Extra Window Memory Injection"
    full_name: str  # "Process Injection: Extra Window Memory Injection" for subs, else == name
    description: str  # raw ATT&CK markdown, still containing "(Citation: X)" markers
    citations: dict[str, Citation]  # label -> Citation, from the technique's own external_references
    tactics: list[str]  # tactic shortnames, ordered by matrix order
    platforms: list[str]
    url: str
    parent_id: str | None  # "T1055" for a sub-technique, None otherwise
    detection_strategies: list[DetectionStrategy] = field(default_factory=list)


@dataclass
class Procedure:
    """How one source (group, software, campaign, or imported layer) used one technique."""

    source_id: str  # "G0128", "S0596", "C0024", or an imported layer label such as "Observed Activity"
    source_name: str  # "ZIRCONIUM"; for imported layers, the layer label
    technique_id: str  # "T1059.003"
    description: str  # raw markdown text, may contain "(Citation: X)" markers
    citations: list[Citation]  # resolved from the relationship's own external_references, first-seen order


@dataclass
class AttackData:
    version: str  # ATT&CK release, e.g. "19.2"
    domain: str  # "enterprise-attack"
    techniques: dict[str, Technique]  # by ATT&CK ID; revoked and deprecated objects excluded
    tactics: list[Tactic]  # matrix order
    sources: dict[str, str]  # ATT&CK ID -> name for every group, software, and campaign
    procedures: dict[str, list[Procedure]]  # source ATT&CK ID -> procedures of that source


# ---------------------------------------------------------------------------
# Scoring output (populated by lag.scoring)
# ---------------------------------------------------------------------------


@dataclass
class TechniqueEntry:
    """One scored technique in the output layer and plan."""

    technique_id: str
    score: int
    procedures: list[Procedure]  # every procedure that contributed, in input order
    links: list[Citation]  # extra links (e.g. carried over from an imported layer), deduplicated


# ---------------------------------------------------------------------------
# Configuration (loaded by lag.config)
# ---------------------------------------------------------------------------

DEFAULT_NETWORK_DATA_COMPONENTS = [
    "Network Connection Creation",
    "Network Traffic Content",
    "Network Traffic Flow",
]

DEFAULT_GRADIENT = ["#8ec843ff", "#ffe766ff", "#ff6666ff"]

DEFAULT_CAR_COVERAGE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/car/master/docs/coverage/"
    "splunk_analytic_coverage_01_08_2024.json"
)
DEFAULT_JPCERT_TOOL_LIST_URL = (
    "https://raw.githubusercontent.com/JPCERTCC/ToolAnalysisResultSheet/master/tool-list.html"
)


@dataclass
class CustomLayer:
    path: Path
    label: str = "Observed Activity"


CONFIDENCE_LEVELS = ("low", "medium", "high")
DEFAULT_LLM_MODEL = "claude-opus-5"


@dataclass
class ReportSource:
    """A threat report (URL or local file) whose techniques an LLM extracts for the plan."""

    source: str  # http(s) URL or local file path (.pdf, .html, .htm, .txt, .md)
    label: str = ""  # shown as the procedure source; "" means derive one from the source
    weight: int = 1  # score added to every technique extracted from this report
    min_confidence: str = "medium"  # drop techniques below this confidence ("low", "medium", "high")


@dataclass
class Config:
    name: str = "Analytic Plan"
    domain: str = "enterprise-attack"
    output_dir: Path = Path("output")
    # ATT&CK Group / Software / Campaign ID -> positive integer weight
    sources: dict[str, int] = field(default_factory=dict)
    custom_layers: list[CustomLayer] = field(default_factory=list)
    reports: list[ReportSource] = field(default_factory=list)
    # LLM report extraction (Anthropic API; key from ANTHROPIC_API_KEY or an `ant auth login` profile)
    llm_model: str = DEFAULT_LLM_MODEL
    llm_effort: str = "high"  # "low", "medium", "high", "xhigh", or "max"
    # ATT&CK data
    attack_version: str = ""  # "" means latest
    stix_file: Path | None = None  # local STIX bundle; skips download
    cache_dir: Path = Path(".lag_cache")
    offline: bool = False  # never touch the network; fail if something is not cached or local
    # analytics
    car_enabled: bool = True
    car_coverage_url: str = DEFAULT_CAR_COVERAGE_URL
    jpcert_enabled: bool = True
    jpcert_tool_list_url: str = DEFAULT_JPCERT_TOOL_LIST_URL
    network_data_components: list[str] = field(default_factory=lambda: list(DEFAULT_NETWORK_DATA_COMPONENTS))
    # navigator layer
    layer_gradient: list[str] = field(default_factory=lambda: list(DEFAULT_GRADIENT))
    # single-file HTML analytic plan
    html_enabled: bool = True
