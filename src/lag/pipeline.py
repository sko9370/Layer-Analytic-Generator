"""End-to-end run: ATT&CK data (and optional custom layers / threat reports) in,
layer.json / analytic_plan.csv / analytic_plan.html out.

Every step is run through `run_step`, which reports progress before and after the step and,
on failure, raises a `StepError` naming the step, the underlying cause, and a hint for fixing it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

from lag import analytics, attack, html, layers, plan, scoring
from lag.errors import LagError
from lag.models import Config, TechniqueEntry

logger = logging.getLogger(__name__)

T = TypeVar("T")

ProgressFunc = Callable[[str], None]


class StepError(LagError):
    """A pipeline step failed. Carries the step number/title, the original cause, and a hint.

    str(error) == f"Step {step_number}/{step_total} ({step_title}) failed: <cause>\\n  Hint: <hint>".
    For an exception that was not already a LagError, <cause> also names the exception type.
    """

    def __init__(
        self,
        step_number: int,
        step_total: int,
        step_title: str,
        cause: Exception,
        hint: str,
    ) -> None:
        self.step_number = step_number
        self.step_total = step_total
        self.step_title = step_title
        self.cause = cause
        self.hint = hint
        cause_text = str(cause) if isinstance(cause, LagError) else f"{type(cause).__name__}: {cause}"
        message = f"Step {step_number}/{step_total} ({step_title}) failed: {cause_text}\n  Hint: {hint}"
        super().__init__(message)


def run_step(
    progress: ProgressFunc,
    step_number: int,
    step_total: int,
    title: str,
    hint: str,
    func: Callable[[], tuple[T, str]],
) -> T:
    """Run one pipeline step: report progress, run func (which returns (value, short result)),
    report the result, and return the value. Any exception is re-raised as a StepError."""
    progress(f"[{step_number}/{step_total}] {title}...")
    try:
        value, summary = func()
    except LagError as exc:
        raise StepError(step_number, step_total, title, exc, hint) from exc
    except Exception as exc:  # noqa: BLE001 - any failure here must become a helpful StepError
        full_hint = f"{hint} (rerun with -v for the full traceback)"
        raise StepError(step_number, step_total, title, exc, full_hint) from exc
    progress(f"[{step_number}/{step_total}] {title}: {summary}")
    return value


@dataclass
class RunResult:
    attack_version: str
    technique_count: int
    layer_path: Path
    csv_path: Path
    html_path: Path | None = None
    # per-report (label, techniques kept, IDs the model returned that were not in ATT&CK)
    extractions: list[tuple[str, int, list[str]]] = field(default_factory=list)


def _load_attack_step(config: Config) -> tuple[attack.AttackData, str]:
    data = attack.load_attack(config)
    return data, f"ATT&CK {data.version}, {len(data.techniques)} techniques"


def _read_custom_layers_step(
    config: Config, attack_data: attack.AttackData
) -> tuple[list[TechniqueEntry], str]:
    imported: list[TechniqueEntry] = []
    for custom_layer in config.custom_layers:
        imported.extend(layers.read_custom_layer(custom_layer, attack_data))
    return imported, f"{len(imported)} technique(s) from {len(config.custom_layers)} custom layer(s)"


def _extract_reports_step(
    config: Config, attack_data: attack.AttackData
) -> tuple[tuple[list[TechniqueEntry], list[tuple[str, int, list[str]]]], str]:
    from lag import extract  # lazy: only reports configured need the anthropic package

    entries: list[TechniqueEntry] = []
    extractions: list[tuple[str, int, list[str]]] = []
    for report in config.reports:
        extraction, report_entries = extract.run_report(report, attack_data, config)
        if report_entries:
            label = report_entries[0].procedures[0].source_id
        else:
            label = report.label or extraction.title or report.source
        dropped = list(extraction.dropped)
        logger.info(
            "report %s: %d technique(s) kept, %d dropped%s",
            label,
            len(report_entries),
            len(dropped),
            f" ({', '.join(dropped)})" if dropped else "",
        )
        extractions.append((label, len(report_entries), dropped))
        entries.extend(report_entries)

    summary = "; ".join(
        f"{label}: {kept} kept, {len(dropped)} dropped" for label, kept, dropped in extractions
    )
    return (entries, extractions), summary or "no reports"


def _score_step(
    config: Config, attack_data: attack.AttackData, imported: list[TechniqueEntry]
) -> tuple[list[TechniqueEntry], str]:
    entries = scoring.score_techniques(attack_data, config, imported)
    if not entries:
        raise LagError("no techniques were scored: check your sources, custom layers, and reports")
    return entries, f"{len(entries)} technique(s) scored"


def _write_layer_step(
    entries: list[TechniqueEntry], attack_data: attack.AttackData, config: Config, layer_path: Path
) -> tuple[Path, str]:
    layers.write_layer(layers.build_layer(entries, attack_data, config), layer_path)
    return layer_path, str(layer_path)


def _load_analytic_sources_step(config: Config) -> tuple[analytics.AnalyticSources, str]:
    sources = analytics.load_analytic_sources(config)
    return (
        sources,
        f"{len(sources.car_techniques)} CAR technique(s), {len(sources.jpcert_tools)} JPCERT tool(s)",
    )


def _build_plan_step(
    entries: list[TechniqueEntry],
    attack_data: attack.AttackData,
    config: Config,
    sources: analytics.AnalyticSources,
    csv_path: Path,
) -> tuple[list[plan.PlanRow], str]:
    rows = plan.build_plan(entries, attack_data, config, sources)
    plan.write_csv(rows, csv_path)
    return rows, str(csv_path)


def _write_html_step(
    rows: list[plan.PlanRow], attack_data: attack.AttackData, config: Config, html_path: Path
) -> tuple[Path, str]:
    path = html.build_html(rows, attack_data, config, html_path)
    return path, str(path)


def run(config: Config, progress: ProgressFunc | None = None) -> RunResult:
    """Run the full pipeline for one config: load ATT&CK, read custom layers, extract report
    techniques, score, write the layer and CSV, and (if enabled) build the HTML plan.

    progress (default logger.info) receives one "[n/N] step..." line before each step and one
    "[n/N] step: result" line after. Any step failure raises StepError, which names the step,
    the cause, and a hint for fixing it.
    """
    if progress is None:
        progress = logger.info

    output_dir = config.output_dir  # created by the writers, inside their steps

    total = 5  # load, score, write layer, load analytic sources, build plan
    if config.custom_layers:
        total += 1
    if config.reports:
        total += 1
    if config.html_enabled:
        total += 1

    step = 0

    def next_step() -> int:
        nonlocal step
        step += 1
        return step

    attack_data = run_step(
        progress,
        next_step(),
        total,
        "Load ATT&CK data",
        "check network access to raw.githubusercontent.com, or set attack.stix_file to a local "
        "enterprise-attack.json; with attack.offline = true the data must already be cached",
        lambda: _load_attack_step(config),
    )

    imported: list[TechniqueEntry] = []
    if config.custom_layers:
        imported = run_step(
            progress,
            next_step(),
            total,
            "Read custom layers",
            "check the path and that the file is a Navigator layer JSON export",
            lambda: _read_custom_layers_step(config, attack_data),
        )

    report_entries: list[TechniqueEntry] = []
    extractions: list[tuple[str, int, list[str]]] = []
    if config.reports:
        from lag import extract  # lazy: only reports configured need this (and the SDK it wraps)

        llm_settings = extract.resolve_llm_settings(config)
        report_entries, extractions = run_step(
            progress,
            next_step(),
            total,
            f"Extract techniques from reports with {llm_settings.provider}:{llm_settings.model}",
            extract.llm_credentials_hint(llm_settings),
            lambda: _extract_reports_step(config, attack_data),
        )

    entries = run_step(
        progress,
        next_step(),
        total,
        "Score techniques",
        "check source IDs at https://attack.mitre.org (groups G####, software S####, campaigns C####)",
        lambda: _score_step(config, attack_data, imported + report_entries),
    )

    layer_path = output_dir / "layer.json"
    run_step(
        progress,
        next_step(),
        total,
        "Write Navigator layer",
        "check that output_dir is writable",
        lambda: _write_layer_step(entries, attack_data, config, layer_path),
    )

    sources = run_step(
        progress,
        next_step(),
        total,
        "Load analytic sources (CAR, JPCERT)",
        "check network access, or disable a source in [analytics]; these already degrade to "
        "warnings on their own and never fail the run",
        lambda: _load_analytic_sources_step(config),
    )

    csv_path = output_dir / "analytic_plan.csv"
    rows = run_step(
        progress,
        next_step(),
        total,
        "Build analytic plan and write CSV",
        "check that output_dir is writable and the CSV is not open in Excel",
        lambda: _build_plan_step(entries, attack_data, config, sources, csv_path),
    )

    html_path: Path | None = None
    if config.html_enabled:
        html_path = run_step(
            progress,
            next_step(),
            total,
            "Write HTML plan",
            "check that output_dir is writable",
            lambda: _write_html_step(rows, attack_data, config, output_dir / "analytic_plan.html"),
        )

    return RunResult(
        attack_version=attack_data.version,
        technique_count=len(entries),
        layer_path=layer_path,
        csv_path=csv_path,
        html_path=html_path,
        extractions=extractions,
    )
