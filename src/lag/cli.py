"""Command-line interface for lag: `lag init`, `lag build`, and `lag extract`."""

from __future__ import annotations

import argparse
import logging
import re
import sys
import tomllib
import traceback
from dataclasses import replace
from pathlib import Path

from lag import attack, layers, pipeline
from lag import config as config_module
from lag.errors import LagError
from lag.models import CONFIDENCE_LEVELS, LLM_PROVIDERS, Config, ReportSource

logger = logging.getLogger(__name__)


def _parse_source(raw: str) -> tuple[str, int]:
    """Parse a --source argument: "G0128" (weight defaults to 1) or "G0128=2"."""
    if "=" in raw:
        source_id, _, weight_str = raw.partition("=")
        weight_str = weight_str.strip()
        try:
            weight = int(weight_str)
        except ValueError as exc:
            raise LagError(f"Invalid --source {raw!r}: {weight_str!r} is not an integer weight") from exc
    else:
        source_id, weight = raw, 1
    source_id = source_id.strip()
    if not source_id:
        raise LagError(f"Invalid --source {raw!r}: missing source ID")
    return source_id, weight


def _slugify(label: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", label).strip("_").lower()
    return slug or "report"


def _make_progress(quiet: bool) -> pipeline.ProgressFunc:
    if quiet:
        return lambda _msg: None

    def _progress(msg: str) -> None:
        print(msg, file=sys.stderr)

    return _progress


def _init_command(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        raise LagError(f"{path} already exists (use --force to overwrite)")
    path.write_text(config_module.EXAMPLE_CONFIG, encoding="utf-8")
    print(f"Wrote {path}")
    return 0


def _load_config_dict(config_arg: str | None) -> tuple[dict, Path]:
    """Read a config file into a raw dict if given, else an empty dict rooted at cwd."""
    if not config_arg:
        return {}, Path.cwd()
    config_path = Path(config_arg)
    if not config_path.exists():
        raise LagError(f"config file not found: {config_path}")
    with config_path.open("rb") as handle:
        data = tomllib.load(handle)
    return data, config_path.resolve().parent


def _build_command(args: argparse.Namespace) -> int:
    data, base_dir = _load_config_dict(args.config)

    if args.source:
        sources: dict[str, int] = {}
        for raw in args.source:
            source_id, weight = _parse_source(raw)
            sources[source_id] = weight
        data["sources"] = sources

    if args.report:
        reports = list(data.get("reports", []))
        reports.extend({"source": source} for source in args.report)
        data["reports"] = reports

    llm_overrides = {}
    if args.provider:
        llm_overrides["provider"] = args.provider
    if args.model:
        llm_overrides["model"] = args.model
    if args.effort:
        llm_overrides["effort"] = args.effort
    if args.base_url:
        llm_overrides["base_url"] = args.base_url
    if llm_overrides:
        llm_table = dict(data.get("llm", {}))
        llm_table.update(llm_overrides)
        data["llm"] = llm_table

    if args.output_dir:
        data["output_dir"] = args.output_dir
    if args.stix_file:
        data.setdefault("attack", {})["stix_file"] = args.stix_file
    if args.offline:
        data.setdefault("attack", {})["offline"] = True
    if args.no_html:
        data.setdefault("html", {})["enabled"] = False

    config = config_module.config_from_dict(data, base_dir)

    progress = _make_progress(args.quiet)
    result = pipeline.run(config, progress=progress)

    print(f"ATT&CK version: {result.attack_version}")
    print(f"Techniques scored: {result.technique_count}")
    print(f"Layer: {result.layer_path}")
    print(f"Analytic plan CSV: {result.csv_path}")
    if result.html_path is not None:
        print(f"Analytic plan HTML: {result.html_path}")
    for label, kept, dropped in result.extractions:
        note = f", {len(dropped)} ID(s) dropped" if dropped else ""
        print(f"Report {label!r}: {kept} technique(s) kept{note}")
    return 0


def _extract_command(args: argparse.Namespace) -> int:
    data, base_dir = _load_config_dict(args.config)

    def _resolve(value: str, base: Path) -> Path:
        path = Path(value)
        return path if path.is_absolute() else base / path

    attack_table = data.get("attack", {}) if isinstance(data.get("attack"), dict) else {}
    llm_table = data.get("llm", {}) if isinstance(data.get("llm"), dict) else {}

    output_dir = _resolve(args.output_dir or data.get("output_dir", "output"), base_dir)
    stix_file_raw = args.stix_file or attack_table.get("stix_file", "")
    stix_file = _resolve(stix_file_raw, base_dir) if stix_file_raw else None
    cache_dir = _resolve(attack_table.get("cache_dir", ".lag_cache"), base_dir)
    offline = args.offline or bool(attack_table.get("offline", False))

    config = Config(
        domain=data.get("domain", "enterprise-attack"),
        output_dir=output_dir,
        sources={},
        attack_version=attack_table.get("version", ""),
        stix_file=stix_file,
        cache_dir=cache_dir,
        offline=offline,
        llm_provider=args.provider or llm_table.get("provider", "anthropic"),
        llm_model=args.model or llm_table.get("model", ""),
        llm_effort=args.effort or llm_table.get("effort", ""),
        llm_base_url=args.base_url or llm_table.get("base_url", ""),
        llm_api_key_env=llm_table.get("api_key_env", ""),
        llm_pdf_input=llm_table.get("pdf_input", "auto"),
    )

    from lag import extract  # lazy: `lag extract` needs the anthropic/openai package only here

    llm_settings = extract.resolve_llm_settings(config)

    def progress(msg: str) -> None:
        print(msg, file=sys.stderr)

    def _load_attack_step():
        data = attack.load_attack(config)
        return data, f"ATT&CK {data.version}, {len(data.techniques)} techniques"

    total = 2
    attack_data = pipeline.run_step(
        progress,
        1,
        total,
        "Load ATT&CK data",
        "check network access to raw.githubusercontent.com, or pass --stix-file with a local "
        "enterprise-attack.json; with --offline the data must already be cached",
        _load_attack_step,
    )

    report = ReportSource(
        source=args.source,
        label=args.label or "",
        weight=args.weight,
        min_confidence=args.min_confidence,
    )

    def _extract_step():
        extraction, entries = extract.run_report(report, attack_data, config)
        return (
            (extraction, entries),
            f"{len(entries)} technique(s) kept, {len(extraction.dropped)} dropped",
        )

    extraction, entries = pipeline.run_step(
        progress,
        2,
        total,
        f"Extract techniques from report with {llm_settings.provider}:{llm_settings.model}",
        extract.llm_credentials_hint(llm_settings),
        _extract_step,
    )

    if entries:
        label = entries[0].procedures[0].source_id
    else:
        label = report.label or extraction.title or report.source

    out_path = Path(args.output) if args.output else output_dir / f"report_{_slugify(label)}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    layer_config = replace(config, name=label, sources={})
    layers.write_layer(layers.build_layer(entries, attack_data, layer_config), out_path)

    in_layer = {entry.technique_id for entry in entries}
    _print_extraction_table(extraction, attack_data, in_layer)
    dropped_note = f": {', '.join(extraction.dropped)}" if extraction.dropped else ""
    below = len(extraction.techniques) - len(entries)
    print()
    print(
        f"Kept {len(entries)} technique(s); {below} below min_confidence ({report.min_confidence}); "
        f"dropped {len(extraction.dropped)} unknown ID(s){dropped_note}"
    )
    print(f"Wrote layer: {out_path}")
    print(
        "Review the techniques above, then add the layer under [[custom_layers]] once you trust it, "
        "or add this report under [[reports]] to re-extract on every `lag build`."
    )
    return 0


def _print_extraction_table(extraction, attack_data, in_layer: set[str]) -> None:
    header = ["Technique ID", "Confidence", "In layer", "Technique", "Evidence"]
    rows: list[list[str]] = []
    for technique in extraction.techniques:
        known = attack_data.techniques.get(technique.technique_id)
        name = known.full_name if known else "(not in loaded ATT&CK data)"
        evidence = technique.evidence
        if len(evidence) > 80:
            evidence = evidence[:77] + "..."
        included = "yes" if technique.technique_id in in_layer else "no"
        rows.append([technique.technique_id, technique.confidence, included, name, evidence])

    widths = [len(h) for h in header]
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]

    def _fmt(cells: list[str]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))

    print(_fmt(header))
    print(_fmt(["-" * w for w in widths]))
    for row in rows:
        print(_fmt(row))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lag", description="Build weighted ATT&CK Navigator layers and analytic plans."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Write an example config file.")
    init_parser.add_argument("path", nargs="?", default="plan.toml")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing file.")
    init_parser.set_defaults(func=_init_command)

    build_parser = subparsers.add_parser("build", help="Run the pipeline.")
    build_parser.add_argument("-c", "--config", default=None, help="Path to a TOML config file.")
    build_parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="ID[=WEIGHT]",
        help="ATT&CK Group/Software/Campaign ID, optionally with a weight (default 1). Repeatable; "
        "replaces the config file's sources when given.",
    )
    build_parser.add_argument(
        "--report",
        action="append",
        default=[],
        metavar="URL_OR_PATH",
        help="Threat report (URL or local .pdf/.html/.txt/.md file) whose techniques an LLM "
        "extracts (weight 1, medium confidence). Repeatable; adds to the config file's [[reports]].",
    )
    build_parser.add_argument(
        "--provider",
        default=None,
        choices=list(LLM_PROVIDERS),
        help="LLM provider used for report extraction (default: from config, else anthropic).",
    )
    build_parser.add_argument(
        "--model", default=None, help="Override the LLM model used for report extraction."
    )
    build_parser.add_argument(
        "--effort",
        default=None,
        help="LLM effort (anthropic: low/medium/high/xhigh/max; openai: none/minimal/low/medium/"
        "high/xhigh/max; default: provider default).",
    )
    build_parser.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible endpoint (provider openai only), e.g. a local Ollama server.",
    )
    build_parser.add_argument("--offline", action="store_true", help="Never touch the network.")
    build_parser.add_argument("--stix-file", default=None, help="Local STIX bundle, skips download.")
    build_parser.add_argument("--output-dir", default=None, help="Output directory.")
    build_parser.add_argument(
        "--no-html", action="store_true", help="Skip building the single-file HTML analytic plan."
    )
    build_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (INFO) logging.")
    build_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress step-by-step progress lines."
    )
    build_parser.set_defaults(func=_build_command)

    extract_parser = subparsers.add_parser(
        "extract", help="Extract ATT&CK techniques from a threat report with an LLM."
    )
    extract_parser.add_argument(
        "source", metavar="SOURCE", help="Report URL, or a local .pdf/.html/.htm/.txt/.md file."
    )
    extract_parser.add_argument("-c", "--config", default=None, help="Path to a TOML config file.")
    extract_parser.add_argument(
        "--label", default=None, help="Label for the report (default: derived from its title)."
    )
    extract_parser.add_argument(
        "--provider",
        default=None,
        choices=list(LLM_PROVIDERS),
        help="LLM provider (default: from config, else anthropic).",
    )
    extract_parser.add_argument(
        "--model",
        default=None,
        help="LLM model (default: from config, else claude-opus-5 for anthropic; required for openai).",
    )
    extract_parser.add_argument(
        "--effort",
        default=None,
        help="LLM effort (anthropic: low/medium/high/xhigh/max; openai: none/minimal/low/medium/"
        "high/xhigh/max; default: provider default).",
    )
    extract_parser.add_argument(
        "--base-url",
        default=None,
        help="OpenAI-compatible endpoint (provider openai only), e.g. a local Ollama server.",
    )
    extract_parser.add_argument(
        "--min-confidence",
        default="medium",
        choices=CONFIDENCE_LEVELS,
        help="Minimum confidence to keep (default medium).",
    )
    extract_parser.add_argument(
        "--weight", type=int, default=1, help="Score weight if added under [[reports]] (default 1)."
    )
    extract_parser.add_argument(
        "-o", "--output", default=None, help="Output layer JSON path (default output_dir/report_<slug>.json)."
    )
    extract_parser.add_argument("--output-dir", default=None, help="Output directory for the default path.")
    extract_parser.add_argument("--stix-file", default=None, help="Local STIX bundle, skips download.")
    extract_parser.add_argument("--offline", action="store_true", help="Never touch the network.")
    extract_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (INFO) logging.")
    extract_parser.set_defaults(func=_extract_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    verbose = getattr(args, "verbose", False)
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        force=True,
    )

    try:
        return args.func(args)
    except pipeline.StepError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if verbose:
            traceback.print_exception(type(exc.cause), exc.cause, exc.cause.__traceback__, file=sys.stderr)
        return 2
    except LagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - last-resort guard, the CLI never raw-tracebacks by default
        print(f"error: unexpected {type(exc).__name__}: {exc} (rerun with -v for details)", file=sys.stderr)
        if verbose:
            traceback.print_exc(file=sys.stderr)
        return 1
