#!/usr/bin/env python3
"""Benchmark how well an LLM extracts ATT&CK techniques from real threat reports, scored against
ATT&CK's own group/software/campaign mappings as ground truth.

Run `python benchmarks/model_benchmark.py --dry-run` first: it downloads ATT&CK, fetches every
report, and prints token/cost estimates without calling any LLM. A full run additionally extracts
techniques with each requested model (cached under --cache-dir, so reruns are free) and writes a
Markdown + JSON report under benchmarks/results/.

Two backends talk to Claude: "api" (the Anthropic API, needs ANTHROPIC_API_KEY) and "claude-code"
(the locally logged-in Claude Code CLI, using your subscription instead of per-token billing). See
benchmarks/README.md for the full how-to and the caveats on reading these numbers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from lag import attack as attack_module  # noqa: E402
from lag import benchmark, extract  # noqa: E402
from lag.errors import LagError  # noqa: E402
from lag.models import Config  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_REPORTS = [
    "https://www.microsoft.com/en-us/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/",
    "https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust",
    "https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers",
    "https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/",
    "https://www.microsoft.com/en-us/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/",
    "https://cloud.google.com/blog/topics/threat-intelligence/voice-phishing-data-extortion",
    "https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise/",
]

DEFAULT_MODELS = "claude-opus-5,claude-sonnet-5"
MIN_GROUND_TRUTH = 5
REACHABILITY_TIMEOUT = 15
DRY_RUN_OUTPUT_TOKENS_PER_REPORT = 3000
CLAUDE_CODE_TIMEOUT = 900


# ---------------------------------------------------------------------------
# Model spec parsing
# ---------------------------------------------------------------------------


@dataclass
class ModelSpec:
    label: str  # what the user typed, e.g. "claude-opus-5" or "openai:gpt-5.5"
    provider: str  # "anthropic" or "openai"
    model: str  # the bare model name


def parse_model_spec(raw: str) -> ModelSpec:
    if raw.startswith("openai:"):
        model = raw[len("openai:") :]
        if not model:
            raise LagError(f"invalid --models entry {raw!r}: no model name after 'openai:'")
        return ModelSpec(label=raw, provider="openai", model=model)
    return ModelSpec(label=raw, provider="anthropic", model=raw)


# ---------------------------------------------------------------------------
# Report selection
# ---------------------------------------------------------------------------


def normalize_report_urls(raw_reports: list[str] | None) -> list[str]:
    return list(raw_reports) if raw_reports else list(DEFAULT_REPORTS)


def _is_reachable(url: str, *, timeout: float = REACHABILITY_TIMEOUT) -> bool:
    try:
        response = requests.get(url, timeout=timeout, headers={"User-Agent": extract._USER_AGENT})
        return response.status_code < 400
    except requests.RequestException:
        return False


def select_auto_urls(attack_data, count: int) -> list[str]:
    """The count references (any URL cited by a "uses" relationship) cited by the most technique
    relationships, that are reachable (GET, timeout 15s), most-cited first."""
    counts = benchmark.count_citation_urls(attack_data)
    candidates = sorted(counts, key=lambda url: (-counts[url], url))
    selected: list[str] = []
    for url in candidates:
        if not url.lower().startswith(("http://", "https://")):
            continue
        if _is_reachable(url):
            selected.append(url)
            if len(selected) >= count:
                break
        else:
            logger.warning("skipping unreachable candidate report: %s", url)
    return selected


# ---------------------------------------------------------------------------
# Credential preflight (fails fast, before any network or LLM call)
# ---------------------------------------------------------------------------


def default_backend() -> str:
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY"):
        return "api"
    return "claude-code"


def check_credentials(specs: list[ModelSpec], backend: str, base_url: str) -> None:
    """Raise LagError with a clear message if a requested model has no way to authenticate.
    Checked before any ATT&CK download or report fetch, so a missing key fails fast."""
    needs_anthropic_key = False
    needs_claude_cli = False
    needs_openai_key = False
    for spec in specs:
        if spec.provider == "openai":
            needs_openai_key = True
        elif backend == "claude-code":
            needs_claude_cli = True
        else:
            needs_anthropic_key = True

    if needs_claude_cli and shutil.which("claude") is None:
        raise LagError(
            "backend claude-code needs the `claude` CLI on PATH, logged in to your Claude "
            "subscription (run `claude login`); or pass --backend api with ANTHROPIC_API_KEY set"
        )
    if needs_anthropic_key and not os.environ.get("ANTHROPIC_API_KEY"):
        raise LagError(
            "no Anthropic credentials found: set ANTHROPIC_API_KEY (or run `ant auth login`), or "
            "pass --backend claude-code to use your logged-in Claude Code CLI instead"
        )
    if needs_openai_key and not (os.environ.get("OPENAI_API_KEY") or base_url):
        raise LagError(
            "no OpenAI credentials found: set OPENAI_API_KEY (or --base-url for a local/"
            "self-hosted server that needs no key)"
        )


# ---------------------------------------------------------------------------
# claude-code backend: extraction through the locally logged-in Claude Code CLI
# ---------------------------------------------------------------------------


@dataclass
class ClaudeCodeResult:
    extraction: extract.Extraction
    total_cost_usd: float | None  # the CLI's own "API-equivalent list cost"; not actually billed


def _claude_code_cache_path(
    cache_dir: Path, document: extract.Document, model: str, effort: str | None
) -> Path:
    bits = "|".join(["claude-code", model, effort or "", extract.PROMPT_VERSION])
    key = hashlib.sha256((document.sha256 + bits).encode("utf-8")).hexdigest()[:32]
    return Path(cache_dir) / "claude_code_extractions" / f"{key}.json"


def _write_claude_code_cache(
    path: Path, extraction: extract.Extraction, total_cost_usd: float | None
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {**extract._cache_payload(extraction), "total_cost_usd": total_cost_usd}
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def run_claude_code_backend(
    document: extract.Document,
    attack_data,
    model: str,
    effort: str | None,
    cache_dir: Path,
    *,
    offline: bool = False,
    runner=subprocess.run,
) -> ClaudeCodeResult:
    """Extract techniques from document by shelling out to the locally logged-in `claude` CLI,
    reusing lag.extract's system prompt, JSON schema, and response parsing so results are
    comparable with the "api" backend. Cached by (document content, model, effort)."""
    cache_path = _claude_code_cache_path(cache_dir, document, model, effort)
    if cache_path.is_file():
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        cached = extract._load_cached_extraction(payload, document, model, attack_data)
        return ClaudeCodeResult(extraction=cached, total_cost_usd=payload.get("total_cost_usd"))

    if offline:
        raise LagError(f"no cached claude-code extraction for {document.source} and offline mode is enabled")
    if shutil.which("claude") is None:
        raise LagError("the `claude` CLI was not found on PATH (backend claude-code)")

    text = extract._document_text(document)
    prompt = (
        f'<document title="{document.title}">\n{text}\n</document>\n\n{extract._instructions(attack_data)}'
    )

    cmd = [
        "claude",
        "-p",
        "--model",
        model,
        "--output-format",
        "json",
        "--tools",
        "",
        "--no-session-persistence",
        "--system-prompt",
        extract.SYSTEM_PROMPT,
        "--json-schema",
        json.dumps(extract.SCHEMA),
    ]
    if effort:
        cmd += ["--effort", effort]

    with tempfile.TemporaryDirectory(prefix="lag-benchmark-claude-code-") as scratch:
        try:
            proc = runner(
                cmd, input=prompt, capture_output=True, text=True, timeout=CLAUDE_CODE_TIMEOUT, cwd=scratch
            )
        except FileNotFoundError as exc:
            raise LagError("the `claude` CLI was not found on PATH (backend claude-code)") from exc
        except subprocess.TimeoutExpired as exc:
            raise LagError(
                f"claude CLI timed out ({CLAUDE_CODE_TIMEOUT}s) extracting techniques from {document.source}"
            ) from exc

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise LagError(f"claude CLI exited {proc.returncode} for {document.source}: {detail}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise LagError(f"claude CLI returned non-JSON output for {document.source}: {exc}") from exc

    if payload.get("is_error"):
        raise LagError(f"claude CLI reported an error for {document.source}: {payload.get('result')!r}")
    structured_output = payload.get("structured_output")
    if structured_output is None:
        raise LagError(f"claude CLI returned no structured_output for {document.source}")

    extraction = extract._parse_response_text(json.dumps(structured_output), document, model, attack_data)

    raw_usage = payload.get("usage") or {}
    input_tokens = (
        (raw_usage.get("input_tokens") or 0)
        + (raw_usage.get("cache_creation_input_tokens") or 0)
        + (raw_usage.get("cache_read_input_tokens") or 0)
    )
    extraction.usage = {"input_tokens": input_tokens, "output_tokens": raw_usage.get("output_tokens")}
    total_cost_usd = payload.get("total_cost_usd")

    _write_claude_code_cache(cache_path, extraction, total_cost_usd)
    return ClaudeCodeResult(extraction=extraction, total_cost_usd=total_cost_usd)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--report",
        action="append",
        dest="reports",
        metavar="URL",
        help="A report URL to benchmark. Repeatable; replaces the default 7 reports when given.",
    )
    parser.add_argument(
        "--auto",
        type=int,
        default=None,
        metavar="N",
        help="Instead of --report/defaults, pick the N ATT&CK references cited by the most "
        "technique relationships that are reachable from here.",
    )
    parser.add_argument(
        "--models",
        default=DEFAULT_MODELS,
        help=f"Comma-separated models to compare (default {DEFAULT_MODELS}). "
        'Prefix an OpenAI model with "openai:", e.g. openai:gpt-5.5.',
    )
    parser.add_argument("--base-url", default="", help="OpenAI-compatible endpoint for openai: models.")
    parser.add_argument("--effort", default=None, help="LLM effort, passed through to every model.")
    parser.add_argument(
        "--min-confidence",
        default="low",
        choices=["low", "medium", "high"],
        help='Minimum confidence scored as "predicted" (default low = everything kept). Metrics '
        "at medium confidence are always additionally reported.",
    )
    parser.add_argument(
        "--cache-dir",
        default=".lag_cache/benchmark",
        help="Cache directory for ATT&CK data and extractions (default .lag_cache/benchmark).",
    )
    parser.add_argument("--stix-file", default=None, help="Local ATT&CK STIX bundle, skips the download.")
    parser.add_argument(
        "--out", default=None, help="Markdown report path (default benchmarks/results/<UTC timestamp>.md)."
    )
    parser.add_argument(
        "--price",
        action="append",
        dest="prices",
        metavar="model=in/out",
        help="Override or add a price in dollars per million tokens, e.g. gpt-5.5=3/12. Repeatable.",
    )
    parser.add_argument(
        "--backend",
        choices=["api", "claude-code"],
        default=None,
        help="How to talk to Claude models: 'api' (Anthropic API) or 'claude-code' (the locally "
        "logged-in Claude Code CLI). Default: claude-code when neither ANTHROPIC_API_KEY nor "
        "OPENAI_API_KEY is set, else api. OpenAI models always use the API.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch ATT&CK data and every report, and print token/cost estimates. No LLM calls.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (INFO) logging.")
    return parser


def _resolve_prices(overrides: list[str] | None) -> dict[str, tuple[float, float]]:
    prices = dict(benchmark.DEFAULT_PRICES)
    for raw in overrides or []:
        try:
            model, in_price, out_price = benchmark.parse_price_override(raw)
        except ValueError as exc:
            raise LagError(str(exc)) from exc
        prices[model] = (in_price, out_price)
    return prices


def _load_attack(cache_dir: Path, stix_file: str | None):
    config = Config(cache_dir=cache_dir, stix_file=Path(stix_file) if stix_file else None)
    return attack_module.load_attack(config)


def _confidence_levels(min_confidence: str) -> list[str]:
    return list(dict.fromkeys([min_confidence, "medium"]))


@dataclass
class SelectedReport:
    url: str
    document: extract.Document
    ground_truth: benchmark.GroundTruth


def select_reports(args: argparse.Namespace, attack_data) -> list[SelectedReport]:
    """Resolve the report URL list, then drop any report that is unreachable or has fewer than
    MIN_GROUND_TRUTH ground-truth techniques, warning (not failing) for each one dropped."""
    if args.auto:
        urls = select_auto_urls(attack_data, args.auto)
    else:
        urls = normalize_report_urls(args.reports)

    ground_truths = benchmark.build_ground_truth(attack_data, urls)

    selected: list[SelectedReport] = []
    for url in urls:
        truth = ground_truths[url]
        if len(truth.technique_ids) < MIN_GROUND_TRUTH:
            logger.warning(
                "skipping %s: only %d ATT&CK ground-truth technique(s), need at least %d",
                url,
                len(truth.technique_ids),
                MIN_GROUND_TRUTH,
            )
            continue
        try:
            document = extract.load_document(url)
        except LagError as exc:
            logger.warning("skipping unreachable report %s: %s", url, exc)
            continue
        selected.append(SelectedReport(url=url, document=document, ground_truth=truth))

    if not selected:
        raise LagError(
            "no report had both a reachable document and at least "
            f"{MIN_GROUND_TRUTH} ATT&CK ground-truth techniques; nothing to benchmark"
        )
    return selected


def run_dry_run(args: argparse.Namespace, attack_data, reports: list[SelectedReport], prices) -> None:
    specs = [parse_model_spec(m.strip()) for m in args.models.split(",") if m.strip()]
    print(f"ATT&CK version: {attack_data.version}")
    print(f"Reports: {len(reports)}")
    print()

    total_input_tokens = 0
    header = ["Report", "Ground truth", "Type", "Size", "Est. input tokens"]
    rows: list[list[str]] = []
    for report in reports:
        tokens = benchmark.estimate_input_tokens(report.document.media_type, report.document.data)
        total_input_tokens += tokens
        title = report.document.title
        if len(title) > 70:
            title = title[:67] + "..."
        rows.append(
            [
                title,
                str(len(report.ground_truth.technique_ids)),
                report.document.media_type,
                f"{len(report.document.data):,} bytes",
                f"{tokens:,}",
            ]
        )
    print(benchmark.render_text_table(header, rows))
    print()

    print(f"Assuming ~{DRY_RUN_OUTPUT_TOKENS_PER_REPORT:,} output tokens per report:")
    run_costs = benchmark.estimate_run_cost(
        prices, total_input_tokens, len(reports), DRY_RUN_OUTPUT_TOKENS_PER_REPORT
    )
    cost_header = ["Model", "Est. total cost (this run)"]
    cost_rows = [[spec.label, benchmark.format_cost(run_costs.get(spec.model))] for spec in specs]
    print(benchmark.render_text_table(cost_header, cost_rows))


def _extract_for_model(
    spec: ModelSpec,
    report: SelectedReport,
    args: argparse.Namespace,
    attack_data,
    cache_dir: Path,
    backend: str,
) -> tuple[extract.Extraction, float | None]:
    """Run one model's extraction for one report. Returns (extraction, backend_reported_cost),
    where backend_reported_cost is the claude-code CLI's own total_cost_usd, else None."""
    if spec.provider == "anthropic" and backend == "claude-code":
        result = run_claude_code_backend(report.document, attack_data, spec.model, args.effort, cache_dir)
        return result.extraction, result.total_cost_usd

    settings = extract.LlmSettings(
        provider=spec.provider,
        model=spec.model,
        effort=args.effort,
        base_url=args.base_url if spec.provider == "openai" else "",
        api_key_env="",
        pdf_input="native",
    )
    extraction = extract.extract_techniques(
        report.document, attack_data, settings=settings, cache_dir=cache_dir
    )
    return extraction, None


def run_full(
    args: argparse.Namespace, attack_data, reports: list[SelectedReport], prices, backend: str
) -> None:
    specs = [parse_model_spec(m.strip()) for m in args.models.split(",") if m.strip()]
    confidence_levels = _confidence_levels(args.min_confidence)
    cache_dir = Path(args.cache_dir)

    rows: list[benchmark.ReportRow] = []
    for report in reports:
        row = benchmark.ReportRow(
            url=report.url, title=report.document.title, ground_truth=report.ground_truth
        )
        for spec in specs:
            print(f"[{report.document.title}] extracting with {spec.label}...", file=sys.stderr)
            extraction, backend_cost = _extract_for_model(spec, report, args, attack_data, cache_dir, backend)
            result = benchmark.build_model_report_result(
                spec.label,
                extraction.techniques,
                report.ground_truth.technique_ids,
                confidence_levels=confidence_levels,
                usage=extraction.usage,
                # price by the bare model name (spec.model): the price table is keyed by model,
                # not by the "openai:" prefixed label used to distinguish it from the same model
                # name under another provider.
                prices=prices,
                dropped=extraction.dropped,
            )
            # A claude-code extraction's cost is the CLI's own "API-equivalent list cost", which
            # takes priority over our own price-table estimate (computed above, keyed on the
            # label rather than the bare model name, and only right for non-"openai:" labels).
            result.cost = (
                backend_cost
                if backend_cost is not None
                else benchmark.estimate_cost(spec.model, extraction.usage, prices)
            )
            row.results[spec.label] = result
        rows.append(row)

    summaries = [benchmark.summarize_model(spec.label, rows, confidence_levels) for spec in specs]

    generated_at = datetime.now(UTC)
    out_path = (
        Path(args.out) if args.out else Path("benchmarks/results") / f"{generated_at:%Y%m%dT%H%M%SZ}.md"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    backend_note = (
        "\n\nBackend: claude-code (Claude Code CLI, your subscription). Cost is the CLI's own "
        '"API-equivalent list cost": what the same request would cost on the API, not what your '
        "subscription was billed. This adds Claude Code's harness around the request, so absolute "
        "numbers can differ slightly from the API backend, though the model-to-model comparison "
        "stays like for like."
        if backend == "claude-code"
        else ""
    )
    report_md = benchmark.render_markdown_report(
        rows, summaries, attack_data, confidence_levels=confidence_levels, generated_at=generated_at
    )
    report_md += backend_note
    out_path.write_text(report_md, encoding="utf-8")

    json_path = out_path.with_suffix(".json")
    json_report = benchmark.build_json_report(
        rows, summaries, attack_data, confidence_levels=confidence_levels, generated_at=generated_at
    )
    json_report["backend"] = backend
    json_path.write_text(json.dumps(json_report, indent=2, ensure_ascii=False), encoding="utf-8")

    header, table_rows = benchmark.summary_table(summaries, confidence_levels)
    print()
    print(benchmark.render_text_table(header, table_rows))
    print()
    print(f"Report: {out_path}")
    print(f"JSON:   {json_path}")


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s: %(message)s"
    )

    try:
        specs = [parse_model_spec(m.strip()) for m in args.models.split(",") if m.strip()]
        if not specs:
            raise LagError("--models must name at least one model")
        backend = args.backend or default_backend()
        prices = _resolve_prices(args.prices)

        if not args.dry_run:
            check_credentials(specs, backend, args.base_url)

        cache_dir = Path(args.cache_dir)
        attack_data = _load_attack(cache_dir, args.stix_file)
        reports = select_reports(args, attack_data)

        if args.dry_run:
            run_dry_run(args, attack_data, reports, prices)
        else:
            run_full(args, attack_data, reports, prices, backend)
        return 0
    except LagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
