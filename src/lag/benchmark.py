"""Pure logic for the model-comparison benchmark in benchmarks/model_benchmark.py.

Kept in the lag package (not benchmarks/) so it is reusable and easy to unit test: ground truth
from parsed ATT&CK data, report-vs-ground-truth metrics, cost estimation, and Markdown/JSON report
building. Nothing here touches the network, an LLM, or a subprocess; benchmarks/model_benchmark.py
is the thin CLI that wires this up to lag.attack, lag.extract, and (optionally) the Claude Code CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from lag.attack import technique_sort_key
from lag.models import CONFIDENCE_LEVELS, AttackData

# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


@dataclass
class GroundTruth:
    url: str  # the report URL as given, not normalized
    source_name: str = ""  # the ATT&CK citation label used for this reference; "" if never cited
    technique_ids: set[str] = field(default_factory=set)


def normalize_url(url: str) -> str:
    """Drop a trailing "#fragment" and a trailing "/", so a citation URL can be matched to a
    report URL that differs only by those cosmetics."""
    normalized = url.split("#", 1)[0]
    return normalized[:-1] if normalized.endswith("/") else normalized


def build_ground_truth(attack: AttackData, urls: list[str]) -> dict[str, GroundTruth]:
    """Ground truth per url: the active technique IDs from every non-revoked, non-deprecated
    "uses" relationship (group, software, or campaign source) whose own external_references cite
    that URL (matched with normalize_url). attack.procedures already excludes revoked/deprecated
    relationships, sources, and techniques (lag.attack._parse_procedures), so this only has to
    match citation URLs against the requested report URLs.
    """
    by_normalized = {normalize_url(url): url for url in urls}
    truths = {url: GroundTruth(url=url) for url in urls}
    for procedures in attack.procedures.values():
        for procedure in procedures:
            for citation in procedure.citations:
                if not citation.url:
                    continue
                original = by_normalized.get(normalize_url(citation.url))
                if original is None:
                    continue
                truth = truths[original]
                truth.technique_ids.add(procedure.technique_id)
                if not truth.source_name:
                    truth.source_name = citation.label
    return truths


def count_citation_urls(attack: AttackData) -> dict[str, int]:
    """How many distinct (source, technique) procedures cite each URL, across every non-revoked,
    non-deprecated "uses" relationship. Used by --auto to rank candidate reports."""
    counts: dict[str, int] = {}
    for procedures in attack.procedures.values():
        for procedure in procedures:
            seen: set[str] = set()
            for citation in procedure.citations:
                if citation.url and citation.url not in seen:
                    seen.add(citation.url)
                    counts[citation.url] = counts.get(citation.url, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def parent_id(technique_id: str) -> str:
    """ "T1059.003" -> "T1059"; "T1059" -> "T1059" (already a parent)."""
    return technique_id.split(".", 1)[0]


def _confidence_rank(confidence: str) -> int:
    return CONFIDENCE_LEVELS.index(confidence) if confidence in CONFIDENCE_LEVELS else -1


def predicted_ids_at_confidence(techniques, min_confidence: str) -> set[str]:
    """The technique IDs of techniques (an iterable of objects with .technique_id and .confidence,
    e.g. lag.extract.ExtractedTechnique) whose confidence is at or above min_confidence."""
    min_rank = _confidence_rank(min_confidence)
    return {t.technique_id for t in techniques if _confidence_rank(t.confidence) >= min_rank}


@dataclass
class Metrics:
    ground_truth_count: int
    predicted_count: int
    exact_recall: float | None  # |predicted & ground_truth| / |ground_truth|
    parent_recall: float | None  # same, comparing parent technique IDs
    precision: float | None  # |predicted & ground_truth| / |predicted|; see note below
    f1: float | None
    missed: list[str]  # ground truth IDs not predicted, ATT&CK sort order
    extra: list[str]  # predicted IDs not in ground truth, ATT&CK sort order


# ATT&CK's own group/software/campaign mappings are a partial, human-curated ground truth: a
# report almost always describes more behavior than MITRE happened to map. So "precision" here is
# better read as agreement with ATT&CK, not correctness: an "extra" ID is not necessarily a wrong
# extraction, only one ATT&CK's mapping of this report does not (yet) contain.
PRECISION_LABEL = "agreement with ATT&CK"


def _f1_from_counts(intersection_count: int, predicted_count: int, ground_truth_count: int) -> float | None:
    """2 * |intersection| / (|predicted| + |ground_truth|): equivalent to the usual 2pr/(p+r), but
    also well-defined (0.0, not NaN) whenever exactly one side is empty, since the intersection is
    then necessarily 0. None only when both sides are empty (nothing to score)."""
    denominator = predicted_count + ground_truth_count
    return intersection_count / denominator * 2 if denominator else None


def compute_metrics(predicted: set[str], ground_truth: set[str]) -> Metrics:
    intersection = predicted & ground_truth
    predicted_parents = {parent_id(t) for t in predicted}
    truth_parents = {parent_id(t) for t in ground_truth}
    parent_intersection = predicted_parents & truth_parents

    recall = len(intersection) / len(ground_truth) if ground_truth else None
    parent_recall = len(parent_intersection) / len(truth_parents) if truth_parents else None
    precision = len(intersection) / len(predicted) if predicted else None
    f1 = _f1_from_counts(len(intersection), len(predicted), len(ground_truth))

    return Metrics(
        ground_truth_count=len(ground_truth),
        predicted_count=len(predicted),
        exact_recall=recall,
        parent_recall=parent_recall,
        precision=precision,
        f1=f1,
        missed=sorted(ground_truth - predicted, key=technique_sort_key),
        extra=sorted(predicted - ground_truth, key=technique_sort_key),
    )


def jaccard(a: set[str], b: set[str]) -> float | None:
    """|a & b| / |a | b|, or None when both sets are empty."""
    union = a | b
    return len(a & b) / len(union) if union else None


# ---------------------------------------------------------------------------
# Dry-run estimates
# ---------------------------------------------------------------------------


def estimate_input_tokens(media_type: str, data: bytes) -> int:
    """Rough input token estimate for --dry-run, with no LLM call: chars/4 for text, or for a PDF,
    pages * ~800 (via pypdf, if installed) else bytes/10."""
    if media_type == "application/pdf":
        try:
            import io

            import pypdf

            reader = pypdf.PdfReader(io.BytesIO(data))
            return len(reader.pages) * 800
        except Exception:  # noqa: BLE001 - pypdf missing, or the PDF fails to parse; fall back
            return len(data) // 10
    return len(data.decode("utf-8", errors="replace")) // 4


# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------

# Dollars per million tokens, (input, output). Unknown models price as None ("n/a").
DEFAULT_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5": (5.0, 25.0),
    "claude-sonnet-5": (2.0, 10.0),
}


def parse_price_override(raw: str) -> tuple[str, float, float]:
    """Parse one --price argument: "model=in/out" (dollars per million tokens)."""
    if "=" not in raw:
        raise ValueError(f"invalid --price {raw!r}: expected model=in/out")
    model, _, rate = raw.partition("=")
    model = model.strip()
    if "/" not in rate:
        raise ValueError(f"invalid --price {raw!r}: expected model=in/out")
    in_str, _, out_str = rate.partition("/")
    try:
        return model, float(in_str), float(out_str)
    except ValueError as exc:
        raise ValueError(f"invalid --price {raw!r}: in/out must be numbers") from exc


def estimate_cost(model: str, usage: dict | None, prices: dict[str, tuple[float, float]]) -> float | None:
    """Estimated dollar cost of one request, or None when usage is missing or the model has no
    known price (unpriced models report cost as "n/a", never a wrong guess)."""
    if usage is None or model not in prices:
        return None
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if input_tokens is None or output_tokens is None:
        return None
    in_price, out_price = prices[model]
    return input_tokens / 1_000_000 * in_price + output_tokens / 1_000_000 * out_price


def estimate_run_cost(
    prices: dict[str, tuple[float, float]],
    total_input_tokens: int,
    report_count: int,
    output_tokens_per_report: int,
) -> dict[str, float | None]:
    """Estimated cost of running every priced model over report_count reports, assuming
    output_tokens_per_report output tokens each (--dry-run has no real output token count)."""
    usage = {
        "input_tokens": total_input_tokens,
        "output_tokens": report_count * output_tokens_per_report,
    }
    return {model: estimate_cost(model, usage, prices) for model in prices}


# ---------------------------------------------------------------------------
# Per-report, per-model results and per-model aggregates
# ---------------------------------------------------------------------------


@dataclass
class ModelReportResult:
    """One model's result for one report."""

    model: str
    metrics_by_confidence: dict[str, Metrics]  # confidence level -> Metrics
    predicted_by_confidence: dict[str, set[str]]  # confidence level -> predicted technique IDs
    usage: dict | None
    cost: float | None
    dropped: list[str] = field(default_factory=list)  # unknown IDs the model returned


@dataclass
class ReportRow:
    """One report's ground truth plus every model's result for it."""

    url: str
    title: str
    ground_truth: GroundTruth
    results: dict[str, ModelReportResult] = field(default_factory=dict)  # model -> result


def build_model_report_result(
    model: str,
    techniques,
    ground_truth_ids: set[str],
    *,
    confidence_levels: list[str],
    usage: dict | None,
    prices: dict[str, tuple[float, float]],
    dropped: list[str] | None = None,
) -> ModelReportResult:
    """Build one model's ModelReportResult for one report: techniques is an iterable of objects
    with .technique_id and .confidence (e.g. lag.extract.Extraction.techniques, or a fake in
    tests), scored at every level in confidence_levels."""
    predicted_by_confidence = {
        level: predicted_ids_at_confidence(techniques, level) for level in confidence_levels
    }
    metrics_by_confidence = {
        level: compute_metrics(predicted_by_confidence[level], ground_truth_ids)
        for level in confidence_levels
    }
    return ModelReportResult(
        model=model,
        metrics_by_confidence=metrics_by_confidence,
        predicted_by_confidence=predicted_by_confidence,
        usage=usage,
        cost=estimate_cost(model, usage, prices),
        dropped=list(dropped or []),
    )


def _mean(values: list[float | None]) -> float | None:
    present = [v for v in values if v is not None]
    return sum(present) / len(present) if present else None


@dataclass
class ConfidenceScores:
    macro_exact_recall: float | None
    macro_parent_recall: float | None
    macro_precision: float | None
    macro_f1: float | None


@dataclass
class ModelSummary:
    """Macro-averaged metrics and totals for one model, across every scored report."""

    model: str
    reports: int
    scores_by_confidence: dict[str, ConfidenceScores]
    total_input_tokens: int
    total_output_tokens: int
    total_cost: float | None  # None if any report's cost is unknown


def summarize_model(model: str, rows: list[ReportRow], confidence_levels: list[str]) -> ModelSummary:
    """Aggregate one model's ModelReportResult across every row that scored it."""
    results = [row.results[model] for row in rows if model in row.results]
    scores_by_confidence = {
        level: ConfidenceScores(
            macro_exact_recall=_mean([r.metrics_by_confidence[level].exact_recall for r in results]),
            macro_parent_recall=_mean([r.metrics_by_confidence[level].parent_recall for r in results]),
            macro_precision=_mean([r.metrics_by_confidence[level].precision for r in results]),
            macro_f1=_mean([r.metrics_by_confidence[level].f1 for r in results]),
        )
        for level in confidence_levels
    }
    total_in = sum((r.usage or {}).get("input_tokens") or 0 for r in results)
    total_out = sum((r.usage or {}).get("output_tokens") or 0 for r in results)
    total_cost = None if any(r.cost is None for r in results) else sum(r.cost for r in results)
    return ModelSummary(
        model=model,
        reports=len(results),
        scores_by_confidence=scores_by_confidence,
        total_input_tokens=total_in,
        total_output_tokens=total_out,
        total_cost=total_cost,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def format_pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def format_cost(value: float | None) -> str:
    return "n/a" if value is None else f"${value:.4f}"


def _table_rows(header: list[str], rows: list[list[str]]) -> tuple[list[str], list[list[str]]]:
    return header, rows


def render_text_table(header: list[str], rows: list[list[str]]) -> str:
    """A plain, fixed-width table for stdout (same style as lag.cli's extraction table)."""
    widths = [len(h) for h in header]
    for row in rows:
        widths = [max(w, len(cell)) for w, cell in zip(widths, row, strict=True)]

    def fmt(cells: list[str]) -> str:
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))

    lines = [fmt(header), fmt(["-" * w for w in widths])]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def render_markdown_table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def summary_table(
    summaries: list[ModelSummary], confidence_levels: list[str]
) -> tuple[list[str], list[list[str]]]:
    """Header and rows for the model-summary table: macro metrics at each confidence level, plus
    total tokens and estimated cost (once per model; usage does not depend on confidence level)."""
    header = ["Model", "Reports"]
    for level in confidence_levels:
        suffix = f" ({level})" if len(confidence_levels) > 1 else ""
        header += [
            f"Exact recall{suffix}",
            f"Parent recall{suffix}",
            f"{PRECISION_LABEL}{suffix}",
            f"F1{suffix}",
        ]
    header += ["Input tok", "Output tok", "Est. cost"]

    rows: list[list[str]] = []
    for summary in summaries:
        row = [summary.model, str(summary.reports)]
        for level in confidence_levels:
            scores = summary.scores_by_confidence[level]
            row += [
                format_pct(scores.macro_exact_recall),
                format_pct(scores.macro_parent_recall),
                format_pct(scores.macro_precision),
                format_pct(scores.macro_f1),
            ]
        row += [
            str(summary.total_input_tokens),
            str(summary.total_output_tokens),
            format_cost(summary.total_cost),
        ]
        rows.append(row)
    return _table_rows(header, rows)


def _technique_label(attack: AttackData, technique_id: str) -> str:
    technique = attack.techniques.get(technique_id)
    return f"{technique_id} ({technique.name})" if technique else f"{technique_id} (unknown)"


def render_markdown_report(
    rows: list[ReportRow],
    summaries: list[ModelSummary],
    attack: AttackData,
    *,
    confidence_levels: list[str],
    generated_at: datetime,
) -> str:
    """The full Markdown report: summary table, per-report table, and per-report missed/extra
    lists (with technique names) at the primary (first) confidence level."""
    primary = confidence_levels[0]
    lines = [
        "# ATT&CK Extraction Model Benchmark",
        "",
        f"Generated {generated_at.strftime('%Y-%m-%d %H:%M UTC')}. ATT&CK version {attack.version}.",
        "",
        "Caveats: ATT&CK's own group/software/campaign mappings are a partial, human-curated "
        "ground truth, not an exhaustive list of everything a report describes, so a low "
        f'"{PRECISION_LABEL}" does not mean the extra techniques are wrong. Blog pages can change '
        "or disappear after this benchmark ran. The report sample is small, so results are "
        "indicative, not a rigorous evaluation.",
        "",
        "## Summary",
        "",
    ]
    header, table_rows = summary_table(summaries, confidence_levels)
    lines.append(render_markdown_table(header, table_rows))
    lines.append("")

    lines.append("## Per-report results")
    lines.append("")
    per_report_header = [
        "Report",
        "Ground truth",
        "Model",
        "Predicted",
        "Exact recall",
        "Parent recall",
        PRECISION_LABEL.capitalize(),
        "F1",
    ]
    per_report_rows: list[list[str]] = []
    for row in rows:
        for model, result in row.results.items():
            metrics = result.metrics_by_confidence[primary]
            per_report_rows.append(
                [
                    f"[{row.title}]({row.url})",
                    str(len(row.ground_truth.technique_ids)),
                    model,
                    str(metrics.predicted_count),
                    format_pct(metrics.exact_recall),
                    format_pct(metrics.parent_recall),
                    format_pct(metrics.precision),
                    format_pct(metrics.f1),
                ]
            )
    lines.append(render_markdown_table(per_report_header, per_report_rows))
    lines.append("")

    lines.append("## Missed and extra techniques per report")
    lines.append("")
    for row in rows:
        lines.append(f"### {row.title}")
        lines.append(f"<{row.url}>")
        if row.ground_truth.source_name:
            lines.append(f"ATT&CK reference: {row.ground_truth.source_name}")
        lines.append("")
        for model, result in row.results.items():
            metrics = result.metrics_by_confidence[primary]
            lines.append(f"**{model}**")
            missed = ", ".join(_technique_label(attack, t) for t in metrics.missed) or "none"
            extra = ", ".join(_technique_label(attack, t) for t in metrics.extra) or "none"
            lines.append(f"- Missed: {missed}")
            lines.append(f"- Extra: {extra}")
            if result.dropped:
                lines.append(f"- Dropped (not valid ATT&CK IDs): {', '.join(result.dropped)}")
            lines.append("")
        overlap = _pair_jaccard(row, "claude-opus-5", "claude-sonnet-5", primary)
        if overlap is not None:
            lines.append(f"Opus vs Sonnet overlap (Jaccard): {format_pct(overlap)}")
            lines.append("")
    return "\n".join(lines)


def _pair_jaccard(row: ReportRow, model_a: str, model_b: str, confidence: str) -> float | None:
    result_a = row.results.get(model_a)
    result_b = row.results.get(model_b)
    if result_a is None or result_b is None:
        return None
    return jaccard(result_a.predicted_by_confidence[confidence], result_b.predicted_by_confidence[confidence])


def build_json_report(
    rows: list[ReportRow],
    summaries: list[ModelSummary],
    attack: AttackData,
    *,
    confidence_levels: list[str],
    generated_at: datetime,
) -> dict:
    """Everything in the Markdown report as plain JSON-able data."""

    def metrics_dict(m: Metrics) -> dict:
        return {
            "ground_truth_count": m.ground_truth_count,
            "predicted_count": m.predicted_count,
            "exact_recall": m.exact_recall,
            "parent_recall": m.parent_recall,
            "precision": m.precision,
            "f1": m.f1,
            "missed": m.missed,
            "extra": m.extra,
        }

    return {
        "generated_at": generated_at.isoformat(),
        "attack_version": attack.version,
        "confidence_levels": confidence_levels,
        "summaries": [
            {
                "model": s.model,
                "reports": s.reports,
                "scores_by_confidence": {
                    level: {
                        "macro_exact_recall": scores.macro_exact_recall,
                        "macro_parent_recall": scores.macro_parent_recall,
                        "macro_precision": scores.macro_precision,
                        "macro_f1": scores.macro_f1,
                    }
                    for level, scores in s.scores_by_confidence.items()
                },
                "total_input_tokens": s.total_input_tokens,
                "total_output_tokens": s.total_output_tokens,
                "total_cost": s.total_cost,
            }
            for s in summaries
        ],
        "reports": [
            {
                "url": row.url,
                "title": row.title,
                "source_name": row.ground_truth.source_name,
                "ground_truth_technique_ids": sorted(row.ground_truth.technique_ids, key=technique_sort_key),
                "models": {
                    model: {
                        "usage": result.usage,
                        "cost": result.cost,
                        "dropped": result.dropped,
                        "metrics_by_confidence": {
                            level: metrics_dict(m) for level, m in result.metrics_by_confidence.items()
                        },
                    }
                    for model, result in row.results.items()
                },
            }
            for row in rows
        ],
    }
