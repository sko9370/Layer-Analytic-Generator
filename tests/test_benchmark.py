"""Tests for lag.benchmark (ground truth, metrics, cost, rendering) and the model_benchmark.py
CLI script's pure/testable pieces, including the claude-code backend with a faked subprocess.

No test calls a real API, a real LLM, or the real network: requests.get and subprocess.run are
always faked or monkeypatched.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from lag import benchmark
from lag.attack import parse_bundle
from lag.extract import Document, ExtractedTechnique

sys.path.insert(0, str(Path(__file__).parent.parent / "benchmarks"))
import model_benchmark as mb  # noqa: E402

ZSCALER_URL = "https://www.zscaler.com/blogs/security-research/apt-31-leverages-covid-19-vaccine-theme-and-abuses-legitimate-online"
TINY_PDF = b"%PDF-1.4\n%%EOF\n"


@pytest.fixture(scope="module")
def attack(mini_bundle_path: Path):
    with mini_bundle_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    return parse_bundle(bundle)


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com/report", "https://example.com/report"),
        ("https://example.com/report/", "https://example.com/report"),
        ("https://example.com/report#section-2", "https://example.com/report"),
        ("https://example.com/report/#section-2", "https://example.com/report"),
        ("https://example.com/report#", "https://example.com/report"),
    ],
)
def test_normalize_url(raw: str, expected: str) -> None:
    assert benchmark.normalize_url(raw) == expected


# ---------------------------------------------------------------------------
# Ground truth building (fixture bundle)
# ---------------------------------------------------------------------------


def test_build_ground_truth_matches_relationship_count(attack) -> None:
    truths = benchmark.build_ground_truth(attack, [ZSCALER_URL])
    truth = truths[ZSCALER_URL]
    assert truth.source_name == "Zscaler APT31 Covid-19 October 2020"
    assert "T1059.003" in truth.technique_ids
    assert "T1566.002" in truth.technique_ids
    assert len(truth.technique_ids) == 20  # matches the 20 "uses" relationships citing this URL


def test_build_ground_truth_normalizes_url_before_matching(attack) -> None:
    truths = benchmark.build_ground_truth(attack, [ZSCALER_URL + "/#intro"])
    assert len(truths[ZSCALER_URL + "/#intro"].technique_ids) == 20


def test_build_ground_truth_unknown_url_is_empty(attack) -> None:
    truths = benchmark.build_ground_truth(attack, ["https://example.com/nope"])
    truth = truths["https://example.com/nope"]
    assert truth.technique_ids == set()
    assert truth.source_name == ""


def test_count_citation_urls_includes_zscaler_report(attack) -> None:
    counts = benchmark.count_citation_urls(attack)
    assert counts[ZSCALER_URL] == 20


# ---------------------------------------------------------------------------
# Metrics math (hand-built sets)
# ---------------------------------------------------------------------------


def test_compute_metrics_partial_overlap() -> None:
    predicted = {"T1059.003", "T1027", "T1082"}
    ground_truth = {"T1059.003", "T1082", "T1566.002"}
    metrics = benchmark.compute_metrics(predicted, ground_truth)
    assert metrics.ground_truth_count == 3
    assert metrics.predicted_count == 3
    assert metrics.exact_recall == pytest.approx(2 / 3)
    assert metrics.precision == pytest.approx(2 / 3)
    assert metrics.f1 == pytest.approx(2 / 3)
    assert metrics.missed == ["T1566.002"]
    assert metrics.extra == ["T1027"]


def test_compute_metrics_parent_recall_credits_sub_technique_match() -> None:
    predicted = {"T1059.001"}  # a different sub-technique of T1059 than the ground truth
    ground_truth = {"T1059.003"}
    metrics = benchmark.compute_metrics(predicted, ground_truth)
    assert metrics.exact_recall == 0.0
    assert metrics.parent_recall == 1.0


def test_compute_metrics_empty_ground_truth_gives_none_recall() -> None:
    metrics = benchmark.compute_metrics({"T1059"}, set())
    assert metrics.exact_recall is None
    assert metrics.parent_recall is None
    assert metrics.precision == 0.0


def test_compute_metrics_empty_predicted_gives_none_precision_and_zero_f1() -> None:
    metrics = benchmark.compute_metrics(set(), {"T1059"})
    assert metrics.precision is None
    assert metrics.exact_recall == 0.0
    assert metrics.f1 == 0.0


def test_compute_metrics_both_empty_gives_f1_none() -> None:
    metrics = benchmark.compute_metrics(set(), set())
    assert metrics.exact_recall is None
    assert metrics.precision is None
    assert metrics.f1 is None


def test_jaccard() -> None:
    assert benchmark.jaccard({"T1059", "T1027"}, {"T1059", "T1082"}) == pytest.approx(1 / 3)
    assert benchmark.jaccard(set(), set()) is None
    assert benchmark.jaccard({"T1059"}, {"T1059"}) == 1.0


def test_parent_id() -> None:
    assert benchmark.parent_id("T1059.003") == "T1059"
    assert benchmark.parent_id("T1059") == "T1059"


def test_predicted_ids_at_confidence_filters_by_rank() -> None:
    techniques = [
        ExtractedTechnique("T1059.003", "e1", "q1", "high"),
        ExtractedTechnique("T1027", "e2", "q2", "low"),
    ]
    assert benchmark.predicted_ids_at_confidence(techniques, "low") == {"T1059.003", "T1027"}
    assert benchmark.predicted_ids_at_confidence(techniques, "medium") == {"T1059.003"}
    assert benchmark.predicted_ids_at_confidence(techniques, "high") == {"T1059.003"}


# ---------------------------------------------------------------------------
# Cost math
# ---------------------------------------------------------------------------


def test_parse_price_override_valid() -> None:
    assert benchmark.parse_price_override("gpt-5.5=3/12") == ("gpt-5.5", 3.0, 12.0)


@pytest.mark.parametrize("raw", ["gpt-5.5", "gpt-5.5=3", "gpt-5.5=abc/12"])
def test_parse_price_override_invalid(raw: str) -> None:
    with pytest.raises(ValueError):
        benchmark.parse_price_override(raw)


def test_estimate_cost_known_model() -> None:
    usage = {"input_tokens": 1_000_000, "output_tokens": 500_000}
    cost = benchmark.estimate_cost("claude-opus-5", usage, benchmark.DEFAULT_PRICES)
    assert cost == pytest.approx(5.0 + 12.5)


def test_estimate_cost_unknown_model_is_none() -> None:
    usage = {"input_tokens": 100, "output_tokens": 100}
    assert benchmark.estimate_cost("mystery-model", usage, benchmark.DEFAULT_PRICES) is None


def test_estimate_cost_missing_usage_is_none() -> None:
    assert benchmark.estimate_cost("claude-opus-5", None, benchmark.DEFAULT_PRICES) is None


def test_estimate_cost_partial_usage_is_none() -> None:
    usage = {"input_tokens": 100, "output_tokens": None}
    assert benchmark.estimate_cost("claude-opus-5", usage, benchmark.DEFAULT_PRICES) is None


def test_estimate_run_cost_scales_with_reports() -> None:
    prices = {"claude-sonnet-5": (2.0, 10.0)}
    costs = benchmark.estimate_run_cost(prices, 1_000_000, 2, 3000)
    # input: 1M tok @ $2/M = $2; output: 2 reports * 3000 tok = 6000 tok @ $10/M = $0.06
    assert costs["claude-sonnet-5"] == pytest.approx(2.0 + 0.06)


def test_estimate_input_tokens_text() -> None:
    assert benchmark.estimate_input_tokens("text/plain", b"x" * 400) == 100


def test_estimate_input_tokens_pdf_without_pypdf_falls_back_to_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "pypdf", None)
    assert benchmark.estimate_input_tokens("application/pdf", b"x" * 500) == 50


# ---------------------------------------------------------------------------
# Report rendering (fake extract data, no API)
# ---------------------------------------------------------------------------


def _fake_row(
    attack, url: str, title: str, ground_truth_ids: set[str], predictions: dict[str, list]
) -> benchmark.ReportRow:
    truth = benchmark.GroundTruth(url=url, source_name="Fake Source", technique_ids=set(ground_truth_ids))
    row = benchmark.ReportRow(url=url, title=title, ground_truth=truth)
    for model, techniques in predictions.items():
        row.results[model] = benchmark.build_model_report_result(
            model,
            techniques,
            truth.technique_ids,
            confidence_levels=["low", "medium"],
            usage={"input_tokens": 1000, "output_tokens": 200},
            prices=benchmark.DEFAULT_PRICES if model in benchmark.DEFAULT_PRICES else {},
            dropped=[],
        )
    return row


def test_render_markdown_report_smoke(attack) -> None:
    ground_truth_ids = {"T1059.003", "T1566.002", "T1082", "T1027", "T1036"}
    row = _fake_row(
        attack,
        "https://example.com/report",
        "Example Report",
        ground_truth_ids,
        {
            "claude-opus-5": [
                ExtractedTechnique("T1059.003", "ran commands", "cmd.exe", "high"),
                ExtractedTechnique("T1566.002", "spearphish", "clicked link", "high"),
                ExtractedTechnique("T1105", "brought tools in", "downloaded a tool", "low"),
            ],
            "claude-sonnet-5": [
                ExtractedTechnique("T1059.003", "ran commands", "cmd.exe", "medium"),
                ExtractedTechnique("T1082", "recon", "systeminfo", "high"),
            ],
        },
    )
    summaries = [
        benchmark.summarize_model("claude-opus-5", [row], ["low", "medium"]),
        benchmark.summarize_model("claude-sonnet-5", [row], ["low", "medium"]),
    ]
    report = benchmark.render_markdown_report(
        [row],
        summaries,
        attack,
        confidence_levels=["low", "medium"],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert "# ATT&CK Extraction Model Benchmark" in report
    assert "claude-opus-5" in report
    assert "claude-sonnet-5" in report
    assert "Example Report" in report
    assert "Opus vs Sonnet overlap" in report
    assert "\u2014" not in report  # no em dash


def test_build_json_report_smoke(attack) -> None:
    ground_truth_ids = {"T1059.003", "T1566.002", "T1082", "T1027", "T1036"}
    row = _fake_row(
        attack,
        "https://example.com/report",
        "Example Report",
        ground_truth_ids,
        {"claude-opus-5": [ExtractedTechnique("T1059.003", "e", "q", "high")]},
    )
    summaries = [benchmark.summarize_model("claude-opus-5", [row], ["low", "medium"])]
    data = benchmark.build_json_report(
        [row],
        summaries,
        attack,
        confidence_levels=["low", "medium"],
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert data["attack_version"] == attack.version
    assert data["reports"][0]["url"] == "https://example.com/report"
    assert (
        data["reports"][0]["models"]["claude-opus-5"]["metrics_by_confidence"]["low"]["predicted_count"] == 1
    )
    assert data["summaries"][0]["model"] == "claude-opus-5"
    json.dumps(data)  # must be JSON-serializable


def test_summarize_model_macro_average_and_totals(attack) -> None:
    row_a = _fake_row(
        attack,
        "https://example.com/a",
        "A",
        {"T1059.003", "T1082"},
        {"claude-opus-5": [ExtractedTechnique("T1059.003", "e", "q", "high")]},
    )
    row_b = _fake_row(
        attack,
        "https://example.com/b",
        "B",
        {"T1059.003", "T1082"},
        {
            "claude-opus-5": [
                ExtractedTechnique("T1059.003", "e", "q", "high"),
                ExtractedTechnique("T1082", "e", "q", "high"),
            ]
        },
    )
    summary = benchmark.summarize_model("claude-opus-5", [row_a, row_b], ["low"])
    assert summary.reports == 2
    assert summary.scores_by_confidence["low"].macro_exact_recall == pytest.approx((0.5 + 1.0) / 2)
    assert summary.total_input_tokens == 2000
    assert summary.total_output_tokens == 400
    assert summary.total_cost is not None


# ---------------------------------------------------------------------------
# model_benchmark.py: model spec parsing, backend selection, credentials
# ---------------------------------------------------------------------------


def test_parse_model_spec_anthropic() -> None:
    spec = mb.parse_model_spec("claude-opus-5")
    assert spec == mb.ModelSpec(label="claude-opus-5", provider="anthropic", model="claude-opus-5")


def test_parse_model_spec_openai() -> None:
    spec = mb.parse_model_spec("openai:gpt-5.5")
    assert spec == mb.ModelSpec(label="openai:gpt-5.5", provider="openai", model="gpt-5.5")


def test_default_backend_prefers_api_when_a_key_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert mb.default_backend() == "api"


def test_default_backend_is_claude_code_without_any_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert mb.default_backend() == "claude-code"


def test_check_credentials_api_backend_without_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    specs = [mb.parse_model_spec("claude-opus-5")]
    with pytest.raises(mb.LagError, match="ANTHROPIC_API_KEY"):
        mb.check_credentials(specs, "api", "")


def test_check_credentials_claude_code_backend_without_cli_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: None)
    specs = [mb.parse_model_spec("claude-opus-5")]
    with pytest.raises(mb.LagError, match="claude"):
        mb.check_credentials(specs, "claude-code", "")


def test_check_credentials_openai_without_key_raises() -> None:
    specs = [mb.parse_model_spec("openai:gpt-5.5")]
    with pytest.raises(mb.LagError, match="OPENAI_API_KEY"):
        mb.check_credentials(specs, "api", "")


def test_check_credentials_openai_with_base_url_does_not_need_key() -> None:
    specs = [mb.parse_model_spec("openai:gpt-5.5")]
    mb.check_credentials(specs, "api", "http://localhost:11434/v1")  # must not raise


def test_check_credentials_passes_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    specs = [mb.parse_model_spec("claude-opus-5")]
    mb.check_credentials(specs, "api", "")  # must not raise


# ---------------------------------------------------------------------------
# claude-code backend: faked subprocess, no real CLI call
# ---------------------------------------------------------------------------


def _claude_code_payload(techniques=None, usage=None, total_cost_usd=0.0123) -> dict:
    return {
        "is_error": False,
        "subtype": "success",
        "structured_output": {
            "report_title": "A Report",
            "techniques": techniques
            if techniques is not None
            else [
                {"technique_id": "T1059.003", "evidence": "e", "quote": "q", "confidence": "high"},
            ],
        },
        "result": "{}",
        "usage": usage
        if usage is not None
        else {
            "input_tokens": 100,
            "cache_creation_input_tokens": 20,
            "cache_read_input_tokens": 5,
            "output_tokens": 50,
        },
        "total_cost_usd": total_cost_usd,
        "modelUsage": {},
    }


def _fake_runner(stdout_payload: dict, returncode: int = 0, stderr: str = ""):
    def runner(cmd, *, input, capture_output, text, timeout, cwd):  # noqa: A002
        return SimpleNamespace(returncode=returncode, stdout=json.dumps(stdout_payload), stderr=stderr)

    return runner


def test_claude_code_backend_happy_path(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-ok")
    runner = _fake_runner(_claude_code_payload())

    result = mb.run_claude_code_backend(document, attack, "claude-sonnet-5", "high", tmp_path, runner=runner)
    assert [t.technique_id for t in result.extraction.techniques] == ["T1059.003"]
    assert result.extraction.usage == {"input_tokens": 125, "output_tokens": 50}
    assert result.total_cost_usd == 0.0123

    cache_path = mb._claude_code_cache_path(tmp_path, document, "claude-sonnet-5", "high")
    assert cache_path.is_file()


def test_claude_code_backend_cache_hit_skips_subprocess(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-cache")
    mb.run_claude_code_backend(
        document, attack, "claude-sonnet-5", "high", tmp_path, runner=_fake_runner(_claude_code_payload())
    )

    def exploding_runner(*args, **kwargs):
        raise AssertionError("subprocess should not run on a cache hit")

    result = mb.run_claude_code_backend(
        document, attack, "claude-sonnet-5", "high", tmp_path, runner=exploding_runner
    )
    assert result.total_cost_usd == 0.0123


def test_claude_code_backend_is_error_raises(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-err")
    payload = {"is_error": True, "result": "refused"}
    with pytest.raises(mb.LagError, match="refused"):
        mb.run_claude_code_backend(
            document, attack, "claude-sonnet-5", None, tmp_path, runner=_fake_runner(payload)
        )


def test_claude_code_backend_missing_structured_output_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-nostruct")
    payload = {"is_error": False, "usage": {}, "total_cost_usd": 0.0}
    with pytest.raises(mb.LagError, match="structured_output"):
        mb.run_claude_code_backend(
            document, attack, "claude-sonnet-5", None, tmp_path, runner=_fake_runner(payload)
        )


def test_claude_code_backend_nonzero_exit_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-exit")
    runner = _fake_runner({}, returncode=1, stderr="boom")
    with pytest.raises(mb.LagError, match="boom"):
        mb.run_claude_code_backend(document, attack, "claude-sonnet-5", None, tmp_path, runner=runner)


def test_claude_code_backend_non_json_stdout_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-badjson")

    def runner(cmd, *, input, capture_output, text, timeout, cwd):  # noqa: A002
        return SimpleNamespace(returncode=0, stdout="not json", stderr="")

    with pytest.raises(mb.LagError, match="non-JSON"):
        mb.run_claude_code_backend(document, attack, "claude-sonnet-5", None, tmp_path, runner=runner)


def test_claude_code_backend_timeout_raises(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-timeout")

    def runner(cmd, *, input, capture_output, text, timeout, cwd):  # noqa: A002
        raise subprocess.TimeoutExpired(cmd, timeout)

    with pytest.raises(mb.LagError, match="timed out"):
        mb.run_claude_code_backend(document, attack, "claude-sonnet-5", None, tmp_path, runner=runner)


def test_claude_code_backend_missing_cli_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: None)
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-nocli")
    with pytest.raises(mb.LagError, match="PATH"):
        mb.run_claude_code_backend(
            document, attack, "claude-sonnet-5", None, tmp_path, runner=_fake_runner({})
        )


def test_claude_code_backend_offline_without_cache_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mb.shutil, "which", lambda _name: "/usr/bin/claude")
    document = Document(source="r", title="T", media_type="text/plain", data=b"x" * 300, sha256="cc-offline")
    with pytest.raises(mb.LagError, match="offline"):
        mb.run_claude_code_backend(
            document, attack, "claude-sonnet-5", None, tmp_path, offline=True, runner=_fake_runner({})
        )


# ---------------------------------------------------------------------------
# report/URL selection helpers
# ---------------------------------------------------------------------------


def test_normalize_report_urls_defaults() -> None:
    assert mb.normalize_report_urls(None) == mb.DEFAULT_REPORTS
    assert mb.normalize_report_urls([]) == mb.DEFAULT_REPORTS


def test_normalize_report_urls_explicit() -> None:
    assert mb.normalize_report_urls(["https://example.com/a"]) == ["https://example.com/a"]


def test_select_auto_urls_orders_by_citation_count_and_reachability(
    attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_reachable(url, *, timeout=15):
        return "zscaler" in url  # only the top-cited URL is "reachable"

    monkeypatch.setattr(mb, "_is_reachable", fake_reachable)
    selected = mb.select_auto_urls(attack, 1)
    assert selected == [ZSCALER_URL]
