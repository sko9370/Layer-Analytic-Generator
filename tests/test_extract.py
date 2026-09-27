"""Tests for lag.extract: report loading and LLM (Claude) technique extraction.

No test talks to the real network or the real Anthropic API: requests.get and the anthropic
client are always faked or monkeypatched.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import anthropic
import httpx2
import pytest
import requests

from lag.attack import parse_bundle
from lag.errors import LagError
from lag.extract import (
    SCHEMA,
    Document,
    ExtractedTechnique,
    Extraction,
    _cache_path,
    default_label,
    extract_techniques,
    extraction_to_entries,
    load_document,
    run_report,
)
from lag.models import ReportSource

FIXTURES = Path(__file__).parent / "fixtures"

TINY_PDF = b"%PDF-1.4\n%%EOF\n"
LONG_TEXT = "This report describes adversary activity in detail. " * 10  # > 200 chars
SHORT_TEXT = "Too short."


@pytest.fixture(scope="module")
def attack():
    with (FIXTURES / "mini_enterprise.json").open("r", encoding="utf-8") as f:
        bundle = json.load(f)
    return parse_bundle(bundle)


# ---------------------------------------------------------------------------
# fakes for the Anthropic SDK
# ---------------------------------------------------------------------------


class FakeStream:
    def __init__(self, message):
        self._message = message

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get_final_message(self):
        return self._message


class FakeMessages:
    def __init__(self, message=None, error=None):
        self._message = message
        self._error = error
        self.calls: list[dict] = []

    def stream(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return FakeStream(self._message)


class FakeClient:
    def __init__(self, message=None, error=None):
        self.beta = SimpleNamespace(messages=FakeMessages(message, error))


def make_message(stop_reason="end_turn", stop_details=None, text=None):
    content = [SimpleNamespace(type="text", text=text)] if text is not None else []
    return SimpleNamespace(stop_reason=stop_reason, stop_details=stop_details, content=content)


def valid_payload(techniques=None, title="Some Report"):
    return json.dumps(
        {
            "report_title": title,
            "techniques": techniques
            if techniques is not None
            else [
                {
                    "technique_id": "T1059.003",
                    "evidence": "The actor ran commands via cmd.exe.",
                    "quote": "cmd.exe /c whoami",
                    "confidence": "high",
                }
            ],
        }
    )


def make_response(status_code: int, body: dict) -> httpx2.Response:
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    return httpx2.Response(status_code, request=request, json=body)


# ---------------------------------------------------------------------------
# load_document: local files
# ---------------------------------------------------------------------------


def test_load_document_local_pdf(tmp_path: Path) -> None:
    path = tmp_path / "report.pdf"
    path.write_bytes(TINY_PDF)
    doc = load_document(str(path))
    assert doc.media_type == "application/pdf"
    assert doc.data == TINY_PDF
    assert doc.title == "report.pdf"
    assert len(doc.sha256) == 64


def test_load_document_local_txt(tmp_path: Path) -> None:
    path = tmp_path / "report.txt"
    path.write_text(LONG_TEXT, encoding="utf-8")
    doc = load_document(str(path))
    assert doc.media_type == "text/plain"
    assert doc.data.decode("utf-8") == LONG_TEXT
    assert doc.title == "report.txt"


def test_load_document_local_md(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    path.write_text(LONG_TEXT, encoding="utf-8")
    doc = load_document(str(path))
    assert doc.media_type == "text/plain"


def test_load_document_local_html_extracts_text_and_title(tmp_path: Path) -> None:
    html = f"""
    <html><head><title>My Threat Report</title>
    <style>body {{ color: red; }}</style></head>
    <body>
    <nav>skip this nav</nav>
    <script>skip(this);</script>
    <p>{LONG_TEXT}</p>
    <footer>skip this footer</footer>
    </body></html>
    """
    path = tmp_path / "report.html"
    path.write_text(html, encoding="utf-8")
    doc = load_document(str(path))
    assert doc.title == "My Threat Report"
    text = doc.data.decode("utf-8")
    assert "skip this nav" not in text
    assert "skip(this)" not in text
    assert "skip this footer" not in text
    assert "adversary activity" in text


def test_load_document_local_txt_too_short_raises(tmp_path: Path) -> None:
    path = tmp_path / "report.txt"
    path.write_text(SHORT_TEXT, encoding="utf-8")
    with pytest.raises(LagError, match="no readable text"):
        load_document(str(path))


def test_load_document_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match="not found"):
        load_document(str(tmp_path / "nope.pdf"))


def test_load_document_unsupported_suffix_raises(tmp_path: Path) -> None:
    path = tmp_path / "report.docx"
    path.write_text("hello", encoding="utf-8")
    with pytest.raises(LagError, match="unsupported"):
        load_document(str(path))


def test_load_document_pdf_over_size_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lag.extract.MAX_PDF_BYTES", 4)
    path = tmp_path / "report.pdf"
    path.write_bytes(TINY_PDF)
    with pytest.raises(LagError, match="MB PDF"):
        load_document(str(path))


# ---------------------------------------------------------------------------
# load_document: URLs
# ---------------------------------------------------------------------------


class FakeUrlResponse:
    def __init__(self, *, content: bytes = b"", text: str = "", headers=None, status: int = 200):
        self.content = content
        self.text = text
        self.headers = headers or {}
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


def test_load_document_url_pdf(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url, timeout, headers):
        return FakeUrlResponse(content=TINY_PDF, headers={"Content-Type": "application/pdf"})

    monkeypatch.setattr("lag.extract.requests.get", fake_get)
    doc = load_document("https://example.com/reports/apt.pdf")
    assert doc.media_type == "application/pdf"
    assert doc.data == TINY_PDF
    assert doc.title == "apt.pdf"


def test_load_document_url_html(monkeypatch: pytest.MonkeyPatch) -> None:
    html = f"<html><head><title>Web Report</title></head><body><p>{LONG_TEXT}</p></body></html>"

    def fake_get(url, timeout, headers):
        return FakeUrlResponse(text=html, headers={"Content-Type": "text/html"})

    monkeypatch.setattr("lag.extract.requests.get", fake_get)
    doc = load_document("https://example.com/report.html")
    assert doc.media_type == "text/plain"
    assert doc.title == "Web Report"
    assert "adversary activity" in doc.data.decode("utf-8")


def test_load_document_url_network_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url, timeout, headers):
        raise requests.ConnectionError("boom")

    monkeypatch.setattr("lag.extract.requests.get", fake_get)
    with pytest.raises(LagError, match="example.com"):
        load_document("https://example.com/report.pdf")


def test_load_document_url_http_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url, timeout, headers):
        return FakeUrlResponse(text="nope", status=404)

    monkeypatch.setattr("lag.extract.requests.get", fake_get)
    with pytest.raises(LagError):
        load_document("https://example.com/report.html")


# ---------------------------------------------------------------------------
# default_label
# ---------------------------------------------------------------------------


def test_default_label_truncates_title():
    doc = Document(source="s", title="x" * 100, media_type="text/plain", data=b"", sha256="a")
    label = default_label(doc)
    assert label == "Report: " + "x" * 60


# ---------------------------------------------------------------------------
# extract_techniques
# ---------------------------------------------------------------------------


def test_extract_cache_hit_skips_client(tmp_path: Path, attack, caplog: pytest.LogCaptureFixture) -> None:
    document = Document(
        source="report.pdf",
        title="Cached Report",
        media_type="application/pdf",
        data=TINY_PDF,
        sha256="deadbeef",
    )
    cache_path = _cache_path(document, "claude-opus-5", "high", tmp_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "source": "report.pdf",
                "title": "Cached Report",
                "model": "claude-opus-5",
                "techniques": [
                    {"technique_id": "T1059", "evidence": "e", "quote": "q", "confidence": "high"}
                ],
                "dropped": [],
            }
        ),
        encoding="utf-8",
    )

    class ExplodingClient:
        def __getattr__(self, name):
            raise AssertionError("client should not be used on a cache hit")

    with caplog.at_level(logging.INFO):
        extraction = extract_techniques(
            document,
            attack,
            model="claude-opus-5",
            effort="high",
            cache_dir=tmp_path,
            client=ExplodingClient(),
        )
    assert extraction.techniques == [
        ExtractedTechnique(technique_id="T1059", evidence="e", quote="q", confidence="high")
    ]
    assert any("cached" in r.message for r in caplog.records)


def test_extract_offline_without_cache_raises(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="abc123"
    )
    with pytest.raises(LagError, match="offline"):
        extract_techniques(
            document,
            attack,
            model="claude-opus-5",
            effort="high",
            cache_dir=tmp_path,
            offline=True,
            client=FakeClient(),
        )


def test_extract_missing_anthropic_package_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="nopkg"
    )
    monkeypatch.setitem(sys.modules, "anthropic", None)
    with pytest.raises(LagError, match="pip install"):
        extract_techniques(document, attack, model="claude-opus-5", effort="high", cache_dir=tmp_path)


def test_extract_success_writes_cache(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="succ"
    )
    message = make_message(text=valid_payload())
    client = FakeClient(message=message)
    extraction = extract_techniques(
        document, attack, model="claude-opus-5", effort="high", cache_dir=tmp_path, client=client
    )
    assert extraction.title == "Some Report"
    assert [t.technique_id for t in extraction.techniques] == ["T1059.003"]
    assert extraction.dropped == []

    # request shape
    call = client.beta.messages.calls[0]
    assert call["model"] == "claude-opus-5"
    assert call["fallbacks"] == "default"
    assert call["output_config"]["effort"] == "high"
    assert call["output_config"]["format"]["schema"] == SCHEMA
    assert call["messages"][0]["content"][0]["type"] == "document"

    cache_path = _cache_path(document, "claude-opus-5", "high", tmp_path)
    assert cache_path.is_file()


def test_extract_refusal_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="ref")
    message = make_message(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="cyber"):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=client)


def test_extract_max_tokens_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="maxt")
    message = make_message(stop_reason="max_tokens")
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="shorter document"):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=client)


def test_extract_invalid_json_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="badjson")
    message = make_message(text="not json{")
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="not valid JSON"):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=client)


def test_extract_unknown_ids_dropped(tmp_path: Path, attack, caplog: pytest.LogCaptureFixture) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="drop")
    payload = valid_payload(
        techniques=[
            {"technique_id": "T1059.003", "evidence": "e", "quote": "q", "confidence": "high"},
            {"technique_id": "T9999", "evidence": "e2", "quote": "q2", "confidence": "low"},
        ]
    )
    message = make_message(text=payload)
    client = FakeClient(message=message)
    with caplog.at_level(logging.WARNING):
        extraction = extract_techniques(
            document, attack, model="m", effort="high", cache_dir=tmp_path, client=client
        )
    assert [t.technique_id for t in extraction.techniques] == ["T1059.003"]
    assert extraction.dropped == ["T9999"]
    assert any("T9999" in r.message for r in caplog.records)


def test_extract_dedupes_keeping_highest_confidence(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="dedupe")
    payload = valid_payload(
        techniques=[
            {"technique_id": "t1059.003", "evidence": "low one", "quote": "q1", "confidence": "low"},
            {"technique_id": "T1059.003", "evidence": "high one", "quote": "q2", "confidence": "high"},
        ]
    )
    message = make_message(text=payload)
    client = FakeClient(message=message)
    extraction = extract_techniques(
        document, attack, model="m", effort="high", cache_dir=tmp_path, client=client
    )
    assert len(extraction.techniques) == 1
    kept = extraction.techniques[0]
    assert kept.technique_id == "T1059.003"
    assert kept.confidence == "high"
    assert kept.evidence == "high one"


@pytest.mark.parametrize(
    ("exc", "match"),
    [
        (
            anthropic.AuthenticationError("bad key", response=make_response(401, {}), body={}),
            "ANTHROPIC_API_KEY",
        ),
        (
            anthropic.PermissionDeniedError("no access", response=make_response(403, {}), body={}),
            "access denied",
        ),
        (anthropic.NotFoundError("no model", response=make_response(404, {}), body={}), "model"),
        (anthropic.RateLimitError("slow down", response=make_response(429, {}), body={}), "rate limit"),
        (anthropic.APIStatusError("server broke", response=make_response(500, {}), body={}), "status 500"),
    ],
)
def test_extract_maps_sdk_status_errors(tmp_path: Path, attack, exc, match) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256=f"err-{match}")
    client = FakeClient(error=exc)
    with pytest.raises(LagError, match=match):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=client)


def test_extract_maps_connection_error(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="conn")
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    client = FakeClient(error=anthropic.APIConnectionError(request=request))
    with pytest.raises(LagError, match="could not reach"):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=client)


def test_extract_client_construction_failure_gets_auth_hint(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="noclient")

    def boom(*args, **kwargs):
        raise RuntimeError("no credentials configured")

    monkeypatch.setattr(anthropic, "Anthropic", boom)
    with pytest.raises(LagError, match="ANTHROPIC_API_KEY"):
        extract_techniques(document, attack, model="m", effort="high", cache_dir=tmp_path, client=None)


# ---------------------------------------------------------------------------
# extraction_to_entries / run_report
# ---------------------------------------------------------------------------


def test_extraction_to_entries_confidence_filter() -> None:
    extraction = Extraction(
        source="https://example.com/report.pdf",
        title="APT Report",
        model="m",
        techniques=[
            ExtractedTechnique("T1059.003", "e1", "q1", "high"),
            ExtractedTechnique("T1027", "e2", "q2", "low"),
        ],
    )
    report = ReportSource(source=extraction.source, min_confidence="medium", weight=2)
    entries = extraction_to_entries(extraction, report, "Report: APT Report")
    assert [e.technique_id for e in entries] == ["T1059.003"]
    entry = entries[0]
    assert entry.score == 2
    assert entry.procedures[0].source_id == "Report: APT Report"
    assert "e1" in entry.procedures[0].description
    assert "confidence: high" in entry.procedures[0].description
    assert entry.procedures[0].citations[0].url == "https://example.com/report.pdf"
    assert entry.links[0].url == "https://example.com/report.pdf"


def test_extraction_to_entries_local_source_has_no_link_url() -> None:
    extraction = Extraction(
        source="/tmp/report.pdf",
        title="Local Report",
        model="m",
        techniques=[ExtractedTechnique("T1059.003", "e", "q", "high")],
    )
    report = ReportSource(source=extraction.source)
    entries = extraction_to_entries(extraction, report, "Report: Local Report")
    assert entries[0].procedures[0].citations[0].url is None
    assert entries[0].links == []


def test_run_report_end_to_end(tmp_path: Path, attack) -> None:
    path = tmp_path / "report.txt"
    path.write_text(LONG_TEXT, encoding="utf-8")
    report = ReportSource(source=str(path), weight=3)
    message = make_message(text=valid_payload(title="Found Report"))
    client = FakeClient(message=message)
    config = SimpleNamespace(llm_model="claude-opus-5", llm_effort="high", cache_dir=tmp_path, offline=False)
    extraction, entries = run_report(report, attack, config, client=client)
    assert extraction.title == "Found Report"
    assert len(entries) == 1
    assert entries[0].score == 3
    # the label falls back to the loaded document's own title, not the model's report_title
    assert entries[0].procedures[0].source_id == "Report: report.txt"


def test_extract_cache_hit_drops_ids_missing_from_current_attack(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="Old", media_type="application/pdf", data=TINY_PDF, sha256="cafe"
    )
    cache_path = _cache_path(document, "claude-opus-5", "high", tmp_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "title": "Old",
                "model": "claude-opus-5",
                "techniques": [
                    {"technique_id": "T1059", "evidence": "e", "quote": "q", "confidence": "high"},
                    {"technique_id": "T1066", "evidence": "e", "quote": "q", "confidence": "high"},
                ],
                "dropped": [],
            }
        ),
        encoding="utf-8",
    )
    extraction = extract_techniques(document, attack, model="claude-opus-5", cache_dir=tmp_path)
    assert [t.technique_id for t in extraction.techniques] == ["T1059"]
    assert extraction.dropped == ["T1066"]


def test_extract_missing_credentials_gives_clear_error(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="nocreds"
    )

    class NoCredsMessages:
        def stream(self, **kwargs):
            raise TypeError('"Could not resolve authentication method. Expected one of api_key"')

    class NoCredsClient:
        class beta:  # noqa: N801
            messages = NoCredsMessages()

    with pytest.raises(LagError, match="no Anthropic credentials found"):
        extract_techniques(
            document, attack, model="claude-opus-5", cache_dir=tmp_path, client=NoCredsClient()
        )
