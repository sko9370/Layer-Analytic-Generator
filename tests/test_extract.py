"""Tests for lag.extract: report loading and LLM (Claude, OpenAI) technique extraction.

No test talks to the real network or a real LLM API: requests.get and the anthropic/openai
clients are always faked or monkeypatched.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import anthropic
import httpx2
import openai
import pytest
import requests

from lag.attack import parse_bundle
from lag.errors import LagError
from lag.extract import (
    OPENAI_MODEL_REQUIRED_MSG,
    SCHEMA,
    Document,
    ExtractedTechnique,
    Extraction,
    LlmSettings,
    _cache_path,
    default_label,
    extract_techniques,
    extraction_to_entries,
    llm_credentials_hint,
    load_document,
    resolve_llm_settings,
    run_report,
)
from lag.models import Config, ReportSource

FIXTURES = Path(__file__).parent / "fixtures"

TINY_PDF = b"%PDF-1.4\n%%EOF\n"
LONG_TEXT = "This report describes adversary activity in detail. " * 10  # > 200 chars
SHORT_TEXT = "Too short."


def _settings(
    provider: str = "anthropic",
    model: str = "claude-opus-5",
    effort: str | None = "high",
    base_url: str = "",
    api_key_env: str = "",
    pdf_input: str = "native",
) -> LlmSettings:
    return LlmSettings(
        provider=provider,
        model=model,
        effort=effort,
        base_url=base_url,
        api_key_env=api_key_env,
        pdf_input=pdf_input,
    )


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


def make_message(stop_reason="end_turn", stop_details=None, text=None, usage=None):
    content = [SimpleNamespace(type="text", text=text)] if text is not None else []
    return SimpleNamespace(stop_reason=stop_reason, stop_details=stop_details, content=content, usage=usage)


# ---------------------------------------------------------------------------
# fakes for the OpenAI SDK
# ---------------------------------------------------------------------------


class FakeCompletions:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._response


class FakeOpenAIClient:
    def __init__(self, response=None, error=None):
        self.chat = SimpleNamespace(completions=FakeCompletions(response, error))


def make_openai_response(finish_reason="stop", content=None, refusal=None, usage=None):
    message = SimpleNamespace(content=content, refusal=refusal)
    choice = SimpleNamespace(finish_reason=finish_reason, message=message)
    return SimpleNamespace(choices=[choice], usage=usage)


def make_openai_error_response(status_code: int, body: dict) -> httpx2.Response:
    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    return httpx2.Response(status_code, request=request, json=body)


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
    cache_path = _cache_path(document, _settings(), tmp_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "source": "report.pdf",
                "title": "Cached Report",
                "model": "claude-opus-5",
                "raw_techniques": [
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
            settings=_settings(),
            cache_dir=tmp_path,
            client=ExplodingClient(),
        )
    assert extraction.techniques == [
        ExtractedTechnique(technique_id="T1059", evidence="e", quote="q", confidence="high")
    ]
    assert extraction.usage is None  # the cache file above predates the "usage" field
    assert any("cached" in r.message for r in caplog.records)


def test_extract_offline_without_cache_raises(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="abc123"
    )
    with pytest.raises(LagError, match="offline"):
        extract_techniques(
            document,
            attack,
            settings=_settings(),
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
        extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path)


def test_extract_success_writes_cache(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="succ"
    )
    message = make_message(text=valid_payload())
    client = FakeClient(message=message)
    extraction = extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path, client=client)
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

    cache_path = _cache_path(document, _settings(), tmp_path)
    assert cache_path.is_file()


def test_extract_captures_usage_from_message_and_persists_it(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="usage-ok"
    )
    message = make_message(text=valid_payload(), usage=SimpleNamespace(input_tokens=120, output_tokens=45))
    client = FakeClient(message=message)
    extraction = extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path, client=client)
    assert extraction.usage == {"input_tokens": 120, "output_tokens": 45}

    cache_path = _cache_path(document, _settings(), tmp_path)
    cached_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert cached_payload["usage"] == {"input_tokens": 120, "output_tokens": 45}

    # a fresh call re-reads the cached usage unchanged
    reloaded = extract_techniques(
        document, attack, settings=_settings(), cache_dir=tmp_path, client=ExplodingUsageClient()
    )
    assert reloaded.usage == {"input_tokens": 120, "output_tokens": 45}


class ExplodingUsageClient:
    def __getattr__(self, name):
        raise AssertionError("client should not be used on a cache hit")


def test_extract_no_usage_on_message_gives_none(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="T", media_type="application/pdf", data=TINY_PDF, sha256="usage-none"
    )
    message = make_message(text=valid_payload())  # usage defaults to None
    client = FakeClient(message=message)
    extraction = extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path, client=client)
    assert extraction.usage is None


def test_extract_refusal_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="ref")
    message = make_message(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="cyber"):
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client)


def test_extract_max_tokens_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="maxt")
    message = make_message(stop_reason="max_tokens")
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="shorter document"):
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client)


def test_extract_invalid_json_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="badjson")
    message = make_message(text="not json{")
    client = FakeClient(message=message)
    with pytest.raises(LagError, match="not valid JSON"):
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client)


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
            document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client
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
        document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client
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
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client)


def test_extract_maps_connection_error(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="conn")
    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    client = FakeClient(error=anthropic.APIConnectionError(request=request))
    with pytest.raises(LagError, match="could not reach"):
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=client)


def test_extract_client_construction_failure_gets_auth_hint(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="noclient")

    def boom(*args, **kwargs):
        raise RuntimeError("no credentials configured")

    monkeypatch.setattr(anthropic, "Anthropic", boom)
    with pytest.raises(LagError, match="ANTHROPIC_API_KEY"):
        extract_techniques(document, attack, settings=_settings(model="m"), cache_dir=tmp_path, client=None)


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
    config = SimpleNamespace(
        llm_provider="anthropic",
        llm_model="claude-opus-5",
        llm_effort="high",
        llm_base_url="",
        llm_api_key_env="",
        llm_pdf_input="native",
        cache_dir=tmp_path,
        offline=False,
    )
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
    cache_path = _cache_path(document, _settings(), tmp_path)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(
        json.dumps(
            {
                "title": "Old",
                "model": "claude-opus-5",
                "raw_techniques": [
                    {"technique_id": "T1059", "evidence": "e", "quote": "q", "confidence": "high"},
                    {"technique_id": "T1066", "evidence": "e", "quote": "q", "confidence": "high"},
                ],
                "dropped": [],
            }
        ),
        encoding="utf-8",
    )
    extraction = extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path)
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
        extract_techniques(document, attack, settings=_settings(), cache_dir=tmp_path, client=NoCredsClient())


# ---------------------------------------------------------------------------
# resolve_llm_settings
# ---------------------------------------------------------------------------


def test_resolve_llm_settings_anthropic_defaults() -> None:
    config = Config(sources={"G0128": 1})
    settings = resolve_llm_settings(config)
    assert settings.provider == "anthropic"
    assert settings.model == "claude-opus-5"
    assert settings.effort == "high"
    assert settings.pdf_input == "native"


def test_resolve_llm_settings_anthropic_explicit_values_kept() -> None:
    config = Config(sources={"G0128": 1}, llm_model="claude-sonnet-5", llm_effort="low")
    settings = resolve_llm_settings(config)
    assert settings.model == "claude-sonnet-5"
    assert settings.effort == "low"


def test_resolve_llm_settings_openai_without_model_raises() -> None:
    config = Config(sources={"G0128": 1}, llm_provider="openai")
    with pytest.raises(LagError, match=re.escape(OPENAI_MODEL_REQUIRED_MSG)):
        resolve_llm_settings(config)


def test_resolve_llm_settings_openai_effort_none_when_unset() -> None:
    config = Config(sources={"G0128": 1}, llm_provider="openai", llm_model="gpt-5.5")
    settings = resolve_llm_settings(config)
    assert settings.effort is None
    assert settings.pdf_input == "native"


def test_resolve_llm_settings_openai_keeps_explicit_effort() -> None:
    config = Config(sources={"G0128": 1}, llm_provider="openai", llm_model="gpt-5.5", llm_effort="minimal")
    settings = resolve_llm_settings(config)
    assert settings.effort == "minimal"


def test_resolve_llm_settings_openai_with_base_url_defaults_pdf_input_to_text() -> None:
    config = Config(
        sources={"G0128": 1},
        llm_provider="openai",
        llm_model="gpt-5.5",
        llm_base_url="http://localhost:11434/v1",
    )
    settings = resolve_llm_settings(config)
    assert settings.pdf_input == "text"
    assert settings.base_url == "http://localhost:11434/v1"


def test_resolve_llm_settings_explicit_pdf_input_kept() -> None:
    config = Config(
        sources={"G0128": 1},
        llm_provider="openai",
        llm_model="gpt-5.5",
        llm_base_url="http://localhost:11434/v1",
        llm_pdf_input="native",
    )
    settings = resolve_llm_settings(config)
    assert settings.pdf_input == "native"


# ---------------------------------------------------------------------------
# llm_credentials_hint
# ---------------------------------------------------------------------------


def test_llm_credentials_hint_anthropic() -> None:
    hint = llm_credentials_hint(_settings(provider="anthropic"))
    assert "ANTHROPIC_API_KEY" in hint
    assert "ant auth login" in hint


def test_llm_credentials_hint_openai_with_base_url() -> None:
    hint = llm_credentials_hint(
        _settings(provider="openai", model="gpt-5.5", base_url="http://localhost:11434/v1")
    )
    assert "OPENAI_API_KEY" in hint
    assert "http://localhost:11434/v1" in hint


def test_llm_credentials_hint_openai_custom_key_env() -> None:
    hint = llm_credentials_hint(_settings(provider="openai", model="gpt-5.5", api_key_env="MY_KEY"))
    assert "MY_KEY" in hint


# ---------------------------------------------------------------------------
# cache key
# ---------------------------------------------------------------------------


def test_cache_key_differs_by_provider_model_effort_base_url_and_pdf_input(tmp_path: Path) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="samehash")
    paths = {
        _cache_path(document, _settings(provider="anthropic", model="claude-opus-5"), tmp_path),
        _cache_path(document, _settings(provider="openai", model="claude-opus-5"), tmp_path),
        _cache_path(
            document, _settings(provider="openai", model="claude-opus-5", base_url="http://x"), tmp_path
        ),
        _cache_path(
            document, _settings(provider="openai", model="claude-opus-5", pdf_input="text"), tmp_path
        ),
        _cache_path(document, _settings(provider="anthropic", model="claude-opus-5", effort="low"), tmp_path),
        _cache_path(document, _settings(provider="anthropic", model="claude-sonnet-5"), tmp_path),
    }
    assert len(paths) == 6


# ---------------------------------------------------------------------------
# OpenAI request shape and happy path
# ---------------------------------------------------------------------------


def test_openai_happy_path_native_pdf(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="oa-native"
    )
    response = make_openai_response(content=valid_payload())
    client = FakeOpenAIClient(response=response)
    settings = _settings(provider="openai", model="gpt-5.5", effort="medium", pdf_input="native")

    extraction = extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)
    assert extraction.title == "Some Report"
    assert [t.technique_id for t in extraction.techniques] == ["T1059.003"]

    call = client.chat.completions.calls[0]
    assert call["model"] == "gpt-5.5"
    assert call["reasoning_effort"] == "medium"
    assert call["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "attack_techniques", "schema": SCHEMA, "strict": True},
    }
    user_content = call["messages"][1]["content"]
    assert user_content[0]["type"] == "file"
    assert user_content[0]["file"]["filename"] == "R"
    assert user_content[0]["file"]["file_data"].startswith("data:application/pdf;base64,")

    cache_path = _cache_path(document, settings, tmp_path)
    assert cache_path.is_file()


def test_openai_captures_usage_from_response(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="oa-usage"
    )
    response = make_openai_response(
        content=valid_payload(), usage=SimpleNamespace(prompt_tokens=200, completion_tokens=80)
    )
    client = FakeOpenAIClient(response=response)
    settings = _settings(provider="openai", model="gpt-5.5")

    extraction = extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)
    assert extraction.usage == {"input_tokens": 200, "output_tokens": 80}

    cache_path = _cache_path(document, settings, tmp_path)
    cached_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert cached_payload["usage"] == {"input_tokens": 200, "output_tokens": 80}


def test_openai_no_usage_on_response_gives_none(tmp_path: Path, attack) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="oa-usage-none"
    )
    response = make_openai_response(content=valid_payload())  # usage defaults to None
    client = FakeOpenAIClient(response=response)
    extraction = extract_techniques(
        document,
        attack,
        settings=_settings(provider="openai", model="gpt-5.5"),
        cache_dir=tmp_path,
        client=client,
    )
    assert extraction.usage is None


def test_openai_text_mode_sends_text_part(tmp_path: Path, attack) -> None:
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-text"
    )
    response = make_openai_response(content=valid_payload())
    client = FakeOpenAIClient(response=response)
    settings = _settings(provider="openai", model="gpt-5.5", pdf_input="text")

    extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)

    call = client.chat.completions.calls[0]
    user_content = call["messages"][1]["content"]
    assert user_content[0]["type"] == "text"
    assert "<document title=" in user_content[0]["text"]
    assert LONG_TEXT in user_content[0]["text"]


def test_openai_reasoning_effort_omitted_when_not_set(tmp_path: Path, attack) -> None:
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-noeffort"
    )
    response = make_openai_response(content=valid_payload())
    client = FakeOpenAIClient(response=response)
    settings = _settings(provider="openai", model="gpt-5.5", effort=None)

    extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)

    call = client.chat.completions.calls[0]
    assert "reasoning_effort" not in call


def test_openai_refusal_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-refusal")
    response = make_openai_response(content=None, refusal="policy violation")
    client = FakeOpenAIClient(response=response)
    with pytest.raises(LagError, match="policy violation"):
        extract_techniques(
            document,
            attack,
            settings=_settings(provider="openai", model="gpt-5.5"),
            cache_dir=tmp_path,
            client=client,
        )


def test_openai_length_finish_reason_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-length")
    response = make_openai_response(finish_reason="length", content="{}")
    client = FakeOpenAIClient(response=response)
    with pytest.raises(LagError, match="max_completion_tokens"):
        extract_techniques(
            document,
            attack,
            settings=_settings(provider="openai", model="gpt-5.5"),
            cache_dir=tmp_path,
            client=client,
        )


def test_openai_content_filter_finish_reason_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-cf")
    response = make_openai_response(finish_reason="content_filter", content=None)
    client = FakeOpenAIClient(response=response)
    with pytest.raises(LagError, match="content filter"):
        extract_techniques(
            document,
            attack,
            settings=_settings(provider="openai", model="gpt-5.5"),
            cache_dir=tmp_path,
            client=client,
        )


def test_openai_empty_content_raises(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-empty")
    response = make_openai_response(content="")
    client = FakeOpenAIClient(response=response)
    with pytest.raises(LagError, match="no content"):
        extract_techniques(
            document,
            attack,
            settings=_settings(provider="openai", model="gpt-5.5"),
            cache_dir=tmp_path,
            client=client,
        )


@pytest.mark.parametrize(
    ("exc", "match"),
    [
        (
            openai.AuthenticationError("bad key", response=make_openai_error_response(401, {}), body={}),
            "OPENAI_API_KEY",
        ),
        (
            openai.PermissionDeniedError("no access", response=make_openai_error_response(403, {}), body={}),
            "access denied",
        ),
        (openai.NotFoundError("no model", response=make_openai_error_response(404, {}), body={}), "model"),
        (
            openai.RateLimitError("slow down", response=make_openai_error_response(429, {}), body={}),
            "rate limit",
        ),
        (
            openai.BadRequestError("bad schema", response=make_openai_error_response(400, {}), body={}),
            "structured outputs",
        ),
        (
            openai.APIStatusError("server broke", response=make_openai_error_response(500, {}), body={}),
            "status 500",
        ),
    ],
)
def test_openai_maps_sdk_status_errors(tmp_path: Path, attack, exc, match) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256=f"oa-err-{match}")
    client = FakeOpenAIClient(error=exc)
    with pytest.raises(LagError, match=match):
        extract_techniques(
            document,
            attack,
            settings=_settings(provider="openai", model="gpt-5.5"),
            cache_dir=tmp_path,
            client=client,
        )


def test_openai_maps_connection_error_with_base_url_hint(tmp_path: Path, attack) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-conn")
    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    client = FakeOpenAIClient(error=openai.APIConnectionError(request=request))
    settings = _settings(provider="openai", model="gpt-5.5", base_url="http://127.0.0.1:9/v1")
    with pytest.raises(LagError, match="could not reach") as excinfo:
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)
    assert "http://127.0.0.1:9/v1" in str(excinfo.value)


# ---------------------------------------------------------------------------
# OpenAI client construction: api_key_env, base_url fallback, missing credentials
# ---------------------------------------------------------------------------


def test_openai_api_key_env_used(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_OPENAI_KEY", "secret-value")
    captured: dict = {}

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(response=make_openai_response(content=valid_payload()))

    monkeypatch.setattr(openai, "OpenAI", fake_openai)
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-keyenv"
    )
    settings = _settings(provider="openai", model="gpt-5.5", api_key_env="MY_OPENAI_KEY")

    extraction = extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=None)
    assert captured["api_key"] == "secret-value"
    assert extraction.title == "Some Report"


def test_openai_api_key_env_missing_raises(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOME_MISSING_KEY", raising=False)
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-keyenvmissing"
    )
    settings = _settings(provider="openai", model="gpt-5.5", api_key_env="SOME_MISSING_KEY")
    with pytest.raises(LagError, match="SOME_MISSING_KEY"):
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=None)


def test_openai_base_url_without_key_uses_not_needed(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    captured: dict = {}

    def fake_openai(**kwargs):
        captured.update(kwargs)
        return FakeOpenAIClient(response=make_openai_response(content=valid_payload()))

    monkeypatch.setattr(openai, "OpenAI", fake_openai)
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-notneeded"
    )
    settings = _settings(provider="openai", model="gpt-5.5", base_url="http://localhost:11434/v1")

    extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=None)
    assert captured["api_key"] == "not-needed"
    assert captured["base_url"] == "http://localhost:11434/v1"


def test_openai_missing_credentials_gives_clear_error(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def boom(**kwargs):
        raise openai.OpenAIError("Missing credentials.")

    monkeypatch.setattr(openai, "OpenAI", boom)
    document = Document(
        source="r", title="T", media_type="text/plain", data=LONG_TEXT.encode(), sha256="oa-nocreds"
    )
    settings = _settings(provider="openai", model="gpt-5.5")
    with pytest.raises(LagError, match="no OpenAI credentials found"):
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=None)


def test_extract_missing_openai_package_raises(
    tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = Document(source="r", title="T", media_type="text/plain", data=b"x", sha256="oa-nopkg")
    monkeypatch.setitem(sys.modules, "openai", None)
    settings = _settings(provider="openai", model="gpt-5.5")
    with pytest.raises(LagError, match="pip install"):
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path)


# ---------------------------------------------------------------------------
# PDF as text (pypdf), for either provider
# ---------------------------------------------------------------------------


def test_pdf_as_text_extracts_via_pypdf(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="pdf-text-ok"
    )

    class FakePage:
        def extract_text(self):
            return LONG_TEXT

    class FakeReader:
        def __init__(self, stream):
            self.pages = [FakePage(), FakePage()]

    import pypdf

    monkeypatch.setattr(pypdf, "PdfReader", FakeReader)

    message = make_message(text=valid_payload())
    client = FakeClient(message=message)
    settings = _settings(pdf_input="text")

    extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=client)

    call = client.beta.messages.calls[0]
    document_block = call["messages"][0]["content"][0]
    assert document_block["source"]["type"] == "text"
    assert LONG_TEXT in document_block["source"]["data"]


def test_pdf_as_text_scanned_pdf_raises(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="pdf-scanned"
    )

    class FakePage:
        def extract_text(self):
            return ""

    class FakeReader:
        def __init__(self, stream):
            self.pages = [FakePage()]

    import pypdf

    monkeypatch.setattr(pypdf, "PdfReader", FakeReader)

    settings = _settings(pdf_input="text")
    with pytest.raises(LagError, match="looks scanned"):
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=FakeClient())


def test_pdf_as_text_missing_pypdf_raises(tmp_path: Path, attack, monkeypatch: pytest.MonkeyPatch) -> None:
    document = Document(
        source="report.pdf", title="R", media_type="application/pdf", data=TINY_PDF, sha256="pdf-nopypdf"
    )
    monkeypatch.setitem(sys.modules, "pypdf", None)
    settings = _settings(pdf_input="text")
    with pytest.raises(LagError, match="pip install"):
        extract_techniques(document, attack, settings=settings, cache_dir=tmp_path, client=FakeClient())


def test_parse_response_text_accepts_code_fenced_json(attack) -> None:
    from lag.extract import _parse_response_text

    document = Document(source="r.txt", title="R", media_type="text/plain", data=b"x", sha256="f")
    item = {"technique_id": "t1059", "evidence": "e", "quote": "q", "confidence": "high"}
    text = "```json\n" + json.dumps({"report_title": "R", "techniques": [item]}) + "\n```"
    extraction = _parse_response_text(text, document, "m", attack)
    assert [t.technique_id for t in extraction.techniques] == ["T1059"]


def test_parse_response_text_rejects_non_object(attack) -> None:
    from lag.extract import _parse_response_text

    document = Document(source="r.txt", title="R", media_type="text/plain", data=b"x", sha256="f")
    with pytest.raises(LagError, match="not a JSON object"):
        _parse_response_text("[1, 2]", document, "m", attack)


def test_revoked_ids_are_mapped_to_their_replacement(attack) -> None:
    from lag.extract import _extraction_from_items

    attack.revoked_techniques["T9001"] = "T1059"
    items = [
        {"technique_id": "t9001", "evidence": "old id", "quote": "q", "confidence": "medium"},
        {"technique_id": "T1059", "evidence": "new id", "quote": "q", "confidence": "high"},
        {"technique_id": "T0000", "evidence": "bogus", "quote": "q", "confidence": "high"},
    ]
    try:
        extraction = _extraction_from_items(items, source="s", title="t", model="m", attack=attack)
    finally:
        del attack.revoked_techniques["T9001"]
    assert [(t.technique_id, t.confidence) for t in extraction.techniques] == [("T1059", "high")]
    assert extraction.remapped == [("T9001", "T1059")]
    assert extraction.dropped == ["T0000"]
    assert len(extraction.raw_items) == 3


def test_cache_stores_raw_items_and_revalidates_on_load(tmp_path: Path, attack) -> None:
    from lag.extract import _cache_payload, _extraction_from_items, _load_cached_extraction

    document = Document(source="r", title="R", media_type="text/plain", data=b"x", sha256="raw")
    items = [{"technique_id": "T9002", "evidence": "e", "quote": "q", "confidence": "high"}]
    first = _extraction_from_items(items, source="r", title="R", model="m", attack=attack)
    assert first.techniques == [] and first.dropped == ["T9002"]
    attack.revoked_techniques["T9002"] = "T1059"  # a later ATT&CK load that knows the replacement
    try:
        reloaded = _load_cached_extraction(_cache_payload(first), document, "m", attack)
    finally:
        del attack.revoked_techniques["T9002"]
    assert [t.technique_id for t in reloaded.techniques] == ["T1059"]
