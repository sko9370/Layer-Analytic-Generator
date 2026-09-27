"""Tests for lag.fetch: caching, expiry, offline mode, and network-error fallback."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest
import requests

from lag.errors import LagError
from lag.fetch import _cache_path, fetch_text

URL = "https://example.com/data/enterprise.json"


class FakeResponse:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


def test_cache_path_uses_hash_and_suffix(tmp_path: Path) -> None:
    path = _cache_path(URL, tmp_path)
    digest = hashlib.sha256(URL.encode("utf-8")).hexdigest()[:32]
    assert path == tmp_path / f"{digest}.json"


def test_fetch_writes_cache_and_returns_body(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_get(url: str, timeout: float) -> FakeResponse:
        calls.append(url)
        return FakeResponse('{"ok": true}')

    monkeypatch.setattr(requests, "get", fake_get)
    result = fetch_text(URL, tmp_path)
    assert result == '{"ok": true}'
    assert calls == [URL]
    cache_file = _cache_path(URL, tmp_path)
    assert cache_file.is_file()
    assert cache_file.read_text(encoding="utf-8") == '{"ok": true}'


def test_fetch_uses_cache_without_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_file = _cache_path(URL, tmp_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("cached body", encoding="utf-8")

    def fail_get(*args, **kwargs):
        raise AssertionError("network should not be called")

    monkeypatch.setattr(requests, "get", fail_get)
    result = fetch_text(URL, tmp_path)
    assert result == "cached body"


def test_fetch_refreshes_expired_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_file = _cache_path(URL, tmp_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("stale body", encoding="utf-8")
    old_time = time.time() - 3600 * 48
    import os

    os.utime(cache_file, (old_time, old_time))

    def fake_get(url: str, timeout: float) -> FakeResponse:
        return FakeResponse("fresh body")

    monkeypatch.setattr(requests, "get", fake_get)
    result = fetch_text(URL, tmp_path, max_age_hours=24)
    assert result == "fresh body"
    assert cache_file.read_text(encoding="utf-8") == "fresh body"


def test_fetch_max_age_none_never_expires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_file = _cache_path(URL, tmp_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("very old body", encoding="utf-8")
    old_time = time.time() - 3600 * 24 * 365
    import os

    os.utime(cache_file, (old_time, old_time))

    def fail_get(*args, **kwargs):
        raise AssertionError("network should not be called")

    monkeypatch.setattr(requests, "get", fail_get)
    result = fetch_text(URL, tmp_path, max_age_hours=None)
    assert result == "very old body"


def test_offline_without_cache_raises(tmp_path: Path) -> None:
    with pytest.raises(LagError, match=URL):
        fetch_text(URL, tmp_path, offline=True)


def test_offline_with_cache_returns_it_even_if_stale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_file = _cache_path(URL, tmp_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("offline body", encoding="utf-8")
    old_time = time.time() - 3600 * 24 * 365
    import os

    os.utime(cache_file, (old_time, old_time))

    def fail_get(*args, **kwargs):
        raise AssertionError("network should not be called")

    monkeypatch.setattr(requests, "get", fail_get)
    result = fetch_text(URL, tmp_path, offline=True, max_age_hours=1)
    assert result == "offline body"


def test_network_error_falls_back_to_stale_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    cache_file = _cache_path(URL, tmp_path)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("stale but usable", encoding="utf-8")
    old_time = time.time() - 3600 * 48
    import os

    os.utime(cache_file, (old_time, old_time))

    def fake_get(url: str, timeout: float) -> FakeResponse:
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(requests, "get", fake_get)
    with caplog.at_level("WARNING"):
        result = fetch_text(URL, tmp_path, max_age_hours=1)
    assert result == "stale but usable"
    assert any("stale" in record.message for record in caplog.records)


def test_network_error_without_cache_raises_lag_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_get(url: str, timeout: float) -> FakeResponse:
        raise requests.ConnectionError("boom")

    monkeypatch.setattr(requests, "get", fake_get)
    with pytest.raises(LagError, match=URL) as excinfo:
        fetch_text(URL, tmp_path)
    assert excinfo.value.__cause__ is not None


def test_fetch_creates_cache_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache_dir = tmp_path / "nested" / "cache"

    def fake_get(url: str, timeout: float) -> FakeResponse:
        return FakeResponse("body")

    monkeypatch.setattr(requests, "get", fake_get)
    fetch_text(URL, cache_dir)
    assert cache_dir.is_dir()


def test_fetch_raises_for_http_error_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url: str, timeout: float) -> FakeResponse:
        return FakeResponse("not found", status=404)

    monkeypatch.setattr(requests, "get", fake_get)
    with pytest.raises(LagError):
        fetch_text(URL, tmp_path)
