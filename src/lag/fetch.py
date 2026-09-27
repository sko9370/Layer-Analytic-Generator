"""Fetch text over HTTP with a local, expiring, on-disk cache."""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from lag.errors import LagError

logger = logging.getLogger(__name__)


def _cache_path(url: str, cache_dir: Path) -> Path:
    """Cache file for url: cache_dir / sha256(url)[:32] + original suffix."""
    suffix = Path(urlparse(url).path).suffix
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
    return cache_dir / f"{digest}{suffix}"


def _is_fresh(path: Path, max_age_hours: float | None) -> bool:
    if max_age_hours is None:
        return True
    age_hours = (time.time() - path.stat().st_mtime) / 3600
    return age_hours <= max_age_hours


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def fetch_text(
    url: str,
    cache_dir: Path,
    *,
    offline: bool = False,
    max_age_hours: float | None = None,
    timeout: float = 60,
) -> str:
    """Fetch url as text, using a cache under cache_dir.

    A cached copy is used without a network request when it is fresh: younger than
    max_age_hours, or any age at all when max_age_hours is None. offline=True never
    touches the network: it returns any cached copy, however old, and raises
    LagError naming the url when there is none. On a network error, a stale cached
    copy is returned with a warning logged; without any cached copy, LagError is
    raised naming the url and the underlying cause.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(url, cache_dir)
    cached = path.is_file()

    if offline:
        if cached:
            return path.read_text(encoding="utf-8")
        raise LagError(f"offline and no cached copy of {url}")

    if cached and _is_fresh(path, max_age_hours):
        return path.read_text(encoding="utf-8")

    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        if cached:
            logger.warning("failed to fetch %s, using stale cached copy: %s", url, exc)
            return path.read_text(encoding="utf-8")
        raise LagError(f"failed to fetch {url}: {exc}") from exc

    text = response.text
    _write_atomic(path, text)
    return text
