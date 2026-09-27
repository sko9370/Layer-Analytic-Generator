"""Optional analytic-coverage sources: MITRE CAR and the JPCERT Tool Analysis Result Sheet."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from lag.errors import LagError
from lag.fetch import fetch_text
from lag.models import Config

logger = logging.getLogger(__name__)

CAR_URL = "https://car.mitre.org/analytics/by_technique"
JPCERT_BASE_URL = "https://jpcertcc.github.io/ToolAnalysisResultSheet/"

_TRAILING_PAREN_RE = re.compile(r"\s*\([^)]*\)\s*$")


@dataclass
class AnalyticSources:
    car_techniques: set[str] = field(default_factory=set)
    jpcert_tools: list[tuple[str, str]] = field(default_factory=list)


def load_analytic_sources(config: Config) -> AnalyticSources:
    """Load the enabled analytic sources. A disabled or failing source is left empty."""
    car_techniques: set[str] = set()
    jpcert_tools: list[tuple[str, str]] = []
    if config.car_enabled:
        car_techniques = _load_car_techniques(config)
    if config.jpcert_enabled:
        jpcert_tools = _load_jpcert_tools(config)
    return AnalyticSources(car_techniques=car_techniques, jpcert_tools=jpcert_tools)


def _load_car_techniques(config: Config) -> set[str]:
    try:
        text = fetch_text(
            config.car_coverage_url,
            config.cache_dir,
            offline=config.offline,
            max_age_hours=24 * 7,
        )
        layer = json.loads(text)
        return {t["techniqueID"] for t in layer.get("techniques", []) if t.get("techniqueID")}
    except (LagError, ValueError, AttributeError, TypeError, KeyError) as exc:
        logger.warning("Could not load CAR coverage from %s: %s", config.car_coverage_url, exc)
        return set()


def _load_jpcert_tools(config: Config) -> list[tuple[str, str]]:
    try:
        text = fetch_text(
            config.jpcert_tool_list_url,
            config.cache_dir,
            offline=config.offline,
            max_age_hours=24 * 7,
        )
        soup = BeautifulSoup(text, "html.parser")
        tbody = soup.find("tbody")
        if tbody is None:
            raise LagError(f"No tool table found in {config.jpcert_tool_list_url}")
        tools: list[tuple[str, str]] = []
        for link in tbody.find_all("a", class_="nav-link"):
            name = _TRAILING_PAREN_RE.sub("", link.get_text()).strip().lower()
            if not name:
                continue
            href = link.get("href") or ""
            url = urljoin(JPCERT_BASE_URL, href) if href else JPCERT_BASE_URL
            tools.append((name, url))
        return tools
    except LagError as exc:
        logger.warning("Could not load JPCERT tool list from %s: %s", config.jpcert_tool_list_url, exc)
        return []
    except Exception as exc:  # noqa: BLE001 - a bad/parseable-but-wrong page must not crash the run
        logger.warning("Could not parse JPCERT tool list from %s: %s", config.jpcert_tool_list_url, exc)
        return []


def matching_tools(text: str, tools: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Tools whose name appears as a whole word in text, case-insensitive, unique, in list order."""
    seen: set[tuple[str, str]] = set()
    matches: list[tuple[str, str]] = []
    haystack = text or ""
    for name, url in tools:
        pair = (name, url)
        if pair in seen:
            continue
        pattern = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.IGNORECASE)
        if pattern.search(haystack):
            seen.add(pair)
            matches.append(pair)
    return matches
