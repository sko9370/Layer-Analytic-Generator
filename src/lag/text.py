"""Helpers for ATT&CK description text: citation markers and markdown."""

from __future__ import annotations

import re
from collections.abc import Mapping

from lag.models import Citation

CITATION_RE = re.compile(r"\(Citation: ([^)]+)\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
CODE_TAG_RE = re.compile(r"</?code>")


def citation_labels(text: str) -> list[str]:
    """Citation labels referenced in text, unique, in first-seen order."""
    return list(dict.fromkeys(m.strip() for m in CITATION_RE.findall(text or "")))


def link_citations(text: str, citations: Mapping[str, Citation]) -> str:
    """Replace each "(Citation: X)" with a markdown link to X, or "(X)" when no URL is known."""

    def repl(match: re.Match[str]) -> str:
        label = match.group(1).strip()
        citation = citations.get(label)
        body = f"[{label}]({citation.url})" if citation and citation.url else label
        before = match.string[match.start() - 1] if match.start() > 0 else " "
        return ("" if before.isspace() else " ") + f"({body})"

    return CITATION_RE.sub(repl, text or "")


def strip_citations(text: str) -> str:
    """Remove "(Citation: X)" markers."""
    stripped = CITATION_RE.sub("", text or "")
    return re.sub(r"[ \t]{2,}", " ", stripped).strip()


def strip_markdown_links(text: str) -> str:
    """Turn "[label](url)" into "label"."""
    return MD_LINK_RE.sub(r"\1", text or "")


def plain_text(text: str) -> str:
    """Text with citation markers, markdown links, and <code> tags removed."""
    return CODE_TAG_RE.sub("", strip_markdown_links(strip_citations(text)))


def table_cell(text: str) -> str:
    """Make text safe for a single markdown table cell."""
    return (text or "").replace("|", "\\|").replace("\r", "").replace("\n", "<br>")
