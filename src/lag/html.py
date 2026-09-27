"""Build a single self-contained HTML analytic plan (no MkDocs, no network at view time).

All CSS and JS are inlined so the file works from file:// with no server. Each PlanRow markdown
field is rendered with Python-Markdown at build time; raw "<" / ">" in the source are escaped
before rendering (except literal <code>, </code>, <br> tags), and after rendering only an allowlist
of tags survives, with links restricted to http(s) or same-page anchors.
"""

from __future__ import annotations

import html as html_module
import re
from datetime import UTC, datetime
from pathlib import Path
from string import Template
from typing import TYPE_CHECKING

import markdown

from lag.models import AttackData, Config

if TYPE_CHECKING:
    from lag.plan import PlanRow

_ALLOWED_RAW_TAGS_RE = re.compile(r"</?(?:code|br)\s*/?>", re.IGNORECASE)
# Tags Python-Markdown (with the tables extension) emits for our content. Anything else is escaped.
_ALLOWED_TAGS = {
    "a", "blockquote", "br", "code", "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr",
    "li", "ol", "p", "pre", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
}  # fmt: skip
_TAG_RE = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>")
_HREF_RE = re.compile(r'\bhref="([^"]*)"')
_ALIGN_RE = re.compile(r'\bstyle="(text-align: (?:left|right|center);)"')


def build_html(rows: list[PlanRow], attack: AttackData, config: Config, path: Path) -> Path:
    """Write the single-file HTML analytic plan to path, creating parent dirs. Returns path."""
    path.parent.mkdir(parents=True, exist_ok=True)

    total = len(rows)
    host_count = sum(1 for row in rows if row.category == "host")
    network_count = sum(1 for row in rows if row.category == "network")

    used_tactics = [t.name for t in attack.tactics if any(t.name in row.tactics for row in rows)]
    used_sources = list(dict.fromkeys(a for row in rows for a in row.attribution))

    sidebar_items = "\n".join(_sidebar_item(n, row) for n, row in enumerate(rows, start=1))
    cards = "\n".join(_card_html(n, row) for n, row in enumerate(rows, start=1))
    tactic_chips = "".join(
        f'<button type="button" class="chip-btn" data-tactic="{html_module.escape(t)}">'
        f"{html_module.escape(t)}</button>"
        for t in used_tactics
    )
    source_options = "".join(
        f'<option value="{html_module.escape(s)}">{html_module.escape(s)}</option>' for s in used_sources
    )

    page = _PAGE_TEMPLATE.substitute(
        title=html_module.escape(config.name),
        css=_CSS,
        header=_header_html(config, attack, total, host_count, network_count),
        tactic_chips=tactic_chips,
        source_options=source_options,
        sidebar_items=sidebar_items,
        cards=cards,
        js=_JS,
    )
    path.write_text(page, encoding="utf-8")
    return path


def _pre_escape(text: str) -> str:
    """Escape '<' and '>' in text before markdown rendering, keeping <code>, </code>, <br> literal."""
    parts: list[str] = []
    last = 0
    for match in _ALLOWED_RAW_TAGS_RE.finditer(text or ""):
        parts.append(text[last : match.start()].replace("<", "&lt;").replace(">", "&gt;"))
        parts.append(match.group(0))
        last = match.end()
    parts.append((text or "")[last:].replace("<", "&lt;").replace(">", "&gt;"))
    return "".join(parts)


def _sanitize(fragment: str) -> str:
    """Keep only allowlisted tags without attributes, except a validated href on links and table
    alignment; escape every other tag. Links open in a new tab."""

    def repl(match: re.Match[str]) -> str:
        closing, tag, attrs = match.group(1), match.group(2).lower(), match.group(3)
        if tag not in _ALLOWED_TAGS:
            return html_module.escape(match.group(0), quote=False)
        if closing:
            return f"</{tag}>"
        if tag == "a":
            href_match = _HREF_RE.search(attrs)
            href = href_match.group(1) if href_match else "#"
            if not href.startswith(("http://", "https://", "#")):
                href = "#"
            return f'<a href="{href}" target="_blank" rel="noopener noreferrer">'
        if tag in ("td", "th") and (align := _ALIGN_RE.search(attrs)):
            return f'<{tag} style="{align.group(1)}">'
        return f"<{tag}>"

    return _TAG_RE.sub(repl, fragment)


def _render_md(text: str) -> str:
    """Render a PlanRow markdown field to safe HTML."""
    rendered = markdown.markdown(_pre_escape(text or ""), extensions=["tables"])
    return _sanitize(rendered)


def _plain_list(items: list[str]) -> str:
    if not items:
        return "<p>None.</p>"
    return "<ul>" + "".join(f"<li>{html_module.escape(item)}</li>" for item in items) + "</ul>"


def _details(summary: str, body_html: str, *, open_: bool = False) -> str:
    open_attr = " open" if open_ else ""
    return (
        f"<details{open_attr}><summary>{html_module.escape(summary)}</summary>"
        f'<div class="details-body">{body_html}</div></details>'
    )


def _sources_summary(config: Config, attack: AttackData) -> str:
    parts = []
    for source_id, weight in config.sources.items():
        name = attack.sources.get(source_id, "")
        label = source_id if not name else f"{source_id} {name}"
        parts.append(f"{label} x{weight}")
    return ", ".join(parts) if parts else "none"


def _header_html(config: Config, attack: AttackData, total: int, host: int, network: int) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<h1>{html_module.escape(config.name)}</h1>
<p class="meta">
  ATT&amp;CK version {html_module.escape(attack.version)}
  &middot; Sources: {html_module.escape(_sources_summary(config, attack))}
  &middot; Generated {html_module.escape(generated)}
</p>
<p class="counts">
  <span class="count-badge">{total} total</span>
  <span class="count-badge">{host} host</span>
  <span class="count-badge">{network} network</span>
  <span id="filter-count" class="count-badge count-live">{total} of {total} techniques</span>
</p>"""


def _sidebar_item(n: int, row: PlanRow) -> str:
    tid = html_module.escape(row.technique_id)
    tname = html_module.escape(row.technique_name)
    return (
        f'<li id="toc-{tid}" class="toc-item">'
        f'<a href="#{tid}">'
        f'<span class="toc-num">{n}.</span> '
        f'<span class="toc-id">{tid}</span> '
        f'<span class="toc-name">{tname}</span> '
        f'<span class="score-badge">{row.score}</span>'
        "</a></li>"
    )


def _card_html(n: int, row: PlanRow) -> str:
    tid = html_module.escape(row.technique_id)
    tname = html_module.escape(row.technique_name)
    category = html_module.escape(row.category)
    tactics_attr = html_module.escape("|".join(row.tactics))
    sources_attr = html_module.escape("|".join(row.attribution))
    chips = "".join(f'<span class="chip">{html_module.escape(t)}</span>' for t in row.tactics)

    if row.log_sources_md:
        data_components_html = _render_md(row.log_sources_md)
    elif row.data_components:
        data_components_html = _render_md("\n".join(f"- {dc}" for dc in row.data_components))
    else:
        data_components_html = "<p>None.</p>"

    tactic_question_html = (
        f"<p>{html_module.escape(row.tactic_question)}</p><p><em>{html_module.escape(row.indicator)}</em></p>"
    )

    sections = "".join(
        [
            _details("Tactic / Indicator", tactic_question_html),
            _details("Technique Description", _render_md(row.description_md)),
            _details("Starting Analytics", _render_md(row.analytics_detail_md), open_=True),
            _details("Historical Usage (Evidence)", _render_md(row.evidence_md), open_=True),
            _details("Data Components", data_components_html),
            _details("Attribution", _plain_list(row.attribution)),
            _details("References", _render_md(row.references_md)),
        ]
    )

    return (
        f'<section class="card" id="{tid}" data-tactics="{tactics_attr}" '
        f'data-category="{category}" data-sources="{sources_attr}">\n'
        f"  <h2>{n}. {tid} {tname}</h2>\n"
        f'  <div class="card-badges">'
        f'<span class="score-badge">Score {row.score}</span>'
        f'<span class="badge badge-{category}">{category}</span>'
        f"{chips}</div>\n"
        f"  {sections}\n"
        "</section>"
    )


_CSS = """
:root {
  --bg: #ffffff;
  --fg: #1a1a1a;
  --muted: #5f6368;
  --border: #dcdcdc;
  --card-bg: #f7f7f8;
  --accent: #2563eb;
  --accent-fg: #ffffff;
  --chip-bg: #e8edfb;
  --badge-host: #2563eb;
  --badge-network: #059669;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #121212;
    --fg: #e6e6e6;
    --muted: #a8a8a8;
    --border: #333333;
    --card-bg: #1c1c1e;
    --chip-bg: #23324f;
  }
}
:root[data-theme="dark"] {
  --bg: #121212;
  --fg: #e6e6e6;
  --muted: #a8a8a8;
  --border: #333333;
  --card-bg: #1c1c1e;
  --chip-bg: #23324f;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
}
a { color: var(--accent); }
.site-header {
  padding: 1rem 1.25rem;
  border-bottom: 1px solid var(--border);
}
.site-header h1 { margin: 0 0 0.25rem 0; font-size: 1.4rem; }
.meta, .counts { margin: 0.25rem 0; color: var(--muted); font-size: 0.9rem; }
.count-badge {
  display: inline-block;
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 0.1rem 0.6rem;
  margin-right: 0.35rem;
  font-size: 0.85rem;
}
.count-live { font-weight: 600; }
.top-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
  margin-top: 0.5rem;
}
.top-controls button, .top-controls select, .top-controls input[type="text"] {
  font: inherit;
  padding: 0.35rem 0.6rem;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--fg);
}
#search-input { min-width: 220px; }
.chip-btn, .cat-btn {
  border-radius: 999px;
  cursor: pointer;
}
.chip-btn.active, .cat-btn.active {
  background: var(--accent);
  color: var(--accent-fg);
  border-color: var(--accent);
}
.layout { display: flex; align-items: flex-start; }
.sidebar {
  width: 300px;
  flex-shrink: 0;
  max-height: 100vh;
  overflow-y: auto;
  position: sticky;
  top: 0;
  border-right: 1px solid var(--border);
  padding: 0.75rem;
}
.filters { margin-bottom: 0.5rem; }
.filters-row { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-bottom: 0.5rem; }
.toc { list-style: none; margin: 0; padding: 0; }
.toc-item a {
  display: block;
  padding: 0.35rem 0.25rem;
  text-decoration: none;
  color: var(--fg);
  border-radius: 6px;
  font-size: 0.9rem;
}
.toc-item a:hover { background: var(--chip-bg); }
.toc-num, .toc-id { color: var(--muted); }
.score-badge {
  float: right;
  background: var(--chip-bg);
  border-radius: 999px;
  padding: 0 0.5rem;
  font-size: 0.8rem;
}
.content { flex: 1; padding: 1rem 1.5rem; min-width: 0; }
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem 1.25rem;
  margin-bottom: 1rem;
}
.card h2 { margin: 0 0 0.5rem 0; font-size: 1.1rem; }
.card-badges { margin-bottom: 0.5rem; }
.card-badges .score-badge { float: none; margin-right: 0.35rem; }
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 0.05rem 0.6rem;
  font-size: 0.8rem;
  color: #fff;
  margin-right: 0.35rem;
}
.badge-host { background: var(--badge-host); }
.badge-network { background: var(--badge-network); }
.chip {
  display: inline-block;
  background: var(--chip-bg);
  border-radius: 999px;
  padding: 0.05rem 0.55rem;
  font-size: 0.78rem;
  margin-right: 0.3rem;
}
details { margin: 0.5rem 0; border-top: 1px solid var(--border); padding-top: 0.35rem; }
summary { cursor: pointer; font-weight: 600; }
.details-body { margin-top: 0.4rem; overflow-wrap: anywhere; }
.details-body table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
.details-body th, .details-body td {
  border: 1px solid var(--border);
  padding: 0.3rem 0.5rem;
  text-align: left;
}
@media (max-width: 900px) {
  .layout { flex-direction: column; align-items: stretch; }
  .content { padding: 1rem; }
  .sidebar {
    width: auto;
    max-height: none;
    position: static;
    border-right: none;
    border-bottom: 1px solid var(--border);
  }
}
@media print {
  .sidebar, .top-controls, #theme-toggle { display: none !important; }
  .layout { display: block; }
  details > summary { display: none; }
  details > * { display: block !important; }
}
"""

_JS = """
(function () {
  "use strict";
  var cards = Array.prototype.slice.call(document.querySelectorAll(".card"));
  var searchInput = document.getElementById("search-input");
  var categorySelect = document.getElementById("category-select");
  var sourceSelect = document.getElementById("source-select");
  var tacticButtons = Array.prototype.slice.call(document.querySelectorAll(".chip-btn"));
  var countEl = document.getElementById("filter-count");
  var debounceTimer = null;

  function activeTactics() {
    return tacticButtons.filter(function (b) { return b.classList.contains("active"); })
      .map(function (b) { return b.dataset.tactic; });
  }

  function applyFilters() {
    var q = (searchInput.value || "").trim().toLowerCase();
    var tactics = activeTactics();
    var category = categorySelect.value;
    var source = sourceSelect.value;
    var shown = 0;
    cards.forEach(function (card) {
      var visible = true;
      if (q && card.textContent.toLowerCase().indexOf(q) === -1) visible = false;
      var cardTactics = (card.dataset.tactics || "").split("|");
      var tacticMatch = tactics.some(function (t) { return cardTactics.indexOf(t) !== -1; });
      if (visible && tactics.length && !tacticMatch) {
        visible = false;
      }
      if (visible && category !== "all" && card.dataset.category !== category) visible = false;
      var cardSources = (card.dataset.sources || "").split("|");
      if (visible && source !== "all" && cardSources.indexOf(source) === -1) visible = false;
      card.style.display = visible ? "" : "none";
      var li = document.getElementById("toc-" + card.id);
      if (li) li.style.display = visible ? "" : "none";
      if (visible) shown++;
    });
    countEl.textContent = shown + " of " + cards.length + " techniques";
  }

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(applyFilters, 150);
    });
  }
  if (categorySelect) categorySelect.addEventListener("change", applyFilters);
  if (sourceSelect) sourceSelect.addEventListener("change", applyFilters);
  tacticButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      btn.classList.toggle("active");
      applyFilters();
    });
  });

  var expandAll = document.getElementById("expand-all");
  var collapseAll = document.getElementById("collapse-all");
  if (expandAll) {
    expandAll.addEventListener("click", function () {
      document.querySelectorAll("details").forEach(function (d) { d.open = true; });
    });
  }
  if (collapseAll) {
    collapseAll.addEventListener("click", function () {
      document.querySelectorAll("details").forEach(function (d) { d.open = false; });
    });
  }

  var themeToggle = document.getElementById("theme-toggle");
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var root = document.documentElement;
      var current = root.getAttribute("data-theme") || "auto";
      var next = current === "dark" ? "light" : current === "light" ? "auto" : "dark";
      root.setAttribute("data-theme", next);
      themeToggle.textContent = "Theme: " + next;
    });
  }

  function scrollToHash() {
    if (location.hash) {
      var el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (el) el.scrollIntoView();
    }
  }
  window.addEventListener("hashchange", scrollToHash);
  scrollToHash();
  applyFilters();
})();
"""

_PAGE_TEMPLATE = Template(
    """<!doctype html>
<html lang="en" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>$css</style>
</head>
<body>
<header class="site-header">
$header
<div class="top-controls">
  <input type="text" id="search-input" placeholder="Search techniques...">
  <select id="category-select">
    <option value="all">All categories</option>
    <option value="host">Host</option>
    <option value="network">Network</option>
  </select>
  <select id="source-select">
    <option value="all">All sources</option>
    $source_options
  </select>
  <button type="button" id="expand-all">Expand all</button>
  <button type="button" id="collapse-all">Collapse all</button>
  <button type="button" id="theme-toggle">Theme: auto</button>
</div>
<div class="filters-row">
$tactic_chips
</div>
</header>
<div class="layout">
  <nav class="sidebar" id="sidebar">
    <ol class="toc" id="toc">
$sidebar_items
    </ol>
  </nav>
  <main class="content" id="content">
$cards
  </main>
</div>
<script>$js</script>
</body>
</html>
"""
)
