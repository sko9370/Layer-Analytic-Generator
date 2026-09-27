"""Tests for lag.html: single self-contained HTML analytic plan, no network at view time."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from lag import html as lag_html
from lag.models import AttackData, Config

try:
    from lag.plan import PlanRow  # type: ignore
except ImportError:  # lag.plan not written yet: stand in with the spec'd fields.

    @dataclass
    class PlanRow:  # type: ignore[no-redef]
        technique_id: str
        technique_name: str
        score: int
        tactics: list[str] = field(default_factory=list)
        tactic_question: str = ""
        indicator: str = ""
        category: str = "host"
        analytics_md: str = ""
        analytics_detail_md: str = ""
        evidence_md: str = ""
        data_components: list[str] = field(default_factory=list)
        log_sources_md: str = ""
        description_md: str = ""
        references_md: str = ""
        attribution: list[str] = field(default_factory=list)


def make_row(**overrides) -> PlanRow:
    defaults = dict(
        technique_id="T1059.003",
        technique_name="Command and Scripting Interpreter: Windows Command Shell",
        score=3,
        tactics=["Execution"],
        tactic_question="Has the adversary used Execution on/in the network environment?",
        indicator="Is there evidence of Command and Scripting Interpreter: Windows Command Shell?",
        category="host",
        analytics_md="[DET0103: Some Strategy](https://example.org/DET0103)",
        analytics_detail_md="### [DET0103: Some Strategy](https://example.org/DET0103)\n\nSome detail.",
        evidence_md="**G0128 ZIRCONIUM**: Used cmd.exe.",
        data_components=["Process Creation"],
        log_sources_md="| Data Component | Log Source | Channel |\n| --- | --- | --- |\n"
        "| Process Creation | WinEventLog:Security | EventCode=4688 |",
        description_md="Adversaries may abuse the Windows command shell.",
        references_md="[T1059.003 on MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/003)",
        attribution=["G0128 ZIRCONIUM"],
    )
    defaults.update(overrides)
    return PlanRow(**defaults)


def make_attack(**overrides) -> AttackData:
    defaults = dict(
        version="19.2",
        domain="enterprise-attack",
        techniques={},
        tactics=[],
        sources={"G0128": "ZIRCONIUM", "S0596": "ShadowPad"},
        procedures={},
    )
    defaults.update(overrides)
    return AttackData(**defaults)


def make_config(**overrides) -> Config:
    defaults = dict(
        name="Analytic Plan",
        sources={"G0128": 2, "S0596": 1},
        html_enabled=True,
    )
    defaults.update(overrides)
    return Config(**defaults)


def _external_ref_hosts(text: str) -> list[str]:
    """CDN-looking script src / link href values, for the "no external assets" check."""
    hosts = []
    for m in re.finditer(r'<script[^>]*\ssrc="([^"]*)"', text, re.IGNORECASE):
        hosts.append(m.group(1))
    for m in re.finditer(r'<link[^>]*\shref="([^"]*)"', text, re.IGNORECASE):
        hosts.append(m.group(1))
    return hosts


def test_build_html_creates_file(tmp_path: Path):
    rows = [make_row()]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"

    result = lag_html.build_html(rows, attack, config, out_path)

    assert result == out_path
    assert out_path.exists()
    assert out_path.stat().st_size > 0


def test_no_cdn_script_or_link_tags(tmp_path: Path):
    rows = [make_row()]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert "<script src=" not in text.lower()
    assert "<link " not in text.lower() or 'href="http' not in text.lower()
    for href in _external_ref_hosts(text):
        assert not href.startswith("http"), f"external asset reference found: {href}"


def test_every_row_has_a_section_with_its_id(tmp_path: Path):
    rows = [
        make_row(technique_id="T1059.003"),
        make_row(technique_id="T1071", technique_name="Application Layer Protocol", category="network"),
    ]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert 'id="T1059.003"' in text
    assert 'id="T1071"' in text
    assert 'id="toc-T1059.003"' in text
    assert 'id="toc-T1071"' in text


def test_malicious_content_is_neutralized(tmp_path: Path):
    rows = [
        make_row(
            evidence_md="Adversary planted <script>alert(1)</script> and used "
            "[a link](javascript:alert(1)) to pivot.",
            description_md="See <script>alert('xss')</script> for details.",
        )
    ]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert "<script>alert(1)</script>" not in text
    assert "<script>alert('xss')</script>" not in text
    assert "javascript:alert(1)" not in text
    # the literal text should still appear, escaped rather than dropped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_host_network_counts_in_header(tmp_path: Path):
    rows = [
        make_row(technique_id="T1059.003", category="host"),
        make_row(technique_id="T1071", category="network"),
        make_row(technique_id="T1105", category="network"),
    ]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert "3 total" in text
    assert "1 host" in text
    assert "2 network" in text


def test_html_parses_without_error(tmp_path: Path):
    rows = [
        make_row(technique_id="T1059.003"),
        make_row(technique_id="T1071", category="network"),
    ]
    attack = make_attack()
    config = make_config(name='Odd "Plan": v2 & Friends')
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    class _CollectingParser(HTMLParser):
        def error(self, message):  # pragma: no cover - HTMLParser no longer calls this in py3.10+
            raise AssertionError(message)

    parser = _CollectingParser()
    parser.feed(text)
    parser.close()


def test_code_and_br_tags_survive_preescape(tmp_path: Path):
    rows = [make_row(description_md="Uses <code>cmd.exe</code> then<br>pivots.")]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert "<code>cmd.exe</code>" in text
    assert "<br>" in text


def test_valid_https_link_preserved_and_opens_new_tab(tmp_path: Path):
    rows = [make_row(references_md="[Example](https://example.org/report)")]
    attack = make_attack()
    config = make_config()
    out_path = tmp_path / "analytic_plan.html"
    lag_html.build_html(rows, attack, config, out_path)
    text = out_path.read_text(encoding="utf-8")

    assert '<a href="https://example.org/report" target="_blank" rel="noopener noreferrer">' in text


def test_no_html_when_disabled_is_pipeline_concern_not_html_module(tmp_path: Path):
    # build_html itself always writes; config.html_enabled gating happens in pipeline.run.
    rows = [make_row()]
    attack = make_attack()
    config = make_config(html_enabled=False)
    out_path = tmp_path / "analytic_plan.html"
    result = lag_html.build_html(rows, attack, config, out_path)
    assert result.exists()


def test_sanitize_neutralizes_link_titles_images_and_schemes():
    md = (
        '[a](javascript:alert(1) "t") [b](JAVASCRIPT:x) [c](data:text/html,x) '
        '![img](https://tracker.example/p.png) [ok](https://attack.mitre.org/ "title")'
    )
    out = lag_html._render_md(md)
    assert "javascript" not in out.lower().replace("&lt;", "")
    assert "data:text" not in out
    assert "<img" not in out
    assert 'title="' not in out
    assert '<a href="https://attack.mitre.org/" target="_blank" rel="noopener noreferrer">ok</a>' in out


def test_sanitize_keeps_tables_and_code():
    out = lag_html._render_md("run <code>cmd.exe</code>\n\n| A | B |\n| :-- | --- |\n| 1 | 2 |")
    assert "<code>cmd.exe</code>" in out
    assert '<th style="text-align: left;">A</th>' in out
    assert "<td>2</td>" in out
