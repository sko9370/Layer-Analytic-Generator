"""Tests for lag.plan: PlanRow construction and CSV output."""

from __future__ import annotations

import csv

from lag.analytics import CAR_URL, AnalyticSources
from lag.models import (
    Analytic,
    AttackData,
    Citation,
    Config,
    DetectionStrategy,
    LogSource,
    Procedure,
    Tactic,
    Technique,
    TechniqueEntry,
)
from lag.plan import CSV_COLUMNS, build_plan, write_csv

# ---------------------------------------------------------------------------
# Small factory helpers (no dependency on the STIX loader)
# ---------------------------------------------------------------------------


def make_tactic(shortname: str, name: str, attack_id: str | None = None) -> Tactic:
    return Tactic(attack_id=attack_id or f"TA-{shortname}", shortname=shortname, name=name)


def make_log_source(
    data_component: str = "Process Creation",
    name: str = "WinEventLog:Security",
    channel: str = "EventCode=4688",
) -> LogSource:
    return LogSource(data_component=data_component, name=name, channel=channel)


def make_analytic(
    attack_id: str = "AN0001",
    url: str = "https://attack.mitre.org/analytics/AN0001",
    description: str = "Detects the thing.",
    platforms=None,
    log_sources=None,
) -> Analytic:
    return Analytic(
        attack_id=attack_id,
        url=url,
        description=description,
        platforms=platforms if platforms is not None else ["Windows"],
        log_sources=log_sources if log_sources is not None else [make_log_source()],
    )


def make_strategy(
    attack_id: str = "DET0001",
    name: str = "Detect the thing",
    url: str = "https://attack.mitre.org/detection/DET0001",
    analytics=None,
) -> DetectionStrategy:
    return DetectionStrategy(
        attack_id=attack_id,
        name=name,
        url=url,
        analytics=analytics if analytics is not None else [make_analytic()],
    )


def make_technique(
    attack_id: str = "T1059",
    name: str = "Command Interpreter",
    full_name: str | None = None,
    description: str = "",
    citations=None,
    tactics=None,
    platforms=None,
    url: str | None = None,
    parent_id: str | None = None,
    detection_strategies=None,
) -> Technique:
    return Technique(
        attack_id=attack_id,
        name=name,
        full_name=full_name or name,
        description=description,
        citations=citations or {},
        tactics=tactics if tactics is not None else ["execution"],
        platforms=platforms if platforms is not None else ["Windows"],
        url=url or f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        parent_id=parent_id,
        detection_strategies=detection_strategies if detection_strategies is not None else [],
    )


def make_procedure(
    source_id: str, source_name: str, technique_id: str, description: str = "", citations=None
) -> Procedure:
    return Procedure(
        source_id=source_id,
        source_name=source_name,
        technique_id=technique_id,
        description=description,
        citations=citations or [],
    )


def make_entry(technique_id: str, score: int, procedures=None, links=None) -> TechniqueEntry:
    return TechniqueEntry(
        technique_id=technique_id,
        score=score,
        procedures=procedures if procedures is not None else [],
        links=links if links is not None else [],
    )


def make_attack(
    techniques,
    tactics,
    sources=None,
    procedures=None,
    version: str = "19.2",
    domain: str = "enterprise-attack",
) -> AttackData:
    return AttackData(
        version=version,
        domain=domain,
        techniques={t.attack_id: t for t in techniques},
        tactics=tactics,
        sources=sources or {},
        procedures=procedures or {},
    )


def make_config(**overrides) -> Config:
    config = Config(sources={"G0128": 1})
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


NO_SOURCES = AnalyticSources(car_techniques=set(), jpcert_tools=[])


# ---------------------------------------------------------------------------
# PlanRow field formats
# ---------------------------------------------------------------------------


def test_multi_tactic_question_and_indicator():
    tactics = [make_tactic("execution", "Execution"), make_tactic("persistence", "Persistence")]
    technique = make_technique(
        attack_id="T1059",
        full_name="Foo: Bar",
        tactics=["execution", "persistence"],
    )
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=3)
    rows = build_plan([entry], attack, make_config(), NO_SOURCES)
    assert len(rows) == 1
    row = rows[0]
    assert row.tactics == ["Execution", "Persistence"]
    assert (
        row.tactic_question
        == "Has the adversary used Execution or Persistence on/in the network environment?"
    )
    assert row.indicator == "Is there evidence of Foo: Bar?"
    assert row.technique_name == "Foo: Bar"
    assert row.technique_id == "T1059"
    assert row.score == 3


def test_single_tactic_question_has_no_or():
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(tactics=["execution"])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.tactic_question == "Has the adversary used Execution on/in the network environment?"


def test_evidence_md_bolds_label_and_links_citations():
    tactics = [make_tactic("execution", "Execution")]
    cite = Citation("Foo 2020", "https://example.com/foo")
    proc1 = make_procedure(
        "G0001",
        "Group One",
        "T1059",
        description="Used a tool.(Citation: Foo 2020)",
        citations=[cite],
    )
    proc2 = make_procedure("S0001", "S0001", "T1059", description="No citation here.")
    technique = make_technique(tactics=["execution"], detection_strategies=[])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=2, procedures=[proc1, proc2])
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.evidence_md == (
        "**G0001 Group One**: Used a tool. ([Foo 2020](https://example.com/foo))"
        "\n\n**S0001**: No citation here."
    )


def test_description_md_links_technique_citations():
    tactics = [make_tactic("execution", "Execution")]
    cite = Citation("Bar 2021", "https://example.com/bar")
    technique = make_technique(
        tactics=["execution"],
        description="Does a thing.(Citation: Bar 2021)",
        citations={"Bar 2021": cite},
    )
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.description_md == "Does a thing. ([Bar 2021](https://example.com/bar))"


def test_data_components_unique_sorted_and_skips_empty():
    tactics = [make_tactic("execution", "Execution")]
    an1 = make_analytic(
        attack_id="AN0001",
        log_sources=[
            make_log_source(data_component="Process Creation"),
            make_log_source(data_component=""),
        ],
    )
    an2 = make_analytic(
        attack_id="AN0002", log_sources=[make_log_source(data_component="Network Traffic Flow")]
    )
    strat = make_strategy(analytics=[an1, an2])
    technique = make_technique(tactics=["execution"], detection_strategies=[strat])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.data_components == ["Network Traffic Flow", "Process Creation"]


def test_category_network_when_any_data_component_matches():
    tactics = [make_tactic("command-and-control", "Command and Control")]
    an = make_analytic(log_sources=[make_log_source(data_component="Network Traffic Flow")])
    strat = make_strategy(analytics=[an])
    technique = make_technique(tactics=["command-and-control"], detection_strategies=[strat])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.category == "network"


def test_category_host_when_no_network_data_component():
    tactics = [make_tactic("execution", "Execution")]
    an = make_analytic(log_sources=[make_log_source(data_component="Process Creation")])
    strat = make_strategy(analytics=[an])
    technique = make_technique(tactics=["execution"], detection_strategies=[strat])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.category == "host"


def test_category_host_when_no_analytics_at_all():
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(tactics=["execution"], detection_strategies=[])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.category == "host"
    assert row.data_components == []
    assert row.log_sources_md == ""


def test_log_sources_md_table_format_and_dedup_and_escaping():
    tactics = [make_tactic("execution", "Execution")]
    ls1 = make_log_source(
        data_component="Process Creation", name="WinEventLog:Security", channel="EventCode=4688"
    )
    ls_dup = make_log_source(
        data_component="Process Creation", name="WinEventLog:Security", channel="EventCode=4688"
    )
    ls_special = make_log_source(data_component="Command Execution", name="a|b", channel="line1\nline2")
    an1 = make_analytic(attack_id="AN0001", log_sources=[ls1, ls_dup])
    an2 = make_analytic(attack_id="AN0002", log_sources=[ls_special])
    strat = make_strategy(analytics=[an1, an2])
    technique = make_technique(tactics=["execution"], detection_strategies=[strat])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    lines = row.log_sources_md.splitlines()
    assert lines[0] == "| Data Component | Log Source | Channel |"
    assert lines[1] == "| --- | --- | --- |"
    assert lines[2] == "| Process Creation | WinEventLog:Security | EventCode=4688 |"
    assert lines[3] == "| Command Execution | a\\|b | line1<br>line2 |"
    assert len(lines) == 4  # the duplicate log source row was not repeated


def test_analytics_md_lists_strategy_car_and_tools():
    tactics = [make_tactic("execution", "Execution")]
    strat = make_strategy(
        attack_id="DET0103", name="Suspicious Process", url="https://attack.mitre.org/detection/DET0103"
    )
    technique = make_technique(
        attack_id="T1059",
        description="The actor used BITS to move files.",
        tactics=["execution"],
        detection_strategies=[strat],
    )
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=1)
    sources = AnalyticSources(car_techniques={"T1059"}, jpcert_tools=[("bits", "https://tool.example/bits")])
    row = build_plan([entry], attack, make_config(), sources)[0]
    assert row.analytics_md == (
        "[DET0103: Suspicious Process](https://attack.mitre.org/detection/DET0103)"
        f"\n\n[Cyber Analytics Repository: T1059]({CAR_URL})"
        "\n\n[Tool Analysis Result Sheet: bits](https://tool.example/bits)"
    )


def test_analytics_md_tool_matching_is_whole_word_across_evidence_and_description():
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(
        attack_id="T1059",
        description="Observed on wordpress installs and while tracking satellite orbits.",
        tactics=["execution"],
    )
    attack = make_attack([technique], tactics)
    proc = make_procedure("G0001", "Group One", "T1059", description="No relevant tool words here.")
    entry = make_entry("T1059", score=1, procedures=[proc])
    sources = AnalyticSources(
        car_techniques=set(),
        jpcert_tools=[("rdp", "https://tool.example/rdp"), ("bits", "https://tool.example/bits")],
    )
    row = build_plan([entry], attack, make_config(), sources)[0]
    assert row.analytics_md == ""


def test_analytics_detail_md_sections_in_order():
    tactics = [make_tactic("execution", "Execution")]
    ls = make_log_source(
        data_component="Process Creation", name="WinEventLog:Security", channel="EventCode=4688"
    )
    an = make_analytic(
        attack_id="AN0110",
        url="https://attack.mitre.org/analytics/AN0110",
        description="Looks for X.",
        platforms=["Windows", "Linux"],
        log_sources=[ls],
    )
    strat = make_strategy(
        attack_id="DET0103",
        name="Suspicious Process",
        url="https://attack.mitre.org/detection/DET0103",
        analytics=[an],
    )
    technique = make_technique(attack_id="T1059", tactics=["execution"], detection_strategies=[strat])
    attack = make_attack([technique], tactics)
    sources = AnalyticSources(
        car_techniques={"T1059"}, jpcert_tools=[("psexec", "https://tool.example/psexec")]
    )
    proc = make_procedure("G0001", "Group One", "T1059", description="used psexec")
    entry = make_entry("T1059", score=1, procedures=[proc])
    row = build_plan([entry], attack, make_config(), sources)[0]
    expected = "\n\n".join(
        [
            "### [DET0103: Suspicious Process](https://attack.mitre.org/detection/DET0103)",
            "#### [AN0110](https://attack.mitre.org/analytics/AN0110) (Windows, Linux)\n\n"
            "Looks for X.\n\n"
            "| Data Component | Log Source | Channel |\n"
            "| --- | --- | --- |\n"
            "| Process Creation | WinEventLog:Security | EventCode=4688 |",
            f"[Cyber Analytics Repository: T1059]({CAR_URL})",
            "[Tool Analysis Result Sheet: psexec](https://tool.example/psexec)",
        ]
    )
    assert row.analytics_detail_md == expected


def test_references_md_ordering_and_dedup():
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(
        attack_id="T1059", url="https://attack.mitre.org/techniques/T1059/", tactics=["execution"]
    )
    attack = make_attack([technique], tactics)
    shared = Citation("Shared 2020", "https://example.com/shared")
    only_in_links = Citation("LinksOnly", "https://example.com/links-only")
    no_url = Citation("NoUrl", None)
    proc1 = make_procedure("G0001", "Group One", "T1059", citations=[shared, no_url])
    proc2 = make_procedure("S0001", "Soft One", "T1059", citations=[shared])  # duplicate of proc1's citation
    entry = make_entry("T1059", score=1, procedures=[proc1, proc2], links=[shared, only_in_links])
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.references_md == (
        "[T1059 on MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/)"
        "\n\n[Shared 2020](https://example.com/shared)"
        "\n\nNoUrl"
        "\n\n[LinksOnly](https://example.com/links-only)"
    )


def test_attribution_unique_order_and_label_when_equal():
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(tactics=["execution"])
    attack = make_attack([technique], tactics)
    proc1 = make_procedure("G0001", "Group One", "T1059")
    proc2 = make_procedure("S0001", "S0001", "T1059")  # id == name
    proc3 = make_procedure("G0001", "Group One", "T1059")  # duplicate
    entry = make_entry("T1059", score=1, procedures=[proc1, proc2, proc3])
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    assert row.attribution == ["G0001 Group One", "S0001"]


def test_build_plan_keeps_entry_order():
    tactics = [make_tactic("execution", "Execution")]
    t1 = make_technique(attack_id="T1059", tactics=["execution"])
    t2 = make_technique(attack_id="T1055", tactics=["execution"])
    attack = make_attack([t1, t2], tactics)
    entries = [make_entry("T1055", score=1), make_entry("T1059", score=5)]
    rows = build_plan(entries, attack, make_config(), NO_SOURCES)
    assert [row.technique_id for row in rows] == ["T1055", "T1059"]


# ---------------------------------------------------------------------------
# write_csv
# ---------------------------------------------------------------------------


def _simple_row(**overrides):
    tactics = [make_tactic("execution", "Execution")]
    technique = make_technique(tactics=["execution"])
    attack = make_attack([technique], tactics)
    entry = make_entry("T1059", score=2)
    row = build_plan([entry], attack, make_config(), NO_SOURCES)[0]
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


def test_csv_columns_header():
    assert CSV_COLUMNS == [
        "Tactic",
        "Technique ID",
        "Technique",
        "Score",
        "Category",
        "Indicator",
        "Analytic",
        "Evidence",
        "Data Components",
        "Description",
        "Reference",
        "Attribution",
    ]


def test_write_csv_header_and_rows(tmp_path):
    row = _simple_row(
        data_components=["Process Creation", "File Creation"],
        attribution=["G0001 Group One", "S0001"],
    )
    path = tmp_path / "analytic_plan.csv"
    write_csv([row], path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    assert rows[0] == CSV_COLUMNS
    data_row = dict(zip(CSV_COLUMNS, rows[1], strict=True))
    assert data_row["Technique ID"] == "T1059"
    assert data_row["Score"] == "2"
    assert data_row["Category"] == "host"
    assert data_row["Data Components"] == "Process Creation\n\nFile Creation"
    assert data_row["Attribution"] == "G0001 Group One\n\nS0001"


def test_write_csv_utf8_sig_bom(tmp_path):
    row = _simple_row()
    path = tmp_path / "analytic_plan.csv"
    write_csv([row], path)
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")


def test_write_csv_preserves_newlines_inside_cells(tmp_path):
    row = _simple_row(evidence_md="**G0001 Group One**: line one\n\nline two")
    path = tmp_path / "analytic_plan.csv"
    write_csv([row], path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    data_row = dict(zip(CSV_COLUMNS, rows[1], strict=True))
    assert data_row["Evidence"] == "**G0001 Group One**: line one\n\nline two"


def test_write_csv_truncates_oversized_cells(tmp_path):
    huge = "x" * 40_000
    row = _simple_row(description_md=huge)
    path = tmp_path / "analytic_plan.csv"
    write_csv([row], path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    data_row = dict(zip(CSV_COLUMNS, rows[1], strict=True))
    description = data_row["Description"]
    assert description.endswith("\n\n[truncated]")
    assert description.startswith("x" * 100)
    assert len(description) == 32_000 + len("\n\n[truncated]")


def test_write_csv_creates_parent_directories(tmp_path):
    row = _simple_row()
    path = tmp_path / "nested" / "dir" / "analytic_plan.csv"
    write_csv([row], path)
    assert path.is_file()
