"""Build the analytic plan (one row per scored technique) and write it as CSV."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from lag.analytics import CAR_URL, AnalyticSources, matching_tools
from lag.models import AttackData, Citation, Config, Technique, TechniqueEntry
from lag.text import link_citations, plain_text, table_cell

MAX_CELL_LENGTH = 32_000

CSV_COLUMNS = [
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


@dataclass
class PlanRow:
    technique_id: str
    technique_name: str
    score: int
    tactics: list[str]
    tactic_question: str
    indicator: str
    category: str  # "host" or "network"
    analytics_md: str
    analytics_detail_md: str
    evidence_md: str
    data_components: list[str]
    log_sources_md: str
    description_md: str
    references_md: str
    attribution: list[str]


def build_plan(
    entries: list[TechniqueEntry],
    attack: AttackData,
    config: Config,
    sources: AnalyticSources,
) -> list[PlanRow]:
    """Build one plan row per entry, keeping entry order."""
    rows = []
    for entry in entries:
        technique = attack.techniques[entry.technique_id]
        tactic_names = [t.name for t in attack.tactics if t.shortname in technique.tactics]
        evidence_md = _evidence_md(entry.procedures)
        description_md = link_citations(technique.description, technique.citations)
        data_components = _data_components(technique)
        category = (
            "network" if any(dc in config.network_data_components for dc in data_components) else "host"
        )
        log_source_rows = _log_source_rows(technique)
        log_sources_md = _log_source_table(log_source_rows)
        combined_text = plain_text(evidence_md) + "\n" + plain_text(technique.description)
        tools = matching_tools(combined_text, sources.jpcert_tools)
        analytics_md = _analytics_md(technique, sources, tools)
        analytics_detail_md = _analytics_detail_md(technique, sources, tools)
        references_md = _references_md(technique, entry)
        attribution = _attribution(entry.procedures)
        rows.append(
            PlanRow(
                technique_id=entry.technique_id,
                technique_name=technique.full_name,
                score=entry.score,
                tactics=tactic_names,
                tactic_question=(
                    f"Has the adversary used {' or '.join(tactic_names)} on/in the network environment?"
                ),
                indicator=f"Is there evidence of {technique.full_name}?",
                category=category,
                analytics_md=analytics_md,
                analytics_detail_md=analytics_detail_md,
                evidence_md=evidence_md,
                data_components=data_components,
                log_sources_md=log_sources_md,
                description_md=description_md,
                references_md=references_md,
                attribution=attribution,
            )
        )
    return rows


def _label(source_id: str, source_name: str) -> str:
    return source_id if source_id == source_name else f"{source_id} {source_name}"


def _evidence_md(procedures: list) -> str:
    paragraphs = []
    for proc in procedures:
        label = _label(proc.source_id, proc.source_name)
        citations = {c.label: c for c in proc.citations}
        paragraphs.append(f"**{label}**: " + link_citations(proc.description, citations))
    return "\n\n".join(paragraphs)


def _attribution(procedures: list) -> list[str]:
    seen: set[str] = set()
    out = []
    for proc in procedures:
        label = _label(proc.source_id, proc.source_name)
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _data_components(technique: Technique) -> list[str]:
    names: set[str] = set()
    for strategy in technique.detection_strategies:
        for analytic in strategy.analytics:
            for log_source in analytic.log_sources:
                if log_source.data_component:
                    names.add(log_source.data_component)
    return sorted(names)


def _log_source_rows(technique: Technique) -> list[tuple[str, str, str]]:
    seen: set[tuple[str, str, str]] = set()
    rows = []
    for strategy in technique.detection_strategies:
        for analytic in strategy.analytics:
            for log_source in analytic.log_sources:
                key = (log_source.data_component, log_source.name, log_source.channel)
                if key not in seen:
                    seen.add(key)
                    rows.append(key)
    return rows


def _log_source_table(rows: list[tuple[str, str, str]]) -> str:
    if not rows:
        return ""
    lines = ["| Data Component | Log Source | Channel |", "| --- | --- | --- |"]
    for component, name, channel in rows:
        lines.append(f"| {table_cell(component)} | {table_cell(name)} | {table_cell(channel)} |")
    return "\n".join(lines)


def _analytics_md(technique: Technique, sources: AnalyticSources, tools: list[tuple[str, str]]) -> str:
    lines = []
    for strategy in technique.detection_strategies:
        lines.append(f"[{strategy.attack_id}: {strategy.name}]({strategy.url})")
    if technique.attack_id in sources.car_techniques:
        lines.append(f"[Cyber Analytics Repository: {technique.attack_id}]({CAR_URL})")
    for name, url in tools:
        lines.append(f"[Tool Analysis Result Sheet: {name}]({url})")
    return "\n\n".join(lines)


def _analytics_detail_md(technique: Technique, sources: AnalyticSources, tools: list[tuple[str, str]]) -> str:
    sections = []
    for strategy in technique.detection_strategies:
        sections.append(f"### [{strategy.attack_id}: {strategy.name}]({strategy.url})")
        for analytic in strategy.analytics:
            platforms = ", ".join(analytic.platforms)
            header = f"#### [{analytic.attack_id}]({analytic.url}) ({platforms})"
            parts = [header, analytic.description]
            table = _log_source_table(
                [(ls.data_component, ls.name, ls.channel) for ls in analytic.log_sources]
            )
            if table:
                parts.append(table)
            sections.append("\n\n".join(parts))
    if technique.attack_id in sources.car_techniques:
        sections.append(f"[Cyber Analytics Repository: {technique.attack_id}]({CAR_URL})")
    for name, url in tools:
        sections.append(f"[Tool Analysis Result Sheet: {name}]({url})")
    return "\n\n".join(sections)


def _references_md(technique: Technique, entry: TechniqueEntry) -> str:
    lines = [f"[{technique.attack_id} on MITRE ATT&CK]({technique.url})"]
    seen: set[str] = set()
    all_citations: list[Citation] = [c for proc in entry.procedures for c in proc.citations] + list(
        entry.links
    )
    for citation in all_citations:
        if citation.label in seen:
            continue
        seen.add(citation.label)
        if citation.url:
            lines.append(f"[{citation.label}]({citation.url})")
        else:
            lines.append(citation.label)
    return "\n\n".join(lines)


def _truncate(value: str) -> str:
    if len(value) > MAX_CELL_LENGTH:
        return value[:MAX_CELL_LENGTH] + "\n\n[truncated]"
    return value


def write_csv(rows: list[PlanRow], path: Path) -> None:
    """Write the plan as an Excel-friendly CSV (utf-8-sig), truncating oversized cells."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for row in rows:
            values = [
                row.tactic_question,
                row.technique_id,
                row.technique_name,
                str(row.score),
                row.category,
                row.indicator,
                row.analytics_md,
                row.evidence_md,
                "\n\n".join(row.data_components),
                row.description_md,
                row.references_md,
                "\n\n".join(row.attribution),
            ]
            writer.writerow([_truncate(value) for value in values])
