"""Score techniques by weighted source usage and order them for the layer and plan."""

from __future__ import annotations

import logging

from lag.attack import technique_sort_key
from lag.errors import LagError
from lag.models import AttackData, Citation, Config, TechniqueEntry

logger = logging.getLogger(__name__)


def _merge_links(existing: list[Citation], new: list[Citation]) -> None:
    """Append citations from new onto existing, skipping ones already present."""
    seen = {(c.label, c.url) for c in existing}
    for citation in new:
        key = (citation.label, citation.url)
        if key not in seen:
            existing.append(citation)
            seen.add(key)


def score_techniques(
    attack: AttackData, config: Config, imported: list[TechniqueEntry] | None = None
) -> list[TechniqueEntry]:
    """Score every technique used by config.sources, merge in imported entries, and order the result."""
    unknown = [source_id for source_id in config.sources if source_id not in attack.sources]
    if unknown:
        raise LagError(f"unknown source ID(s): {', '.join(unknown)}")

    entries: dict[str, TechniqueEntry] = {}

    for source_id, weight in config.sources.items():
        procedures = attack.procedures.get(source_id, [])
        if not procedures:
            logger.warning("source %s (%s) has no procedures", source_id, attack.sources[source_id])
            continue
        scored_techniques: set[str] = set()
        for procedure in procedures:
            technique_id = procedure.technique_id
            entry = entries.get(technique_id)
            if entry is None:
                entry = TechniqueEntry(technique_id=technique_id, score=0, procedures=[], links=[])
                entries[technique_id] = entry
            if technique_id not in scored_techniques:
                entry.score += weight
                scored_techniques.add(technique_id)
            entry.procedures.append(procedure)

    for imported_entry in imported or []:
        entry = entries.get(imported_entry.technique_id)
        if entry is None:
            entries[imported_entry.technique_id] = TechniqueEntry(
                technique_id=imported_entry.technique_id,
                score=imported_entry.score,
                procedures=list(imported_entry.procedures),
                links=list(imported_entry.links),
            )
        else:
            entry.score += imported_entry.score
            entry.procedures.extend(imported_entry.procedures)
            _merge_links(entry.links, imported_entry.links)

    return order_entries(list(entries.values()), attack)


def order_entries(entries: list[TechniqueEntry], attack: AttackData) -> list[TechniqueEntry]:
    """Group entries by parent technique, order groups by total score, then order within groups."""

    def parent_of(technique_id: str) -> str:
        technique = attack.techniques.get(technique_id)
        if technique is not None:
            return technique.parent_id or technique_id
        return technique_id.split(".")[0]

    groups: dict[str, list[TechniqueEntry]] = {}
    for entry in entries:
        groups.setdefault(parent_of(entry.technique_id), []).append(entry)

    def group_sort_key(parent_id: str) -> tuple[int, tuple[int, int]]:
        total = sum(e.score for e in groups[parent_id])
        return (-total, technique_sort_key(parent_id))

    ordered_parents = sorted(groups, key=group_sort_key)

    result: list[TechniqueEntry] = []
    for parent_id in ordered_parents:
        group_entries = sorted(
            groups[parent_id], key=lambda e: (-e.score, technique_sort_key(e.technique_id))
        )
        result.extend(group_entries)
    return result
