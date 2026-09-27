"""Build the ATT&CK Navigator layer and read back custom (imported) layers."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from lag.errors import LagError
from lag.models import AttackData, Citation, Config, CustomLayer, Procedure, TechniqueEntry
from lag.text import plain_text

logger = logging.getLogger(__name__)

NAVIGATOR_VERSION = "5.3.2"
LAYER_FORMAT_VERSION = "4.5"


def _procedure_label(source_id: str, source_name: str) -> str:
    return source_id if source_id == source_name else f"{source_id} {source_name}"


def _technique_metadata(entry: TechniqueEntry) -> list[dict]:
    metadata: list[dict] = []
    for i, procedure in enumerate(entry.procedures):
        if i > 0:
            metadata.append({"divider": True})
        metadata.append(
            {
                "name": _procedure_label(procedure.source_id, procedure.source_name),
                "value": plain_text(procedure.description),
            }
        )
    return metadata


def _technique_links(entry: TechniqueEntry) -> list[dict]:
    links: list[dict] = []
    groups_written = 0
    for procedure in entry.procedures:
        procedure_links = [{"label": c.label, "url": c.url} for c in procedure.citations if c.url]
        if not procedure_links:
            continue
        if groups_written > 0:
            links.append({"divider": True})
        links.extend(procedure_links)
        groups_written += 1

    entry_links = [{"label": c.label, "url": c.url} for c in entry.links if c.url]
    if entry_links:
        if groups_written > 0:
            links.append({"divider": True})
        links.extend(entry_links)

    return links


def build_layer(entries: list[TechniqueEntry], attack: AttackData, config: Config) -> dict:
    """Build an ATT&CK Navigator layer (format 4.5) from scored technique entries."""
    techniques = []
    max_score = 0
    for entry in entries:
        max_score = max(max_score, entry.score)
        techniques.append(
            {
                "techniqueID": entry.technique_id,
                "score": entry.score,
                "enabled": True,
                "showSubtechniques": False,
                "metadata": _technique_metadata(entry),
                "links": _technique_links(entry),
            }
        )

    attack_major = attack.version.split(".")[0] if attack.version else ""
    source_summary = ", ".join(f"{source_id} x{weight}" for source_id, weight in config.sources.items())
    description = (
        f"Weighted analytic plan for {source_summary or 'imported activity'} "
        f"against ATT&CK v{attack.version}."
    )

    return {
        "name": config.name,
        "versions": {
            "attack": attack_major,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_FORMAT_VERSION,
        },
        "domain": config.domain,
        "description": description,
        "techniques": techniques,
        "sorting": 3,
        "layout": {
            "layout": "flat",
            "aggregateFunction": "sum",
            "showID": False,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "gradient": {
            "colors": list(config.layer_gradient),
            "minValue": 1,
            "maxValue": max(3, max_score),
        },
        "legendItems": [],
        "metadata": [
            {"name": "ATT&CK version", "value": attack.version},
            {"name": "Sources", "value": source_summary},
        ],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "hideDisabled": False,
    }


def write_layer(layer: dict, path: Path) -> None:
    """Write a layer dict as pretty-printed UTF-8 JSON, creating parent directories."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2, ensure_ascii=False)


def _meta_lines(metadata: list[dict]) -> list[str]:
    lines = []
    for item in metadata:
        if not isinstance(item, dict) or "divider" in item:
            continue
        lines.append(f"{item.get('name', '')}: {item.get('value', '')}")
    return lines


def _layer_links(links: list[dict]) -> list[Citation]:
    citations = []
    for link in links:
        if not isinstance(link, dict) or "divider" in link:
            continue
        label = link.get("label")
        url = link.get("url")
        if label and url:
            citations.append(Citation(label=label, url=url))
    return citations


def read_custom_layer(custom: CustomLayer, attack: AttackData) -> list[TechniqueEntry]:
    """Read an imported Navigator layer as a list of TechniqueEntry, one per distinct technique ID."""
    path = Path(custom.path)
    if not path.is_file():
        raise LagError(f"custom layer not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        raise LagError(f"could not read custom layer {path}: {exc}") from exc

    techniques = data.get("techniques") if isinstance(data, dict) else None
    if not isinstance(techniques, list):
        raise LagError(f"{path} is not a Navigator layer (no techniques list)")

    order: list[str] = []
    merged: dict[str, dict] = {}

    for tech in techniques:
        if not isinstance(tech, dict):
            continue
        technique_id = tech.get("techniqueID")
        if not technique_id:
            continue
        if technique_id not in attack.techniques and technique_id in attack.revoked_techniques:
            replacement = attack.revoked_techniques[technique_id]
            logger.warning(
                "custom layer %s: %s was revoked in ATT&CK %s; using its replacement %s",
                path,
                technique_id,
                attack.version,
                replacement,
            )
            technique_id = replacement
        if technique_id not in attack.techniques:
            logger.warning("custom layer %s: unknown technique ID %s, skipping", path, technique_id)
            continue

        comment = tech.get("comment") or ""
        metadata = tech.get("metadata") or []
        links_raw = tech.get("links") or []
        meta_lines = _meta_lines(metadata)
        entry_links = _layer_links(links_raw)
        has_content = bool(comment) or bool(meta_lines) or bool(entry_links)

        raw_score = tech.get("score")
        if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            raw_score = None
        if raw_score is None or raw_score <= 0:
            if not has_content:
                continue
            score = 1
        else:
            score = int(round(raw_score))
            if score <= 0:
                if not has_content:
                    continue
                score = 1

        description = "\n\n".join(part for part in [comment, "\n\n".join(meta_lines)] if part)

        if technique_id not in merged:
            order.append(technique_id)
            merged[technique_id] = {"score": score, "descriptions": [], "links": []}
        bucket = merged[technique_id]
        bucket["score"] = max(bucket["score"], score)
        if description and description not in bucket["descriptions"]:
            bucket["descriptions"].append(description)
        seen = {(c.label, c.url) for c in bucket["links"]}
        for citation in entry_links:
            key = (citation.label, citation.url)
            if key not in seen:
                bucket["links"].append(citation)
                seen.add(key)

    result = []
    for technique_id in order:
        bucket = merged[technique_id]
        procedure = Procedure(
            source_id=custom.label,
            source_name=custom.label,
            technique_id=technique_id,
            description="\n\n".join(bucket["descriptions"]),
            citations=[],
        )
        result.append(
            TechniqueEntry(
                technique_id=technique_id,
                score=bucket["score"],
                procedures=[procedure],
                links=bucket["links"],
            )
        )
    return result
