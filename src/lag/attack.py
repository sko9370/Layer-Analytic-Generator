"""Parse MITRE ATT&CK STIX bundles into the models used by the rest of LAG."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from lag import text
from lag.errors import LagError
from lag.fetch import fetch_text
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
)

logger = logging.getLogger(__name__)

ATTACK_SOURCE_NAMES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
SOURCE_TYPES = ("intrusion-set", "malware", "tool", "campaign")

STIX_DATA_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"


def stix_url(domain: str, version: str = "") -> str:
    """URL of the ATT&CK STIX bundle for domain, latest or a specific version."""
    if version:
        return f"{STIX_DATA_BASE}/{domain}/{domain}-{version}.json"
    return f"{STIX_DATA_BASE}/{domain}/{domain}.json"


def load_attack(config: Config) -> AttackData:
    """Load and parse ATT&CK data per config: a local STIX file, or a download (cached)."""
    if config.stix_file:
        path = Path(config.stix_file)
        if not path.is_file():
            raise LagError(f"STIX file not found: {path}")
        raw = path.read_text(encoding="utf-8")
    else:
        is_latest = not config.attack_version
        url = stix_url(config.domain, config.attack_version)
        raw = fetch_text(
            url,
            config.cache_dir,
            offline=config.offline,
            max_age_hours=24 if is_latest else None,
        )
    bundle = json.loads(raw)
    return parse_bundle(bundle, config.domain)


def technique_sort_key(technique_id: str) -> tuple[int, int]:
    """ "T1059.003" -> (1059, 3), "T1059" -> (1059, 0)."""
    body = technique_id[1:] if technique_id.startswith("T") else technique_id
    main, _, sub = body.partition(".")
    return int(main), int(sub) if sub else 0


def _is_active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _attack_ref(obj: dict) -> tuple[str | None, str | None]:
    """The (external_id, url) of the external_reference naming this object's own ATT&CK ID."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ATTACK_SOURCE_NAMES:
            return ref.get("external_id"), ref.get("url")
    return None, None


def _own_citations(obj: dict) -> dict[str, Citation]:
    """Non-ATT&CK external_references of obj, keyed by source_name."""
    citations: dict[str, Citation] = {}
    for ref in obj.get("external_references", []):
        name = ref.get("source_name")
        if not name or name in ATTACK_SOURCE_NAMES:
            continue
        citations[name] = Citation(name, ref.get("url"))
    return citations


def _relationship_citations(description: str, external_references: list[dict]) -> list[Citation]:
    """Relationship citations, ordered by first appearance in description, then the rest."""
    by_label: dict[str, Citation] = {}
    order: list[str] = []
    for ref in external_references:
        label = ref.get("source_name")
        if not label or label in by_label:
            continue
        by_label[label] = Citation(label, ref.get("url"))
        order.append(label)

    result: list[Citation] = []
    seen: set[str] = set()
    for label in text.citation_labels(description):
        if label in by_label and label not in seen:
            result.append(by_label[label])
            seen.add(label)
    for label in order:
        if label not in seen:
            result.append(by_label[label])
            seen.add(label)
    return result


def _parse_tactics(objects: list[dict], by_id: dict[str, dict], domain: str) -> list[Tactic]:
    matrices = [o for o in objects if o.get("type") == "x-mitre-matrix" and _is_active(o)]
    if not matrices:
        return []
    matrix = next((m for m in matrices if _attack_ref(m)[0] == domain), matrices[0])

    tactics: list[Tactic] = []
    for ref in matrix.get("tactic_refs", []):
        obj = by_id.get(ref)
        if not obj or not _is_active(obj):
            continue
        attack_id, _ = _attack_ref(obj)
        tactics.append(Tactic(attack_id or "", obj.get("x_mitre_shortname", ""), obj.get("name", "")))
    return tactics


def _parse_techniques(
    objects: list[dict], tactics: list[Tactic]
) -> tuple[dict[str, Technique], dict[str, str]]:
    order_by_shortname = {t.shortname: i for i, t in enumerate(tactics)}

    raw: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _is_active(obj):
            continue
        attack_id, url = _attack_ref(obj)
        if not attack_id:
            continue
        parent_id = attack_id.split(".")[0] if "." in attack_id else None

        phase_names = [
            kcp.get("phase_name")
            for kcp in obj.get("kill_chain_phases", [])
            if kcp.get("kill_chain_name") in ATTACK_SOURCE_NAMES
        ]
        phase_names.sort(key=lambda p: order_by_shortname.get(p, len(tactics)))

        raw.append(
            {
                "stix_id": obj["id"],
                "attack_id": attack_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", "") or "",
                "citations": _own_citations(obj),
                "tactics": phase_names,
                "platforms": obj.get("x_mitre_platforms", []),
                "url": url or "",
                "parent_id": parent_id,
            }
        )

    names_by_id = {r["attack_id"]: r["name"] for r in raw}
    techniques: dict[str, Technique] = {}
    stix_id_to_technique_id: dict[str, str] = {}
    for r in raw:
        parent_name = names_by_id.get(r["parent_id"]) if r["parent_id"] else None
        full_name = f"{parent_name}: {r['name']}" if parent_name else r["name"]
        techniques[r["attack_id"]] = Technique(
            attack_id=r["attack_id"],
            name=r["name"],
            full_name=full_name,
            description=r["description"],
            citations=r["citations"],
            tactics=r["tactics"],
            platforms=r["platforms"],
            url=r["url"],
            parent_id=r["parent_id"],
        )
        stix_id_to_technique_id[r["stix_id"]] = r["attack_id"]

    return techniques, stix_id_to_technique_id


def _build_analytic(obj: dict, by_id: dict[str, dict]) -> Analytic:
    attack_id, url = _attack_ref(obj)
    log_sources = []
    for ls in obj.get("x_mitre_log_source_references", []):
        component = by_id.get(ls.get("x_mitre_data_component_ref"))
        data_component = component.get("name", "") if component else ""
        log_sources.append(LogSource(data_component, ls.get("name", "") or "", ls.get("channel", "") or ""))
    return Analytic(
        attack_id=attack_id or "",
        url=url or "",
        description=obj.get("description", "") or "",
        platforms=obj.get("x_mitre_platforms", []),
        log_sources=log_sources,
    )


def _attach_detection_strategies(
    objects: list[dict],
    by_id: dict[str, dict],
    techniques: dict[str, Technique],
    stix_id_to_technique_id: dict[str, str],
) -> None:
    strategy_ids_by_technique: dict[str, list[str]] = {}
    for rel in objects:
        if (
            rel.get("type") != "relationship"
            or rel.get("relationship_type") != "detects"
            or not _is_active(rel)
        ):
            continue
        technique_id = stix_id_to_technique_id.get(rel.get("target_ref"))
        if not technique_id:
            continue
        strategy_obj = by_id.get(rel.get("source_ref"))
        if (
            not strategy_obj
            or strategy_obj.get("type") != "x-mitre-detection-strategy"
            or not _is_active(strategy_obj)
        ):
            continue
        strategy_ids_by_technique.setdefault(technique_id, []).append(strategy_obj["id"])

    strategy_cache: dict[str, DetectionStrategy] = {}

    def build_strategy(strategy_obj: dict) -> DetectionStrategy:
        sid = strategy_obj["id"]
        if sid in strategy_cache:
            return strategy_cache[sid]
        attack_id, url = _attack_ref(strategy_obj)
        analytics = []
        for ref in strategy_obj.get("x_mitre_analytic_refs", []):
            analytic_obj = by_id.get(ref)
            if not analytic_obj or not _is_active(analytic_obj):
                continue
            analytics.append(_build_analytic(analytic_obj, by_id))
        strategy = DetectionStrategy(
            attack_id=attack_id or "",
            name=strategy_obj.get("name", ""),
            url=url or "",
            analytics=analytics,
        )
        strategy_cache[sid] = strategy
        return strategy

    for technique_id, strategy_ids in strategy_ids_by_technique.items():
        strategies = [build_strategy(by_id[sid]) for sid in strategy_ids]
        strategies.sort(key=lambda s: s.attack_id)
        techniques[technique_id].detection_strategies = strategies


def _revoked_technique_map(
    objects: list[dict], by_id: dict[str, dict], techniques: dict[str, Technique]
) -> dict[str, str]:
    """Revoked technique ID -> the active technique that replaced it, following revoked-by chains."""
    replaced_by: dict[str, str] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "revoked-by":
            continue
        source, target = by_id.get(rel.get("source_ref")), by_id.get(rel.get("target_ref"))
        if source and target and source.get("type") == target.get("type") == "attack-pattern":
            replaced_by[source["id"]] = target["id"]

    result: dict[str, str] = {}
    for stix_id in replaced_by:
        old_id, _ = _attack_ref(by_id[stix_id])
        current, seen = stix_id, set()
        while current in replaced_by and current not in seen:
            seen.add(current)
            current = replaced_by[current]
        new_id, _ = _attack_ref(by_id[current])
        if old_id and new_id in techniques and old_id not in techniques:
            result[old_id] = new_id
    return result


def _parse_sources(objects: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    sources: dict[str, str] = {}
    stix_id_to_source_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") not in SOURCE_TYPES or not _is_active(obj):
            continue
        attack_id, _ = _attack_ref(obj)
        if not attack_id:
            continue
        sources[attack_id] = obj.get("name", "")
        stix_id_to_source_id[obj["id"]] = attack_id
    return sources, stix_id_to_source_id


def _parse_procedures(
    objects: list[dict],
    sources: dict[str, str],
    stix_id_to_source_id: dict[str, str],
    stix_id_to_technique_id: dict[str, str],
    techniques: dict[str, Technique],
) -> dict[str, list[Procedure]]:
    procedures: dict[str, list[Procedure]] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses" or not _is_active(rel):
            continue
        source_id = stix_id_to_source_id.get(rel.get("source_ref"))
        technique_id = stix_id_to_technique_id.get(rel.get("target_ref"))
        if not source_id or not technique_id or technique_id not in techniques:
            continue
        description = rel.get("description", "") or ""
        citations = _relationship_citations(description, rel.get("external_references", []))
        procedures.setdefault(source_id, []).append(
            Procedure(
                source_id=source_id,
                source_name=sources[source_id],
                technique_id=technique_id,
                description=description,
                citations=citations,
            )
        )

    for procs in procedures.values():
        procs.sort(key=lambda p: technique_sort_key(p.technique_id))
    return procedures


def parse_bundle(bundle: dict, domain: str = "enterprise-attack") -> AttackData:
    """Parse a raw ATT&CK STIX bundle (as loaded from JSON) into an AttackData."""
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if "id" in o}

    tactics = _parse_tactics(objects, by_id, domain)
    techniques, stix_id_to_technique_id = _parse_techniques(objects, tactics)
    _attach_detection_strategies(objects, by_id, techniques, stix_id_to_technique_id)
    sources, stix_id_to_source_id = _parse_sources(objects)
    procedures = _parse_procedures(
        objects, sources, stix_id_to_source_id, stix_id_to_technique_id, techniques
    )

    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), None)
    version = collection.get("x_mitre_version", "") if collection else ""

    return AttackData(
        version=version,
        domain=domain,
        techniques=techniques,
        tactics=tactics,
        sources=sources,
        procedures=procedures,
        revoked_techniques=_revoked_technique_map(objects, by_id, techniques),
    )
