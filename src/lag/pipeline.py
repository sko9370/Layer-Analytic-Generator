"""End-to-end run: ATT&CK data in, layer.json / analytic_plan.csv / static site out."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from lag import analytics, attack, html, layers, plan, scoring
from lag.errors import LagError
from lag.models import Config

logger = logging.getLogger(__name__)


@dataclass
class RunResult:
    attack_version: str
    technique_count: int
    layer_path: Path
    csv_path: Path
    html_path: Path | None = None


def run(config: Config) -> RunResult:
    """Run the full pipeline for one config: load ATT&CK, score, write the layer and CSV,
    and (if enabled) build the static site."""
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading ATT&CK data")
    attack_data = attack.load_attack(config)

    imported = [
        entry
        for custom_layer in config.custom_layers
        for entry in layers.read_custom_layer(custom_layer, attack_data)
    ]

    logger.info("Scoring techniques")
    entries = scoring.score_techniques(attack_data, config, imported)
    if not entries:
        raise LagError("No techniques were scored: check your sources and custom layers.")

    logger.info("Writing Navigator layer")
    layer_path = output_dir / "layer.json"
    layers.write_layer(layers.build_layer(entries, attack_data, config), layer_path)

    logger.info("Loading analytic sources (CAR, JPCERT)")
    sources = analytics.load_analytic_sources(config)

    logger.info("Building analytic plan")
    rows = plan.build_plan(entries, attack_data, config, sources)
    csv_path = output_dir / "analytic_plan.csv"
    plan.write_csv(rows, csv_path)

    html_path: Path | None = None
    if config.html_enabled:
        logger.info("Building single-file HTML analytic plan")
        html_path = html.build_html(rows, attack_data, config, output_dir / "analytic_plan.html")

    return RunResult(
        attack_version=attack_data.version,
        technique_count=len(entries),
        layer_path=layer_path,
        csv_path=csv_path,
        html_path=html_path,
    )
