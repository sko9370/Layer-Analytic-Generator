"""Command-line interface for lag: `lag init` and `lag build`."""

from __future__ import annotations

import argparse
import logging
import sys
import tomllib
from pathlib import Path

from lag import config as config_module
from lag import pipeline
from lag.errors import LagError

logger = logging.getLogger(__name__)


def _parse_source(raw: str) -> tuple[str, int]:
    """Parse a --source argument: "G0128" (weight defaults to 1) or "G0128=2"."""
    if "=" in raw:
        source_id, _, weight_str = raw.partition("=")
        weight_str = weight_str.strip()
        try:
            weight = int(weight_str)
        except ValueError as exc:
            raise LagError(f"Invalid --source {raw!r}: {weight_str!r} is not an integer weight") from exc
    else:
        source_id, weight = raw, 1
    source_id = source_id.strip()
    if not source_id:
        raise LagError(f"Invalid --source {raw!r}: missing source ID")
    return source_id, weight


def _init_command(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        raise LagError(f"{path} already exists (use --force to overwrite)")
    path.write_text(config_module.EXAMPLE_CONFIG, encoding="utf-8")
    print(f"Wrote {path}")
    return 0


def _build_command(args: argparse.Namespace) -> int:
    data: dict = {}
    base_dir = Path.cwd()

    if args.config:
        config_path = Path(args.config)
        if not config_path.exists():
            raise LagError(f"Config file not found: {config_path}")
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
        base_dir = config_path.resolve().parent

    if args.source:
        sources: dict[str, int] = {}
        for raw in args.source:
            source_id, weight = _parse_source(raw)
            sources[source_id] = weight
        data["sources"] = sources

    if args.output_dir:
        data["output_dir"] = args.output_dir
    if args.stix_file:
        data.setdefault("attack", {})["stix_file"] = args.stix_file
    if args.offline:
        data.setdefault("attack", {})["offline"] = True
    if args.no_html:
        data.setdefault("html", {})["enabled"] = False

    config = config_module.config_from_dict(data, base_dir)

    result = pipeline.run(config)

    print(f"ATT&CK version: {result.attack_version}")
    print(f"Techniques scored: {result.technique_count}")
    print(f"Layer: {result.layer_path}")
    print(f"Analytic plan CSV: {result.csv_path}")
    if result.html_path is not None:
        print(f"Analytic plan HTML: {result.html_path}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lag", description="Build weighted ATT&CK Navigator layers and analytic plans."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Write an example config file.")
    init_parser.add_argument("path", nargs="?", default="plan.toml")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing file.")
    init_parser.set_defaults(func=_init_command)

    build_parser = subparsers.add_parser("build", help="Run the pipeline.")
    build_parser.add_argument("-c", "--config", default=None, help="Path to a TOML config file.")
    build_parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="ID[=WEIGHT]",
        help="ATT&CK Group/Software/Campaign ID, optionally with a weight (default 1). Repeatable; "
        "replaces the config file's sources when given.",
    )
    build_parser.add_argument("--offline", action="store_true", help="Never touch the network.")
    build_parser.add_argument("--stix-file", default=None, help="Local STIX bundle, skips download.")
    build_parser.add_argument("--output-dir", default=None, help="Output directory.")
    build_parser.add_argument(
        "--no-html", action="store_true", help="Skip building the single-file HTML analytic plan."
    )
    build_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose (INFO) logging.")
    build_parser.set_defaults(func=_build_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    verbose = getattr(args, "verbose", False)
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
        force=True,
    )

    try:
        return args.func(args)
    except LagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
