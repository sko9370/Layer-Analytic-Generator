# Changelog

## 2.0.0

A ground-up rewrite. This is a breaking change from the 2024 Colab notebook in almost every
respect; there is no automatic migration path, but the concepts (weighted Group/Software IDs in,
Navigator layer plus CSV plan plus static site out) carry over directly.

Breaking changes and major changes vs. the July 2024 notebook:

- LAG is now an installable Python package (`pip install "git+https://github.com/sko9370/Layer-Analytic-Generator"`)
  with a `lag` command line tool (`lag init`, `lag build`), instead of a single Colab notebook you
  had to run cell by cell. The notebook still exists (`lag.ipynb`) but is now a thin wrapper around
  the package.
- Requires Python 3.11+.
- Dropped the `mitreattack-python`, `stix2`, `pandas`, and `natsort` dependencies. ATT&CK STIX
  bundles are now parsed directly; there is no periodic "update mitreattack-python and check for
  breaking changes" chore anymore.
- Splunk Security Content integration has been removed. It is planned to return later as an
  optional add-on (see the README's Future Works) rather than a hard dependency that downloads and
  unzips a GitHub release on every run.
- A technique now shows up under every ATT&CK tactic it belongs to in the Navigator layer (no
  `tactic` key is written), instead of being forced under a single tactic via the old
  `tactics_priority` list.
- Adds support for ATT&CK's native detection strategies and analytics
  (`x-mitre-detection-strategy` / `x-mitre-analytic` / `x-mitre-data-component`), which are now
  shown in the plan and the site alongside MITRE CAR and JPCERT/CC Tool Analysis Result Sheet
  matches.
- The host vs. network split in the plan is now based on the ATT&CK data components attached to a
  technique's analytics (configurable via `network_data_components`), instead of the old free-text
  "data sources" substring check.
- Citation matching for procedure descriptions is now exact (matched by citation label against the
  relationship's own external references) instead of a substring search across the whole citations
  table, which could pick up the wrong reference.
- JPCERT/CAR tool matching is now whole-word (regex word boundaries) instead of a plain substring
  search, so a tool name is no longer matched inside an unrelated longer word.
- Custom Navigator layer import is more correct: same technique ID appearing under multiple tactics
  in the source layer is merged (max score, union of text/links) instead of silently keeping
  whichever row happened to sort first; unscored techniques with real content (comment, metadata,
  or links) are kept with a score of 1 instead of being dropped by a `dropna()` call.
- Config now lives in a single validated TOML file (`lag init` writes a fully-commented example;
  `lag build -c plan.toml` reads it) instead of hand-edited notebook cells with no validation.
- Adds offline support: a local `stix_file` to skip downloading ATT&CK data entirely, and a
  time-based on-disk cache (`cache_dir`) for ATT&CK/CAR/JPCERT downloads, with a `--offline` flag
  that fails clearly instead of hanging on the network.
- Adds an automated test suite (`pytest`, network-free by default; `pytest -m live` for a
  periodic check against the real upstream endpoints) and a CI workflow that runs it, plus `ruff`
  linting and formatting, replacing the previous "no tests" state.

## 1.0.0

The original Colab notebook (`lag.ipynb`), first published July 2024. Given a comma-separated list
of MITRE ATT&CK Group and Software IDs with integer multipliers, it downloaded ATT&CK STIX data via
`mitreattack-python`, pulled Splunk Security Content and MITRE CAR coverage, and produced:

- a merged, weighted, colored ATT&CK Navigator layer (`layer.json`) with procedures in technique
  metadata and reference links available on right-click;
- an analytic plan CSV, ordered by overlap score across the given Group/Software IDs;
- a static MkDocs site of the plan (`site.zip`), viewable locally or hosted on a web server.

Known limitations carried forward into the 2.0.0 rewrite: techniques were assigned to a single
tactic via a hardcoded priority list, host/network categorization used a free-text substring check
on ATT&CK's "data sources" field, Splunk Security Content had to be downloaded and unzipped on
every run, and there was no automated test coverage.
