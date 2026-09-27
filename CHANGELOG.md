# Changelog

## 2.0.0

A ground-up rewrite. This is a breaking change from the 2024 Colab notebook in almost every
respect; there is no automatic migration path, but the concepts (weighted Group/Software IDs in,
Navigator layer plus CSV plan plus HTML plan out) carry over directly.

Breaking changes and major changes vs. the July 2024 notebook:

- LAG is now an installable Python package (`pip install "git+https://github.com/sko9370/Layer-Analytic-Generator"`)
  with a `lag` command line tool (`lag init`, `lag build`, `lag extract`), instead of a single
  Colab notebook you had to run cell by cell. The notebook (`lag.ipynb`) is removed entirely; LAG
  is used only through the CLI or the Python API (`from lag.config import load_config; from
  lag.pipeline import run`).
- Requires Python 3.11+.
- Every pipeline step (load ATT&CK data, read custom layers, extract report techniques, score,
  write the layer, load analytic sources, build the plan, write the HTML plan) now reports its own
  `[n/N] step...` progress line and, on failure, raises an error naming the step, the underlying
  cause, and a hint for fixing it, instead of an unlabeled traceback or a bare message.
- Adds LLM-based technique extraction from threat reports (`lag extract <url-or-pdf>`, `[[reports]]`
  in the config, `lag build --report ...`): an LLM reads a report (URL or local PDF/HTML/text file)
  and returns ATT&CK techniques with evidence, a supporting quote, and a confidence level, which
  feed into scoring and the plan like any other source. Results are cached by content hash so
  rebuilds do not re-bill the API. This replaces the old Future Works "TRAM" placeholder with a
  shipped feature. Requires the `layer-analytic-generator[llm]` extra (or `[anthropic]`/`[openai]`
  for a single provider) and an `ANTHROPIC_API_KEY` (or `ant auth login`) or `OPENAI_API_KEY`.
- Adds OpenAI and OpenAI-compatible providers for report extraction (`llm.provider = "openai"`,
  `llm.model`, `llm.base_url`), so a local or self-hosted OpenAI-compatible server (Azure OpenAI,
  Ollama, vLLM, LM Studio) can run extraction instead of, or alongside, the Claude API.
  `llm.pdf_input` picks whether a PDF is sent natively or as text extracted locally with `pypdf`
  (`"auto"` by default: text mode for an OpenAI-compatible `base_url`, native otherwise, since most
  such servers can't take PDF file input). The extraction cache key now also includes provider,
  model, effort, base URL, and PDF input mode.
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
  shown in the plan alongside MITRE CAR and JPCERT/CC Tool Analysis Result Sheet matches.
- The MkDocs static site (a project directory built and zipped on every run) has been replaced by
  `analytic_plan.html`, a single self-contained file with inline CSS/JS, search, and filters by
  tactic, category, and source, that opens by double-click and needs no build step, no separate
  site directory, and no web server. The `[site]` config table (`enabled`/`mode`/`zip`) is replaced
  by `[html]` (`enabled`); `mkdocs` is no longer a dependency.
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
