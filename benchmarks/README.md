# Model benchmark

`model_benchmark.py` measures how well an LLM extracts MITRE ATT&CK techniques from real threat
reports, scored against ATT&CK's own group/software/campaign mappings as ground truth. Use it to
compare `claude-opus-5` vs `claude-sonnet-5` (or an OpenAI-compatible model) on the same reports.

## Setup

```sh
pip install -e ".[llm]"   # anthropic, openai, pypdf
```

Pick one backend:

- **api** (the Anthropic/OpenAI API): set `ANTHROPIC_API_KEY` (and/or `OPENAI_API_KEY`).
- **claude-code** (your logged-in Claude Code CLI, billed through your subscription instead of
  per-token): run `claude login` once. This is the default when neither `ANTHROPIC_API_KEY` nor
  `OPENAI_API_KEY` is set.

## Dry run (no LLM calls, no credentials needed)

```sh
python benchmarks/model_benchmark.py --dry-run
```

Downloads current ATT&CK data, fetches the 7 default reports, and prints ground-truth technique
counts plus estimated input tokens and cost per model, with no LLM call and no cost.

## Full run

```sh
python benchmarks/model_benchmark.py
```

Compares `claude-opus-5` and `claude-sonnet-5` on the default 7 reports. Useful options:

```sh
# Specific reports, one model, medium confidence as the primary threshold
python benchmarks/model_benchmark.py \
  --report https://example.com/report-1 --report https://example.com/report-2 \
  --models claude-sonnet-5 --min-confidence medium

# Auto-pick the 10 ATT&CK references cited by the most technique relationships that are reachable
python benchmarks/model_benchmark.py --auto 10

# Also compare an OpenAI-compatible model, and force the API backend
python benchmarks/model_benchmark.py --models claude-opus-5,claude-sonnet-5,openai:gpt-5.5 --backend api

# Override/add a price (dollars per million tokens, in/out)
python benchmarks/model_benchmark.py --price gpt-5.5=3/12
```

Results are cached under `--cache-dir` (default `.lag_cache/benchmark`), keyed by document content,
model, effort, and backend, so re-running the same comparison costs nothing. Output is a Markdown
report and a JSON file under `benchmarks/results/` (default name: the UTC timestamp), plus a summary
table printed to stdout.

## Reading the metrics

For each report x model:

- **Exact recall**: the fraction of ATT&CK's ground-truth technique IDs the model also found.
- **Parent recall**: the same, but a sub-technique (`T1059.003`) counts as a match for its parent
  (`T1059`), crediting a model that identifies the right technique family at a coarser grain.
- **Agreement with ATT&CK** (labelled this way instead of "precision"): the fraction of the model's
  predictions that are also in ATT&CK's ground truth.
- **F1**: the harmonic mean of exact recall and agreement with ATT&CK.
- **Missed / extra**: the ground-truth IDs the model did not predict, and the IDs it predicted that
  ATT&CK does not list for this report.

Metrics are always reported at `--min-confidence` (default `low`, i.e. every technique the model
returned) and additionally at `medium`, so you can see how much a model's recall depends on keeping
its lower-confidence guesses.

**Caveats**, worth keeping in mind before treating any of this as a verdict:

- ATT&CK's group/software/campaign mappings are a **partial, human-curated ground truth**, not an
  exhaustive list of every technique a report describes. A model that finds real techniques ATT&CK
  has not (yet) mapped will show up as lower "agreement with ATT&CK", not as wrong. Read agreement
  and recall together, not agreement alone.
- Blog pages can change or disappear after this benchmark ran; a report that was reachable when
  ground truth was built may not extract the same way (or at all) later.
- The default sample is 7 reports: enough to spot a large gap between models, not enough for a
  statistically rigorous evaluation. Use `--auto N` with a larger `N`, or your own `--report` list,
  for a bigger sample.
- The **claude-code** backend adds Claude Code's own harness (system prompt, tool scaffolding)
  around the request, so its absolute token/cost numbers can differ slightly from the API backend.
  The model-to-model comparison within one backend stays like for like. Its "cost" column is the
  CLI's own *API-equivalent list cost*: what the same request would cost on the API, not what your
  subscription was actually billed.
