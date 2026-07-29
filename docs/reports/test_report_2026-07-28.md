# Test Report — 2026-07-28

Scope: OOD benchmark feature (`scripts/eval_ood.py`, `scripts/paraphrase_probe.py`,
`src/data_loader.py` holdout registry, `scripts/train.py` per-family gating).

## Execution summary

| | Count |
|---|---|
| Total | 219 |
| Passed | **219** |
| Failed | 0 |
| Skipped | 0 |
| New this change | 30 |

Command: `python -m pytest tests/ --ignore=tests/security`
Runtime: 23s (46s with coverage). Security tier reported separately.

## Coverage

| Scope | Line coverage |
|---|---|
| `src/` total | **85%** (1,499 statements, 222 missed) |

Notable per-module figures:

| Module | Coverage | Note |
|---|---|---|
| `src/data_loader.py` | 37% | Network-dependent loaders are not exercised in unit tests by design; the holdout *registry* logic is fully covered |
| `src/embedder.py` | 43% | Model-loading paths need weights; covered by the integration tier |
| `src/detector.py` | 84% | — |
| `src/rule_engine.py`, `src/schema.py`, `src/audit.py`, three guards | 100% | — |

Coverage did not regress; the new scripts under `scripts/` are outside the `--cov=src`
scope, and their pure-logic functions are tested via `tests/unit/test_ood_eval.py`.

## New tests

### `tests/unit/test_data_loader.py` (+7)

Holdout isolation. These exist because the failure they prevent is silent: if a held-out
source reaches the training set, the similarity layer compares held-out attacks against
themselves and the benchmark reports a number that means nothing, with no error anywhere.

| Test | Guards against |
|---|---|
| `test_holdout_and_training_sources_are_disjoint` | Any name in both registries |
| `test_holdout_loader_functions_not_reused_in_training` | Same function registered twice under different names |
| `test_wildjailbreak_is_holdout_not_training` | Regression of the specific bug found: its loader was already in `SOURCE_LOADERS`, one `build_dataset.py` run away from contaminating training |
| `test_dolly_is_training_so_alpaca_must_be_the_ood_negative` | Benign holdout silently reverting to Dolly |
| `test_load_holdout_rejects_unknown_source` | Typo'd source name silently yielding no data |
| `test_load_holdout_returns_empty_for_missing_cache` | Missing-cache contract |
| `test_load_holdout_selects_requested_subset` | `--sources` selection |

### `tests/unit/test_ood_eval.py` (+13, new file)

| Group | Tests |
|---|---|
| Config integrity | Weights and threshold are the same objects as `src.detector`'s, so the benchmark cannot silently score a configuration that differs from what ships; split seed matches `train.py` |
| `metrics_at` | Perfect separation; threshold changes result; AUC omitted for single-class; **all-negative reports FPR and omits P/R/F1**; FPR reported alongside F1 when both classes present |
| `layer_profile` | Splits by label; returns `None` rather than a number for an absent class |
| `paraphrase` | Rewrites trigger vocabulary; deterministic per seed; leaves unrelated text alone; handles empty string |

The all-negative test is the one worth naming. Before it, the Alpaca holdout reported
`F1 = 0.0000`, which reads as total failure when the true result was a 3.8% false-positive
rate. That is precisely the class of misleading number this feature was built to eliminate,
so it is now pinned by a test.

## Failures found and fixed during the run

Three defects surfaced from the first benchmark run, all in code written for this change:

1. **Self-match leakage in the in-distribution control.** `known_attacks.jsonl` contains
   every positive including the test split, so each attack matched itself at cosine 1.0
   and the similarity layer reported a perfect `mean_positive`. Fixed by masking
   self-matches by sample id when scoring in-distribution data (347/347 masked). This
   changed a conclusion, not just a number: the similarity layer went from "strong" to
   "near-useless".
2. **Degenerate metrics on single-class holdouts.** Fixed as described above.
3. **`_combined` re-embedded everything.** Now concatenates already-computed per-source
   scores. No correctness impact; removed roughly 3,600 redundant embeddings per run.

A fourth issue was found in the *plan* rather than the code: the control run was expected
to reproduce `benchmark.json`'s F1 0.9699. It does not and cannot — `train.py` scores the
classifier alone while `eval_ood.py` scores the ensemble. Recorded in the benchmark report
and corrected in `docs/OVERVIEW.md` instead of being papered over.

## Tier justification

New feature → unit + integration + E2E per the `testing-and-reports` skill. Integration
and E2E tiers were exercised by the existing suite (`tests/integration/test_detector.py`,
`test_gateway.py`, `test_api.py`) plus the benchmark runs themselves, which are end-to-end
executions of the full artifact-loading and scoring path against real datasets. Stress
tier unchanged and passing (513 rps, p50 1.7ms / p95 2.4ms / p99 5.3ms, measured).
