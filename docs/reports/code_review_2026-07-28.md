# Code Review — 2026-07-28

Feature: out-of-distribution benchmark (P3-1). Plan: `docs/plans/plan_pid_ood_benchmark.md`
(meta-repo).

## Scope

| File | Change | Lines |
|---|---|---|
| `scripts/eval_ood.py` | New | 348 |
| `scripts/paraphrase_probe.py` | New | 193 |
| `tests/unit/test_ood_eval.py` | New | 160 |
| `src/data_loader.py` | Holdout registry, two loaders, pinned revisions | +149 |
| `tests/unit/test_data_loader.py` | Holdout isolation tests | +53 |
| `scripts/download_data.sh` | Held-out source downloads | +27 |
| `scripts/train.py` | Per-family recall gating | +22/−7 |
| `docs/OVERVIEW.md` | Measured limits replace prose | +27/−7 |
| `docs/changelog/CHANGELOG.md` | Entries | +28 |

Total ≈ 990 lines added across implementation, tests, and docs.

## Quality assessment

**Readability.** Functions are single-purpose and short; the longest is `main()` in
`eval_ood.py` at roughly 70 lines, mostly linear orchestration. Constants sit in a marked
block at the top of each file per project convention. Naming follows the existing codebase
(`load_<source>`, `SOURCE_LOADERS` / `HOLDOUT_LOADERS`).

**Comments.** Denser than the surrounding codebase, deliberately and, I think, correctly:
most of the non-obvious content here is *why a number is or is not trustworthy*, which is
invisible from the code. `score_samples()`'s masking block, `metrics_at()`'s class-presence
branching, and the holdout-isolation test header all encode reasoning that a future reader
would otherwise have to rediscover by making the same mistake. No docstrings or annotations
were added to untouched code.

**Convention compliance.** Matches project rules: constants blocked at top, no bare
`except` (all handlers name a type or re-raise), forward slashes, tests mirroring `src/`.
`scripts/` remains non-package, so the test module imports by path via `importlib` — this
is a wart, but the alternative is restructuring `scripts/` which is out of scope.

**Complexity.** `score_samples()` is the only function doing real work; it is vectorised
and linear. The self-match masking loop is O(n) over evaluated samples with a dict lookup.

**Performance.** The first implementation re-embedded all 3,662 held-out samples to compute
the `_combined` row. Now it concatenates already-computed per-source arrays — roughly a
third off the runtime. Per-sample scores are persisted to `output/ood_scores.npz` so any
re-analysis skips embedding entirely.

## Findings

| # | File | Line | Severity | Description | Resolution |
|---|---|---|---|---|---|
| 1 | `scripts/eval_ood.py` | `score_samples` | **High** | In-distribution scoring let every test positive match itself at cosine 1.0, because `known_attacks.jsonl` contains all positives including the test split. The similarity layer reported a perfect `mean_positive` | Fixed — self-match masking by sample id. Changed a conclusion, not just a number |
| 2 | `scripts/eval_ood.py` | `metrics_at` | **High** | All-negative holdouts reported `F1 = 0.0`, which reads as total failure when the real result is a false-positive rate | Fixed — P/R/F1 emitted only when positives exist; FPR emitted whenever negatives exist. Pinned by test |
| 3 | `src/data_loader.py` | new loaders | Medium | Held-out datasets loaded without revision pinning, contradicting the report's reproducibility claim | Fixed — both pinned; counts verified unchanged |
| 4 | `scripts/eval_ood.py` | `main` | Low | `_combined` re-embedded everything | Fixed — concatenates existing scores |
| 5 | `scripts/eval_ood.py` | `main` | Low | `--sources` with no arguments yielded `[]`, which fell through to "all sources" rather than erroring | Fixed 2026-07-29 — `nargs="+"` so argparse rejects an empty list |
| 6 | `src/data_loader.py` | training loaders | Medium | Three pre-existing HF loaders unpinned | Fixed 2026-07-29 — pinned after verifying the pinned revisions rebuild `dataset_v1.jsonl` to an identical digest, so the model artifact stays valid. `wildjailbreak` remains unpinned; its revision needs an HF login |
| 7 | `scripts/train.py` | `MIN_FAMILY_N` | Low | Threshold of 10 is a judgment call, not derived | Accepted — documented inline; any value here is a judgment call, and the previous behaviour of publishing n=1 recalls was strictly worse |

Findings 1 and 2 were both self-inflicted, both in code written for this change, and both
found by inspecting the first run's output rather than by a test. That is worth recording:
the tests written up front covered the registry invariants well and the metric semantics
not at all. Tests were added for both after the fact.

## Design notes

**Importing weights rather than restating them.** `eval_ood.py` imports `W_RULE`, `W_CLS`,
`W_SIM`, and `INJECTION_THRESHOLD` from `src.detector`, and a test asserts they are the
same objects. A benchmark that hardcodes its own copy would drift silently and report on a
configuration that does not ship. This is the single most important structural decision in
the change.

**`load_holdout()` deliberately differs from `load_all()`.** `load_all()` skips missing
sources so training can proceed with whatever is present. `load_holdout()` returns empty
and lets `eval_ood.py` abort, because computing metrics over whatever happened to download
is the exact failure mode this feature exists to eliminate. The asymmetry is intentional
and documented in both docstrings.

**Not fixing the measured weakness.** The similarity layer contributes 0.054 of separation
on unseen data while carrying 20% of the ensemble weight, and threshold 0.20 would roughly
triple held-out F1. Neither was changed. Tuning against the held-out set would convert it
into a second training set and destroy the benchmark's value. Both are recorded as
follow-ups in the benchmark report.

**Test-enforced invariant.** The disjointness of `SOURCE_LOADERS` and `HOLDOUT_LOADERS` is
enforced by test rather than convention, because the failure is silent: a contaminated
holdout produces a plausible number with no error anywhere. The bug being guarded against
was real — `wildjailbreak` was already registered for training and only escaped
contamination because nobody had downloaded it.

## Verdict

**Approved with notes.**

219 tests pass, coverage 85%, security scan clean of High/Critical with four dependency
CVEs resolved. The two High findings were caught and fixed before any number was published.

Notes carried forward after the 2026-07-29 follow-up pass (findings 5 and 6 now fixed):
finding 7 (the `MIN_FAMILY_N` threshold is a judgment call) and the single-holdout-source limitation — `wildjailbreak` is gated behind an HF
login, so the 0.198 recall figure rests on one dataset and cannot yet distinguish "fails
out of distribution" from "fails on deepset". That caveat is stated in the benchmark
report, `OVERVIEW.md`, and the interview notes rather than left for a reader to notice.
