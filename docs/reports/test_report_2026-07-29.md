# Test Report — 2026-07-29

Scope: the seven code-review findings against `63af750..HEAD` (OOD benchmark +
fail-closed circuit breaker). Two major, five low; all fixed.

## Execution summary

`.venv-dev/bin/python -m pytest tests/ --ignore=tests/security -q`

| | Count |
|---|---|
| Passed | 227 |
| Failed | 0 |
| Skipped | 0 |

Collected across tiers: 206 unit, 18 integration, 3 stress, 3 security. The security
tier shells out to Bandit / detect-secrets / pip-audit and runs separately; the other
227 run in one pass. Previous total was 219 — the eight new tests are
`tests/unit/test_eval_masking.py`.

Run in `.venv-dev`, not Docker. The touched code is the offline evaluation path, which
does not exercise the gateway container.

## New coverage

`tests/unit/test_eval_masking.py` (8 tests) pins `src/eval_masking.py`, extracted from
the inline loop in `eval_ood.py`. The absence of this coverage is the direct reason the
same leak survived in `paraphrase_probe.py`: the masking logic lived inside a
model-weight-dependent function, so nothing tested it, and the second script simply
did not reimplement it.

| Test | What it pins |
|---|---|
| `test_masks_the_rows_own_corpus_entry` | id match blanks that column and no other |
| `test_masks_duplicate_twin_under_a_different_id` | the de-duplication hole — same prompt, two ids |
| `test_text_match_is_case_and_whitespace_insensitive` | normalisation |
| `test_source_text_masks_even_when_the_scored_row_differs` | the paraphrase arm: row text names the *source* |
| `test_masked_value_drops_out_of_max_and_clips_to_zero` | `-inf` survives `.max()`, clips to 0.0 |
| `test_rejects_mismatched_shapes` | 3 shape-validation paths |
| `test_unknown_id_and_text_masks_nothing` | no false masking |
| `test_normalise_collapses_case_and_whitespace` | the normalisation primitive |

One of these caught a bug in its own first draft (a 2×3 `sims` passed with 1 row) —
the shape validation was doing its job before the suite was green.

## Re-runs of the affected measurements

Both benchmarks were re-run because the fix changes what they measure.

**Paraphrase probe** — `python scripts/paraphrase_probe.py`, 200/200 source attacks
masked in each arm:

| | Recall | rule | classifier | similarity |
|---|---|---|---|---|
| Original | 0.9650 | 0.1600 | 0.9529 | 0.8567 |
| Paraphrased | 0.9150 | 0.0270 | 0.8914 | 0.7971 |
| Δ | −0.050 | −0.133 | −0.062 | −0.060 |

Previously published: original recall 0.9750 / similarity 1.0000, Δrecall −0.045,
Δsimilarity −0.101. The similarity delta was the badly distorted figure — most of it
was the original arm falling off a self-match, not the rewrite drifting from the corpus.

**OOD benchmark** — `python scripts/eval_ood.py --in-dist --sources deepset_pi
alpaca_negative`:

| Source | Recall | Precision | F1 | FPR | sim(pos) |
|---|---|---|---|---|---|
| in_dist (self-masked) | 0.9597 | 0.9852 | 0.9723 | 0.0050 | 0.8573 |
| deepset_pi | 0.1977 | 1.0000 | 0.3302 | 0.0000 | 0.6258 |
| alpaca_negative | n/a | n/a | n/a | 0.0380 | n/a |

Unchanged to four decimal places, and 347/1347 masked exactly as before. Adding text
matching to the id-based mask found no duplicate twins among the test positives, so
finding 5 was a latent hole rather than an active distortion. Recorded as such rather
than presented as a correction.

## Second review pass

A follow-up review found no correctness defects and two low-severity notes, both fixed.

**Half-specified masking could score unmasked while reporting otherwise.**
`score_samples()` gated on `known_ids is not None and known_texts is not None`, so a
caller passing only one silently got unmasked scores while `evaluate()` still wrote
`"self_match_masked": true` — from the caller's intent rather than from what happened.
That is precisely the silent-inflation class this whole change exists to remove.
`score_samples()` now raises on a half-specified call, returns the masked count, and
the report flag is derived from it (`n_self_masked > 0`) alongside the raw count.

**"Holdouts are unseen" was an assumption, not a measurement.** Once masking became
text-aware, the old justification (holdouts share no ids with the corpus) no longer
covered the real risk: a holdout prompt verbatim-identical to a training entry scores
its similarity on corpus membership. Nothing checked for that. `evaluate()` now
reports `n_verbatim_in_corpus` per source on every run:

| Source | n | verbatim in corpus |
|---|---|---|
| in_dist test split | 1347 | 347 (= the 347 masked; positives are in the corpus by construction) |
| deepset_pi | 662 | **0** |
| alpaca_negative | 3000 | **0** |

So the holdout results contain no corpus-membership contamination — now a measured
fact rather than a stated assumption. Metrics are unchanged by the check.

## Verification of the non-test fixes

| Fix | How verified |
|---|---|
| Pinned downloader | `bash -n scripts/download_data.sh`; the exact `python -c` snippet run for deepset against a scratch `cache_dir` → 662 samples at the pinned revision |
| `--in-dist` pre-flight | inspected; `DATASET_PATH` now in the required list only when `--in-dist` is set |
| deepset `language` | `"unknown"`; `src/schema.py` field description widened to match |
| USAGE `fail_mode` | removed from the top-level sample, added under `guards:` where it is actually read |

## Security

Bandit on the changed and new files (`src/eval_masking.py`, `scripts/eval_ood.py`,
`scripts/paraphrase_probe.py`): clean. No new dependencies, so no pip-audit delta. Full
security tier not re-run — nothing in this change touches the gateway, its
dependencies, or any credential path.

## Verdict

Pass. All seven findings fixed, one published figure corrected with a dated revision
note in both language versions of the report.
