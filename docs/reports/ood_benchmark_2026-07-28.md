# Out-of-Distribution Benchmark — 2026-07-28

Measures how the shipped detector behaves on data it has never seen. `docs/OVERVIEW.md`
has always listed "in-distribution only" as a known limitation; this report replaces that
unfalsifiable sentence with numbers.

Nothing here was retrained, retuned, or re-weighted. `scripts/eval_ood.py` imports the
weights and threshold from `src/detector.py`, so the configuration under test is the one
that ships.

## Headline

**Recall on genuinely unseen attacks falls from 0.960 to 0.198 at the shipped threshold.**

Two findings matter more than that number:

1. The similarity layer never discriminated. It looked useful in-distribution only
   because of self-match leakage in the evaluation.
2. Most of the collapse is calibration, not blindness. AUC on the held-out attacks is
   0.838 — the ranking still works; the 0.50 threshold is simply wrong for that
   distribution.

## Setup

| | Source | n | Positives | Negatives |
|---|---|---|---|---|
| Control | `dataset_v1` 20% test split (seed 42) | 1,347 | 347 | 1,000 |
| Held-out attacks | `deepset/prompt-injections` | 662 | 263 | 399 |
| Held-out benign | `tatsu-lab/alpaca` (capped) | 3,000 | 0 | 3,000 |

Held-out sources are registered in `HOLDOUT_LOADERS` and are excluded from
`SOURCE_LOADERS`, enforced by `tests/unit/test_data_loader.py`. The benign holdout
deliberately does not reuse Dolly, which supplies 5,000 of the 6,732 training samples;
measuring OOD false positives against training data would measure nothing.

Config under test: weights `rule 0.30 / classifier 0.50 / similarity 0.20`,
threshold `0.50`, embedder `nomic-embed-text-v1.5`, similarity corpus 1,732 known attacks.

## Results

| Dataset | Recall | Precision | F1 | FPR | AUC |
|---|---|---|---|---|---|
| In-dist test split (self-match masked) | 0.9597 | 0.9852 | 0.9723 | 0.0050 | — |
| deepset (unseen attacks) | **0.1977** | 1.0000 | 0.3302 | 0.0000 | 0.8385 |
| alpaca (unseen benign) | n/a | n/a | n/a | **0.0380** | n/a |

Alpaca is all-negative, so precision, recall, and F1 are undefined there — the script
suppresses them rather than emitting the 0.0 that those formulas produce. False-positive
rate is the meaningful figure, and it rises from 0.5% in-distribution to 3.8% on unseen
benign text, roughly 7.6×.

### Per-layer contribution

Mean score by layer, split by true label. The gap between the two columns is the layer's
discriminative power.

| | Positives | Negatives | Gap |
|---|---|---|---|
| **In-distribution** | | | |
| rule | 0.1719 | 0.0003 | 0.172 |
| classifier | 0.9478 | 0.0551 | 0.893 |
| similarity | 0.8582 | 0.5388 | 0.319 |
| **Held out (deepset)** | | | |
| rule | 0.0603 | 0.0010 | 0.059 |
| classifier | 0.3768 | 0.1035 | 0.273 |
| similarity | 0.6258 | 0.5718 | **0.054** |

The similarity layer carries 20% of the ensemble weight and separates unseen attacks from
unseen benign text by 0.054. That is close to noise. It is not that the layer degrades
out of distribution — it barely worked to begin with, and the in-distribution figure above
is already the corrected one.

### The leakage that hid it

`scripts/train.py` writes **every** positive to `known_attacks.jsonl`, including the ones
in its own test split. Scoring that split unmasked lets each attack match itself at cosine
1.0, which is how the similarity layer reported a perfect `mean_positive = 1.0`. In
production a fresh request is never already in the corpus, so that number was an artefact
of the evaluation, not a property of the detector.

`score_samples()` now masks self-matches by sample id when scoring in-distribution data
(347 of 347 positives masked). With masking the similarity layer scores 0.858 rather than
1.000, and the ensemble F1 moves 0.9767 → 0.9723 — small at the ensemble level, because
the layer only carries 20% weight, but it is the difference between "this layer is strong"
and "this layer is near-useless", which is the conclusion that actually matters.

### Threshold sensitivity

deepset, sweeping the decision threshold:

| Threshold | Recall | F1 | FPR |
|---|---|---|---|
| 0.15 | 0.890 | 0.658 | 0.536 |
| **0.20** | 0.722 | **0.722** | 0.183 |
| 0.25 | 0.563 | 0.676 | 0.068 |
| 0.30 | 0.422 | 0.581 | 0.020 |
| 0.40 | 0.293 | 0.449 | 0.008 |
| **0.50 (shipped)** | **0.198** | 0.330 | 0.000 |

At 0.20 the detector recovers to F1 0.722 on the same data, at the cost of an 18.3% false
positive rate. So the detector is not blind to these attacks — its scores rank them
correctly (AUC 0.838), but the score *distribution* shifts down enough that a fixed 0.50
cut rejects most true positives. That is a calibration failure, and it is a different
problem with different fixes than a representation failure would be.

## Paraphrase probe

A separate failure mode: does the detector recognise the attack, or the wording? 200
training positives were rewritten with deterministic, offline lexical substitutions
(`scripts/paraphrase_probe.py`); 164 of 200 changed.

| | Recall | rule | classifier | similarity |
|---|---|---|---|---|
| Original | 0.9650 | 0.1600 | 0.9529 | 0.8567 |
| Paraphrased | 0.9150 | 0.0270 | 0.8914 | 0.7971 |
| Δ | −0.050 | **−0.133 (−83%)** | −0.062 | −0.060 |

Both arms exclude each prompt's source attack from the similarity layer
(`src/eval_masking.py`); 200/200 masked in each. Without that the `original` row scores
similarity 1.0000 against itself and its recall is a property of corpus membership rather
than of detection.

The rule layer is all but erased by synonym substitution — expected, since several
substitutions target the exact tokens `src/rule_engine.py` matches. The classifier barely
moves. Overall recall drops 5.0 points.

**This is a lower bound, not a measurement.** Rule-based rewriting stays lexically close
to the source, so embeddings move less than they would under real paraphrase or a human
rewriting from scratch. That caveat is recorded in the script's module docstring so the
numbers cannot be quoted without it.

> **Revised 2026-07-29.** The figures above replace an earlier version of this table that
> was computed unmasked (`Original` recall 0.9750, similarity 1.0000; Δ recall −0.045,
> Δ similarity −0.101). The similarity delta in particular was an artifact: most of it was
> the original arm falling from a self-match, not the paraphrase moving away from the
> corpus. The masking bug was found by code review — it is the same leak already fixed in
> `scripts/eval_ood.py`, which had not been carried across to the probe.

Read together with the OOD results: the classifier generalises to *rewordings of attacks
it knows* but not to *attacks from a different distribution*.

## Holdout overlap with the training corpus

Held-out sources are scored unmasked, which is only sound if they are genuinely unseen.
Measured (2026-07-29, `n_verbatim_in_corpus` in `output/benchmark_ood.json`): **0 of 662**
deepset prompts and **0 of 3000** Alpaca prompts appear verbatim in
`known_attacks.jsonl` under normalised comparison. The OOD figures above therefore
contain no corpus-membership contamination. This is now reported on every run rather
than assumed.

## Correction to a published figure

`output/benchmark.json` reports F1 0.9699, and `docs/OVERVIEW.md` presented it as the
detector's performance. It is not. `scripts/train.py` computes its metrics from the
**classifier's** predictions alone, not the three-layer ensemble. The two measure
different things and should never have been used interchangeably.

The ensemble on the same split scores F1 0.9723 (self-match masked), so the headline claim
was not inflated — but it was mislabelled, and the plan for this work wrongly assumed the
control run would reproduce 0.9699. It did not, and should not have.

## What this does not cover

- **One held-out attack source, 263 positives.** `allenai/wildjailbreak` is gated behind
  an HF login and could not be fetched, so the attack side rests on deepset alone. A
  single source cannot separate "the detector fails out of distribution" from "the
  detector fails on deepset specifically". Re-run with wildjailbreak before treating
  0.198 as a general figure.
- **English only.** Both held-out sources are predominantly English; the multilingual
  limitation in `OVERVIEW.md` is untouched by this work.
- **Single-turn only.** No multi-turn or Crescendo-style attacks were evaluated.
- **No IPI.** Still out of scope, as documented.

## Reproducing

```bash
bash scripts/download_data.sh                                   # includes held-out sources
python scripts/eval_ood.py --in-dist --sources deepset_pi alpaca_negative
python scripts/paraphrase_probe.py
```

Outputs: `output/benchmark_ood.json`, `output/ood_scores.npz` (per-sample layer scores,
so the analysis above can be recomputed without re-embedding), `output/paraphrase_probe.json`.

## Follow-ups

Deliberately **not** done here — the point of this benchmark was to measure, and tuning
against the held-out set would have turned it into a second training set.

| Item | Note |
|---|---|
| Similarity layer earns its 20% weight? | Gap of 0.054 on unseen data says no. Either replace the max-cosine rule with something better calibrated, or cut the weight and redistribute |
| Threshold calibration | A fixed 0.50 does not transfer. Per-deployment calibration, or a score normalisation step |
| Re-run with wildjailbreak | Needs `huggingface-cli login` |

**Correction (2026-07-29).** An earlier draft of this section proposed "fix the
`known_attacks.jsonl` leak at source, so `train.py` writes only training-split positives".
That is wrong and has been removed. In production the similarity corpus *should* contain
every known attack — a larger corpus is strictly better for a fresh request, which is
never already in it. There is no leak in the artifact; the leak was in evaluating against
it, and masking self-matches in `eval_ood.py` is the correct and complete fix.
