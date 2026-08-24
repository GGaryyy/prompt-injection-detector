"""Out-of-distribution benchmark for the PI detector.

Scores the FROZEN artifacts against held-out sources that never entered
training. Nothing here refits, retunes the threshold, or adjusts the ensemble
weights — those are imported from src.detector so they cannot drift from what
the service actually ships.

The headline number is not the F1 drop. It is the per-layer breakdown: the
similarity layer compares against data/processed/known_attacks.jsonl, which IS
the training positives, so on genuinely unseen attacks that layer has nothing
to match and its contribution collapses by construction.

Run:
    python scripts/eval_ood.py                 # held-out sources
    python scripts/eval_ood.py --in-dist       # reproduce benchmark.json first
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import rule_engine  # noqa: E402
from src.classifier import InjectionClassifier  # noqa: E402
from src.data_loader import load_holdout  # noqa: E402
from src.detector import (  # noqa: E402
    INJECTION_THRESHOLD,
    W_CLS,
    W_RULE,
    W_SIM,
)
from src.embedder import Embedder  # noqa: E402
from src.eval_masking import mask_self_matches, normalise  # noqa: E402
from src.schema import TrainingSample  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# --- Paths (mirror scripts/train.py) ---
DATASET_PATH = Path("data/processed/dataset_v1.jsonl")
MODEL_PATH = Path("data/model/classifier.pkl")
KNOWN_ATTACKS_PATH = Path("data/processed/known_attacks.jsonl")
KNOWN_EMBEDDINGS_PATH = Path("data/embeddings/known_attacks.npy")
REPORT_OUT = Path("output/benchmark_ood.json")
SCORES_OUT = Path("output/ood_scores.npz")  # per-sample layer scores, for re-analysis without re-embedding

# --- Evaluation constants ---
SPLIT_SEED = 42  # must match scripts/train.py for --in-dist reproduction
SPLIT_TEST_SIZE = 0.20
THRESHOLD_SWEEP = [round(x, 2) for x in np.arange(0.05, 1.00, 0.05)]
EMBED_BATCH = 64


def load_jsonl(path: Path) -> list[TrainingSample]:
    samples: list[TrainingSample] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(TrainingSample.model_validate_json(line))
    return samples


def score_samples(
    samples: list[TrainingSample],
    embedder: Embedder,
    classifier: InjectionClassifier,
    known_embeddings: np.ndarray,
    known_ids: list[str] | None = None,
    known_texts: list[str] | None = None,
) -> dict[str, np.ndarray]:
    """Vectorised equivalent of Detector.detect() over many samples.

    Returns per-layer scores so the collapse can be attributed to a layer
    rather than reported as one opaque F1 delta.

    Passing `known_ids` + `known_texts` enables self-match masking. train.py
    writes EVERY positive to known_attacks.jsonl, including the ones in its own
    test split, so scoring the in-distribution split unmasked lets each attack
    match itself at cosine 1.0. That inflates the similarity layer to a perfect
    score and is pure leakage — in production a fresh request is never already
    in the corpus. See src/eval_masking.py.

    Held-out sources are scored unmasked, on the grounds that they are genuinely
    unseen. evaluate() measures that assumption rather than trusting it and
    reports `n_verbatim_in_corpus` per source.
    """
    texts = [s.prompt for s in samples]

    rule = np.array([rule_engine.detect(t)[0] for t in texts], dtype=np.float32)

    vecs = embedder.encode(texts, batch_size=EMBED_BATCH, show_progress=True)
    cls = classifier.predict_proba(vecs).astype(np.float32)

    # known_embeddings and vecs are both L2-normalised, so dot product = cosine.
    sims = vecs @ known_embeddings.T

    # Half-specifying the mask would score unmasked while the caller believes
    # otherwise — the exact silent-inflation failure this masking exists to stop.
    if (known_ids is None) != (known_texts is None):
        raise ValueError("known_ids and known_texts must be given together")

    n_masked = 0
    if known_ids is not None and known_texts is not None:
        n_masked = mask_self_matches(
            sims, [s.id for s in samples], texts, known_ids, known_texts
        )
        logger.info(f"Masked {n_masked}/{len(samples)} self-matches in similarity layer")

    sim = np.clip(sims.max(axis=1), 0.0, None).astype(np.float32)

    ensemble = np.clip(W_RULE * rule + W_CLS * cls + W_SIM * sim, 0.0, 1.0)

    return {
        "rule": rule,
        "cls": cls,
        "sim": sim,
        "ensemble": ensemble,
        "label": np.array([s.label for s in samples], dtype=np.int8),
        "n_self_masked": n_masked,
    }


def metrics_at(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    """Metrics appropriate to what the sample actually contains.

    An all-negative holdout has no meaningful precision, recall, or F1 — they
    collapse to 0.0 regardless of how the detector behaved. Publishing
    "alpaca F1 = 0.0" would read as total failure when the real result is a
    false-positive rate. So P/R/F1 are only emitted when positives exist, and
    the false-positive rate is emitted whenever negatives exist.
    """
    pred = (scores >= threshold).astype(np.int8)
    has_pos = bool((labels == 1).any())
    has_neg = bool((labels == 0).any())

    out: dict = {"threshold": threshold}

    if has_pos:
        out["recall"] = float(recall_score(labels, pred, zero_division=0))
    if has_pos and has_neg:
        out["precision"] = float(precision_score(labels, pred, zero_division=0))
        out["f1"] = float(f1_score(labels, pred, zero_division=0))
        out["auc"] = float(roc_auc_score(labels, scores))
        out["confusion_matrix"] = confusion_matrix(labels, pred).tolist()
    if has_neg:
        neg = labels == 0
        fp = int((pred[neg] == 1).sum())
        out["n_negative"] = int(neg.sum())
        out["false_positives"] = fp
        out["false_positive_rate"] = float(fp / neg.sum())
    return out


def layer_profile(res: dict[str, np.ndarray]) -> dict:
    """Mean per-layer score split by true label.

    The positives row is the one that matters: it shows how much signal each
    layer actually contributes on attacks it is supposed to catch.
    """
    labels = res["label"]
    profile: dict[str, dict[str, float]] = {}
    for layer in ("rule", "cls", "sim", "ensemble"):
        vals = res[layer]
        profile[layer] = {
            "mean_positive": float(vals[labels == 1].mean()) if (labels == 1).any() else None,
            "mean_negative": float(vals[labels == 0].mean()) if (labels == 0).any() else None,
        }
    return profile


def evaluate(
    name: str,
    samples: list[TrainingSample],
    ctx: dict,
    mask_self: bool = False,
) -> tuple[dict, dict[str, np.ndarray]]:
    logger.info(f"[{name}] scoring {len(samples)} samples")
    res = score_samples(
        samples,
        ctx["embedder"],
        ctx["classifier"],
        ctx["known_embeddings"],
        known_ids=ctx["known_ids"] if mask_self else None,
        known_texts=ctx["known_texts"] if mask_self else None,
    )
    # Report what masking actually did, not what the caller asked for.
    n_self_masked = res.pop("n_self_masked")

    report = {
        "n": len(samples),
        "n_positive": int((res["label"] == 1).sum()),
        "n_negative": int((res["label"] == 0).sum()),
        "self_match_masked": n_self_masked > 0,
        "n_self_masked": n_self_masked,
        # Held-out sources are scored unmasked on the grounds that they are genuinely
        # unseen. That is an assumption about the data, so measure it rather than
        # assert it: any prompt here that is verbatim in the training corpus scores
        # its similarity on corpus membership, not on detection.
        "n_verbatim_in_corpus": sum(
            1 for s in samples if normalise(s.prompt) in ctx["known_normalised"]
        ),
        "at_shipped_threshold": metrics_at(res["ensemble"], res["label"], INJECTION_THRESHOLD),
        "layer_profile": layer_profile(res),
        "threshold_sweep": [
            metrics_at(res["ensemble"], res["label"], t) for t in THRESHOLD_SWEEP
        ],
    }
    # F1 only exists when both classes are present; an all-negative source has
    # no "best threshold" in the F1 sense and must not be given a fake one.
    scored = [m for m in report["threshold_sweep"] if "f1" in m]
    if scored:
        best = max(scored, key=lambda m: m["f1"])
        report["best_threshold"] = best["threshold"]
        report["best_f1"] = best["f1"]
    else:
        report["best_threshold"] = None
        report["best_f1"] = None
    return report, res


def run_in_dist(ctx: dict) -> tuple[dict, dict[str, np.ndarray]]:
    """Re-score the same 20% test split train.py used, as the control arm.

    Note this does NOT reproduce output/benchmark.json, and should not be
    expected to: train.py reports the CLASSIFIER's predictions, while this
    scores the full shipped ensemble. The two measure different things.

    Self-matches are masked — see score_samples().
    """
    samples = load_jsonl(DATASET_PATH)
    labels = np.array([s.label for s in samples], dtype=np.int8)
    idx = np.arange(len(samples))
    _, idx_test = train_test_split(
        idx, test_size=SPLIT_TEST_SIZE, random_state=SPLIT_SEED, stratify=labels
    )
    test_samples = [samples[i] for i in idx_test]
    return evaluate("in_dist_test_split", test_samples, ctx, mask_self=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--in-dist",
        action="store_true",
        help="Also re-score the in-distribution test split as a control",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=None,
        help="Holdout source names (default: all registered)",
    )
    args = parser.parse_args()

    required = [MODEL_PATH, KNOWN_ATTACKS_PATH, KNOWN_EMBEDDINGS_PATH]
    if args.in_dist:
        # run_in_dist() re-splits the training corpus, so it needs the dataset too.
        required.append(DATASET_PATH)
    for p in required:
        if not p.exists():
            raise FileNotFoundError(f"Missing artifact: {p}. Run scripts/train.py first.")

    known_attacks = load_jsonl(KNOWN_ATTACKS_PATH)
    known_embeddings = np.load(KNOWN_EMBEDDINGS_PATH)
    if len(known_attacks) != known_embeddings.shape[0]:
        raise ValueError(
            f"Artifact mismatch: known_attacks={len(known_attacks)} "
            f"known_embeddings={known_embeddings.shape[0]}. Retrain before evaluating."
        )

    ctx = {
        "embedder": Embedder(),
        "classifier": InjectionClassifier.load(MODEL_PATH),
        "known_embeddings": known_embeddings,
        "known_ids": [s.id for s in known_attacks],
        "known_texts": [s.prompt for s in known_attacks],
        "known_normalised": {normalise(s.prompt) for s in known_attacks},
    }
    raw_scores: dict[str, np.ndarray] = {}

    report: dict = {
        "config": {
            "weights": {"rule": W_RULE, "classifier": W_CLS, "similarity": W_SIM},
            "shipped_threshold": INJECTION_THRESHOLD,
            "embedder": ctx["embedder"].model_name,
            "known_attacks_n": len(known_attacks),
        },
        "in_dist": None,
        "holdout": {},
    }

    if args.in_dist:
        report["in_dist"], raw_scores["in_dist"] = run_in_dist(ctx)

    holdout = load_holdout(args.sources)
    empty = [k for k, v in holdout.items() if not v]
    if empty:
        # Reporting OOD metrics over whatever happened to download is exactly the
        # kind of unfalsifiable claim this benchmark exists to replace.
        raise RuntimeError(
            f"Holdout sources returned no samples: {empty}. "
            f"Run scripts/download_data.sh, or pass --sources to select only what is available."
        )

    per_source: dict[str, dict[str, np.ndarray]] = {}
    for name, samples in holdout.items():
        report["holdout"][name], per_source[name] = evaluate(name, samples, ctx)

    if len(holdout) > 1:
        # Concatenate the already-computed scores rather than re-embedding.
        combined = {
            key: np.concatenate([per_source[n][key] for n in holdout])
            for key in ("rule", "cls", "sim", "ensemble", "label")
        }
        report["holdout"]["_combined"] = {
            "n": int(len(combined["label"])),
            "n_positive": int((combined["label"] == 1).sum()),
            "n_negative": int((combined["label"] == 0).sum()),
            "self_match_masked": False,
            "at_shipped_threshold": metrics_at(
                combined["ensemble"], combined["label"], INJECTION_THRESHOLD
            ),
            "layer_profile": layer_profile(combined),
            "note": "Mix of sources; the per-source rows are the meaningful ones.",
        }
        per_source["_combined"] = combined

    raw_scores.update(per_source)

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    np.savez_compressed(
        SCORES_OUT,
        **{f"{src}__{layer}": arr for src, res in raw_scores.items() for layer, arr in res.items()},
    )
    logger.info(f"Wrote {REPORT_OUT} and {SCORES_OUT}")

    def fmt(name: str, r: dict) -> str:
        m = r["at_shipped_threshold"]
        lp = r["layer_profile"]
        parts = [f"{name:22s}"]
        for key, label in (("recall", "R"), ("precision", "P"), ("f1", "F1")):
            parts.append(f"{label}={m[key]:.4f}" if key in m else f"{label}=n/a   ")
        if "false_positive_rate" in m:
            parts.append(f"FPR={m['false_positive_rate']:.4f}")
        sim_pos = lp["sim"]["mean_positive"]
        parts.append(f"| sim(pos)={sim_pos:.4f}" if sim_pos is not None else "| sim(pos)=n/a")
        return "  ".join(parts)

    print("\n=== OOD benchmark (shipped threshold %.2f) ===" % INJECTION_THRESHOLD)
    if report["in_dist"]:
        print(fmt("in_dist (self-masked)", report["in_dist"]))
    for name, r in report["holdout"].items():
        print(fmt(name, r))


if __name__ == "__main__":
    main()
