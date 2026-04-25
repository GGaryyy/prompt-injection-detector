"""Train the PI detector end-to-end.

Steps:
  1. Load processed dataset from data/processed/dataset_v1.jsonl
  2. Embed all prompts (cached to data/embeddings/)
  3. Train/test split (stratified by label, 80/20)
  4. Fit Logistic Regression baseline
  5. Compute metrics: precision / recall / F1 / AUC, per attack family
  6. Save:
     - data/model/classifier.pkl
     - data/processed/known_attacks.jsonl  (positives only, used for similarity search)
     - data/embeddings/known_attacks.npy   (positives only)
  7. Print benchmark report

Run inside container:
    docker compose run --rm app python scripts/train.py
"""

from __future__ import annotations

import json
import logging
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

# Allow running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.classifier import InjectionClassifier  # noqa: E402
from src.embedder import Embedder  # noqa: E402
from src.schema import TrainingSample  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATASET_PATH = Path("data/processed/dataset_v1.jsonl")
MODEL_OUT = Path("data/model/classifier.pkl")
KNOWN_ATTACKS_OUT = Path("data/processed/known_attacks.jsonl")
KNOWN_EMBEDDINGS_OUT = Path("data/embeddings/known_attacks.npy")
ALL_EMBEDDINGS_CACHE = Path("data/embeddings/dataset_v1.npy")
REPORT_OUT = Path("output/benchmark.json")


def load_dataset(path: Path) -> list[TrainingSample]:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}. Run scripts/build_dataset.py first."
        )
    samples: list[TrainingSample] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(TrainingSample.model_validate_json(line))
    return samples


def main() -> None:
    samples = load_dataset(DATASET_PATH)
    logger.info(f"Loaded {len(samples)} samples")

    # Build feature matrix
    embedder = Embedder()
    texts = [s.prompt for s in samples]
    labels = np.array([s.label for s in samples], dtype=np.int8)

    if ALL_EMBEDDINGS_CACHE.exists():
        logger.info(f"Loading cached embeddings from {ALL_EMBEDDINGS_CACHE}")
        X = np.load(ALL_EMBEDDINGS_CACHE)
        if X.shape[0] != len(texts):
            logger.warning("Cache size mismatch; re-encoding")
            X = embedder.encode(texts, show_progress=True)
            ALL_EMBEDDINGS_CACHE.parent.mkdir(parents=True, exist_ok=True)
            np.save(ALL_EMBEDDINGS_CACHE, X)
    else:
        X = embedder.encode(texts, show_progress=True)
        ALL_EMBEDDINGS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        np.save(ALL_EMBEDDINGS_CACHE, X)
        logger.info(f"Cached embeddings to {ALL_EMBEDDINGS_CACHE}")

    # Stratified split
    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X,
        labels,
        np.arange(len(samples)),
        test_size=0.20,
        random_state=42,
        stratify=labels,
    )
    logger.info(f"Split: train={len(X_train)} test={len(X_test)}")

    # Train
    clf = InjectionClassifier(kind="lr")
    clf.fit(X_train, y_train)

    # Evaluate
    y_proba = clf.predict_proba(X_test)
    y_pred = (y_proba >= 0.5).astype(np.int8)

    metrics = {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "auc": float(roc_auc_score(y_test, y_proba)) if len(set(y_test)) > 1 else float("nan"),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    # Per-attack-family recall
    test_samples = [samples[i] for i in idx_test]
    family_perf: dict[str, dict] = {}
    for fam in {s.attack_family for s in test_samples if s.attack_family}:
        mask = np.array([s.attack_family == fam for s in test_samples])
        if mask.sum() == 0:
            continue
        y_t = y_test[mask]
        y_p = y_pred[mask]
        family_perf[fam] = {
            "n": int(mask.sum()),
            "recall": float(recall_score(y_t, y_p, zero_division=0)),
        }
    metrics["per_attack_family_recall"] = family_perf

    # Save artifacts
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    clf.save(MODEL_OUT)

    # Known attacks (positives) — corpus for similarity search at inference
    pos_samples = [s for s in samples if s.label == 1]
    pos_idx = np.array([i for i, s in enumerate(samples) if s.label == 1])
    pos_embeds = X[pos_idx]
    KNOWN_ATTACKS_OUT.parent.mkdir(parents=True, exist_ok=True)
    with KNOWN_ATTACKS_OUT.open("w", encoding="utf-8") as f:
        for s in pos_samples:
            f.write(s.model_dump_json() + "\n")
    KNOWN_EMBEDDINGS_OUT.parent.mkdir(parents=True, exist_ok=True)
    np.save(KNOWN_EMBEDDINGS_OUT, pos_embeds)
    logger.info(f"Saved {len(pos_samples)} known attacks for similarity search")

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_OUT.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Pretty print
    print()
    print("=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(f"  N (train / test):     {metrics['n_train']} / {metrics['n_test']}")
    print(f"  Accuracy:             {metrics['accuracy']:.4f}")
    print(f"  Precision (injection): {metrics['precision']:.4f}")
    print(f"  Recall (injection):    {metrics['recall']:.4f}")
    print(f"  F1:                   {metrics['f1']:.4f}")
    print(f"  AUC:                  {metrics['auc']:.4f}")
    print(f"  Confusion matrix:     {metrics['confusion_matrix']}")
    print()
    print("  Per attack family recall:")
    for fam, p in sorted(family_perf.items(), key=lambda kv: -kv[1]["n"]):
        print(f"    {fam:40s}  n={p['n']:4d}  recall={p['recall']:.3f}")
    print("=" * 60)
    print(f"  Saved: model -> {MODEL_OUT}")
    print(f"  Saved: known attacks -> {KNOWN_ATTACKS_OUT}")
    print(f"  Saved: known embeddings -> {KNOWN_EMBEDDINGS_OUT}")
    print(f"  Saved: report -> {REPORT_OUT}")


if __name__ == "__main__":
    main()
