"""Main detector — combines rule engine + embedding classifier + similarity search.

Loads everything once at construction (model, classifier, known-attack corpus + embeddings),
then `detect(text)` runs a single inference end-to-end.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from pathlib import Path

import numpy as np

from src import rule_engine
from src.classifier import InjectionClassifier
from src.embedder import Embedder
from src.schema import (
    AttackFamily,
    DetectionResult,
    SimilarKnownAttack,
    TrainingSample,
)

logger = logging.getLogger(__name__)

# Default ensemble weights — tuned on Gandalf experience and adjustable via env if needed
W_RULE = 0.30
W_CLS = 0.50
W_SIM = 0.20

# Decision threshold for is_injection
INJECTION_THRESHOLD = 0.50


class Detector:
    """End-to-end PI detector."""

    def __init__(
        self,
        embedder: Embedder,
        classifier: InjectionClassifier,
        known_attacks: list[TrainingSample],
        known_embeddings: np.ndarray,
    ) -> None:
        self.embedder = embedder
        self.classifier = classifier
        self.known_attacks = known_attacks
        self.known_embeddings = known_embeddings

        if len(known_attacks) != known_embeddings.shape[0]:
            raise ValueError(
                f"known_attacks ({len(known_attacks)}) and known_embeddings "
                f"({known_embeddings.shape[0]}) length mismatch"
            )

    @classmethod
    def from_artifacts(
        cls,
        classifier_path: Path,
        known_attacks_path: Path,
        known_embeddings_path: Path,
        embedder: Embedder | None = None,
    ) -> "Detector":
        """Build a Detector from saved artifacts on disk."""
        import json

        embedder = embedder or Embedder()
        classifier = InjectionClassifier.load(classifier_path)

        known_attacks: list[TrainingSample] = []
        with known_attacks_path.open("r", encoding="utf-8") as f:
            for line in f:
                known_attacks.append(TrainingSample.model_validate_json(line))

        known_embeddings = np.load(known_embeddings_path)
        return cls(embedder, classifier, known_attacks, known_embeddings)

    def detect(self, text: str, top_k: int = 5) -> DetectionResult:
        """Run end-to-end detection on a single text."""
        t0 = time.perf_counter()

        # 1. Rule layer
        rule_score, rule_hits = rule_engine.detect(text)

        # 2. Embedding layer
        vec = self.embedder.encode(text)  # shape (1, D)
        if vec.ndim == 2:
            vec = vec[0]

        # 3. Classifier
        cls_score = float(self.classifier.predict_proba(vec.reshape(1, -1))[0])

        # 4. Similarity search
        sims = self.known_embeddings @ vec  # already L2-normalised
        top_idx = np.argsort(sims)[::-1][:top_k]
        top_similar = [
            SimilarKnownAttack(
                prompt=self.known_attacks[i].prompt[:200],
                attack_family=self.known_attacks[i].attack_family,
                similarity=float(sims[i]),
                source=self.known_attacks[i].source,
            )
            for i in top_idx
        ]
        sim_score = float(sims[top_idx[0]]) if len(top_idx) > 0 else 0.0
        # Cosine sim is in [-1, 1] for normalised vectors; clip & rescale to [0, 1]
        sim_score = max(0.0, sim_score)

        # 5. Ensemble
        ensemble = (
            W_RULE * rule_score + W_CLS * cls_score + W_SIM * sim_score
        )
        ensemble = float(min(max(ensemble, 0.0), 1.0))

        # 6. Predicted attack family — vote among top-k similar (excluding None)
        family_votes = Counter(
            s.attack_family for s in top_similar if s.attack_family is not None
        )
        predicted_family: AttackFamily | None = (
            family_votes.most_common(1)[0][0] if family_votes else None
        )

        # 7. Explanation
        explanation_parts: list[str] = []
        if rule_hits:
            cats = sorted({h.category for h in rule_hits})
            explanation_parts.append(f"Rule matches: {', '.join(cats)}")
        if cls_score > 0.5:
            explanation_parts.append(f"Classifier P(injection)={cls_score:.2f}")
        if sim_score > 0.7:
            explanation_parts.append(
                f"High similarity ({sim_score:.2f}) to known attack"
                + (f" (family={predicted_family})" if predicted_family else "")
            )
        if not explanation_parts:
            explanation_parts.append("No strong signal across rule / classifier / similarity")

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return DetectionResult(
            is_injection=ensemble >= INJECTION_THRESHOLD,
            rule_based_score=rule_score,
            embedding_based_score=cls_score,
            ensemble_score=ensemble,
            predicted_attack_family=predicted_family,
            top_similar_known_attacks=top_similar,
            explanation="; ".join(explanation_parts),
            latency_ms=elapsed_ms,
        )
