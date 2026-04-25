"""Lightweight classifier on top of embeddings.

Two backends:
- LogisticRegression (default, fast, interpretable)
- RandomForest (optional, captures nonlinear patterns)

Outputs probability of injection in [0, 1].
"""

from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Literal

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)

ClassifierKind = Literal["lr", "rf"]


class InjectionClassifier:
    """Wraps a sklearn classifier with a stable interface."""

    def __init__(self, kind: ClassifierKind = "lr") -> None:
        self.kind = kind
        self._model = self._build()
        self._fitted = False

    def _build(self):
        if self.kind == "lr":
            return LogisticRegression(
                max_iter=1000,
                C=1.0,
                class_weight="balanced",
                random_state=42,
            )
        elif self.kind == "rf":
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                min_samples_leaf=2,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            )
        else:
            raise ValueError(f"Unknown classifier kind: {self.kind}")

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        if X.ndim != 2:
            raise ValueError(f"X must be 2D, got shape {X.shape}")
        if X.shape[0] != y.shape[0]:
            raise ValueError(f"X/y length mismatch: {X.shape[0]} vs {y.shape[0]}")
        logger.info(f"Fitting {self.kind} classifier on {X.shape[0]} samples ({X.shape[1]}-dim)")
        self._model.fit(X, y)
        self._fitted = True

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Return P(injection) for each row."""
        if not self._fitted:
            raise RuntimeError("Classifier not fitted yet")
        if X.ndim == 1:
            X = X.reshape(1, -1)
        proba = self._model.predict_proba(X)
        # column 1 = positive class (injection)
        return proba[:, 1]

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(np.int8)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as f:
            pickle.dump({"kind": self.kind, "model": self._model, "fitted": self._fitted}, f)
        logger.info(f"Classifier saved to {path}")

    @classmethod
    def load(cls, path: Path) -> "InjectionClassifier":
        with path.open("rb") as f:
            payload = pickle.load(f)
        c = cls(kind=payload["kind"])
        c._model = payload["model"]
        c._fitted = payload["fitted"]
        logger.info(f"Classifier loaded from {path} (kind={c.kind}, fitted={c._fitted})")
        return c
