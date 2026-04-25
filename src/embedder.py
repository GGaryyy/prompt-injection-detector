"""Sentence embedding wrapper.

Default model: nomic-ai/nomic-embed-text-v1.5 (768-dim, multilingual-decent, US-origin).
Falls back to all-MiniLM-L6-v2 (384-dim, no special deps) if nomic load fails.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable

import numpy as np

logger = logging.getLogger(__name__)


# Defaults — overridable via env or constructor arg
DEFAULT_MODEL = os.environ.get("PI_EMBED_MODEL", "nomic-ai/nomic-embed-text-v1.5")
FALLBACK_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


class Embedder:
    """Lazy-loading sentence-transformer wrapper with batch inference."""

    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        device: str | None = None,
    ) -> None:
        self.model_name = model_name
        self.device = device  # None = auto (cpu fallback if no cuda)
        self._model = None  # lazy load
        self._dim: int | None = None

    def _load(self) -> None:
        if self._model is not None:
            return
        from sentence_transformers import SentenceTransformer

        try:
            logger.info(f"Loading embedding model: {self.model_name}")
            self._model = SentenceTransformer(
                self.model_name,
                device=self.device,
                trust_remote_code=True,
            )
        except Exception as exc:
            logger.warning(
                f"Failed to load {self.model_name} ({exc}); falling back to {FALLBACK_MODEL}"
            )
            self.model_name = FALLBACK_MODEL
            self._model = SentenceTransformer(self.model_name, device=self.device)

        self._dim = self._model.get_sentence_embedding_dimension()
        logger.info(f"Embedder ready: model={self.model_name} dim={self._dim}")

    @property
    def dim(self) -> int:
        if self._dim is None:
            self._load()
        assert self._dim is not None
        return self._dim

    def encode(
        self,
        texts: str | Iterable[str],
        batch_size: int = 32,
        show_progress: bool = False,
    ) -> np.ndarray:
        """Encode one or many texts.

        Args:
            texts: Single string or iterable of strings.
            batch_size: Encoding batch size.
            show_progress: Show a progress bar (useful for large corpora).

        Returns:
            (N, dim) float32 numpy array. N = len(texts).
        """
        self._load()
        single = isinstance(texts, str)
        if single:
            texts_list = [texts]
        else:
            texts_list = list(texts)

        if not texts_list:
            return np.zeros((0, self.dim), dtype=np.float32)

        vecs = self._model.encode(  # type: ignore[union-attr]
            texts_list,
            batch_size=batch_size,
            show_progress_bar=show_progress,
            normalize_embeddings=True,  # cosine similarity = dot product
            convert_to_numpy=True,
        )
        return vecs.astype(np.float32)

    @staticmethod
    def cosine_sim(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Cosine similarity between vectors (assumes both already L2-normalised)."""
        return a @ b.T


def cache_path(processed_dataset_path: Path, model_name: str) -> Path:
    """Standard path for cached embeddings of a given dataset+model."""
    safe = model_name.replace("/", "_").replace("-", "_")
    stem = processed_dataset_path.stem
    return processed_dataset_path.parent.parent / "embeddings" / f"{stem}__{safe}.npy"
