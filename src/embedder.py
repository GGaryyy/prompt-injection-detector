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


def _ensure_extended_attention_mask() -> None:
    """Restore PreTrainedModel.get_extended_attention_mask, removed in transformers 5.

    nomic-embed-text-v1.5 runs remote code (nomic-bert-2048) that still calls it, so on
    transformers 5 encoding fails with AttributeError. Staying on transformers 4 is not an
    option: pip-audit reports vulnerabilities there that are only fixed in 5.x.
    This is the transformers 4.x encoder-path implementation; decoder (causal) models are
    not supported because no model this project loads is one.
    """
    import torch
    from transformers import PreTrainedModel

    if hasattr(PreTrainedModel, "get_extended_attention_mask"):
        return

    def get_extended_attention_mask(self, attention_mask, input_shape, device=None, dtype=None):
        if getattr(self.config, "is_decoder", False):
            raise NotImplementedError("extended attention mask shim covers encoder models only")
        if dtype is None:
            dtype = self.dtype
        if attention_mask.dim() == 3:
            extended = attention_mask[:, None, :, :]
        elif attention_mask.dim() == 2:
            extended = attention_mask[:, None, None, :]
        else:
            raise ValueError(
                f"Wrong shape for input_ids (shape {input_shape}) or attention_mask "
                f"(shape {attention_mask.shape})"
            )
        extended = extended.to(dtype=dtype)
        return (1.0 - extended) * torch.finfo(dtype).min

    PreTrainedModel.get_extended_attention_mask = get_extended_attention_mask


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

        _ensure_extended_attention_mask()
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

        # Renamed to get_embedding_dimension in sentence-transformers 5.x; keep both working.
        get_dim = getattr(self._model, "get_embedding_dimension", None) or (
            self._model.get_sentence_embedding_dimension
        )
        self._dim = get_dim()
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
