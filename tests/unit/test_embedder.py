"""Unit tests for the transformers-5 compatibility shim in src/embedder.py."""

from __future__ import annotations

import pytest
import torch
from transformers import PreTrainedModel

from src.embedder import _ensure_extended_attention_mask


class _FakeConfig:
    is_decoder = False


class _FakeModel:
    config = _FakeConfig()
    dtype = torch.float32


def test_shim_present_after_ensure() -> None:
    _ensure_extended_attention_mask()
    assert hasattr(PreTrainedModel, "get_extended_attention_mask")


def test_shim_masks_padding_and_keeps_tokens() -> None:
    _ensure_extended_attention_mask()
    mask = torch.tensor([[1, 1, 0]])
    out = PreTrainedModel.get_extended_attention_mask(_FakeModel(), mask, mask.shape)
    assert out.shape == (1, 1, 1, 3)
    assert out[0, 0, 0, 0].item() == 0.0
    assert out[0, 0, 0, 2].item() == torch.finfo(torch.float32).min


def test_shim_rejects_decoder() -> None:
    _ensure_extended_attention_mask()
    model = _FakeModel()
    model.config = type("C", (), {"is_decoder": True})()
    mask = torch.ones(1, 3)
    with pytest.raises(NotImplementedError):
        PreTrainedModel.get_extended_attention_mask(model, mask, mask.shape)
