"""Unit tests for src.classifier (synthetic data, no real embedder needed)."""

from __future__ import annotations

import numpy as np
import pytest

from src.classifier import InjectionClassifier

pytestmark = pytest.mark.unit


def test_unfitted_predict_raises() -> None:
    clf = InjectionClassifier(kind="lr")
    with pytest.raises(RuntimeError):
        clf.predict_proba(np.zeros((1, 16), dtype=np.float32))


def test_fit_predict_lr(small_dataset, random_embeddings) -> None:
    clf = InjectionClassifier(kind="lr")
    y = np.array([s.label for s in small_dataset])
    clf.fit(random_embeddings, y)

    proba = clf.predict_proba(random_embeddings)
    assert proba.shape == (len(small_dataset),)
    assert (proba >= 0.0).all()
    assert (proba <= 1.0).all()

    # The fixture injects a learnable signal so fit-time accuracy should be >= 0.9
    pred = clf.predict(random_embeddings)
    acc = (pred == y).mean()
    assert acc >= 0.9, f"Expected high fit accuracy, got {acc}"


def test_fit_predict_rf(small_dataset, random_embeddings) -> None:
    clf = InjectionClassifier(kind="rf")
    y = np.array([s.label for s in small_dataset])
    clf.fit(random_embeddings, y)
    proba = clf.predict_proba(random_embeddings)
    assert proba.shape == (len(small_dataset),)


def test_save_and_load(tmp_path, small_dataset, random_embeddings) -> None:
    clf = InjectionClassifier(kind="lr")
    y = np.array([s.label for s in small_dataset])
    clf.fit(random_embeddings, y)

    path = tmp_path / "clf.pkl"
    clf.save(path)
    assert path.exists()

    clf2 = InjectionClassifier.load(path)
    assert clf2.kind == "lr"
    np.testing.assert_array_equal(
        clf.predict_proba(random_embeddings),
        clf2.predict_proba(random_embeddings),
    )


def test_invalid_X_dim_raises(small_dataset) -> None:
    clf = InjectionClassifier(kind="lr")
    y = np.array([s.label for s in small_dataset])
    with pytest.raises(ValueError):
        clf.fit(np.array([1, 2, 3]), y)


def test_xy_length_mismatch_raises() -> None:
    clf = InjectionClassifier(kind="lr")
    X = np.random.standard_normal((10, 16)).astype(np.float32)
    y = np.array([0, 1, 0])  # length 3 != 10
    with pytest.raises(ValueError):
        clf.fit(X, y)


def test_unknown_kind_raises() -> None:
    with pytest.raises(ValueError):
        InjectionClassifier(kind="xgboost")  # type: ignore[arg-type]
