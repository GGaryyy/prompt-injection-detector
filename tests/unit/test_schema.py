"""Unit tests for src.schema."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from src.schema import (
    AttackFamily,
    DetectionResult,
    DetectRequest,
    SimilarKnownAttack,
    TrainingSample,
)


pytestmark = pytest.mark.unit


class TestTrainingSample:
    def test_minimal_valid(self) -> None:
        s = TrainingSample(id="x1", prompt="hi", label=0, source="t")
        assert s.label == 0
        assert s.attack_family is None
        assert s.gary_personally_tested is False
        assert s.tested_against == []

    def test_invalid_label(self) -> None:
        with pytest.raises(ValidationError):
            TrainingSample(id="x", prompt="p", label=2, source="t")  # type: ignore[arg-type]

    def test_attack_family_typed(self) -> None:
        s = TrainingSample(
            id="x", prompt="p", label=1, source="t",
            attack_family="meta_conversation",
        )
        assert s.attack_family == "meta_conversation"

    def test_invalid_attack_family(self) -> None:
        with pytest.raises(ValidationError):
            TrainingSample(
                id="x", prompt="p", label=1, source="t",
                attack_family="not_a_real_family",  # type: ignore[arg-type]
            )

    def test_round_trip_json(self) -> None:
        s = TrainingSample(
            id="g1",
            prompt="ignore previous",
            label=1,
            source="gandalf",
            attack_family="trust_partitioning",
            gary_personally_tested=True,
            gary_test_context="L6",
        )
        j = s.model_dump_json()
        s2 = TrainingSample.model_validate_json(j)
        assert s == s2


class TestDetectionResult:
    def test_minimal(self) -> None:
        r = DetectionResult(
            is_injection=True,
            rule_based_score=0.5,
            embedding_based_score=0.6,
            ensemble_score=0.55,
            latency_ms=10.0,
        )
        assert r.is_injection
        assert r.predicted_attack_family is None
        assert r.top_similar_known_attacks == []

    @pytest.mark.parametrize("score", [-0.1, 1.1, 2.0])
    def test_score_bounds(self, score: float) -> None:
        with pytest.raises(ValidationError):
            DetectionResult(
                is_injection=True,
                rule_based_score=score,
                embedding_based_score=0.5,
                ensemble_score=0.5,
                latency_ms=1.0,
            )


class TestDetectRequest:
    def test_minimal(self) -> None:
        r = DetectRequest(text="hello")
        assert r.text == "hello"
        assert r.return_top_k == 5

    def test_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            DetectRequest(text="")

    def test_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            DetectRequest(text="x" * 10_001)


class TestSimilarKnownAttack:
    def test_similarity_bounds(self) -> None:
        s = SimilarKnownAttack(prompt="x", similarity=0.5, source="t")
        assert s.similarity == 0.5

    def test_similarity_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            SimilarKnownAttack(prompt="x", similarity=1.5, source="t")
