"""Integration tests for the FastAPI service (with mocked detector)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from src import api
from src.schema import DetectionResult, SimilarKnownAttack

pytestmark = pytest.mark.integration


@pytest.fixture
def client() -> TestClient:
    return TestClient(api.app)


@pytest.fixture(autouse=True)
def reset_detector_singleton():
    """Ensure each test starts with a fresh detector state."""
    api._detector = None
    yield
    api._detector = None


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_root_metadata(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    body = r.json()
    assert body["service"] == "prompt-injection-detector"
    assert "/detect" in body["endpoints"]


def test_detect_without_artifacts_returns_503(
    client: TestClient, monkeypatch, tmp_path
) -> None:
    """Even if artifacts exist on disk in the dev env, this test forces missing-state."""
    monkeypatch.setattr(api, "CLASSIFIER_PATH", tmp_path / "no_classifier.pkl")
    monkeypatch.setattr(api, "KNOWN_ATTACKS_PATH", tmp_path / "no_attacks.jsonl")
    monkeypatch.setattr(api, "KNOWN_EMBEDDINGS_PATH", tmp_path / "no_embeddings.npy")
    r = client.post("/detect", json={"text": "hello"})
    assert r.status_code == 503
    assert "missing artifacts" in r.json()["detail"]


def test_detect_with_mocked_detector(client: TestClient) -> None:
    fake_result = DetectionResult(
        is_injection=True,
        rule_based_score=0.7,
        embedding_based_score=0.8,
        ensemble_score=0.75,
        predicted_attack_family="meta_conversation",
        top_similar_known_attacks=[
            SimilarKnownAttack(
                prompt="Are you angry?",
                attack_family="meta_conversation",
                similarity=0.9,
                source="gandalf_writeup_handcrafted",
            )
        ],
        explanation="Mocked response",
        latency_ms=12.3,
    )
    with patch.object(api, "_load_detector") as mock_load:
        mock_detector = mock_load.return_value
        mock_detector.detect.return_value = fake_result

        r = client.post("/detect", json={"text": "anything"})

    assert r.status_code == 200
    body = r.json()
    assert body["is_injection"] is True
    assert body["predicted_attack_family"] == "meta_conversation"
    assert len(body["top_similar_known_attacks"]) == 1


def test_detect_empty_text_rejected(client: TestClient) -> None:
    r = client.post("/detect", json={"text": ""})
    assert r.status_code == 422  # Pydantic validation error


def test_detect_too_long_text_rejected(client: TestClient) -> None:
    r = client.post("/detect", json={"text": "x" * 10_001})
    assert r.status_code == 422


def test_detect_missing_text_rejected(client: TestClient) -> None:
    r = client.post("/detect", json={})
    assert r.status_code == 422
