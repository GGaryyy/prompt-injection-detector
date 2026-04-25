"""FastAPI service exposing the detector.

Endpoints:
- GET /health        liveness check
- GET /              service metadata
- POST /detect       run detection on a text input

Run locally:
    docker compose up api          # http://localhost:8000

Or one-shot:
    docker compose run --rm app uvicorn src.api:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException

from src.detector import Detector
from src.embedder import Embedder
from src.schema import DetectRequest, DetectionResult

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# === Artifact paths (override via env) ===
ARTIFACT_DIR = Path(os.environ.get("PI_ARTIFACT_DIR", "data"))
CLASSIFIER_PATH = ARTIFACT_DIR / "model" / "classifier.pkl"
KNOWN_ATTACKS_PATH = ARTIFACT_DIR / "processed" / "known_attacks.jsonl"
KNOWN_EMBEDDINGS_PATH = ARTIFACT_DIR / "embeddings" / "known_attacks.npy"


app = FastAPI(
    title="Prompt Injection Detector",
    description=(
        "Embedding-based detector for prompt-injection attacks against LLMs. "
        "Rule engine + sentence-transformer classifier + similarity search ensemble."
    ),
    version="0.1.0",
)

_detector: Detector | None = None


def _load_detector() -> Detector:
    """Lazy-load detector at first request (so /health works even before training)."""
    global _detector
    if _detector is not None:
        return _detector

    missing = [
        p
        for p in (CLASSIFIER_PATH, KNOWN_ATTACKS_PATH, KNOWN_EMBEDDINGS_PATH)
        if not p.exists()
    ]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Detector not ready — missing artifacts: {[str(p) for p in missing]}. "
                f"Run `docker compose run --rm app python scripts/train.py` first."
            ),
        )

    logger.info("Loading detector artifacts...")
    _detector = Detector.from_artifacts(
        classifier_path=CLASSIFIER_PATH,
        known_attacks_path=KNOWN_ATTACKS_PATH,
        known_embeddings_path=KNOWN_EMBEDDINGS_PATH,
        embedder=Embedder(),
    )
    logger.info("Detector ready")
    return _detector


@app.get("/")
def root() -> dict:
    return {
        "service": "prompt-injection-detector",
        "version": app.version,
        "endpoints": ["/health", "/detect"],
        "ready": _detector is not None,
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/detect", response_model=DetectionResult)
def detect(req: DetectRequest) -> DetectionResult:
    detector = _load_detector()
    return detector.detect(req.text, top_k=req.return_top_k)
