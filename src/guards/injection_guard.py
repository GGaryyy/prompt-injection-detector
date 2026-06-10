"""LLM01 Prompt Injection guard (inbound).

Thin wrapper around the existing PI detector (src.detector.Detector). The guard
does not reimplement detection — it runs the ensemble detector and maps its
DetectionResult onto a GuardVerdict.

ML deps (torch / sentence-transformers / sklearn) are imported lazily inside
`_load()` so this module imports cleanly in environments without them (e.g. the
light test venv). Tests inject a duck-typed fake detector and never load real ML.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Constants ===

DEFAULT_THRESHOLD = 0.5
FLAG_MARGIN = 0.15  # FLAG band sits [threshold - FLAG_MARGIN, threshold)

# Artifact paths (mirror src/api.py).
ARTIFACT_DIR = Path("data")
CLASSIFIER_PATH = ARTIFACT_DIR / "model" / "classifier.pkl"
KNOWN_ATTACKS_PATH = ARTIFACT_DIR / "processed" / "known_attacks.jsonl"
KNOWN_EMBEDDINGS_PATH = ARTIFACT_DIR / "embeddings" / "known_attacks.npy"


@register_guard
class InjectionGuard(Guard):
    guard_id = "llm01_injection"
    owasp_id = "LLM01"
    direction = Direction.INBOUND

    def __init__(self, config: Optional[dict] = None, detector: object = None) -> None:
        super().__init__(config)
        # Optional injected detector for testing; otherwise lazy-loaded on first use.
        self.detector = detector

    def _load(self) -> object:
        if self.detector is not None:
            return self.detector

        # Lazy import — keeps ML deps off the module-import path.
        from src.detector import Detector
        from src.embedder import Embedder

        self.detector = Detector.from_artifacts(
            classifier_path=CLASSIFIER_PATH,
            known_attacks_path=KNOWN_ATTACKS_PATH,
            known_embeddings_path=KNOWN_EMBEDDINGS_PATH,
            embedder=Embedder(),
        )
        return self.detector

    def check(self, ctx: GuardContext) -> GuardVerdict:
        t0 = time.perf_counter()

        if ctx.direction is not Direction.INBOUND:
            return self._verdict(GuardDecision.PASS, 0.0, [], {}, t0)

        threshold = float(self.config.get("threshold", DEFAULT_THRESHOLD))
        detector = self._load()
        result = detector.detect(ctx.text)

        score = float(result.ensemble_score)
        decision = self._decide(result.is_injection, score, threshold)
        reasons = self._reasons(result)
        detail = {
            "explanation": result.explanation,
            "predicted_attack_family": result.predicted_attack_family,
            "is_injection": result.is_injection,
            "threshold": threshold,
        }
        return self._verdict(decision, score, reasons, detail, t0)

    def _decide(self, is_injection: bool, score: float, threshold: float) -> GuardDecision:
        if is_injection and score >= threshold:
            return GuardDecision.BLOCK
        if (threshold - FLAG_MARGIN) <= score < threshold:
            return GuardDecision.FLAG
        return GuardDecision.PASS

    def _reasons(self, result: object) -> list[str]:
        reasons: list[str] = []
        family = getattr(result, "predicted_attack_family", None)
        if family:
            reasons.append(f"predicted_attack_family={family}")

        top = getattr(result, "top_similar_known_attacks", None) or []
        if top:
            first = top[0]
            sim = getattr(first, "similarity", None)
            prompt = getattr(first, "prompt", "") or ""
            note = prompt[:60].replace("\n", " ")
            if sim is not None:
                reasons.append(f"top similar (sim={float(sim):.2f}): {note}")
            else:
                reasons.append(f"top similar: {note}")
        return reasons

    def _verdict(
        self,
        decision: GuardDecision,
        score: float,
        reasons: list[str],
        detail: dict,
        t0: float,
    ) -> GuardVerdict:
        return GuardVerdict(
            guard_id=self.guard_id,
            owasp_id=self.owasp_id,
            direction=self.direction,
            decision=decision,
            score=score,
            reasons=reasons,
            detail=detail,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
        )
