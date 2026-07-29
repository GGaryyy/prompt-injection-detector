"""Paraphrase robustness probe for the PI detector.

Rewrites known attacks while preserving intent, then re-scores them with the
frozen artifacts. This isolates a different failure mode from scripts/eval_ood.py:
OOD tests whether the detector generalises to attacks from another distribution;
this tests whether it learned the attack or memorised its surface form.

Rewrites are deterministic and rule-based. No external LLM is called — PID's
whole design claim is that it runs offline, and a probe that phones out to
another model would undercut the artifact it is measuring.

WHAT THIS UNDERSTATES AND OVERSTATES — read before quoting any number:
  - Overstates the rule layer's fragility. Several rewrites swap the exact
    trigger words src/rule_engine.py matches on ("ignore" -> "disregard" is
    still caught, but "ignore all previous" -> "set aside everything stated
    earlier" is not). That is a genuine weakness but a narrow one.
  - Understates the classifier layer's fragility. Rule-based rewriting stays
    lexically close to the original, so embeddings move less than they would
    under real LLM paraphrase or a human rewriting from scratch.
Treat the result as a lower bound on paraphrase degradation, not a measurement
of it.

Run:
    python scripts/paraphrase_probe.py
"""

from __future__ import annotations

import json
import logging
import random
import re
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import rule_engine  # noqa: E402
from src.classifier import InjectionClassifier  # noqa: E402
from src.detector import (  # noqa: E402
    INJECTION_THRESHOLD,
    W_CLS,
    W_RULE,
    W_SIM,
)
from src.embedder import Embedder  # noqa: E402
from src.schema import TrainingSample  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

KNOWN_ATTACKS_PATH = Path("data/processed/known_attacks.jsonl")
MODEL_PATH = Path("data/model/classifier.pkl")
KNOWN_EMBEDDINGS_PATH = Path("data/embeddings/known_attacks.npy")
REPORT_OUT = Path("output/paraphrase_probe.json")

SAMPLE_N = 200
SEED = 42
EMBED_BATCH = 64

# Intent-preserving lexical substitutions, applied case-insensitively.
SUBSTITUTIONS: list[tuple[str, str]] = [
    (r"\bignore\b", "set aside"),
    (r"\bdisregard\b", "pay no attention to"),
    (r"\bforget\b", "put out of mind"),
    (r"\boverride\b", "supersede"),
    (r"\bprevious\b", "earlier-stated"),
    (r"\bprior\b", "earlier-stated"),
    (r"\babove\b", "given further up"),
    (r"\binstructions?\b", "guidance"),
    (r"\brules?\b", "guidance"),
    (r"\bnew\s+task\b", "revised objective"),
    (r"\bpretend\s+to\s+be\b", "take on the part of"),
    (r"\bact\s+as\b", "take on the part of"),
    (r"\byou\s+are\s+now\b", "from here on you operate as"),
    (r"\bsystem\s+prompt\b", "configuration text"),
    (r"\brepeat\b", "restate"),
    (r"\breveal\b", "make known"),
    (r"\bpassword\b", "secret phrase"),
]

# Benign-looking openers, to shift the imperative away from the first token.
PREFIXES = [
    "Quick question before we continue — ",
    "For my own understanding: ",
    "One thing I wanted to check: ",
]


def paraphrase(text: str, rng: random.Random) -> str:
    out = text
    for pattern, replacement in SUBSTITUTIONS:
        out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
    if rng.random() < 0.5:
        out = rng.choice(PREFIXES) + out[0].lower() + out[1:] if out else out
    return out


def load_jsonl(path: Path) -> list[TrainingSample]:
    samples: list[TrainingSample] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                samples.append(TrainingSample.model_validate_json(line))
    return samples


def score(
    texts: list[str],
    embedder: Embedder,
    classifier: InjectionClassifier,
    known_embeddings: np.ndarray,
) -> dict[str, np.ndarray]:
    rule = np.array([rule_engine.detect(t)[0] for t in texts], dtype=np.float32)
    vecs = embedder.encode(texts, batch_size=EMBED_BATCH, show_progress=True)
    cls = classifier.predict_proba(vecs).astype(np.float32)
    sim = np.clip((vecs @ known_embeddings.T).max(axis=1), 0.0, None).astype(np.float32)
    ensemble = np.clip(W_RULE * rule + W_CLS * cls + W_SIM * sim, 0.0, 1.0)
    return {"rule": rule, "cls": cls, "sim": sim, "ensemble": ensemble}


def summarise(res: dict[str, np.ndarray]) -> dict:
    detected = res["ensemble"] >= INJECTION_THRESHOLD
    return {
        "recall": float(detected.mean()),
        "mean_rule": float(res["rule"].mean()),
        "mean_cls": float(res["cls"].mean()),
        "mean_sim": float(res["sim"].mean()),
        "mean_ensemble": float(res["ensemble"].mean()),
    }


def main() -> None:
    for p in (KNOWN_ATTACKS_PATH, MODEL_PATH, KNOWN_EMBEDDINGS_PATH):
        if not p.exists():
            raise FileNotFoundError(f"Missing artifact: {p}. Run scripts/train.py first.")

    # Deterministic sampling is the requirement here, not unpredictability — the probe
    # must select the same 200 prompts on every run so results stay comparable.
    rng = random.Random(SEED)  # nosec B311 - reproducibility, not cryptographic use
    known = load_jsonl(KNOWN_ATTACKS_PATH)
    picked = rng.sample(known, min(SAMPLE_N, len(known)))
    originals = [s.prompt for s in picked]
    rewritten = [paraphrase(t, rng) for t in originals]

    changed = sum(1 for a, b in zip(originals, rewritten) if a != b)
    logger.info(f"{changed}/{len(originals)} prompts actually changed")

    embedder = Embedder()
    classifier = InjectionClassifier.load(MODEL_PATH)
    known_embeddings = np.load(KNOWN_EMBEDDINGS_PATH)

    logger.info("Scoring originals")
    res_orig = score(originals, embedder, classifier, known_embeddings)
    logger.info("Scoring paraphrases")
    res_para = score(rewritten, embedder, classifier, known_embeddings)

    before = summarise(res_orig)
    after = summarise(res_para)

    report = {
        "n_sampled": len(picked),
        "n_changed": changed,
        "seed": SEED,
        "shipped_threshold": INJECTION_THRESHOLD,
        "original": before,
        "paraphrased": after,
        "delta": {k: after[k] - before[k] for k in before},
        "caveat": (
            "Rule-based rewriting stays lexically close to the source, so this is a "
            "lower bound on paraphrase degradation, not a measurement of it. "
            "See module docstring."
        ),
    }

    REPORT_OUT.parent.mkdir(parents=True, exist_ok=True)
    REPORT_OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"Wrote {REPORT_OUT}")

    print("\n=== Paraphrase probe ===")
    print(f"{'':14s} {'recall':>8s} {'rule':>8s} {'cls':>8s} {'sim':>8s}")
    for label, m in (("original", before), ("paraphrased", after)):
        print(
            f"{label:14s} {m['recall']:8.4f} {m['mean_rule']:8.4f} "
            f"{m['mean_cls']:8.4f} {m['mean_sim']:8.4f}"
        )


if __name__ == "__main__":
    main()
