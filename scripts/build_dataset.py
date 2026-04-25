"""Consolidate raw datasets into a single JSONL file with the unified schema.

Reads from `data/raw/` (populated by `scripts/download_data.sh`),
writes to `data/processed/dataset_v1.jsonl`.

Run inside container:
    docker compose run --rm app python scripts/build_dataset.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# Allow running as script
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.data_loader import load_all  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    samples = load_all()
    if not samples:
        logger.error("No samples loaded. Run `bash scripts/download_data.sh` first.")
        sys.exit(1)

    out = Path("data/processed/dataset_v1.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    with out.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(s.model_dump_json() + "\n")

    n_pos = sum(1 for s in samples if s.label == 1)
    n_neg = sum(1 for s in samples if s.label == 0)
    n_gary = sum(1 for s in samples if s.gary_personally_tested)

    logger.info(f"Wrote {len(samples)} samples to {out}")
    logger.info(f"  positive (injection): {n_pos}")
    logger.info(f"  negative (benign):    {n_neg}")
    logger.info(f"  gary-personally-tested: {n_gary}")

    # Per-source breakdown
    from collections import Counter

    by_source = Counter(s.source for s in samples)
    by_family = Counter(s.attack_family for s in samples if s.attack_family)
    logger.info(f"By source: {dict(by_source)}")
    logger.info(f"By attack family: {dict(by_family)}")


if __name__ == "__main__":
    main()
