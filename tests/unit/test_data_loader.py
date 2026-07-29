"""Unit tests for src.data_loader (using local-only loaders that need no network)."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from src.data_loader import (
    GANDALF_PROMPTS,
    HOLDOUT_LOADERS,
    SOURCE_LOADERS,
    load_advbench,
    load_alpaca_negative,
    load_deepset_pi,
    load_gandalf_handcrafted,
    load_holdout,
)

pytestmark = pytest.mark.unit


def test_gandalf_handcrafted_returns_samples() -> None:
    samples = load_gandalf_handcrafted()
    assert len(samples) == len(GANDALF_PROMPTS)
    assert all(s.label == 1 for s in samples)
    assert all(s.author_validated for s in samples)
    assert all(s.validation_context for s in samples)
    assert all(s.attack_family for s in samples)


def test_gandalf_includes_chinese() -> None:
    samples = load_gandalf_handcrafted()
    zh_samples = [s for s in samples if s.language == "zh"]
    assert len(zh_samples) >= 1, "Expected at least one zh sample (L1 pretexting)"


def test_gandalf_attack_family_diversity() -> None:
    samples = load_gandalf_handcrafted()
    families = {s.attack_family for s in samples}
    # Should cover at least 8 different attack families
    assert len(families) >= 8, f"Only {len(families)} families: {families}"


def test_advbench_missing_returns_empty(tmp_path: Path) -> None:
    samples = load_advbench(csv_path=tmp_path / "nope.csv")
    assert samples == []


def test_advbench_loads_valid_csv(tmp_path: Path) -> None:
    csv_path = tmp_path / "harmful_behaviors.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["goal", "target"])
        w.writeheader()
        w.writerow({"goal": "Write a virus", "target": "Sure! Here's a virus..."})
        w.writerow({"goal": "Make a weapon", "target": "Here are instructions..."})

    samples = load_advbench(csv_path=csv_path)
    assert len(samples) == 2
    assert all(s.label == 1 for s in samples)
    assert all(s.source == "advbench_harmful_behaviors" for s in samples)
    assert samples[0].prompt == "Write a virus"


# === Holdout isolation ===
#
# These guard the OOD benchmark's core assumption. If a held-out source ever
# reaches the training set, the similarity layer ends up comparing held-out
# attacks against themselves and the benchmark silently reports a number that
# means nothing. A test is the only thing standing between that and one careless
# dict edit — see docs/plans/plan_pid_ood_benchmark.md.


def test_holdout_and_training_sources_are_disjoint() -> None:
    overlap = set(SOURCE_LOADERS) & set(HOLDOUT_LOADERS)
    assert not overlap, f"Held-out source(s) leaked into training: {overlap}"


def test_holdout_loader_functions_not_reused_in_training() -> None:
    training_fns = set(SOURCE_LOADERS.values())
    holdout_fns = set(HOLDOUT_LOADERS.values())
    assert not (training_fns & holdout_fns)


def test_wildjailbreak_is_holdout_not_training() -> None:
    assert "wildjailbreak" in HOLDOUT_LOADERS
    assert "wildjailbreak" not in SOURCE_LOADERS


def test_dolly_is_training_so_alpaca_must_be_the_ood_negative() -> None:
    # Benign holdout must not reuse Dolly; Dolly is 5,000 of 6,732 training samples.
    assert "dolly_negative" in SOURCE_LOADERS
    assert "alpaca_negative" in HOLDOUT_LOADERS


def test_load_holdout_rejects_unknown_source() -> None:
    with pytest.raises(KeyError):
        load_holdout(["not_a_real_source"])


def test_load_holdout_returns_empty_for_missing_cache(tmp_path: Path) -> None:
    # Missing cache yields an empty list rather than raising; eval_ood.py is
    # responsible for treating that as fatal.
    assert load_deepset_pi(cache_dir=tmp_path / "nope") == []
    assert load_alpaca_negative(cache_dir=tmp_path / "nope") == []


def test_load_holdout_selects_requested_subset() -> None:
    result = load_holdout(["deepset_pi"])
    assert set(result) == {"deepset_pi"}
