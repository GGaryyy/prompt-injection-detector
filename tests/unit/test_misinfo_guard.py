"""Unit tests for src.guards.misinfo_guard (LLM09 Misinformation).

This guard is best-effort heuristic-only, disabled by default, and never blocks.
"""

from __future__ import annotations

import pytest

from src.guards.base import GuardContext
from src.guards.misinfo_guard import MisinformationGuard
from src.schema import Direction, GuardDecision

pytestmark = pytest.mark.unit


def _ctx(text: str) -> GuardContext:
    return GuardContext(request_id="r1", direction=Direction.OUTBOUND, text=text)


def _check(text: str):
    return MisinformationGuard().check(_ctx(text))


def test_guard_attrs() -> None:
    g = MisinformationGuard()
    assert g.guard_id == "llm09_misinfo"
    assert g.owasp_id == "LLM09"
    assert g.direction == Direction.OUTBOUND


def test_disabled_by_default() -> None:
    assert MisinformationGuard().enabled is False
    # Explicit config still respected.
    assert MisinformationGuard({"enabled": True}).enabled is True
    assert MisinformationGuard({"enabled": False}).enabled is False


# === Heuristic 1: overconfident absolute near a factual claim ===

def test_overconfident_definitely_flags() -> None:
    v = _check("This medication definitely cures the disease in 2 weeks.")
    assert v.decision == GuardDecision.FLAG
    assert any("overconfident" in r.lower() for r in v.reasons)
    assert v.score <= 0.5


def test_overconfident_guaranteed_flags() -> None:
    v = _check("Investing here is 100% guaranteed to double your money by 2030.")
    assert v.decision == GuardDecision.FLAG
    assert "overconfident_claim" in v.detail


def test_overconfident_without_a_doubt_flags() -> None:
    v = _check("Without a doubt, the treaty was signed in 1648.")
    assert v.decision == GuardDecision.FLAG


def test_overconfident_phrase_without_claim_passes() -> None:
    # "definitely" with no assertable claim nearby should not fire.
    v = _check("Sure, I can definitely help you brainstorm some ideas!")
    # No copula/date/number claim -> heuristic 1 does not fire.
    assert "overconfident_claim" not in v.detail


# === Heuristic 2: fabricated-citation smell ===

def test_bare_numeric_citation_no_sources_flags() -> None:
    v = _check("The drug reduces risk by 40% [1] and improves recovery [2].")
    assert v.decision == GuardDecision.FLAG
    assert any("citation" in r.lower() for r in v.reasons)
    assert v.score <= 0.5


def test_bare_citation_with_references_section_passes() -> None:
    text = (
        "The result holds [1].\n\n"
        "References:\n"
        "[1] Smith, J. (2020). A Real Paper. Some Journal.\n"
    )
    v = _check(text)
    assert "fabricated_citation" not in v.detail


def test_vague_source_no_name_flags() -> None:
    v = _check("Research shows that this approach is the best option available.")
    assert v.decision == GuardDecision.FLAG
    assert any("citation" in r.lower() for r in v.reasons)


def test_vague_source_with_named_source_passes() -> None:
    v = _check("Research shows this works (Smith et al., 2021), per the study.")
    assert "fabricated_citation" not in v.detail


def test_doi_shaped_string_flags() -> None:
    v = _check("See the paper at doi 10.1234/fake.journal.2099.0001 for proof.")
    assert v.decision == GuardDecision.FLAG
    assert any("doi" in r.lower() for r in v.reasons)


# === Heuristic 3: hallucinated-URL smell ===

def test_anchor_org_domain_mismatch_flags() -> None:
    v = _check("Read more on [Wikipedia](https://totally-not-wikipedia.ru/page).")
    assert v.decision == GuardDecision.FLAG
    assert any("url" in r.lower() for r in v.reasons)


def test_anchor_org_domain_match_passes() -> None:
    v = _check("Read more on [Wikipedia](https://en.wikipedia.org/wiki/Foo).")
    assert "hallucinated_url" not in v.detail


# === No false positives: careful hedged answer ===

def test_hedged_answer_passes() -> None:
    text = (
        "Based on what I know, this may be the case, but I'm not certain. "
        "You should verify with a primary source before relying on it. "
        "See the [official docs](https://example.com/guide) for details."
    )
    v = _check(text)
    assert v.decision == GuardDecision.PASS
    assert v.reasons == []
    assert v.score == 0.0


def test_empty_text_passes() -> None:
    v = _check("")
    assert v.decision == GuardDecision.PASS
    assert v.score == 0.0


# === Scoring / never-blocks invariants ===

def test_score_never_exceeds_half() -> None:
    # Trigger all three heuristics at once.
    text = (
        "This is definitely true in 1999. Research shows it works [1]. "
        "See [Wikipedia](https://evil.example/x). doi 10.1234/abc.def"
    )
    v = _check(text)
    assert v.decision == GuardDecision.FLAG
    assert v.score <= 0.5


def test_never_blocks_or_redacts() -> None:
    text = "This is 100% guaranteed to work in 2050. Studies show it [1]."
    v = _check(text)
    assert v.decision in (GuardDecision.PASS, GuardDecision.FLAG)
    assert v.redacted_text is None


def test_verdict_metadata_fields() -> None:
    v = _check("This definitely causes cancer.")
    assert v.guard_id == "llm09_misinfo"
    assert v.owasp_id == "LLM09"
    assert v.direction == Direction.OUTBOUND
    assert v.latency_ms >= 0.0
