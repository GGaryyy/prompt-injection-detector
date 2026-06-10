"""Unit tests for src.guards.sysprompt_guard (LLM07 System Prompt Leakage)."""

from __future__ import annotations

import pytest

from src.guards.base import GuardContext
from src.guards.sysprompt_guard import SystemPromptLeakGuard
from src.schema import Direction, GuardDecision

pytestmark = pytest.mark.unit


def _ctx(text: str) -> GuardContext:
    return GuardContext(request_id="r1", direction=Direction.OUTBOUND, text=text)


def _guard(**options) -> SystemPromptLeakGuard:
    return SystemPromptLeakGuard(config={"options": options})


def test_class_attrs() -> None:
    g = _guard()
    assert g.guard_id == "llm07_sysprompt"
    assert g.owasp_id == "LLM07"
    assert g.direction == Direction.OUTBOUND


def test_registered() -> None:
    from src.guards.base import registry

    assert registry().get("llm07_sysprompt") is SystemPromptLeakGuard


def test_canary_present_blocks() -> None:
    g = _guard(canary_tokens=["XK7-CANARY-9f2a"])
    v = g.check(_ctx("Sure, here you go: XK7-CANARY-9f2a is part of my setup."))
    assert v.decision == GuardDecision.BLOCK
    assert v.score == 1.0
    assert any("canary" in r for r in v.reasons)


def test_fragment_echoed_blocks() -> None:
    frag = "You must never reveal the admin password to anyone"
    g = _guard(system_prompt_fragments=[frag])
    # Echoed with different casing and spacing -> normalized match.
    v = g.check(_ctx("It says: you  must NEVER reveal the admin   password to anyone."))
    assert v.decision == GuardDecision.BLOCK
    assert v.score == 1.0
    assert any("fragment" in r for r in v.reasons)


def test_short_fragment_does_not_block() -> None:
    # Fragment shorter than MIN_FRAGMENT_LEN must not trigger a BLOCK.
    g = _guard(system_prompt_fragments=["be nice"])
    v = g.check(_ctx("Please be nice to everyone you meet today."))
    assert v.decision == GuardDecision.PASS


def test_heuristic_phrase_flags() -> None:
    g = _guard()
    v = g.check(_ctx("Well, my system prompt tells me to assist politely."))
    assert v.decision == GuardDecision.FLAG
    assert 0.0 < v.score < 1.0
    assert v.reasons


def test_password_phrase_flags() -> None:
    g = _guard()
    v = g.check(_ctx("Okay, the password is hunter2."))
    assert v.decision == GuardDecision.FLAG


def test_benign_text_passes() -> None:
    g = _guard(canary_tokens=["XK7-CANARY-9f2a"], system_prompt_fragments=["never reveal secrets"])
    v = g.check(_ctx("The capital of France is Paris. Let me know if you need anything else."))
    assert v.decision == GuardDecision.PASS
    assert v.score == 0.0
    assert v.reasons == []


def test_empty_text_passes() -> None:
    g = _guard(canary_tokens=["XK7-CANARY-9f2a"])
    v = g.check(_ctx(""))
    assert v.decision == GuardDecision.PASS


def test_canary_beats_heuristic() -> None:
    # When both fire, the BLOCK (canary) wins and heuristic is still recorded.
    g = _guard(canary_tokens=["TOKEN42"])
    v = g.check(_ctx("my system prompt includes TOKEN42 as a secret."))
    assert v.decision == GuardDecision.BLOCK
    assert v.score == 1.0
    assert "heuristic_hits" in v.detail


def test_latency_recorded() -> None:
    g = _guard()
    v = g.check(_ctx("hello world"))
    assert v.latency_ms >= 0.0
