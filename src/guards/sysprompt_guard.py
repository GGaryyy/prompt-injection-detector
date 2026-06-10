"""LLM07 System Prompt Leakage guard (outbound).

Inspects the model's outbound response for signs that the system prompt (or any
configured secret) has leaked. Three detection layers, strongest first:

1. Canary tokens — unique strings planted in the system prompt. Any verbatim
   substring match is a definitive leak -> BLOCK.
2. System-prompt fragments — known sentences from the real system prompt. A
   normalized substring match (casefold + collapsed whitespace) for a fragment
   of meaningful length -> BLOCK.
3. Heuristic leak phrases — generic regex patterns of a model narrating its own
   instructions -> FLAG (suspicious, not definitive).

Pure stdlib regex/logic; no ML deps.
"""

from __future__ import annotations

import re
import time

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Constants ===

MIN_FRAGMENT_LEN = 20  # normalized fragment must be at least this long to match
BLOCK_SCORE = 1.0
HEURISTIC_SCORE = 0.6
_WHITESPACE = re.compile(r"\s+")

# Heuristic leak phrases — a model narrating its own instructions / secrets.
HEURISTIC_PHRASES = [
    r"my system prompt",
    r"my instructions are",
    r"i was instructed to",
    r"here are my (rules|instructions|guidelines)",
    r"the system (message|prompt) (says|is)",
    r"you are \w+\. do not reveal",
    r"the password is",
]

_HEURISTIC_RES = [re.compile(p, re.IGNORECASE) for p in HEURISTIC_PHRASES]


def _normalize(text: str) -> str:
    return _WHITESPACE.sub(" ", text.casefold()).strip()


@register_guard
class SystemPromptLeakGuard(Guard):
    guard_id = "llm07_sysprompt"
    owasp_id = "LLM07"
    direction = Direction.OUTBOUND

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()

        options = self.config.get("options", {})
        canary_tokens = options.get("canary_tokens", [])
        fragments = options.get("system_prompt_fragments", [])

        text = ctx.text or ""
        reasons: list[str] = []
        decision = GuardDecision.PASS
        score = 0.0
        detail: dict = {}

        # 1. Canary tokens — verbatim substring is a definitive leak.
        canary_hits = [tok for tok in canary_tokens if tok and tok in text]
        if canary_hits:
            decision = GuardDecision.BLOCK
            score = BLOCK_SCORE
            for tok in canary_hits:
                reasons.append(f"canary token leaked: {tok!r}")
            detail["canary_hits"] = canary_hits

        # 2. System-prompt fragments — normalized substring match.
        norm_text = _normalize(text)
        fragment_hits: list[str] = []
        for frag in fragments:
            norm_frag = _normalize(frag)
            if len(norm_frag) >= MIN_FRAGMENT_LEN and norm_frag in norm_text:
                fragment_hits.append(frag)
        if fragment_hits:
            decision = GuardDecision.BLOCK
            score = BLOCK_SCORE
            for frag in fragment_hits:
                reasons.append(f"system prompt fragment echoed: {frag!r}")
            detail["fragment_hits"] = fragment_hits

        # 3. Heuristic leak phrases — suspicious but not definitive.
        heuristic_hits = [r.pattern for r in _HEURISTIC_RES if r.search(text)]
        if heuristic_hits:
            detail["heuristic_hits"] = heuristic_hits
            for pat in heuristic_hits:
                reasons.append(f"heuristic leak phrase: {pat!r}")
            if decision is GuardDecision.PASS:
                decision = GuardDecision.FLAG
                score = HEURISTIC_SCORE

        latency_ms = (time.perf_counter() - start) * 1000.0
        return GuardVerdict(
            guard_id=self.guard_id,
            owasp_id=self.owasp_id,
            direction=self.direction,
            decision=decision,
            score=score,
            reasons=reasons,
            detail=detail,
            latency_ms=latency_ms,
        )
