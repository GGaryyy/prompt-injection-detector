"""LLM09 Misinformation guard (outbound).

BEST-EFFORT heuristics only, DISABLED by default (enabled defaults to False).
Pure stdlib regex logic — no ML deps, no network. An offline gateway cannot
fact-check, so this guard NEVER blocks and NEVER redacts: the maximum decision
is FLAG. It only surfaces *smells* of likely misinformation for human review.

Heuristics over ctx.text:
  - overconfident absolutes sitting near a factual-looking claim
  - fabricated-citation smell (bare [N] markers with no references section,
    "according to a study" / "research shows" with no named source,
    fake-looking DOI 10.NNNN/...)
  - hallucinated-URL smell (anchor text names a well-known org but the linked
    domain does not match it — heuristic, brand-vs-domain mismatch only)

decision = FLAG if any heuristic fires (each capped so score <= 0.5); else PASS.
"""

from __future__ import annotations

import re
import time

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Constants ===

# This guard is heuristic and noisy; it is off unless explicitly enabled.
_DEFAULT_ENABLED = False

# Max score this guard may emit. It never blocks, so we keep the ceiling low.
_MAX_SCORE = 0.5
# Per-heuristic contribution; summed then capped at _MAX_SCORE.
_HEURISTIC_WEIGHT = 0.25


# === Heuristic 1: overconfident absolutes ===
# Phrases that assert certainty an honest answer would usually hedge.
OVERCONFIDENT = [
    r"\bdefinitely\b",
    r"\b100%\s*guaranteed\b",
    r"\bwithout\s+a\s+doubt\b",
    r"\bit\s+is\s+certain\s+that\b",
    r"\bundeniably\b",
    r"\babsolutely\s+certain\b",
]

# A "factual claim" looks like an assertion about the world: a copula or a
# date/number/proper-noun-shaped statement. We only need a coarse signal that
# the overconfident phrase sits next to something assertable.
FACTUAL_CLAIM = [
    r"\b(is|are|was|were|will\s+be|causes?|cures?|proves?|means?)\b",
    r"\b(in|by|since)\s+\d{3,4}\b",          # "in 1999", "by 2030"
    r"\b\d+(\.\d+)?\s*(%|percent|million|billion|years?|months?|weeks?|days?)\b",
]


# === Heuristic 2: fabricated-citation smell ===
# Bare bracket-number markers like [1] [2] used inline as citations.
BARE_CITATION = [
    r"\[\d{1,3}\]",
]

# Phrases that appeal to research/studies without naming a source.
VAGUE_SOURCE = [
    r"\baccording\s+to\s+a\s+(study|paper|report|survey)\b",
    r"\bresearch\s+shows?\b",
    r"\bstudies\s+(show|have\s+shown|prove|suggest)\b",
    r"\bscientists\s+(say|found|believe)\b",
    r"\bexperts\s+agree\b",
]

# DOI-shaped string. Real DOIs follow 10.NNNN/suffix; we only flag its presence
# (combined with other smells) since we cannot resolve it offline.
DOI_PATTERN = [
    r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b",
]

# A "references section" anchor — if present, bare [N] markers are far less
# suspicious because the answer is actually providing a bibliography.
REFERENCES_SECTION = re.compile(
    r"(?m)^\s*(references|bibliography|sources|works\s+cited)\b[:\s]*$",
    re.IGNORECASE,
)

# A named source looks like a Proper-Cased multi-word org / journal, "et al.",
# a year-in-parens citation, or a domain. Used to suppress VAGUE_SOURCE.
NAMED_SOURCE = re.compile(
    r"(\bet\s+al\.|\(\d{4}\)|[A-Z][a-z]+\s+(University|Institute|Journal|Lab|"
    r"Foundation|Review)\b|\b\w+\.(org|edu|gov)\b)",
)


# === Heuristic 3: hallucinated-URL smell (brand vs domain mismatch) ===
# Markdown links [anchor](url). If the anchor names a well-known org but the URL
# host does not contain that org's token, the link is suspicious. Heuristic only.
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\(\s*(https?://[^)\s]+)\s*\)")
URL_HOST = re.compile(r"https?://([^/]+)", re.IGNORECASE)

# Known-org anchor tokens we recognise and the token we expect in the domain.
KNOWN_ORG_TOKENS = [
    "wikipedia",
    "github",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "nasa",
    "openai",
    "reuters",
    "bbc",
    "nytimes",
    "arxiv",
]


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_OVERCONFIDENT = _compile(OVERCONFIDENT)
_FACTUAL_CLAIM = _compile(FACTUAL_CLAIM)
_BARE_CITATION = _compile(BARE_CITATION)
_VAGUE_SOURCE = _compile(VAGUE_SOURCE)
_DOI = _compile(DOI_PATTERN)


def _first_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _overconfident_claim(text: str) -> str | None:
    """Fire only when an overconfident phrase co-occurs with a factual claim."""
    over = _first_match(_OVERCONFIDENT, text)
    if not over:
        return None
    claim = _first_match(_FACTUAL_CLAIM, text)
    if not claim:
        return None
    return f"{over!r} asserting {claim!r}"


def _fabricated_citation(text: str) -> str | None:
    """Fire on citation smells the answer cannot back up."""
    bare = _first_match(_BARE_CITATION, text)
    if bare and not REFERENCES_SECTION.search(text):
        return f"bare citation {bare} with no references section"

    vague = _first_match(_VAGUE_SOURCE, text)
    if vague and not NAMED_SOURCE.search(text):
        return f"appeal to source without naming it: {vague!r}"

    doi = _first_match(_DOI, text)
    if doi:
        return f"unverifiable DOI-shaped string: {doi}"

    return None


def _hallucinated_url(text: str) -> str | None:
    """Fire when link anchor names a known org but the domain mismatches.

    Match the org token against a dot-delimited host *label* (not a raw substring)
    so that look-alike domains like 'totally-not-wikipedia.ru' do not count as a
    legitimate match. We also reject the token appearing only inside a hyphenated
    label component (e.g. 'not-wikipedia').
    """
    for anchor, url in MARKDOWN_LINK.findall(text):
        host_match = URL_HOST.match(url)
        if not host_match:
            continue
        host = host_match.group(1).lower()
        labels = host.split(".")
        anchor_low = anchor.lower()
        for token in KNOWN_ORG_TOKENS:
            if token in anchor_low and token not in labels:
                return f"anchor names '{token}' but URL host is '{host}'"
    return None


@register_guard
class MisinformationGuard(Guard):
    guard_id = "llm09_misinfo"
    owasp_id = "LLM09"
    direction = Direction.OUTBOUND

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        # Off by default: this is best-effort heuristic-only and prone to noise.
        self.enabled = bool((config or {}).get("enabled", _DEFAULT_ENABLED))

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()
        text = ctx.text or ""

        reasons: list[str] = []
        detail: dict[str, str] = {}

        overconfident = _overconfident_claim(text)
        if overconfident:
            reasons.append(f"overconfident absolute near a factual claim: {overconfident}")
            detail["overconfident_claim"] = overconfident[:120]

        citation = _fabricated_citation(text)
        if citation:
            reasons.append(f"fabricated-citation smell: {citation}")
            detail["fabricated_citation"] = citation[:120]

        url = _hallucinated_url(text)
        if url:
            reasons.append(f"hallucinated-URL smell: {url}")
            detail["hallucinated_url"] = url[:120]

        # Never blocks or redacts — max decision is FLAG.
        if reasons:
            decision = GuardDecision.FLAG
            score = min(_MAX_SCORE, _HEURISTIC_WEIGHT * len(reasons))
        else:
            decision = GuardDecision.PASS
            score = 0.0

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
