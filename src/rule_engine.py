"""Rule-based PI detection layer.

Keyword + regex patterns derived from `03_owasp_llm_top10_crosswalk.md` LLM01 偵測訊號.
This is a fast, interpretable first-pass; the embedding + classifier layers add semantic depth.

Returns a continuous score in [0, 1] based on which rule categories triggered, plus the
list of hits for explainability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# === Pattern categories (aligned with crosswalk LLM01 偵測訊號 1-6) ===

# 1. Instruction override / overwrite attempts
INSTRUCTION_OVERRIDE = [
    r"\b(ignore|forget|disregard|override)\b.{0,20}\b(all|the|previous|prior|above)",
    r"\bnew\s+(instructions?|task|rules?)\b",
    r"\bfrom\s+now\s+on\b",
    r"\b(stop|cease)\s+(following|obeying)\b",
    r"\bdo\s+not\s+(follow|listen\s+to)\s+(any|the)\s+(previous|prior)",
]

# 2. Role reshaping / persona override
ROLE_RESHAPING = [
    r"\byou\s+are\s+(now|actually)\b",
    r"\b(pretend|imagine|act)\s+(to\s+be|as|you'?re)\b",
    r"\broleplay\s+as\b",
    r"\bDAN\b",  # Do Anything Now
    r"\b(jailbreak|jailbroken)\b",
    r"\bdeveloper\s+mode\b",
]

# 3. Meta-reference to context / system prompt
META_REFERENCE = [
    r"\bsystem\s+prompt\b",
    r"\binitial\s+instructions?\b",
    r"\byour\s+(context|rules?|guidelines?|limits?|restrictions?|constraints?)\b",
    r"\bprevious\s+(messages?|conversation|context)\b",
    r"\b(repeat|summarize|paraphrase|reveal)\b.{0,30}\b(above|prior|before|first|original)\b",
    r"\bwhat\s+(was|were)\s+you\s+(told|instructed)\b",
]

# 4. Delimiter forgery — fake role boundary markers
DELIMITER_FORGERY = [
    r"\[/?(SYSTEM|INST|USER|ASSISTANT)\]",
    r"</?(system|inst|user|assistant)>",
    r"<\|im_(start|end)\|>",
    r"###\s+(Instruction|System|Task|New\s+Prompt)",
    r"\bEND\s+(USER|ASSISTANT)\s+MESSAGE\b",
    r"\bBEGIN\s+(USER|ASSISTANT)\s+MESSAGE\b",
]

# 5. Direct exfiltration requests
EXFILTRATION = [
    r"\b(reveal|tell|show|give|expose|leak|share)\b.{0,30}\b(password|secret|key|token|credential|api\s*key)",
    r"\bwhat\s+(is|are)\s+(your|the)\s+(password|secret|api\s*key|credential)",
    r"\bprint\b.{0,15}\b(password|secret|key)\b",
]

# 6. Unusual / suspicious structure
# NOTE: The first pattern intentionally contains bidi / zero-width characters
# because that is exactly what we are *detecting* — Trojan-source style attacks
# where attackers smuggle invisible chars into prompts. Bandit B613 is a false
# positive here; the chars are literal regex character class members, not code.
UNUSUAL_STRUCTURE = [
    r"[​-‏‪-‮⁠]",      # zero-width / bidi / word-joiner  # nosec B613
    r"[A-Za-z0-9+/]{80,}={0,2}",                 # very long base64-like blocks
    r"\\x[0-9a-fA-F]{2}",                        # \x?? escapes
]


# === Per-category weight (max sum > 1.0; we cap at 1.0) ===

_WEIGHTS: dict[str, float] = {
    "instruction_override": 0.35,
    "role_reshaping": 0.30,
    "meta_reference": 0.25,
    "delimiter_forgery": 0.40,
    "exfiltration": 0.30,
    "unusual_structure": 0.20,
}


@dataclass(frozen=True)
class RuleHit:
    """One rule pattern match in the input text."""

    category: str
    pattern: str
    matched_text: str


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


_RULES: dict[str, list[re.Pattern[str]]] = {
    "instruction_override": _compile(INSTRUCTION_OVERRIDE),
    "role_reshaping": _compile(ROLE_RESHAPING),
    "meta_reference": _compile(META_REFERENCE),
    "delimiter_forgery": _compile(DELIMITER_FORGERY),
    "exfiltration": _compile(EXFILTRATION),
    "unusual_structure": _compile(UNUSUAL_STRUCTURE),
}


def detect(text: str) -> tuple[float, list[RuleHit]]:
    """Run all rule categories over `text`.

    Args:
        text: User-supplied prompt to evaluate.

    Returns:
        A tuple (score, hits) where score is in [0, 1] (0 = no rule triggered, 1 = max risk),
        and hits is the full list of rule matches for explainability.

        Each category contributes its weight ONCE even if multiple patterns within match,
        to avoid runaway scores from repeated keywords.
    """
    if not text:
        return 0.0, []

    hits: list[RuleHit] = []
    triggered: set[str] = set()

    for category, patterns in _RULES.items():
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                hits.append(
                    RuleHit(
                        category=category,
                        pattern=pattern.pattern,
                        matched_text=m.group(0),
                    )
                )
                triggered.add(category)

    score = sum(_WEIGHTS[c] for c in triggered)
    return min(score, 1.0), hits


def categories() -> list[str]:
    """List the rule category names. Useful for diagnostics / blog visualisation."""
    return list(_RULES.keys())
