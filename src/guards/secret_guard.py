"""LLM02 Sensitive Information Disclosure guard (outbound).

Scans outbound response text for secrets / PII using pure-stdlib regex + Luhn.
No ML deps. Each match becomes a labeled reason + a detail entry. By default a
match BLOCKs the response; with options.redact_on_match the guard instead REDACTs
(replacing every match with a [REDACTED:<category>] mask).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Detection patterns (one labeled category each) ===

EMAIL = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

# International (+CC) or US-style phone with separators. Requires structure to
# avoid matching arbitrary digit runs (those are handled by card/SSN/entropy).
PHONE = r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3}[\s.-]\d{3,4}[\s.-]?\d{0,4}(?!\w)"

# Candidate card digit-run (13-19 digits, optional space/dash grouping); Luhn-validated below.
CARD_CANDIDATE = r"(?<![\d-])(?:\d[ -]?){13,19}(?![\d-])"

SSN = r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"

# IBAN: 2 letters + 2 check digits + 11-30 alnum.
IBAN = r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"

AWS_ACCESS_KEY = r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"

# AWS secret: a 40-char base64-ish token appearing near 'aws' or 'secret'.
# NOTE on the bandit B105 suppressions below: these are DETECTION PATTERNS, not
# credentials — a secret-scanner's regexes inherently resemble the secrets they match.
AWS_SECRET = r"(?i)(?:aws|secret)[^\n]{0,40}?\b([A-Za-z0-9/+]{40})\b"  # nosec B105

GOOGLE_API_KEY = r"\bAIza[0-9A-Za-z_-]{35}\b"

SLACK_TOKEN = r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"  # nosec B105

PRIVATE_KEY = r"-----BEGIN [A-Z ]*PRIVATE KEY-----"  # pragma: allowlist secret

JWT = r"\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+\b"

# Generic credential assignment: password=/api_key=/secret=/token= ...
GENERIC_ASSIGN = r"(?i)\b(?:password|passwd|pwd|api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?([^\s'\";,]{4,})"

# High-entropy standalone tokens (handled after the specific categories to avoid double-counting).
HEX_TOKEN = r"\b[0-9a-fA-F]{32,}\b"  # nosec B105
B64_TOKEN = r"\b[A-Za-z0-9+/]{40,}={0,2}\b"  # nosec B105


# === Severity weights (private key / credit card = high) ===

_SEVERITY: dict[str, float] = {
    "private_key": 1.0,
    "credit_card": 0.9,
    "aws_secret": 0.8,  # nosec B105 — severity weight, not a credential
    "aws_access_key": 0.8,
    "google_api_key": 0.7,  # nosec B105 — severity weight, not a credential
    "slack_token": 0.7,
    "jwt": 0.6,
    "iban": 0.6,
    "ssn": 0.6,
    "generic_credential": 0.5,
    "email": 0.3,
    "phone": 0.3,
    "high_entropy_token": 0.4,  # nosec B105 — severity weight, not a credential
}


@dataclass(frozen=True)
class SecretHit:
    category: str
    raw: str       # the exact substring to redact
    masked: str    # masked snippet for the reason string


def _luhn_ok(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask(value: str) -> str:
    """Keep first 2 + last 2 chars, star the middle; short values fully masked."""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _find_simple(pattern: str, text: str, category: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for m in re.finditer(pattern, text):
        raw = m.group(0)
        hits.append(SecretHit(category=category, raw=raw, masked=_mask(raw)))
    return hits


def _find_group1(pattern: str, text: str, category: str) -> list[SecretHit]:
    # Use the captured secret (group 1) as the redaction target, not the whole match.
    hits: list[SecretHit] = []
    for m in re.finditer(pattern, text):
        raw = m.group(1)
        hits.append(SecretHit(category=category, raw=raw, masked=_mask(raw)))
    return hits


def _find_cards(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for m in re.finditer(CARD_CANDIDATE, text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append(SecretHit(category="credit_card", raw=raw, masked=_mask(digits)))
    return hits


def _scan(text: str) -> list[SecretHit]:
    """Run all categories. Order matters: specific high-value categories first so
    their spans claim characters before the generic high-entropy fallbacks."""
    hits: list[SecretHit] = []
    claimed: set[str] = set()  # raw substrings already attributed to a category

    def add(new: list[SecretHit]) -> None:
        for h in new:
            hits.append(h)
            claimed.add(h.raw)

    add([SecretHit("private_key", m.group(0), "-----BEGIN PRIVATE KEY-----")  # pragma: allowlist secret
         for m in re.finditer(PRIVATE_KEY, text)])
    add(_find_cards(text))
    add(_find_simple(AWS_ACCESS_KEY, text, "aws_access_key"))
    add(_find_group1(AWS_SECRET, text, "aws_secret"))
    add(_find_simple(GOOGLE_API_KEY, text, "google_api_key"))
    add(_find_simple(SLACK_TOKEN, text, "slack_token"))
    add(_find_simple(JWT, text, "jwt"))
    add(_find_simple(IBAN, text, "iban"))
    add(_find_simple(SSN, text, "ssn"))
    add(_find_group1(GENERIC_ASSIGN, text, "generic_credential"))
    add(_find_simple(EMAIL, text, "email"))
    add(_find_simple(PHONE, text, "phone"))

    # High-entropy fallback: only report tokens not already claimed by a category.
    for pat in (HEX_TOKEN, B64_TOKEN):
        for m in re.finditer(pat, text):
            raw = m.group(0)
            if any(raw in c or c in raw for c in claimed):
                continue
            h = SecretHit("high_entropy_token", raw=raw, masked=_mask(raw))
            hits.append(h)
            claimed.add(raw)

    return hits


def _score(hits: list[SecretHit]) -> float:
    if not hits:
        return 0.0
    # Sum of per-category severities, capped at 1.0 (more + higher-severity -> higher).
    total = sum(_SEVERITY.get(h.category, 0.4) for h in hits)
    return min(total, 1.0)


def _redact(text: str, hits: list[SecretHit]) -> str:
    out = text
    # Longest raw first so overlapping shorter spans don't corrupt longer masks.
    for h in sorted(hits, key=lambda x: len(x.raw), reverse=True):
        out = out.replace(h.raw, f"[REDACTED:{h.category}]")
    return out


@register_guard
class SecretGuard(Guard):
    guard_id = "llm02_secret"
    owasp_id = "LLM02"
    direction = Direction.OUTBOUND

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()
        text = ctx.text or ""
        hits = _scan(text)
        latency = (time.perf_counter() - start) * 1000.0

        if not hits:
            return GuardVerdict(
                guard_id=self.guard_id,
                owasp_id=self.owasp_id,
                direction=self.direction,
                decision=GuardDecision.PASS,
                score=0.0,
                latency_ms=latency,
            )

        options = self.config.get("options", {})
        redact = bool(options.get("redact_on_match", False))

        reasons = [f"{h.category}: {h.masked}" for h in hits]
        detail: dict = {"match_count": len(hits), "categories": {}}
        for h in hits:
            detail["categories"].setdefault(h.category, []).append(h.masked)

        verdict = GuardVerdict(
            guard_id=self.guard_id,
            owasp_id=self.owasp_id,
            direction=self.direction,
            decision=GuardDecision.REDACT if redact else GuardDecision.BLOCK,
            score=_score(hits),
            reasons=reasons,
            detail=detail,
            latency_ms=latency,
        )
        if redact:
            verdict.redacted_text = _redact(text, hits)
        return verdict
