"""LLM05 Improper Output Handling guard (outbound).

Pure stdlib regex logic. Inspects model OUTPUT for content that a downstream
client might unsafely render or execute (XSS, dangerous URIs, data-exfil markdown
links, SQL meta, SSRF/internal targets, template-injection markers).

No ML deps. Each category maps to a labeled reason. BLOCK for the dangerous
client-side-execution / exfil categories; FLAG for softer signals; else PASS.
"""

from __future__ import annotations

import re
import time

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Pattern categories ===
# Each value: list of regex strings. Severity classification lives in _SEVERITY below.

# Raw script / iframe tags
SCRIPT_IFRAME = [
    r"<\s*script\b",
    r"<\s*/\s*script\s*>",
    r"<\s*iframe\b",
]

# Inline event handlers inside a tag (onerror=, onload=, on<word>=)
EVENT_HANDLER = [
    r"<[^>]*\bon[a-z]+\s*=",
]

# javascript: URI
JS_URI = [
    r"javascript\s*:",
]

# data:text/html URI
DATA_HTML_URI = [
    r"data\s*:\s*text/html",
]

# Markdown image/link whose URL is external AND carries a query string that looks
# like exfiltration (a key=value where the value plausibly carries data).
# Matches both ![alt](url) and [text](url) forms.
EXFIL_LINK = [
    r"!?\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]*\b(?:d|data|leak|q|c|exfil|out|payload|secret|token)\b[a-z0-9_]*=",
]

# SQL meta in output
SQL_META = [
    r"\bUNION\s+SELECT\b",
    r";\s*DROP\s+TABLE\b",
    r"\bOR\s+1\s*=\s*1\b",
]

# SSRF / internal targets
SSRF_INTERNAL = [
    r"169\.254\.169\.254",
    r"https?://localhost\b",
    r"https?://127\.0\.0\.1\b",
    r"\bfile\s*:\s*//",
]

# Template-injection markers: {{ ... }} mustache or ${ ... } dollar-brace
TEMPLATE_INJECTION = [
    r"\{\{.*?\}\}",
    r"\$\{.*?\}",
]


# === Severity → decision mapping ===
# "block" categories force BLOCK; "flag" categories raise to FLAG (unless a block hit exists).

_SEVERITY: dict[str, str] = {
    "script_iframe": "block",
    "event_handler": "block",
    "js_uri": "block",
    "exfil_link": "block",
    "data_html_uri": "flag",
    "sql_meta": "flag",
    "ssrf_internal": "flag",
    "template_injection": "flag",
}


def _compile(patterns: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


_RULES: dict[str, list[re.Pattern[str]]] = {
    "script_iframe": _compile(SCRIPT_IFRAME),
    "event_handler": _compile(EVENT_HANDLER),
    "js_uri": _compile(JS_URI),
    "exfil_link": _compile(EXFIL_LINK),
    "data_html_uri": _compile(DATA_HTML_URI),
    "sql_meta": _compile(SQL_META),
    "ssrf_internal": _compile(SSRF_INTERNAL),
    "template_injection": _compile(TEMPLATE_INJECTION),
}

# Human-readable reason label per category.
_LABELS: dict[str, str] = {
    "script_iframe": "raw script/iframe tag",
    "event_handler": "inline event handler in tag",
    "js_uri": "javascript: URI",
    "exfil_link": "markdown link to external URL with data-exfil query",
    "data_html_uri": "data:text/html URI",
    "sql_meta": "SQL meta-command in output",
    "ssrf_internal": "SSRF / internal target",
    "template_injection": "template-injection marker",
}


def _scan(text: str) -> dict[str, str]:
    """Return {category: first matched text} for every category that fired."""
    fired: dict[str, str] = {}
    for category, patterns in _RULES.items():
        for pattern in patterns:
            m = pattern.search(text)
            if m:
                fired[category] = m.group(0)
                break
    return fired


@register_guard
class OutputHandlingGuard(Guard):
    guard_id = "llm05_output"
    owasp_id = "LLM05"
    direction = Direction.OUTBOUND

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()
        text = ctx.text or ""
        fired = _scan(text)

        reasons: list[str] = []
        detail: dict[str, str] = {}
        has_block = False
        has_flag = False
        for category, matched in fired.items():
            reasons.append(f"{_LABELS[category]}: {matched[:80]}")
            detail[category] = matched[:120]
            if _SEVERITY[category] == "block":
                has_block = True
            else:
                has_flag = True

        if has_block:
            decision = GuardDecision.BLOCK
        elif has_flag:
            decision = GuardDecision.FLAG
        else:
            decision = GuardDecision.PASS

        # score: weight block hits heavier than flag hits, saturate at 1.0.
        block_hits = sum(1 for c in fired if _SEVERITY[c] == "block")
        flag_hits = len(fired) - block_hits
        score = min(1.0, 0.5 * block_hits + 0.25 * flag_hits)

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
