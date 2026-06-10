"""LLM06 Excessive Agency guard.

Inspects tool / function-call structures in the request or response payload and
flags or blocks calls to tools outside an allowlist, or tool arguments that carry
dangerous-action keywords. Pure stdlib logic; works in both directions.
"""

from __future__ import annotations

import re
import time

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Constants ===

# Score for a tool used when no allowlist is configured (visibility-only signal).
_NO_ALLOWLIST_SCORE = 0.4
# Score for a tool referenced that is not in a configured allowlist.
_NOT_ALLOWED_SCORE = 0.7
# Score when dangerous keywords appear in tool arguments.
_DANGEROUS_SCORE = 1.0

# Dangerous-action keywords scanned inside tool arguments.
_DANGEROUS_PATTERNS = [
    r"\bdelete\b",
    r"\bdrop\s+table\b",
    r"\brm\s+-rf\b",
    r"\bsudo\b",
    r"\btransfer\b",
    r"\bwire\b",
    r"\bsend_email\b",
    r"\bexec\b",
    r"\beval\b",
    r"\bshutdown\b",
]

_DANGEROUS_RE = [re.compile(p, re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


def _as_str(value: object) -> str:
    """Coerce a tool-argument value to a scannable string (args may be dict or str)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return repr(value)


def _extract_tools(payload: dict) -> list[tuple[str, str]]:
    """Return (tool_name, arguments_string) pairs from common LLM API payload shapes."""
    found: list[tuple[str, str]] = []

    # OpenAI request "tools": [{"type":"function","function":{"name":..,"parameters":..}}]
    for tool in _as_list(payload.get("tools")):
        if isinstance(tool, dict):
            fn = tool.get("function", tool)
            if isinstance(fn, dict) and "name" in fn:
                args = fn.get("arguments", fn.get("parameters"))
                found.append((str(fn["name"]), _as_str(args)))

    # Legacy "functions": [{"name":..,"parameters":..}]
    for fn in _as_list(payload.get("functions")):
        if isinstance(fn, dict) and "name" in fn:
            args = fn.get("arguments", fn.get("parameters"))
            found.append((str(fn["name"]), _as_str(args)))

    # Assistant-message "tool_calls": [{"function":{"name":..,"arguments":..}}]
    found.extend(_extract_tool_calls(payload.get("tool_calls")))

    # Legacy single "function_call": {"name":..,"arguments":..}
    fc = payload.get("function_call")
    if isinstance(fc, dict) and "name" in fc:
        found.append((str(fc["name"]), _as_str(fc.get("arguments"))))

    # OpenAI response: choices[i].message.tool_calls[j].function.{name,arguments}
    for choice in _as_list(payload.get("choices")):
        if isinstance(choice, dict):
            message = choice.get("message")
            if isinstance(message, dict):
                found.extend(_extract_tool_calls(message.get("tool_calls")))
                mfc = message.get("function_call")
                if isinstance(mfc, dict) and "name" in mfc:
                    found.append((str(mfc["name"]), _as_str(mfc.get("arguments"))))

    return found


def _extract_tool_calls(tool_calls: object) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for call in _as_list(tool_calls):
        if isinstance(call, dict):
            fn = call.get("function", call)
            if isinstance(fn, dict) and "name" in fn:
                out.append((str(fn["name"]), _as_str(fn.get("arguments"))))
    return out


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else []


def _dangerous_keywords(args: str) -> list[str]:
    return [r.pattern for r in _DANGEROUS_RE if r.search(args)]


@register_guard
class AgencyGuard(Guard):
    guard_id = "llm06_agency"
    owasp_id = "LLM06"
    direction = Direction.INBOUND

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()

        options = self.config.get("options", {})
        allowlist = {str(t) for t in options.get("tool_allowlist", [])}
        strict = bool(options.get("strict", False))

        payload = ctx.payload
        if not isinstance(payload, dict):
            return self._verdict(ctx, GuardDecision.PASS, 0.0, [], {}, start)

        tools = _extract_tools(payload)
        if not tools:
            return self._verdict(ctx, GuardDecision.PASS, 0.0, [], {}, start)

        reasons: list[str] = []
        flagged_tools: list[str] = []
        dangerous_tools: list[str] = []
        score = 0.0
        decision = GuardDecision.PASS

        for name, args in tools:
            keywords = _dangerous_keywords(args)
            if keywords:
                dangerous_tools.append(name)
                reasons.append(
                    f"tool '{name}' arguments contain dangerous action(s): "
                    + ", ".join(keywords)
                )
                decision = GuardDecision.BLOCK
                score = max(score, _DANGEROUS_SCORE)
                continue

            if not allowlist:
                flagged_tools.append(name)
                reasons.append(f"tool '{name}' used with no allowlist configured")
                if decision != GuardDecision.BLOCK:
                    decision = GuardDecision.FLAG
                score = max(score, _NO_ALLOWLIST_SCORE)
            elif name not in allowlist:
                flagged_tools.append(name)
                reasons.append(f"tool '{name}' is not in tool_allowlist")
                if decision != GuardDecision.BLOCK:
                    decision = GuardDecision.BLOCK if strict else GuardDecision.FLAG
                score = max(score, _NOT_ALLOWED_SCORE)

        detail = {
            "tools_seen": [name for name, _ in tools],
            "flagged_tools": flagged_tools,
            "dangerous_tools": dangerous_tools,
        }
        return self._verdict(ctx, decision, score, reasons, detail, start)

    def _verdict(
        self,
        ctx: GuardContext,
        decision: GuardDecision,
        score: float,
        reasons: list[str],
        detail: dict,
        start: float,
    ) -> GuardVerdict:
        return GuardVerdict(
            guard_id=self.guard_id,
            owasp_id=self.owasp_id,
            direction=ctx.direction,
            decision=decision,
            score=score,
            reasons=reasons,
            detail=detail,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )
