"""LLM10 Unbounded Consumption guard (inbound).

Enforces three pure-stdlib resource limits on inbound requests:
  - max_input_chars: hard cap on prompt length.
  - requests_per_minute: per-client sliding 60s rate limit.
  - max_concurrent: cap on in-flight requests (read from ctx.meta).

No ML deps. Time source is injectable for deterministic tests.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Optional

from src.guards.base import Guard, GuardContext, register_guard
from src.schema import Direction, GuardDecision, GuardVerdict


# === Constants ===

WINDOW_SECONDS = 60.0
GLOBAL_KEY = "global"


@register_guard
class ConsumptionGuard(Guard):
    guard_id = "llm10_consumption"
    owasp_id = "LLM10"
    direction = Direction.INBOUND

    def __init__(
        self,
        config: Optional[dict] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(config)
        self.clock = clock
        options = self.config.get("options", {})
        self.max_input_chars = options.get("max_input_chars")
        self.requests_per_minute = options.get("requests_per_minute")
        self.max_concurrent = options.get("max_concurrent")
        # key -> deque of request timestamps within the current window
        self._hits: dict[str, "deque[float]"] = defaultdict(deque)

    def check(self, ctx: GuardContext) -> GuardVerdict:
        start = self.clock()
        reasons: list[str] = []
        detail: dict = {}

        if self.max_input_chars is not None and len(ctx.text) > self.max_input_chars:
            reasons.append(
                f"max_input_chars exceeded: {len(ctx.text)} > {self.max_input_chars}"
            )
            detail["input_chars"] = len(ctx.text)

        if self.max_concurrent is not None:
            active = ctx.meta.get("active_requests", 0)
            if active >= self.max_concurrent:
                reasons.append(
                    f"max_concurrent exceeded: {active} >= {self.max_concurrent}"
                )
                detail["active_requests"] = active

        if self.requests_per_minute is not None:
            key = ctx.client_ip or GLOBAL_KEY
            count = self._record_and_count(key)
            if count > self.requests_per_minute:
                reasons.append(
                    f"requests_per_minute exceeded: {count} > {self.requests_per_minute}"
                )
                detail["rpm_count"] = count

        decision = GuardDecision.BLOCK if reasons else GuardDecision.PASS
        score = 1.0 if reasons else 0.0
        latency_ms = (self.clock() - start) * 1000.0

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

    def _record_and_count(self, key: str) -> int:
        now = self.clock()
        window = self._hits[key]
        window.append(now)
        cutoff = now - WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        return len(window)
