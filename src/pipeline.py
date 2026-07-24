"""Guard pipeline — runs the guards for one direction and aggregates verdicts.

Failure isolation is the core safety property here: one guard raising must never
take down the gateway. Each guard runs inside a try/except; on error the verdict
follows that guard's fail_mode (closed -> BLOCK, open -> PASS). A per-guard circuit
breaker suspends check() calls for a guard that errors repeatedly — but the guard's
fail_mode is still enforced on every request while tripped (a fail-closed guard keeps
blocking). The breaker saves compute; it never opens the gate.
"""

from __future__ import annotations

import logging
import time

from src.config import GatewayConfig
from src.guards.base import Guard, GuardContext, registry
from src.schema import (
    DECISION_SEVERITY,
    Direction,
    GatewayDecision,
    GuardDecision,
    GuardVerdict,
)

logger = logging.getLogger(__name__)

# === Constants ===
CIRCUIT_TRIP_THRESHOLD = 5  # consecutive errors before a guard is auto-disabled
FLAG_BAND = 0.15  # not used here directly; guards own their bands

CONSUMPTION_GUARD_ID = "llm10_consumption"


class GuardPipeline:
    """Builds enabled guards from config and runs them per direction."""

    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self._guards: dict[Direction, list[Guard]] = {
            Direction.INBOUND: [],
            Direction.OUTBOUND: [],
        }
        self._error_streak: dict[str, int] = {}
        self._tripped: set[str] = set()
        self._build()

    def _build(self) -> None:
        for guard_id, cls in registry().items():
            gc = self.config.guard(guard_id)
            if not gc.enabled:
                continue

            options = dict(gc.options)
            if guard_id == CONSUMPTION_GUARD_ID:
                rl = self.config.rate_limit
                if not rl.enabled:
                    continue
                options.setdefault("max_input_chars", rl.max_input_chars)
                options.setdefault("requests_per_minute", rl.requests_per_minute)
                options.setdefault("max_concurrent", rl.max_concurrent)

            guard_cfg = {
                "enabled": True,
                "threshold": gc.threshold,
                "fail_mode": gc.fail_mode,
                "options": options,
            }
            guard = cls(guard_cfg)
            self._guards[cls.direction].append(guard)
            logger.info("guard enabled: %s (%s, %s)", guard_id, cls.owasp_id, cls.direction.value)

    def guards_for(self, direction: Direction) -> list[Guard]:
        return list(self._guards[direction])

    def run(self, direction: Direction, ctx: GuardContext) -> GatewayDecision:
        verdicts: list[GuardVerdict] = []
        for guard in self._guards[direction]:
            if guard.guard_id in self._tripped:
                # Breaker suspends check() calls, but fail_mode is still enforced:
                # a tripped fail-closed guard keeps BLOCKing — it never opens the gate.
                verdicts.append(self._tripped_verdict(guard, ctx))
            else:
                verdicts.append(self._run_one(guard, ctx))
        return self._aggregate(direction, ctx, verdicts)

    def tripped_guards(self) -> list[str]:
        """Guard ids whose circuit breaker has tripped (check() suspended, fail_mode enforced)."""
        return sorted(self._tripped)

    def _run_one(self, guard: Guard, ctx: GuardContext) -> GuardVerdict:
        start = time.perf_counter()
        try:
            verdict = guard.check(ctx)
            self._error_streak[guard.guard_id] = 0
            return verdict
        except Exception as exc:  # deliberate isolation boundary — recorded, never swallowed
            streak = self._error_streak.get(guard.guard_id, 0) + 1
            self._error_streak[guard.guard_id] = streak
            logger.error("guard %s errored: %s (streak %d)", guard.guard_id, exc, streak)
            if streak >= CIRCUIT_TRIP_THRESHOLD:
                self._tripped.add(guard.guard_id)
                logger.error(
                    "guard %s circuit tripped — check() suspended; fail_mode still enforced",
                    guard.guard_id,
                )
            return self._failure_verdict(
                guard, ctx, start, f"guard error: {type(exc).__name__}", detail={"error": str(exc)}
            )

    def _tripped_verdict(self, guard: Guard, ctx: GuardContext) -> GuardVerdict:
        """Verdict for a guard whose breaker has tripped — fail_mode is still enforced."""
        return self._failure_verdict(
            guard, ctx, time.perf_counter(), "circuit tripped", detail={"tripped": True}
        )

    def _failure_verdict(
        self,
        guard: Guard,
        ctx: GuardContext,
        start: float,
        reason: str,
        detail: dict | None = None,
    ) -> GuardVerdict:
        """Build a fail_mode-driven verdict (closed -> BLOCK, open -> PASS)."""
        fail_closed = guard.fail_mode == "closed"
        return GuardVerdict(
            guard_id=guard.guard_id,
            owasp_id=guard.owasp_id,
            direction=ctx.direction,
            decision=GuardDecision.BLOCK if fail_closed else GuardDecision.PASS,
            score=1.0 if fail_closed else 0.0,
            reasons=[f"{reason} ({'fail-closed' if fail_closed else 'fail-open'})"],
            detail=detail or {},
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _aggregate(
        self, direction: Direction, ctx: GuardContext, verdicts: list[GuardVerdict]
    ) -> GatewayDecision:
        if not verdicts:
            # Reached only when no guards are registered for this direction. Tripped
            # guards still emit a fail_mode verdict (see run/_tripped_verdict), so a
            # fail-closed guard can never silently fall through to this PASS.
            return GatewayDecision(
                request_id=ctx.request_id,
                direction=direction,
                final_decision=GuardDecision.PASS,
                verdicts=[],
            )

        worst = max(verdicts, key=lambda v: DECISION_SEVERITY[v.decision])
        raw_decision = worst.decision

        # Any guard that offers a redaction makes one available; only llm02_secret
        # currently does, so chaining multiple is not a concern yet.
        redacted_text = None
        for v in verdicts:
            if v.redacted_text is not None:
                redacted_text = v.redacted_text

        effective = self._apply_mode(raw_decision, redacted_text is not None)

        return GatewayDecision(
            request_id=ctx.request_id,
            direction=direction,
            final_decision=effective,
            verdicts=verdicts,
            blocked_by=worst.guard_id if effective == GuardDecision.BLOCK else None,
            redacted_text=redacted_text,
        )

    def _apply_mode(self, decision: GuardDecision, has_redaction: bool) -> GuardDecision:
        """Translate the raw worst-decision into an enforced decision per gateway mode."""
        mode = self.config.mode
        if mode == "monitor":
            # log only — downgrade any enforcing decision to FLAG
            if decision in (GuardDecision.BLOCK, GuardDecision.REDACT, GuardDecision.ERROR):
                return GuardDecision.FLAG
            return decision
        if mode == "redact" and decision == GuardDecision.BLOCK and has_redaction:
            return GuardDecision.REDACT
        return decision
