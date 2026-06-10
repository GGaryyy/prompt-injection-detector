"""Unit tests for the guard pipeline — isolation, circuit breaker, aggregation, modes."""

from __future__ import annotations

import pytest

from src.config import GatewayConfig, GuardConfig
from src.guards.base import Guard, GuardContext
from src.pipeline import CIRCUIT_TRIP_THRESHOLD, GuardPipeline
from src.schema import Direction, GuardDecision, GuardVerdict


def _config(mode: str = "block") -> GatewayConfig:
    # Disable the ML-backed injection guard so the pipeline is testable offline.
    return GatewayConfig(
        upstream_url="http://upstream.invalid",
        mode=mode,
        guards={"llm01_injection": GuardConfig(enabled=False)},
    )


def _ctx(direction: Direction = Direction.OUTBOUND, text: str = "hello") -> GuardContext:
    return GuardContext(request_id="req-1", direction=direction, text=text)


class _FixedGuard(Guard):
    guard_id = "fixed"
    owasp_id = "LLMxx"
    direction = Direction.OUTBOUND

    def __init__(self, decision: GuardDecision, score: float, redacted: str | None = None):
        super().__init__({})
        self._decision = decision
        self._score = score
        self._redacted = redacted

    def check(self, ctx: GuardContext) -> GuardVerdict:
        return GuardVerdict(
            guard_id=self.guard_id,
            owasp_id=self.owasp_id,
            direction=ctx.direction,
            decision=self._decision,
            score=self._score,
            redacted_text=self._redacted,
        )


class _ErrorGuard(Guard):
    guard_id = "boom"
    owasp_id = "LLMxx"
    direction = Direction.INBOUND

    def __init__(self, fail_mode: str):
        super().__init__({"fail_mode": fail_mode})

    def check(self, ctx: GuardContext) -> GuardVerdict:
        raise RuntimeError("intentional failure")


def _pipeline_with(direction: Direction, *guards: Guard, mode: str = "block") -> GuardPipeline:
    p = GuardPipeline(_config(mode))
    p._guards[direction] = list(guards)
    return p


def test_empty_pipeline_passes():
    p = _pipeline_with(Direction.OUTBOUND)
    d = p.run(Direction.OUTBOUND, _ctx())
    assert d.final_decision == GuardDecision.PASS
    assert d.verdicts == []


def test_aggregation_worst_wins():
    p = _pipeline_with(
        Direction.OUTBOUND,
        _FixedGuard(GuardDecision.FLAG, 0.4),
        _FixedGuard(GuardDecision.BLOCK, 0.9),
    )
    d = p.run(Direction.OUTBOUND, _ctx())
    assert d.final_decision == GuardDecision.BLOCK
    assert d.blocked_by == "fixed"
    assert len(d.verdicts) == 2


def test_monitor_mode_downgrades_block_to_flag():
    p = _pipeline_with(Direction.OUTBOUND, _FixedGuard(GuardDecision.BLOCK, 0.9), mode="monitor")
    d = p.run(Direction.OUTBOUND, _ctx())
    assert d.final_decision == GuardDecision.FLAG
    assert d.blocked_by is None
    # raw verdict is preserved for audit
    assert d.verdicts[0].decision == GuardDecision.BLOCK


def test_redact_mode_prefers_redaction_over_block():
    p = _pipeline_with(
        Direction.OUTBOUND,
        _FixedGuard(GuardDecision.BLOCK, 0.9, redacted="masked"),
        mode="redact",
    )
    d = p.run(Direction.OUTBOUND, _ctx())
    assert d.final_decision == GuardDecision.REDACT
    assert d.redacted_text == "masked"


def test_error_guard_fail_closed_blocks():
    p = _pipeline_with(Direction.INBOUND, _ErrorGuard("closed"))
    d = p.run(Direction.INBOUND, _ctx(Direction.INBOUND))
    assert d.final_decision == GuardDecision.BLOCK
    assert "fail-closed" in d.verdicts[0].reasons[0]


def test_error_guard_fail_open_passes():
    p = _pipeline_with(Direction.INBOUND, _ErrorGuard("open"))
    d = p.run(Direction.INBOUND, _ctx(Direction.INBOUND))
    assert d.final_decision == GuardDecision.PASS
    assert "fail-open" in d.verdicts[0].reasons[0]


def test_circuit_breaker_trips_after_threshold():
    guard = _ErrorGuard("closed")
    p = _pipeline_with(Direction.INBOUND, guard)
    for _ in range(CIRCUIT_TRIP_THRESHOLD):
        p.run(Direction.INBOUND, _ctx(Direction.INBOUND))
    assert guard.guard_id in p._tripped
    # once tripped, the guard is skipped -> no verdicts, pass
    d = p.run(Direction.INBOUND, _ctx(Direction.INBOUND))
    assert d.verdicts == []
    assert d.final_decision == GuardDecision.PASS


def test_real_guards_built_by_direction():
    # llm01 disabled; remaining real guards split across directions.
    p = GuardPipeline(_config())
    inbound_ids = {g.guard_id for g in p.guards_for(Direction.INBOUND)}
    outbound_ids = {g.guard_id for g in p.guards_for(Direction.OUTBOUND)}
    assert "llm10_consumption" in inbound_ids
    assert "llm06_agency" in inbound_ids
    assert "llm02_secret" in outbound_ids
    assert "llm01_injection" not in inbound_ids  # disabled


def test_shipped_config_disables_misinfo():
    # The shipped config.yaml turns LLM09 off; that is the source of truth.
    from pathlib import Path

    from src.config import load_config

    cfg_path = Path(__file__).resolve().parents[2] / "config.yaml"
    p = GuardPipeline(load_config(cfg_path))
    outbound_ids = {g.guard_id for g in p.guards_for(Direction.OUTBOUND)}
    assert "llm09_misinfo" not in outbound_ids
