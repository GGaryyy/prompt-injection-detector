"""Unit tests for the LLM10 Unbounded Consumption guard."""

from __future__ import annotations

from src.guards.base import GuardContext
from src.guards.consumption_guard import ConsumptionGuard
from src.schema import Direction, GuardDecision


class FakeClock:
    """Monotonic-ish clock whose value tests advance explicitly."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_ctx(text: str = "hello", client_ip: str = "1.1.1.1", active: int = 0):
    return GuardContext(
        request_id="r1",
        direction=Direction.INBOUND,
        text=text,
        client_ip=client_ip,
        meta={"active_requests": active},
    )


def test_benign_request_passes():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"max_input_chars": 100, "requests_per_minute": 10, "max_concurrent": 5}},
        clock=clock,
    )
    verdict = guard.check(make_ctx(text="short prompt", active=0))
    assert verdict.decision == GuardDecision.PASS
    assert verdict.score == 0.0
    assert verdict.reasons == []
    assert verdict.guard_id == "llm10_consumption"
    assert verdict.owasp_id == "LLM10"


def test_oversize_text_blocks():
    guard = ConsumptionGuard(
        config={"options": {"max_input_chars": 10}},
        clock=FakeClock(),
    )
    verdict = guard.check(make_ctx(text="x" * 11))
    assert verdict.decision == GuardDecision.BLOCK
    assert verdict.score == 1.0
    assert any("max_input_chars" in r for r in verdict.reasons)
    assert verdict.detail["input_chars"] == 11


def test_oversize_boundary_passes():
    # exactly at the limit is allowed (strictly greater-than blocks)
    guard = ConsumptionGuard(
        config={"options": {"max_input_chars": 10}},
        clock=FakeClock(),
    )
    verdict = guard.check(make_ctx(text="x" * 10))
    assert verdict.decision == GuardDecision.PASS


def test_rpm_trips_within_window():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"requests_per_minute": 3}},
        clock=clock,
    )
    ctx = make_ctx(text="hi", client_ip="9.9.9.9")
    # 3 requests within the window all pass (count <= limit)
    for _ in range(3):
        clock.advance(1.0)
        assert guard.check(ctx).decision == GuardDecision.PASS
    # 4th request inside the same 60s window trips the limit
    clock.advance(1.0)
    verdict = guard.check(ctx)
    assert verdict.decision == GuardDecision.BLOCK
    assert verdict.score == 1.0
    assert any("requests_per_minute" in r for r in verdict.reasons)
    assert verdict.detail["rpm_count"] == 4


def test_rpm_old_timestamps_expire():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"requests_per_minute": 2}},
        clock=clock,
    )
    ctx = make_ctx(text="hi", client_ip="8.8.8.8")
    guard.check(ctx)
    clock.advance(1.0)
    guard.check(ctx)
    # advance past the 60s window so the first two timestamps expire
    clock.advance(120.0)
    verdict = guard.check(ctx)
    assert verdict.decision == GuardDecision.PASS


def test_rpm_per_client_isolation():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"requests_per_minute": 1}},
        clock=clock,
    )
    a = make_ctx(text="hi", client_ip="2.2.2.2")
    b = make_ctx(text="hi", client_ip="3.3.3.3")
    assert guard.check(a).decision == GuardDecision.PASS
    # different client is unaffected by a's history
    assert guard.check(b).decision == GuardDecision.PASS
    # second hit from a within window trips
    assert guard.check(a).decision == GuardDecision.BLOCK


def test_rpm_uses_global_key_when_no_ip():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"requests_per_minute": 1}},
        clock=clock,
    )
    ctx = GuardContext(request_id="r", direction=Direction.INBOUND, text="hi", client_ip=None)
    assert guard.check(ctx).decision == GuardDecision.PASS
    assert guard.check(ctx).decision == GuardDecision.BLOCK


def test_max_concurrent_trips():
    guard = ConsumptionGuard(
        config={"options": {"max_concurrent": 5}},
        clock=FakeClock(),
    )
    verdict = guard.check(make_ctx(text="hi", active=5))
    assert verdict.decision == GuardDecision.BLOCK
    assert verdict.score == 1.0
    assert any("max_concurrent" in r for r in verdict.reasons)
    assert verdict.detail["active_requests"] == 5


def test_max_concurrent_below_limit_passes():
    guard = ConsumptionGuard(
        config={"options": {"max_concurrent": 5}},
        clock=FakeClock(),
    )
    assert guard.check(make_ctx(text="hi", active=4)).decision == GuardDecision.PASS


def test_multiple_limits_reported_together():
    clock = FakeClock()
    guard = ConsumptionGuard(
        config={"options": {"max_input_chars": 2, "max_concurrent": 1}},
        clock=clock,
    )
    verdict = guard.check(make_ctx(text="too long", active=3))
    assert verdict.decision == GuardDecision.BLOCK
    assert any("max_input_chars" in r for r in verdict.reasons)
    assert any("max_concurrent" in r for r in verdict.reasons)


def test_no_options_never_blocks():
    # with no limits configured, everything passes
    guard = ConsumptionGuard(config={}, clock=FakeClock())
    big = make_ctx(text="x" * 10000, active=9999)
    assert guard.check(big).decision == GuardDecision.PASS


def test_registered_in_registry():
    from src.guards.base import registry

    assert registry().get("llm10_consumption") is ConsumptionGuard
