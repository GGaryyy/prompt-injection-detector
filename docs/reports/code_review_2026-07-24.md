# Code Review — 2026-07-24

**Reviewer**: reviewer subagent (independent, stronger model per CLAUDE.md). Read the full current `src/pipeline.py`, `src/config.py`, `src/gateway.py`, `src/guards/base.py`, `src/guards/consumption_guard.py`, `config.yaml`, `src/schema.py`, and updated tests; ran the affected tests (29 passed) and bandit (clean).

## Scope

Fix decoupling the circuit breaker from fail-closed semantics.

| File | Change |
|---|---|
| `src/pipeline.py` | tripped guard emits `fail_mode` verdict via new `_tripped_verdict`/`_failure_verdict` instead of being skipped; new `tripped_guards()`; docstring + `_aggregate` comment |
| `src/config.py` | removed dead `GatewayConfig.fail_mode` (`FailMode` still used by `GuardConfig`) |
| `config.yaml` | removed gateway-level `fail_mode` block |
| `src/gateway.py` | `/_guard/health` returns `tripped_guards` |
| `tests/unit/test_pipeline.py` | updated breaker test + 2 new regression tests |
| `tests/integration/test_gateway.py` | updated health assertion |

## Quality assessment

- **Correctness**: fail-closed genuinely preserved on trip — a tripped fail-closed guard returns BLOCK on every request; fail-open guard passes with no regression. Aggregation still selects worst verdict; the empty-verdicts PASS branch is now only reachable when no guards are registered for a direction.
- **Readability / maintainability**: the `_failure_verdict` helper removes duplication between the error path and tripped path; single-purpose functions; comment density matches surrounding code.
- **Convention compliance**: naming, constants block, deliberate non-bare `except Exception` isolation boundary, and helper structure all match CLAUDE.md style. ✅
- **Config safety (verified)**: removing gateway-level `fail_mode` does not break load — pydantic v2 `extra="ignore"` means a stale `config.yaml` still validates. `FailMode` import retained (used at `config.py:30`).
- **Latency**: `latency_ms` on the tripped path is a small non-negative delta (`schema.py` enforces `ge=0.0`); sensible since no `check()` runs.

## Findings

| File:Line | Severity | Description | Resolution |
|---|---|---|---|
| `pipeline.py` reasons | Low | Audit `reasons` string format reordered (reason-first). No in-repo consumer parses it, but persisted to `output/attacks.*`; external dashboards matching the old shape break silently. | **Noted in CHANGELOG** (Audit format note). Accepted. |
| breaker design | Low | No half-open/reset: `_tripped` never clears, so a repeatedly-failing fail-closed critical guard = permanent 403 for all traffic until restart (self-DoS). | **Intended** per `docs/plans/plan_fail_closed_circuit_breaker.md` decision A. Operator guidance: set that guard `fail_mode: "open"` if availability outranks it. Half-open recovery = future work, out of scope. |
| `gateway.py:75 vs 81` | Info | `/health` uses `getattr(...,"gw",None)` fallback; `/ready` reads `app.state.gw` directly. Inconsistent robustness; neither hits the missing-attr path in practice. | Left as-is (harmless belt-and-suspenders). Not blocking. |
| `gateway.py` health | Info (+) | Adding `tripped_guards` while keeping `status:"ok"` preserves the liveness contract; monitor-mode still downgrades a tripped BLOCK to FLAG consistently. | None. |

## Performance notes
No new network calls or per-request cost on the hot path. Tripped guards now do construct a verdict object (previously skipped) — negligible (no `check()`, no embedding).

## Verdict

**Approved with Notes.** No Critical/High. The change strengthens security posture by closing a silent fail-open path; both Low findings are accepted with documented rationale (audit-format note added to changelog; self-DoS trade-off is the intended decision-A behavior).
