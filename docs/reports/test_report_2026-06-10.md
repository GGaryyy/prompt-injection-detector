# Test Report — v1.0 LLM Guard Gateway — 2026-06-10

## Execution summary

| | Count |
|--|--|
| Light venv (pure-logic + proxy) | **173** pass |
| **Docker (full, real ML + stress + pip-audit)** | **200 pass / 0 fail** |
| Failed | 0 |
| Skipped | 0 |

Environment note: the dev shell has no Docker / system pip (see `ISSUE_001`). All
pure-logic and proxy code was verified in an isolated `.venv-dev` (pydantic, fastapi,
httpx, pytest). Tests that require torch / sentence-transformers / sklearn or the
trained artifacts are **deferred to a Docker run** and are NOT counted as passed here.

Run command:
```
PYTHONPATH=. pytest tests/unit/ tests/integration/test_gateway.py \
  --ignore=tests/unit/test_classifier.py --ignore=tests/unit/test_data_loader.py
```

## Breakdown by type

| Type | File(s) | Tests | Result |
|------|---------|-------|--------|
| Unit — guards | `test_{injection,consumption,secret,sysprompt,output,agency,misinfo}_guard.py` | 108 | ✅ pass |
| Unit — pipeline | `test_pipeline.py` | 10 | ✅ pass |
| Unit — audit | `test_audit.py` | 6 | ✅ pass |
| Unit — textio | `test_textio.py` | 10 | ✅ pass |
| Unit — pre-existing (rule_engine/schema) | `test_rule_engine.py`, `test_schema.py` | 36 | ✅ pass |
| Integration — gateway proxy | `test_gateway.py` | 6 | ✅ pass |

### Guard unit coverage highlights
- **llm01_injection** (12): wraps detector via injected fake; BLOCK/FLAG/PASS bands, threshold override, outbound no-op.
- **llm02_secret** (21): Luhn valid/invalid, one positive per secret category, benign no-FP, block vs redact masking.
- **llm05_output** (per category): script/iframe/js-uri/exfil-link/SQL/SSRF/template; benign markdown no-FP.
- **llm06_agency**: OpenAI tools payload, non-allowlisted FLAG, dangerous-arg BLOCK, payload=None PASS.
- **llm07_sysprompt**: canary BLOCK, fragment-echo BLOCK, heuristic FLAG, benign PASS.
- **llm09_misinfo**: FLAG-only, never blocks, disabled-by-default verified.
- **llm10_consumption**: deterministic clock — oversize, rpm window + expiry, per-client isolation, concurrency.

### Pipeline / gateway behaviour verified
- Failure isolation: a guard raising → its fail_mode decides (closed→BLOCK, open→PASS); other guards still run.
- Circuit breaker trips after 5 consecutive errors → guard disabled (monitor).
- Decision aggregation by severity; monitor mode downgrades BLOCK→FLAG; redact mode prefers redaction.
- Proxy end-to-end (stub upstream): benign pass-through, inbound oversize block (stage=request),
  outbound secret block (stage=response), outbound redact in redact-mode, monitor-mode pass-through,
  management endpoints (`/_guard/health|ready|owasp`).

## Docker run (real ML) — FINAL — 2026-06-10

Ran the **complete** suite in a freshly-rebuilt container, using `docker.exe` from WSL
(Windows CLI auto-translates `/mnt/d`→`D:\`; no WSL integration needed):

**200 passed, 0 failed in 24.6s.** ✅

- Real detector (nomic embedder + classifier + similarity): `test_detector`, `test_api` `/detect`, `test_classifier`, `test_data_loader` — pass with real artifacts.
- Gateway integration (proxy, block/redact/monitor, mgmt endpoints), all guard/pipeline/audit/textio unit tests — pass.
- Security audits incl. `pip-audit` — pass on the fresh image (the stale-image dev-dep CVEs cleared once current versions were pulled).
- Stress (below) — pass.

Note: the first Docker run (196 passed, 1 failed) failed only on `pip-audit` against a
stale 6-week image's dev deps (jupyter/notebook/urllib3/starlette…); the rebuild resolved it.

## Stress — ✅ run

`tests/stress/test_gateway_stress.py` (3 tests, pass). LLM01 disabled so this isolates
**proxy + guard overhead** (ML detector path stress is a separate Docker concern):

| Metric | Value |
|--------|-------|
| Sequential throughput | ~518 rps |
| Latency p50 | 1.8 ms |
| Latency p95 | 2.4 ms |
| Latency p99 | 2.9 ms |
| Concurrent (200 reqs / 16 workers) | all 200 OK |
| Oversize body | rejected 413 before upstream |

Proxy overhead is well under the 50 ms p95 budget; the dominant cost in production is the
LLM01 detector inference (measured in the detector's own benchmark, p95 within target).

## Deferred (Docker-only) tests — must run before release
| File | Why deferred |
|------|--------------|
| `tests/unit/test_classifier.py` | numpy/sklearn |
| `tests/unit/test_data_loader.py` | numpy/datasets |
| `tests/integration/test_detector.py` | real embedder + classifier |
| `tests/integration/test_api.py` | `/detect` needs trained artifacts |
| `tests/security/test_security_audits.py` | re-run under full deps |
| `tests/stress/*` | load harness + real model |
| New: e2e gateway with **real** LLM01 detector | needs artifacts |

## Fixes made during this cycle
- `src/guards/__init__.py` now imports all guard modules so the registry is always
  fully populated (a guard built only when its test imported it → fixed).
- Pipeline redaction collection now reads `redacted_text` from any verdict, not only
  REDACT verdicts (enables redact-mode to use a blocking guard's redaction).
- `tests/conftest.py`: numpy import made lazy (was breaking collection of all tests in
  the light venv).
