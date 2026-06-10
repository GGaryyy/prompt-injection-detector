# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v1.0 LLM Guard Gateway (in progress)

Upgrade from a single `/detect` API (LLM01 only) to an offline reverse-proxy
gateway covering the runtime-defensible OWASP LLM Top 10 (2025) categories.
See `docs/plans/plan_llm_guard_gateway.md` (meta-repo) and `docs/owasp_coverage.md`.

### Added
- `src/schema.py` — gateway schemas: `Direction`, `GuardDecision`, `GuardVerdict`, `GatewayDecision`, `AttackRecord`, `GapRecord`, `DECISION_SEVERITY`
- `src/guards/base.py` — `Guard` ABC, `GuardContext`, guard registry (`register_guard` / `registry`)
- `src/config.py` — `config.yaml` loader (`GatewayConfig` / `GuardConfig` / `RateLimitConfig` / `AuditConfig`), env overrides
- `src/owasp_gaps.py` — declared runtime gaps (LLM03 / LLM04 / LLM08) with recommended controls
- `config.yaml` — gateway config template (upstream, port 33707, mode, fail-mode, per-guard toggles)
- `docs/owasp_coverage.md` — OWASP LLM Top 10 (2025) coverage + honest gap declaration
- `src/guards/` — seven OWASP guards (LLM01/02/05/06/07/09/10) + mirrored unit tests (108 tests)
- `src/pipeline.py` — guard orchestration, per-guard failure isolation, circuit breaker, severity aggregation, mode handling
- `src/audit.py` — attack log to JSONL + SQLite (`attacks` + `gaps` tables)
- `src/textio.py` — request/response text extraction + redaction injection (OpenAI/Anthropic/bare shapes)
- `src/gateway.py` + `main.py` — reverse-proxy app: inbound/outbound guard pipelines, fail-closed posture, `/_guard/health|ready|owasp`
- `Dockerfile` / `docker-compose.yml` — `gateway` service on 33707 (default `python main.py`)
- `docs/usage/USAGE.md` — full deployment + configuration guide
- `docs/reports/{test,security,code_review}_2026-06-10.md` — sprint reports
- `tests/integration/test_gateway.py`, `tests/unit/test_{pipeline,audit,textio}.py`

### Changed
- `pyproject.toml` — added runtime deps `httpx`, `pyyaml`
- `src/guards/__init__.py` — imports all guard modules so the registry is always fully populated
- `tests/conftest.py` — numpy import made lazy (light-venv collection fix)

- `tests/stress/test_gateway_stress.py` — proxy throughput / concurrency / oversize-body stress tests

### Security
- bandit SAST clean (0/0/0) after annotating detection-pattern false positives (`# nosec B105`) and the intentional container bind (`# nosec B104`)
- detect-secrets clean (private-key *pattern* allowlisted with `# pragma: allowlist secret`)
- pip-audit ✅ pass on freshly rebuilt Docker image

### Validation
- **Docker (real ML, fresh image): 200 passed / 0 failed** — unit + integration + stress + security (incl. pip-audit).
- Light venv: 173 pass (pure-logic guards + proxy). Stress: ~518 rps, p95 2.4 ms proxy overhead.
- Docker reached from WSL via `docker.exe` (auto-translates `/mnt/d`→`D:\`). See `docs/issues/ISSUE_001.md`.

## [0.1.0] - 2026-04-25 — MVP

First working release. Three-layer ensemble PI detector trained on 6732 samples
from 4 public datasets + 12 hand-crafted Gandalf prompts.

### Added
- `src/rule_engine.py` — 6-category keyword + regex layer (instruction override, role reshaping, meta reference, delimiter forgery, exfiltration, unusual structure)
- `src/embedder.py` — `nomic-ai/nomic-embed-text-v1.5` wrapper with `all-MiniLM-L6-v2` fallback
- `src/data_loader.py` — Loaders for Lakera / AdvBench / JailbreakBench / Databricks Dolly + 12 hand-crafted Gandalf attack prompts (`gary_personally_tested=True`)
- `src/classifier.py` — `LogisticRegression` / `RandomForest` wrapper with save/load
- `src/detector.py` — Three-layer ensemble (rule + classifier + similarity), explainability, latency tracking
- `src/api.py` — FastAPI service with `/health` + `/detect` (lazy-load artifacts)
- `scripts/download_data.sh` — Public dataset downloader (graceful degradation)
- `scripts/build_dataset.py` — Consolidate raw → `data/processed/dataset_v1.jsonl`
- `scripts/train.py` — End-to-end training + benchmark + artifact dump
- 58 tests:39 unit + 16 integration + 3 security audits
- Docker / Compose dev workflow with persistent volumes for HF model cache
- Three sprint reports in `docs/reports/`

### Benchmark (v0.1.0)
- Accuracy 0.9844 / Precision 0.9657 / Recall 0.9741 / F1 0.9699 / AUC 0.9989
- Train / test = 5385 / 1347 (stratified by label)

### Security
- bandit B613 false positive on `src/rule_engine.py:66` annotated with `# nosec` (bidi chars are intentional detection target)
- Accepted risk: pip CVE-2026-3219 (no upstream fix; pip is build-tool layer)

### Known Limitations
- English only
- Zero-shot weakness on unseen attack families
- No IPI defense (out of scope)
- Single-turn detection only

## [0.0.1] - 2026-04-25 — Skeleton

### Added
- Repo skeleton依 CLAUDE.md Part 2 規範
- `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, `.gitignore`, `LICENSE` (MIT)
- `src/schema.py` — `TrainingSample` + `DetectionResult` + 22 個 `AttackFamily` literal
- `docs/flow/system_flow.md`, `docs/workflow/workflow.md` 初版
