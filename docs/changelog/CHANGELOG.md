# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v1.0 LLM Guard Gateway (in progress)

Upgrade from a single `/detect` API (LLM01 only) to an offline reverse-proxy
gateway covering the runtime-defensible OWASP LLM Top 10 (2025) categories.
See `docs/plans/plan_llm_guard_gateway.md` (meta-repo) and `docs/owasp_coverage.md`.

### Added
- `docs/issues/ISSUE_002.md` — `/usr/bin/docker` returning `Input/output error` in WSL after
  the Docker Desktop integration is enabled. Stale iso9660 mount of `cli-tools`, not a
  configuration problem; the daemon is healthy and only the WSL-side CLI is broken.
  Worked around with a `docker.exe` alias, with the path-translation caveat recorded
- `scripts/eval_ood.py` — out-of-distribution benchmark against held-out sources.
  Scores the frozen artifacts with no refit, no threshold change, and weights imported
  from `src.detector` so they cannot drift from what ships. Reports per-layer scores,
  not just an F1 delta: the similarity layer matches against the training positives
  themselves, so its contribution to genuinely unseen attacks collapses by construction,
  and an aggregate number would hide that
- `scripts/paraphrase_probe.py` — deterministic, offline paraphrase robustness probe.
  Separates "learned the attack" from "memorised its surface form", which is a different
  failure mode from OOD. Documents in-module that it is a lower bound, since rule-based
  rewriting stays lexically closer than real paraphrase would
- `src/data_loader.py` — `HOLDOUT_LOADERS` registry plus `load_deepset_pi()` and
  `load_alpaca_negative()`. Benign holdout deliberately does not reuse Dolly: Dolly is
  5,000 of the 6,732 training samples, so OOD precision measured against it would be
  meaningless
- `scripts/download_data.sh` — held-out source downloads, in a section marked as such
- `docs/reports/ood_benchmark_2026-07-28.md` — measured results. Headline: recall on unseen
  attacks falls 0.960 → 0.198 at the shipped threshold, but AUC holds at 0.838, so most of
  the loss is threshold calibration rather than blindness

### Changed
- `src/data_loader.py` — `wildjailbreak` moved out of `SOURCE_LOADERS` into
  `HOLDOUT_LOADERS`. Its loader already existed and the data had never been fetched, so
  it was one `build_dataset.py` run away from silently entering training and invalidating
  the OOD benchmark
- `src/data_loader.py` — new `load_holdout()` does **not** skip failing sources the way
  `load_all()` does; `eval_ood.py` aborts rather than reporting metrics over whatever
  happened to download
- `src/data_loader.py` — every HuggingFace dataset pinned to a fixed revision. An unpinned
  dataset breaks two things at once: the training corpus stops matching the shipped model
  artifact, and benchmark numbers stop being reproducible. The training pins were verified
  safe first — downloaded to a scratch cache, they rebuild `dataset_v1.jsonl` to an
  identical digest over all 6,732 samples, so the existing artifact stays valid.
  `allenai/wildjailbreak` is still unpinned; its revision needs an HF login
- `docs/OVERVIEW.md` — the v0.1.0 benchmark table is now labelled as **classifier-layer only**.
  `train.py` scores the classifier's predictions, not the three-layer ensemble, and the two
  had been used interchangeably. Ensemble on the same split is F1 0.9723
- `docs/OVERVIEW.md` — limitation 1 replaced with measured figures instead of the previous
  unfalsifiable "zero-shot weakness" sentence
- `scripts/train.py` — per-family recall now suppressed below `MIN_FAMILY_N = 10`.
  Most families had a single test sample, where recall is 0.0 or 1.0 and means neither;
  `benchmark.json` was publishing "meta_conversation: recall 0.0" off one sample, which
  reads as "cannot detect this family"
- Public-release prep: renamed `TrainingSample.gary_personally_tested` → `author_validated`
  and `gary_test_context` → `validation_context` across `src/`, `scripts/`, and tests;
  set project attribution to Chuan Peng (LICENSE, `pyproject.toml`)
- `docs/OVERVIEW.md` added — canonical scope, architecture, and OWASP coverage reference;
  replaced two dangling links to the private meta-repo plan with in-repo references

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

### Fixed
- Circuit breaker no longer opens a fail-closed guard. A tripped guard's `check()`
  calls are suspended, but its `fail_mode` is still enforced on every request
  (fail-closed → keep BLOCKing, fail-open → PASS). Previously a guard that errored
  past the threshold was skipped entirely, silently letting its traffic through —
  directly contradicting the fail-closed posture. `src/pipeline.py`; regression tests
  added in `tests/unit/test_pipeline.py`.
- `/_guard/health` now reports `tripped_guards`, so guard degradation is observable
  instead of silent. `src/gateway.py`.
- **Audit format note:** guard-failure/tripped `reasons` strings are now ordered
  reason-first — `"guard error: RuntimeError (fail-closed)"` / `"circuit tripped
  (fail-closed)"`. External dashboards string-matching the previous
  `"guard error (fail-closed): ..."` shape should update their match.

### Removed
- Dead `GatewayConfig.fail_mode` (gateway-wide fail mode was loaded but never read;
  per-guard `fail_mode` is the single source of truth). `src/config.py`, `config.yaml`.

### Security
- Resolved 4 dependency CVEs found by pip-audit: `starlette` 1.2.1 → ≥1.3.1
  (PYSEC-2026-248, PYSEC-2026-249) and `setuptools` 78.1.0 → ≥83.0.0 (PYSEC-2025-49,
  PYSEC-2026-3447). Re-scan clean; suite re-run 219 passed. Note `torch` (CPU wheel from
  the PyTorch index) cannot be resolved by pip-audit and is unscanned, not clean
- Held-out dataset loads pinned to fixed revisions — an unpinned third-party dataset is
  both a supply-chain exposure and a reproducibility hole (bandit B615)
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
- `src/data_loader.py` — Loaders for Lakera / AdvBench / JailbreakBench / Databricks Dolly + 12 hand-crafted Gandalf attack prompts (`author_validated=True`)
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
