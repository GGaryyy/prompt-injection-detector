# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
