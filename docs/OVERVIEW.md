# Project Overview — Prompt Injection Detector & LLM Guard Gateway

> Language: **English** · [繁體中文](OVERVIEW.zh.md)

This document explains what the project is, what it deliberately does and does not
cover, how it is built, and the reasoning behind the main design choices. It is the
canonical reference for the project's scope.

## What it is

Two components that share one codebase:

1. **Prompt Injection Detector** — an embedding-based classifier that scores a single
   piece of text for prompt-injection intent. It combines three independent layers into
   one ensemble score: a keyword/regex rule engine, a sentence-transformer embedding fed
   to a LogisticRegression classifier, and cosine-similarity search against a corpus of
   known attacks. It exposes a `POST /detect` API.

2. **LLM Guard Gateway** (v1.0) — an offline reverse proxy that sits in front of any AI
   service. Every request and response passes through a set of guards, each mapped to one
   OWASP LLM Top 10 (2025) category. The gateway is fail-closed: if a guard errors it
   blocks rather than silently letting traffic through. The detector above is the engine
   behind the LLM01 guard.

The project is a defensive tool. It grew out of hands-on offensive practice (Lakera
Gandalf, red-team writeups) reframed into a runtime control.

## Scope

### In scope

- Runtime inspection of request/response text for the OWASP LLM categories that are
  observable in a single request/response pair (see coverage matrix).
- Single-text prompt-injection detection with an explainable, per-layer score.
- A drop-in reverse proxy requiring no change to the protected upstream service.
- Fully offline operation: the only outbound call is forwarding to the configured
  upstream. Detection uses a local embedding model and local rules; no third-party LLM or
  API is called.

### Explicitly out of scope

- **Indirect Prompt Injection (IPI) defense.** Defending IPI requires tagging content by
  trust source across a RAG/agent pipeline; that is an architecture-level control, not
  something a single-text detector or a request/response proxy can see. IPI is handled in
  a separate project.
- **Build-time and training-time risks** (LLM03 Supply Chain, LLM04 Data & Model
  Poisoning). Nothing in one request reveals a poisoned dataset or a compromised
  dependency. These are documented as runtime gaps, each pointing at the control that does
  address them (CI dependency scanning, SBOM, data provenance).
- **Retrieval/vector-store weaknesses** (LLM08). These live in the retrieval corpus and
  access model, not in the proxied traffic.
- **Multi-turn / session-level attacks** (many-shot, crescendo, context drift). The
  detector is single-turn; session monitoring is future work.
- **Adversarial-suffix robustness.** GCG-style suffixes can find dissimilar-but-effective
  payloads that evade embedding-based detection. This is a known weakness, not a solved
  problem.

## Architecture

### Detector (three-layer ensemble)

```
Input text
   ├─► Rule engine        keyword + regex, 6 categories
   ├─► Embedder           nomic-embed-text-v1.5 (768-dim), MiniLM fallback
   │      ├─► Classifier      LogisticRegression P(injection)
   │      └─► Similarity      cosine vs corpus of known attacks
   ▼
Ensemble score = 0.30·rule + 0.50·classifier + 0.20·similarity
```

Each layer is independent, so a failure or low confidence in one does not blind the
others, and the response carries the per-layer scores for explainability.

### Gateway (reverse proxy + guards)

The gateway forwards traffic to `upstream_url` after inbound guards pass, and inspects the
response before returning it. It has three modes — `block` (default, fail-closed),
`monitor` (log only, for threshold tuning), and `redact` (block inbound attacks, mask
outbound leaks) — and writes an audit trail (JSONL + SQLite) for every flagged request.
Guards are independent modules under `src/guards/`; each declares its own fail mode and
the gateway aggregates their verdicts by severity.

## OWASP LLM Top 10 (2025) coverage

Seven categories are defended at runtime by a dedicated guard; three are out of a
runtime proxy's reach and are declared as explicit gaps (in `src/owasp_gaps.py`, the
startup log, and the `/owasp` endpoint) rather than left silent.

| OWASP | Category | Status | Where |
|-------|----------|--------|-------|
| LLM01 | Prompt Injection | Covered | `injection_guard` + the ensemble detector |
| LLM02 | Sensitive Information Disclosure | Covered | `secret_guard` (block or redact) |
| LLM03 | Supply Chain | Documented gap | build-time — CI scan / SBOM / pinned hashes |
| LLM04 | Data & Model Poisoning | Documented gap | training-time — data provenance / signing |
| LLM05 | Improper Output Handling | Covered | `output_guard` (incl. SSRF patterns) |
| LLM06 | Excessive Agency | Covered | `agency_guard` |
| LLM07 | System Prompt Leakage | Covered | `sysprompt_guard` |
| LLM08 | Vector & Embedding Weaknesses | Documented gap | retrieval arch — per-tenant isolation |
| LLM09 | Misinformation | Partial | `misinfo_guard` |
| LLM10 | Unbounded Consumption | Covered | `consumption_guard` (rate + concurrency + size) |

The honesty about the three gaps is deliberate: a runtime proxy that claimed full Top 10
coverage would be misrepresenting what a request/response inspector can actually see.

## Detector performance (v0.1.0 benchmark)

**Classifier layer only**, on the in-distribution test split:

| Metric | Value | MVP target |
|--------|-------|-----------|
| Accuracy | 0.9844 | — |
| Precision | 0.9657 | ≥ 0.85 |
| Recall | 0.9741 | ≥ 0.75 |
| F1 | 0.9699 | ≥ 0.80 |
| AUC | 0.9989 | ≥ 0.90 |

Train/test split 5385 / 1347. `scripts/train.py` scores the classifier's predictions, not
the three-layer ensemble the service actually runs — the two are not interchangeable. The
full ensemble on the same split scores F1 0.9723 (`scripts/eval_ood.py --in-dist`).

These are in-distribution figures on the consolidated corpus. For what happens on data the
model has not seen, see limitation 1 below and
`docs/reports/ood_benchmark_2026-07-28.md` — the short version is that recall falls to
0.198 at the shipped threshold.

## Datasets & training

6,732 samples consolidated from five public sources: Lakera (1,000), AdvBench (520),
JailbreakBench (200), Databricks Dolly 15k (5,000 benign negatives), and 12 hand-crafted
Gandalf attack prompts validated by the author. The 12 hand-crafted samples are marked
`author_validated=True` and cover 12 attack families observed first-hand on Lakera Gandalf
levels 1–7. All training data derives from public corpora; no private or production data
is used.

Three further public sources are registered as **held out** and never enter training
(`HOLDOUT_LOADERS` in `src/data_loader.py`): deepset/prompt-injections, tatsu-lab/alpaca,
and allenai/wildjailbreak. They exist so `scripts/eval_ood.py` can measure generalisation
against data the model has not seen. The benign holdout deliberately does not reuse Dolly,
which supplies 5,000 of the 6,732 training samples.

## Tech stack

Python 3.10+, FastAPI/Uvicorn, sentence-transformers (nomic-embed-text-v1.5), scikit-learn,
Pydantic v2, NumPy/pandas, httpx, PyYAML. Containerized with Docker / docker-compose.
Security tooling in CI-style checks: Bandit (SAST), detect-secrets, pip-audit.

## Testing

189 test functions across the tiers: 165 unit, 18 integration, 3 stress, 3 security. Unit
and integration cover the schema, loaders, rule engine, each guard, the pipeline, and the
gateway aggregation logic; the security tier runs Bandit / detect-secrets / pip-audit. The
full ML-backed suite runs in Docker (the detector and embedder need the model weights);
the pure-logic subset runs in an isolated venv without the heavy ML dependencies.

## Known limitations

1. **Measured out-of-distribution weakness.** On held-out attacks the detector recovers
   0.198 recall at the shipped 0.50 threshold, against 0.960 in-distribution; false
   positives on unseen benign text rise from 0.5% to 3.8%. AUC stays at 0.838, so the
   ranking survives and most of the loss is threshold calibration rather than blindness.
   The similarity layer separates unseen attacks from unseen benign text by 0.054 and does
   not earn its 20% ensemble weight. Full numbers, caveats, and the single-source
   limitation: `docs/reports/ood_benchmark_2026-07-28.md`.
2. English-validated only; the embedder is multilingual but unvalidated for injection in
   other languages.
3. No IPI defense (out of scope, see above).
4. GCG-style adversarial suffixes can bypass embedding-based detection.
5. Single-turn only; multi-turn attacks need session-level monitoring.
6. Model artifacts use `pickle` (trusted-source only); a later version will switch to
   `joblib`.

## How to run

```bash
docker compose build
docker compose run --rm app bash scripts/download_data.sh   # public datasets
docker compose run --rm app python scripts/build_dataset.py # consolidate to JSONL
docker compose run --rm app python scripts/train.py         # train + benchmark
docker compose run --rm app pytest                          # full suite
docker compose up api                                       # serve /detect on :8000
```

The gateway runs as its own service (default port 33707, `block` mode, fail-closed) and
forwards to the configured `upstream_url`; all settings are in `config.yaml` and can be
overridden by `GUARD_*` environment variables.

## Design rationale

- **Offline-first.** A guard that phones a third-party API to judge safety adds a new
  dependency and a new data-exfiltration path. Detection runs locally so the tool can sit
  in front of sensitive services without widening the trust boundary.
- **Fail-closed.** A security control that fails open is worse than none, because it
  creates false confidence. A guard error is treated as a block by default, and the
  per-guard circuit breaker only suspends calls to a persistently failing guard — it
  keeps enforcing that guard's fail mode, so a broken fail-closed guard never opens the gate.
- **Reverse proxy, not a library.** The upstream service needs no code change, which makes
  the gateway deployable in front of existing systems.
- **Explicit gaps over silent coverage.** The three runtime-undetectable OWASP categories
  are declared and routed to the correct control, so the tool's coverage is not overstated.
