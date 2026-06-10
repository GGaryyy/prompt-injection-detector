# OWASP LLM Top 10 (2025) — Gateway Coverage Declaration

This document states **exactly** what the LLM Guard Gateway defends at runtime and,
just as importantly, **what it cannot** — because a reverse-proxy that only sees one
request/response at a time genuinely cannot address some categories. Those are not
silent gaps; each points at the control that does address it.

Legend: ✅ enforced at runtime · ⚠️ partial / best-effort · ❌ not runtime-defensible (declared gap)

| ID | Category | Coverage | Intercept | Guard / Control |
|----|----------|----------|-----------|-----------------|
| **LLM01** | Prompt Injection | ✅ | inbound | `llm01_injection` — three-layer ensemble detector (rule + classifier + similarity) |
| **LLM02** | Sensitive Information Disclosure | ✅ | outbound | `llm02_secret` — PII / credential / key / JWT / high-entropy scan; block or redact |
| **LLM03** | Supply Chain | ❌ gap | — | build-time: AutoTest `bundle_scan` + SBOM, `pip-audit` in CI, pinned hashes |
| **LLM04** | Data and Model Poisoning | ❌ gap | — | training-time: data provenance, ingestion validation, dataset signing |
| **LLM05** | Improper Output Handling | ✅ | outbound | `llm05_output` — unsanitized HTML/JS, exfil markdown links, SSRF targets, template injection |
| **LLM06** | Excessive Agency | ⚠️ | in/out | `llm06_agency` — tool/function-call allowlist + dangerous-argument gating (only when tool calls are present in the payload) |
| **LLM07** | System Prompt Leakage | ✅ | outbound | `llm07_sysprompt` — canary tokens + system-prompt fragment echo + leak-phrase heuristics |
| **LLM08** | Vector and Embedding Weaknesses | ❌ gap | — | architecture: per-tenant vector isolation, retrieval access control, RAG IPI testing (project 2) |
| **LLM09** | Misinformation | ⚠️ | outbound | `llm09_misinfo` — best-effort overconfidence / fabricated-citation heuristics; **off by default**, never blocks (offline cannot fact-check) |
| **LLM10** | Unbounded Consumption | ✅ | inbound | `llm10_consumption` — rate limit, input-size cap, concurrency cap, upstream timeout |

## Runtime-defensible summary
- **Fully enforced:** LLM01, LLM02, LLM05, LLM07, LLM10
- **Partial / conditional:** LLM06 (needs tool-call payloads), LLM09 (heuristic, off by default)
- **Declared gaps (NOT runtime-defensible):** LLM03, LLM04, LLM08 — see `src/owasp_gaps.py`

## Why the gaps are real, not laziness
A request/response proxy sees traffic, not the model's training data, its dependency
tree, or its vector store. LLM03 (supply chain) and LLM04 (poisoning) are decided
before any traffic exists; LLM08 (vector/embedding) lives in the retrieval
architecture and corpus. Pretending to "defend" them at the proxy would be security
theatre. Instead, the gateway logs them as gaps and routes them to the right control
layer — primarily the AutoTest framework (CI / SBOM / RAG testing) and data governance.

The gateway surfaces these gaps at startup, on the `/owasp` endpoint, and here, so an
operator is never under the illusion that "the gateway has all ten covered."
