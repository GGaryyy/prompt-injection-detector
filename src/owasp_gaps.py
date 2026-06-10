"""OWASP LLM Top 10 (2025) categories that a runtime reverse-proxy gateway
cannot defend, declared explicitly for transparency.

These are surfaced in `docs/owasp_coverage.md`, in the gateway's startup log, and
on the `/owasp` endpoint. They are NOT silent gaps — each points at the control
that *does* address it (mostly AutoTest / CI / data governance).
"""

from src.schema import GapRecord

RUNTIME_GAPS: list[GapRecord] = [
    GapRecord(
        owasp_id="LLM03",
        name="Supply Chain",
        reason="Compromised models/packages/datasets are a build-time and dependency "
        "concern; nothing in a single request/response reveals them at runtime.",
        recommended_control="AutoTest bundle_scan + SBOM, pip-audit in CI, pinned hashes.",
    ),
    GapRecord(
        owasp_id="LLM04",
        name="Data and Model Poisoning",
        reason="Poisoning happens during training/fine-tuning/RAG-ingestion, before "
        "any traffic reaches the gateway.",
        recommended_control="Training-data provenance, ingestion validation, dataset signing.",
    ),
    GapRecord(
        owasp_id="LLM08",
        name="Vector and Embedding Weaknesses",
        reason="RAG/vector-store weaknesses live in the retrieval architecture and "
        "corpus, not in the request/response the proxy can see.",
        recommended_control="Per-tenant vector isolation, retrieval access control, "
        "RAG IPI testing (project 2 / AutoTest).",
    ),
]
