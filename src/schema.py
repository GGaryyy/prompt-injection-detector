"""Unified data schemas for the PI detector.

Defines:
- TrainingSample: unified format for any data source (Lakera, JailbreakBench, ShareGPT, the author's Gandalf prompts)
- DetectionResult: API response schema
- AttackFamily: enum of attack family labels (aligned with 03_owasp_llm_top10_crosswalk.md)
"""

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


# Aligned with crosswalk file's attack family taxonomy.
# Author-validated families come first (handled by hands-on tuning); rest are training-only coverage.
AttackFamily = Literal[
    # === Author-validated (Gandalf) ===
    "pretexting",
    "semantic_indirection",
    "hint_extraction",
    "narrative_framing",
    "multi_sample_cross_reference",
    "meta_conversation",
    "trust_partitioning",
    "phishing_authority_impersonation",
    "completion_smuggling",
    "system_prompt_exfiltration",
    "role_boundary_confusion",
    "code_injection_disguise",
    # === Training-data-only coverage ===
    "indirect_prompt_injection",
    "multimodal_injection",
    "adversarial_suffix",
    "many_shot_jailbreak",
    "skeleton_key",
    "crescendo",
    "token_level_attack",
    "multilingual_injection",
    "context_drift",
    "persona_override",
    "direct_instruction_override",  # generic catch-all for "ignore previous" style
    "other",
]


class TrainingSample(BaseModel):
    """Unified schema for one training sample."""

    id: str = Field(..., description="Unique sample ID, e.g. 'lakera_001'")
    prompt: str = Field(..., description="The actual prompt text")
    label: Literal[0, 1] = Field(..., description="0 = benign, 1 = injection")
    source: str = Field(..., description="Dataset source name")
    attack_family: Optional[AttackFamily] = Field(
        default=None, description="Attack family (None for benign samples)"
    )
    subfamily: Optional[str] = Field(
        default=None, description="Optional finer-grained attack subfamily"
    )
    language: str = Field(
        default="en", description='ISO 639-1 language code, or "unknown" if the source does not say'
    )
    tested_against: list[str] = Field(
        default_factory=list,
        description="LLMs this attack was reported against (e.g. ['GPT-4', 'Claude-3'])",
    )
    author_validated: bool = Field(
        default=False,
        description="True if the author validated this attack hands-on (e.g., during Gandalf)",
    )
    validation_context: Optional[str] = Field(
        default=None,
        description="If author_validated, where (e.g. 'Gandalf L2', 'Gandalf L7 attempt 4')",
    )
    notes: str = Field(default="")


class SimilarKnownAttack(BaseModel):
    """One nearest-neighbour result for explainability."""

    prompt: str
    attack_family: Optional[AttackFamily] = None
    similarity: float = Field(..., ge=-1.0, le=1.0)
    source: str


class DetectionResult(BaseModel):
    """API response schema for POST /detect."""

    is_injection: bool
    rule_based_score: float = Field(..., ge=0.0, le=1.0)
    embedding_based_score: float = Field(..., ge=0.0, le=1.0)
    ensemble_score: float = Field(..., ge=0.0, le=1.0)
    predicted_attack_family: Optional[AttackFamily] = None
    top_similar_known_attacks: list[SimilarKnownAttack] = Field(default_factory=list)
    explanation: str = Field(default="")
    latency_ms: float = Field(..., ge=0.0)


class DetectRequest(BaseModel):
    """API request schema for POST /detect."""

    text: str = Field(..., min_length=1, max_length=10_000)
    return_top_k: int = Field(default=5, ge=0, le=20)


# ============================================================================
# Gateway / Guard schemas (v1.0 — LLM Guard Gateway)
# ============================================================================


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class GuardDecision(str, Enum):
    PASS = "pass"
    FLAG = "flag"      # suspicious, recorded, not blocked
    REDACT = "redact"  # content modified, allowed through
    BLOCK = "block"
    ERROR = "error"    # guard failed to run


# Severity ordering for aggregating multiple guard verdicts into one decision.
DECISION_SEVERITY = {
    GuardDecision.PASS: 0,
    GuardDecision.FLAG: 1,
    GuardDecision.REDACT: 2,
    GuardDecision.ERROR: 3,
    GuardDecision.BLOCK: 4,
}


class GuardVerdict(BaseModel):
    """One guard's verdict on one direction of one request."""

    guard_id: str
    owasp_id: str  # e.g. "LLM01"
    direction: Direction
    decision: GuardDecision
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    redacted_text: Optional[str] = None
    detail: dict = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)


class GatewayDecision(BaseModel):
    """Aggregated decision across all guards for one direction."""

    request_id: str
    direction: Direction
    final_decision: GuardDecision
    verdicts: list[GuardVerdict] = Field(default_factory=list)
    blocked_by: Optional[str] = None  # guard_id that forced the block
    redacted_text: Optional[str] = None


class AttackRecord(BaseModel):
    """One audit-log entry for a flagged/blocked/redacted request."""

    request_id: str
    timestamp: str  # ISO-8601, stamped at write time
    direction: Direction
    owasp_id: str
    guard_id: str
    decision: GuardDecision
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    client_ip: Optional[str] = None
    session_id: Optional[str] = None
    reasons: list[str] = Field(default_factory=list)
    payload_excerpt: str = ""  # truncated + sanitized


class GapRecord(BaseModel):
    """An OWASP category the gateway cannot defend at runtime — logged for transparency."""

    owasp_id: str
    name: str
    reason: str
    recommended_control: str
