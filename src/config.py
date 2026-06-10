"""Gateway configuration — loaded from config.yaml, overridable via env.

The gateway is offline-first: no config option enables an external network call
other than forwarding to the configured upstream AI service.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field

# === Defaults ===
DEFAULT_PORT = 33707  # uncommon registered-range port; override in config.yaml
DEFAULT_UPSTREAM_TIMEOUT_S = 60.0
DEFAULT_MAX_BODY_BYTES = 1_000_000

FailMode = Literal["open", "closed"]
GatewayMode = Literal["block", "monitor", "redact"]


class GuardConfig(BaseModel):
    """Per-guard settings. `options` carries guard-specific knobs."""

    enabled: bool = True
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    fail_mode: FailMode = "closed"
    options: dict = Field(default_factory=dict)


class AuditConfig(BaseModel):
    jsonl_path: str = "output/attacks.jsonl"
    sqlite_path: str = "output/attacks.db"
    payload_excerpt_chars: int = Field(default=500, ge=0)


class RateLimitConfig(BaseModel):
    """LLM10 — Unbounded Consumption controls."""

    enabled: bool = True
    requests_per_minute: int = Field(default=120, ge=0)
    max_concurrent: int = Field(default=64, ge=1)
    max_input_chars: int = Field(default=20_000, ge=0)


class GatewayConfig(BaseModel):
    upstream_url: str
    listen_host: str = "0.0.0.0"  # nosec B104 — gateway binds all interfaces inside its container; host networking controls exposure
    listen_port: int = DEFAULT_PORT
    mode: GatewayMode = "block"
    fail_mode: FailMode = "closed"
    upstream_timeout_s: float = DEFAULT_UPSTREAM_TIMEOUT_S
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES

    # JSON paths used to extract the text to inspect from request/response bodies.
    # "auto" = heuristic over common LLM API shapes (OpenAI/Anthropic style).
    request_text_field: str = "auto"
    response_text_field: str = "auto"

    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    guards: dict[str, GuardConfig] = Field(default_factory=dict)

    def guard(self, guard_id: str) -> GuardConfig:
        return self.guards.get(guard_id, GuardConfig())


def load_config(path: Optional[str | Path] = None) -> GatewayConfig:
    """Load config.yaml. Env GUARD_CONFIG overrides the path; a few scalars
    can be overridden via env for container deploys."""
    cfg_path = Path(path or os.environ.get("GUARD_CONFIG", "config.yaml"))
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

    if "GUARD_UPSTREAM_URL" in os.environ:
        data["upstream_url"] = os.environ["GUARD_UPSTREAM_URL"]
    if "GUARD_LISTEN_PORT" in os.environ:
        data["listen_port"] = int(os.environ["GUARD_LISTEN_PORT"])
    if "GUARD_MODE" in os.environ:
        data["mode"] = os.environ["GUARD_MODE"]

    return GatewayConfig.model_validate(data)
