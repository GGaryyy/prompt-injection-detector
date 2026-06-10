"""Guard base interface + registry.

Every OWASP guard is a small single-purpose unit that inspects one GuardContext
(an inbound request or an outbound response) and returns a GuardVerdict. The
pipeline runs the relevant guards for each direction and aggregates their verdicts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from src.schema import Direction, GuardVerdict


@dataclass
class GuardContext:
    """Everything a guard may inspect for one direction of one request."""

    request_id: str
    direction: Direction
    text: str  # primary text to inspect (extracted prompt or response body)
    headers: dict[str, str] = field(default_factory=dict)
    payload: Optional[dict] = None  # parsed JSON body, if the body was JSON
    client_ip: Optional[str] = None
    session_id: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)


class Guard(ABC):
    """Base class for all guards.

    Subclasses set `guard_id`, `owasp_id`, `direction` and implement `check`.
    A guard must never raise for normal suspicious input — it returns a verdict.
    Unexpected internal failures propagate; the pipeline isolates them per-guard.
    """

    guard_id: str = "base"
    owasp_id: str = ""
    direction: Direction = Direction.INBOUND

    def __init__(self, config: Optional[dict] = None) -> None:
        self.config = config or {}
        self.enabled: bool = bool(self.config.get("enabled", True))
        self.fail_mode: str = str(self.config.get("fail_mode", "closed"))

    @abstractmethod
    def check(self, ctx: GuardContext) -> GuardVerdict:
        """Inspect ctx and return a verdict. Must not block on network I/O."""
        raise NotImplementedError


_REGISTRY: dict[str, type[Guard]] = {}


def register_guard(cls: type[Guard]) -> type[Guard]:
    """Class decorator — register a guard by its guard_id."""
    if cls.guard_id in _REGISTRY:
        raise ValueError(f"duplicate guard_id: {cls.guard_id}")
    _REGISTRY[cls.guard_id] = cls
    return cls


def registry() -> dict[str, type[Guard]]:
    return dict(_REGISTRY)
