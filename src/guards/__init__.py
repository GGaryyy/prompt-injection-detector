"""OWASP guards package.

Importing this package registers all built-in guards via @register_guard, so the
pipeline always sees the full set regardless of import order. Guard modules keep
heavy ML imports lazy, so importing the package stays cheap.
"""

from src.guards.base import Guard, GuardContext, register_guard, registry

# Import side-effects register each guard into the registry.
from src.guards import (  # noqa: E402,F401
    agency_guard,
    consumption_guard,
    injection_guard,
    misinfo_guard,
    output_guard,
    secret_guard,
    sysprompt_guard,
)

__all__ = ["Guard", "GuardContext", "register_guard", "registry"]
