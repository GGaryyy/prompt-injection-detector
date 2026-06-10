"""Unit tests for src.guards.agency_guard (LLM06 Excessive Agency)."""

from __future__ import annotations

import pytest

from src.guards.agency_guard import AgencyGuard
from src.guards.base import GuardContext
from src.schema import Direction, GuardDecision

pytestmark = pytest.mark.unit


def _ctx(payload):
    return GuardContext(
        request_id="req-1",
        direction=Direction.INBOUND,
        text="",
        payload=payload,
    )


def _guard(allowlist=None, strict=False):
    options = {}
    if allowlist is not None:
        options["tool_allowlist"] = allowlist
    options["strict"] = strict
    return AgencyGuard(config={"options": options})


def test_payload_none_passes() -> None:
    verdict = _guard(allowlist=["search"]).check(_ctx(None))
    assert verdict.decision == GuardDecision.PASS
    assert verdict.score == 0.0


def test_payload_without_tools_passes() -> None:
    payload = {"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}
    verdict = _guard(allowlist=["search"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.PASS


def test_allowlisted_benign_tool_passes() -> None:
    payload = {
        "tools": [
            {"type": "function", "function": {"name": "search", "arguments": "{}"}}
        ]
    }
    verdict = _guard(allowlist=["search", "weather"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.PASS
    assert verdict.score == 0.0


def test_non_allowlisted_tool_flags() -> None:
    payload = {
        "tools": [
            {"type": "function", "function": {"name": "delete_user", "arguments": "{}"}}
        ]
    }
    verdict = _guard(allowlist=["search"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.FLAG
    assert "delete_user" in verdict.detail["flagged_tools"]
    assert any("delete_user" in r for r in verdict.reasons)


def test_non_allowlisted_tool_strict_blocks() -> None:
    payload = {
        "tools": [
            {"type": "function", "function": {"name": "wipe_db", "arguments": "{}"}}
        ]
    }
    verdict = _guard(allowlist=["search"], strict=True).check(_ctx(payload))
    assert verdict.decision == GuardDecision.BLOCK


def test_empty_allowlist_flags_every_tool() -> None:
    payload = {"functions": [{"name": "lookup", "parameters": "{}"}]}
    verdict = _guard(allowlist=[]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.FLAG
    assert verdict.score == pytest.approx(0.4)
    assert "lookup" in verdict.detail["flagged_tools"]


def test_dangerous_argument_blocks() -> None:
    payload = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "run_sql",
                    "arguments": '{"query": "DROP TABLE users"}',
                },
            }
        ]
    }
    verdict = _guard(allowlist=["run_sql"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.BLOCK
    assert verdict.score == 1.0
    assert "run_sql" in verdict.detail["dangerous_tools"]


def test_dangerous_argument_overrides_allowlist() -> None:
    # Even an allowlisted tool blocks when arguments carry a dangerous action.
    payload = {
        "tools": [
            {"function": {"name": "shell", "arguments": "rm -rf /"}}
        ]
    }
    verdict = _guard(allowlist=["shell"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.BLOCK


def test_openai_response_tool_calls_blocks_on_danger() -> None:
    payload = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "transfer_funds",
                                "arguments": '{"action": "wire 5000"}',
                            },
                        }
                    ],
                }
            }
        ]
    }
    verdict = _guard(allowlist=["transfer_funds"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.BLOCK
    assert "transfer_funds" in verdict.detail["dangerous_tools"]


def test_top_level_tool_calls_flagged() -> None:
    payload = {
        "tool_calls": [
            {"function": {"name": "unknown_tool", "arguments": "{}"}}
        ]
    }
    verdict = _guard(allowlist=["search"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.FLAG
    assert "unknown_tool" in verdict.detail["tools_seen"]


def test_legacy_function_call_shape() -> None:
    payload = {"function_call": {"name": "send_email", "arguments": "to=a@b.com"}}
    verdict = _guard(allowlist=["send_email"]).check(_ctx(payload))
    # send_email is a dangerous keyword in args? name is send_email, arg has no keyword.
    # Name matches allowlist; argument "to=a@b.com" has no dangerous keyword -> PASS.
    assert verdict.decision == GuardDecision.PASS


def test_mixed_benign_and_dangerous_blocks() -> None:
    payload = {
        "tools": [
            {"function": {"name": "search", "arguments": "{}"}},
            {"function": {"name": "admin", "arguments": "sudo reboot"}},
        ]
    }
    verdict = _guard(allowlist=["search", "admin"]).check(_ctx(payload))
    assert verdict.decision == GuardDecision.BLOCK
    assert "admin" in verdict.detail["dangerous_tools"]
