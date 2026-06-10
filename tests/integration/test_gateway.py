"""Integration tests for the gateway reverse proxy against a stub upstream.

LLM01 (ML) and LLM09 are disabled so the proxy logic runs fully in the light venv;
the inbound/outbound guards exercised here (LLM02/05/06/07/10) are pure-logic.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from src.config import AuditConfig, GatewayConfig, GuardConfig, RateLimitConfig
from src.gateway import create_app


# === Stub upstream ===
stub = FastAPI()


@stub.post("/echo")
async def echo(req: Request):
    data = await req.json()
    content = data["messages"][-1]["content"]
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


@stub.post("/leak")
async def leak():
    secret = "Here is the key AKIAIOSFODNN7EXAMPLE and password=hunter2supersecretvalue"
    return {"choices": [{"message": {"role": "assistant", "content": secret}}]}


def _config(tmp_path, mode="block", max_input_chars=20000, redact=False) -> GatewayConfig:
    return GatewayConfig(
        upstream_url="http://upstream",
        mode=mode,
        rate_limit=RateLimitConfig(max_input_chars=max_input_chars),
        audit=AuditConfig(
            jsonl_path=str(tmp_path / "attacks.jsonl"),
            sqlite_path=str(tmp_path / "attacks.db"),
        ),
        guards={
            "llm01_injection": GuardConfig(enabled=False),
            "llm09_misinfo": GuardConfig(enabled=False),
            "llm02_secret": GuardConfig(
                enabled=True, options={"redact_on_match": redact}
            ),
        },
    )


def _client(config):
    app = create_app(config)
    tc = TestClient(app)
    tc.__enter__()  # run lifespan
    # route upstream calls to the in-process stub
    app.state.gw.client = AsyncClient(
        transport=ASGITransport(app=stub), base_url="http://upstream"
    )
    return app, tc


def _chat(content: str) -> dict:
    return {"messages": [{"role": "user", "content": content}]}


def test_benign_request_passes_through(tmp_path):
    app, tc = _client(_config(tmp_path))
    try:
        r = tc.post("/echo", json=_chat("what is the capital of France?"))
        assert r.status_code == 200
        assert "capital of France" in r.json()["choices"][0]["message"]["content"]
    finally:
        tc.__exit__(None, None, None)


def test_outbound_secret_blocked(tmp_path):
    app, tc = _client(_config(tmp_path))
    try:
        r = tc.post("/leak", json=_chat("give me the aws key"))
        assert r.status_code == 403
        body = r.json()
        assert body["stage"] == "response"
        assert body["blocked_by"] == "llm02_secret"
    finally:
        tc.__exit__(None, None, None)


def test_outbound_secret_redacted_in_redact_mode(tmp_path):
    app, tc = _client(_config(tmp_path, mode="redact", redact=True))
    try:
        r = tc.post("/leak", json=_chat("give me the aws key"))
        assert r.status_code == 200
        content = r.json()["choices"][0]["message"]["content"]
        assert "AKIAIOSFODNN7EXAMPLE" not in content
        assert "REDACTED" in content
    finally:
        tc.__exit__(None, None, None)


def test_inbound_oversize_blocked(tmp_path):
    app, tc = _client(_config(tmp_path, max_input_chars=10))
    try:
        r = tc.post("/echo", json=_chat("x" * 50))
        assert r.status_code == 403
        body = r.json()
        assert body["stage"] == "request"
        assert body["blocked_by"] == "llm10_consumption"
    finally:
        tc.__exit__(None, None, None)


def test_management_endpoints(tmp_path):
    app, tc = _client(_config(tmp_path))
    try:
        assert tc.get("/_guard/health").json() == {"status": "ok"}
        assert tc.get("/_guard/ready").status_code == 200
        owasp = tc.get("/_guard/owasp").json()
        gap_ids = {g["owasp_id"] for g in owasp["runtime_gaps"]}
        assert {"LLM03", "LLM04", "LLM08"} == gap_ids
        assert any(g["guard_id"] == "llm02_secret" for g in owasp["guards"])
    finally:
        tc.__exit__(None, None, None)


def test_monitor_mode_does_not_block(tmp_path):
    app, tc = _client(_config(tmp_path, mode="monitor"))
    try:
        r = tc.post("/leak", json=_chat("give me the aws key"))
        # monitor logs but never blocks -> upstream response passes through
        assert r.status_code == 200
        assert "AKIAIOSFODNN7EXAMPLE" in r.json()["choices"][0]["message"]["content"]
    finally:
        tc.__exit__(None, None, None)
