"""Stress / load tests for the gateway proxy path.

LLM01 is disabled so this measures *proxy + guard* overhead (the ML detector path is
stress-tested separately under Docker). Asserts correctness under concurrency and that
latency stays bounded; prints p50/p95/p99 for the report.
"""

from __future__ import annotations

import statistics
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from src.config import AuditConfig, GatewayConfig, GuardConfig, RateLimitConfig
from src.gateway import create_app

NUM_SEQUENTIAL = 200
NUM_CONCURRENT = 200
CONCURRENT_WORKERS = 16
P95_BUDGET_S = 2.0  # generous — includes TestClient overhead; ML SLA is measured in Docker

stub = FastAPI()


@stub.post("/echo")
async def echo(req: Request):
    data = await req.json()
    content = data["messages"][-1]["content"]
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def _config(tmp_path) -> GatewayConfig:
    return GatewayConfig(
        upstream_url="http://upstream",
        # High limits so the rate limiter doesn't trip while measuring proxy overhead.
        rate_limit=RateLimitConfig(
            requests_per_minute=1_000_000, max_concurrent=100_000, max_input_chars=1_000_000
        ),
        audit=AuditConfig(
            jsonl_path=str(tmp_path / "a.jsonl"), sqlite_path=str(tmp_path / "a.db")
        ),
        guards={
            "llm01_injection": GuardConfig(enabled=False),
            "llm09_misinfo": GuardConfig(enabled=False),
        },
    )


def _client(config):
    app = create_app(config)
    tc = TestClient(app)
    tc.__enter__()
    app.state.gw.client = AsyncClient(transport=ASGITransport(app=stub), base_url="http://upstream")
    return tc


def _percentiles(latencies: list[float]) -> dict[str, float]:
    s = sorted(latencies)
    n = len(s)
    return {
        "p50": s[int(n * 0.50)],
        "p95": s[int(n * 0.95)],
        "p99": s[min(int(n * 0.99), n - 1)],
    }


def test_sequential_throughput(tmp_path, capsys):
    tc = _client(_config(tmp_path))
    try:
        latencies = []
        start = time.perf_counter()
        for i in range(NUM_SEQUENTIAL):
            t0 = time.perf_counter()
            r = tc.post("/echo", json={"messages": [{"role": "user", "content": f"q{i}"}]})
            latencies.append(time.perf_counter() - t0)
            assert r.status_code == 200
        total = time.perf_counter() - start
        pct = _percentiles(latencies)
        rps = NUM_SEQUENTIAL / total
        with capsys.disabled():
            print(
                f"\n[stress seq] {NUM_SEQUENTIAL} reqs in {total:.2f}s "
                f"({rps:.0f} rps) p50={pct['p50']*1000:.1f}ms "
                f"p95={pct['p95']*1000:.1f}ms p99={pct['p99']*1000:.1f}ms"
            )
        assert pct["p95"] < P95_BUDGET_S
    finally:
        tc.__exit__(None, None, None)


def test_concurrent_load_correctness(tmp_path):
    tc = _client(_config(tmp_path))
    try:
        def one(i: int) -> int:
            r = tc.post("/echo", json={"messages": [{"role": "user", "content": f"q{i}"}]})
            return r.status_code

        with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as pool:
            codes = list(pool.map(one, range(NUM_CONCURRENT)))
        assert all(c == 200 for c in codes)
        assert len(codes) == NUM_CONCURRENT
    finally:
        tc.__exit__(None, None, None)


def test_oversize_body_rejected_fast(tmp_path):
    # max_body_bytes guard should reject a huge body without forwarding upstream.
    cfg = _config(tmp_path)
    cfg.max_body_bytes = 1000
    tc = _client(cfg)
    try:
        r = tc.post("/echo", content=b"x" * 5000, headers={"content-type": "application/json"})
        assert r.status_code == 413
    finally:
        tc.__exit__(None, None, None)
