"""Unit tests for the attack audit log — JSONL + SQLite sinks, gap recording."""

from __future__ import annotations

import json
import sqlite3

from src.audit import AuditLog
from src.config import AuditConfig
from src.guards.base import GuardContext
from src.schema import (
    Direction,
    GatewayDecision,
    GuardDecision,
    GuardVerdict,
)


def _audit(tmp_path) -> AuditLog:
    cfg = AuditConfig(
        jsonl_path=str(tmp_path / "attacks.jsonl"),
        sqlite_path=str(tmp_path / "attacks.db"),
        payload_excerpt_chars=20,
    )
    return AuditLog(cfg)


def _decision(*verdicts: GuardVerdict) -> GatewayDecision:
    return GatewayDecision(
        request_id="req-1",
        direction=Direction.OUTBOUND,
        final_decision=GuardDecision.BLOCK,
        verdicts=list(verdicts),
    )


def _verdict(decision: GuardDecision, guard_id="g", owasp="LLM02") -> GuardVerdict:
    return GuardVerdict(
        guard_id=guard_id, owasp_id=owasp, direction=Direction.OUTBOUND, decision=decision, score=0.9
    )


def test_only_recordable_verdicts_written(tmp_path):
    audit = _audit(tmp_path)
    ctx = GuardContext(request_id="req-1", direction=Direction.OUTBOUND, text="secret leaked")
    decision = _decision(
        _verdict(GuardDecision.PASS, "g_pass"),
        _verdict(GuardDecision.BLOCK, "g_block"),
        _verdict(GuardDecision.FLAG, "g_flag"),
    )
    records = audit.record(decision, ctx)
    assert len(records) == 2  # PASS excluded
    assert {r.guard_id for r in records} == {"g_block", "g_flag"}


def test_jsonl_and_sqlite_in_sync(tmp_path):
    audit = _audit(tmp_path)
    ctx = GuardContext(request_id="req-1", direction=Direction.OUTBOUND, text="x")
    audit.record(_decision(_verdict(GuardDecision.BLOCK)), ctx)

    lines = (tmp_path / "attacks.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["decision"] == "block"

    conn = sqlite3.connect(str(tmp_path / "attacks.db"))
    rows = conn.execute("SELECT decision, owasp_id FROM attacks").fetchall()
    conn.close()
    assert rows == [("block", "LLM02")]


def test_excerpt_truncates_and_collapses_whitespace(tmp_path):
    audit = _audit(tmp_path)
    ctx = GuardContext(
        request_id="req-1",
        direction=Direction.OUTBOUND,
        text="line one\n\n   line two with lots of words here",
    )
    records = audit.record(_decision(_verdict(GuardDecision.BLOCK)), ctx)
    excerpt = records[0].payload_excerpt
    assert "\n" not in excerpt
    assert len(excerpt) <= 20


def test_no_records_when_all_pass(tmp_path):
    audit = _audit(tmp_path)
    ctx = GuardContext(request_id="req-1", direction=Direction.OUTBOUND, text="x")
    records = audit.record(_decision(_verdict(GuardDecision.PASS)), ctx)
    assert records == []
    assert not (tmp_path / "attacks.jsonl").exists()


def test_record_gaps(tmp_path):
    audit = _audit(tmp_path)
    audit.record_gaps()
    conn = sqlite3.connect(str(tmp_path / "attacks.db"))
    ids = {r[0] for r in conn.execute("SELECT owasp_id FROM gaps").fetchall()}
    conn.close()
    assert {"LLM03", "LLM04", "LLM08"} == ids


def test_record_gaps_idempotent(tmp_path):
    audit = _audit(tmp_path)
    audit.record_gaps()
    audit.record_gaps()
    conn = sqlite3.connect(str(tmp_path / "attacks.db"))
    count = conn.execute("SELECT COUNT(*) FROM gaps").fetchone()[0]
    conn.close()
    assert count == 3  # INSERT OR REPLACE, no duplicates
