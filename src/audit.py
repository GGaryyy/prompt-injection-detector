"""Attack audit log — every flagged/blocked/redacted verdict is recorded.

Two sinks: append-only JSONL (easy to tail / ship to a SIEM) and SQLite (queryable
by the Phase-2 AutoTest dashboard). Also records the declared runtime gaps once at
startup so an operator can see them in the same store.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from src.config import AuditConfig
from src.guards.base import GuardContext
from src.owasp_gaps import RUNTIME_GAPS
from src.schema import AttackRecord, GatewayDecision, GuardDecision

logger = logging.getLogger(__name__)

# Verdicts worth recording (PASS is not an attack).
RECORDABLE = {
    GuardDecision.FLAG,
    GuardDecision.REDACT,
    GuardDecision.BLOCK,
    GuardDecision.ERROR,
}

_ATTACKS_DDL = """
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    timestamp TEXT,
    direction TEXT,
    owasp_id TEXT,
    guard_id TEXT,
    decision TEXT,
    score REAL,
    client_ip TEXT,
    session_id TEXT,
    reasons TEXT,
    payload_excerpt TEXT
)
"""

_GAPS_DDL = """
CREATE TABLE IF NOT EXISTS gaps (
    owasp_id TEXT PRIMARY KEY,
    name TEXT,
    reason TEXT,
    recommended_control TEXT,
    declared_at TEXT
)
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self.jsonl_path = Path(config.jsonl_path)
        self.sqlite_path = Path(config.sqlite_path)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.sqlite_path), check_same_thread=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute(_ATTACKS_DDL)
            self._conn.execute(_GAPS_DDL)
            self._conn.commit()

    def record(self, decision: GatewayDecision, ctx: GuardContext) -> list[AttackRecord]:
        excerpt = self._excerpt(ctx.text)
        ts = _now_iso()
        records = [
            AttackRecord(
                request_id=ctx.request_id,
                timestamp=ts,
                direction=decision.direction,
                owasp_id=v.owasp_id,
                guard_id=v.guard_id,
                decision=v.decision,
                score=v.score,
                client_ip=ctx.client_ip,
                session_id=ctx.session_id,
                reasons=v.reasons,
                payload_excerpt=excerpt,
            )
            for v in decision.verdicts
            if v.decision in RECORDABLE
        ]
        if records:
            self._write(records)
        return records

    def record_gaps(self) -> None:
        ts = _now_iso()
        with self._lock:
            for g in RUNTIME_GAPS:
                self._conn.execute(
                    "INSERT OR REPLACE INTO gaps "
                    "(owasp_id, name, reason, recommended_control, declared_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (g.owasp_id, g.name, g.reason, g.recommended_control, ts),
                )
            self._conn.commit()

    def _excerpt(self, text: str) -> str:
        collapsed = " ".join(text.split())
        return collapsed[: self.config.payload_excerpt_chars]

    def _write(self, records: list[AttackRecord]) -> None:
        with self._lock:
            with self.jsonl_path.open("a", encoding="utf-8") as f:
                for r in records:
                    f.write(r.model_dump_json() + "\n")
            self._conn.executemany(
                "INSERT INTO attacks "
                "(request_id, timestamp, direction, owasp_id, guard_id, decision, "
                "score, client_ip, session_id, reasons, payload_excerpt) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        r.request_id,
                        r.timestamp,
                        r.direction.value,
                        r.owasp_id,
                        r.guard_id,
                        r.decision.value,
                        r.score,
                        r.client_ip,
                        r.session_id,
                        "; ".join(r.reasons),
                        r.payload_excerpt,
                    )
                    for r in records
                ],
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
