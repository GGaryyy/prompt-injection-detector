"""Unit tests for request/response text extraction + redaction injection."""

from __future__ import annotations

from src import textio


def test_extract_request_openai_messages():
    payload = {"messages": [{"role": "user", "content": "hello world"}]}
    assert textio.extract_request_text(payload) == "hello world"


def test_extract_request_content_blocks():
    payload = {"messages": [{"role": "user", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}]}
    assert textio.extract_request_text(payload) == "a\nb"


def test_extract_request_prompt_key():
    assert textio.extract_request_text({"prompt": "do thing"}) == "do thing"


def test_extract_request_dotted_path():
    payload = {"data": {"q": "deep"}}
    assert textio.extract_request_text(payload, "data.q") == "deep"


def test_extract_response_openai():
    payload = {"choices": [{"message": {"role": "assistant", "content": "answer"}}]}
    assert textio.extract_response_text(payload) == "answer"


def test_extract_response_anthropic():
    payload = {"content": [{"type": "text", "text": "claude says hi"}]}
    assert textio.extract_response_text(payload) == "claude says hi"


def test_extract_response_completion_text():
    payload = {"choices": [{"text": "legacy completion"}]}
    assert textio.extract_response_text(payload) == "legacy completion"


def test_inject_response_openai():
    payload = {"choices": [{"message": {"role": "assistant", "content": "secret"}}]}
    out = textio.inject_response_text(payload, "[REDACTED]")
    assert out["choices"][0]["message"]["content"] == "[REDACTED]"
    # original untouched (deep copy)
    assert payload["choices"][0]["message"]["content"] == "secret"


def test_inject_response_anthropic_block():
    payload = {"content": [{"type": "text", "text": "secret"}]}
    out = textio.inject_response_text(payload, "[REDACTED]")
    assert out["content"][0]["text"] == "[REDACTED]"


def test_extract_none_payload():
    assert textio.extract_request_text(None) is None
    assert textio.extract_response_text(None) is None
