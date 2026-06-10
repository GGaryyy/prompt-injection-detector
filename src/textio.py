"""Extract / re-inject the inspectable text from LLM request & response bodies.

"auto" handles the common OpenAI/Anthropic chat + completion shapes. A dotted path
(e.g. "choices.0.message.content") forces an exact location.
"""

from __future__ import annotations

import copy
from typing import Any, Optional

REQUEST_TEXT_KEYS = ("prompt", "input", "text", "query")
RESPONSE_TEXT_KEYS = ("completion", "output", "text", "response")


def _content_to_text(content: Any) -> Optional[str]:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                t = block.get("text") or block.get("content")
                if isinstance(t, str):
                    parts.append(t)
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts) if parts else None
    return None


def _last_message_content(messages: Any) -> Optional[str]:
    if not isinstance(messages, list) or not messages:
        return None
    msg = messages[-1]
    if not isinstance(msg, dict):
        return None
    return _content_to_text(msg.get("content"))


def extract_request_text(payload: Any, field: str = "auto") -> Optional[str]:
    if payload is None:
        return None
    if field != "auto":
        return _dotted_get(payload, field)
    if isinstance(payload, dict):
        if "messages" in payload:
            t = _last_message_content(payload["messages"])
            if t is not None:
                return t
        for k in REQUEST_TEXT_KEYS:
            if isinstance(payload.get(k), str):
                return payload[k]
    return None


def extract_response_text(payload: Any, field: str = "auto") -> Optional[str]:
    if payload is None:
        return None
    if field != "auto":
        return _dotted_get(payload, field)
    if isinstance(payload, dict):
        choices = payload.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            c0 = choices[0]
            if isinstance(c0.get("message"), dict):
                t = _content_to_text(c0["message"].get("content"))
                if t is not None:
                    return t
            if isinstance(c0.get("text"), str):
                return c0["text"]
        t = _content_to_text(payload.get("content"))
        if t is not None:
            return t
        for k in RESPONSE_TEXT_KEYS:
            if isinstance(payload.get(k), str):
                return payload[k]
    return None


def inject_response_text(payload: Any, redacted: str, field: str = "auto") -> Any:
    """Return a deep copy of payload with the response text replaced by `redacted`."""
    p = copy.deepcopy(payload)
    if field != "auto":
        _dotted_set(p, field, redacted)
        return p
    if isinstance(p, dict):
        choices = p.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            c0 = choices[0]
            if isinstance(c0.get("message"), dict) and "content" in c0["message"]:
                c0["message"]["content"] = redacted
                return p
            if "text" in c0:
                c0["text"] = redacted
                return p
        if isinstance(p.get("content"), str):
            p["content"] = redacted
            return p
        if isinstance(p.get("content"), list):
            for block in p["content"]:
                if isinstance(block, dict) and "text" in block:
                    block["text"] = redacted
                    return p
        for k in RESPONSE_TEXT_KEYS:
            if isinstance(p.get(k), str):
                p[k] = redacted
                return p
    return p


def _dotted_get(payload: Any, path: str) -> Optional[str]:
    cur = payload
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur if isinstance(cur, str) else None


def _dotted_set(payload: Any, path: str, value: str) -> None:
    parts = path.split(".")
    cur = payload
    for part in parts[:-1]:
        cur = cur[int(part)] if isinstance(cur, list) else cur[part]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
