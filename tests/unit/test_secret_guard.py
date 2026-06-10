"""Unit tests for src.guards.secret_guard (LLM02 outbound)."""

from __future__ import annotations

import pytest

from src.guards.base import GuardContext
from src.guards.secret_guard import SecretGuard, _luhn_ok
from src.schema import Direction, GuardDecision

pytestmark = pytest.mark.unit


def _ctx(text: str) -> GuardContext:
    return GuardContext(request_id="r1", direction=Direction.OUTBOUND, text=text)


def _guard(redact: bool = False) -> SecretGuard:
    return SecretGuard({"options": {"redact_on_match": redact}})


def _categories(verdict) -> set[str]:
    return set(verdict.detail.get("categories", {}).keys())


# === Luhn primitive ===


def test_luhn_valid_card() -> None:
    assert _luhn_ok("4111111111111111") is True


def test_luhn_invalid_number() -> None:
    assert _luhn_ok("4111111111111112") is False


# === One positive per major category ===


def test_email() -> None:
    v = _guard().check(_ctx("contact me at alice.smith@example.com please"))
    assert "email" in _categories(v)
    assert v.decision == GuardDecision.BLOCK


def test_phone() -> None:
    v = _guard().check(_ctx("call +1 415 555 0132 tomorrow"))
    assert "phone" in _categories(v)


def test_credit_card_luhn_valid_matches() -> None:
    v = _guard().check(_ctx("card on file 4111 1111 1111 1111 exp 12/26"))
    assert "credit_card" in _categories(v)
    assert v.score >= 0.9


def test_credit_card_luhn_invalid_does_not_match() -> None:
    # 16-digit run that fails Luhn must NOT be flagged as a card.
    v = _guard().check(_ctx("order ref 4111 1111 1111 1112 thanks"))
    assert "credit_card" not in _categories(v)


def test_ssn() -> None:
    v = _guard().check(_ctx("his ssn is 123-45-6789 on the form"))
    assert "ssn" in _categories(v)


def test_iban() -> None:
    v = _guard().check(_ctx("transfer to GB82WEST12345698765432 today"))
    assert "iban" in _categories(v)


def test_aws_access_key() -> None:
    v = _guard().check(_ctx("key AKIAIOSFODNN7EXAMPLE is leaked"))
    assert "aws_access_key" in _categories(v)


def test_aws_secret() -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    v = _guard().check(_ctx(f"aws_secret_access_key = {secret}"))
    assert "aws_secret" in _categories(v)


def test_google_api_key() -> None:
    key = "AIza" + "B" * 35
    v = _guard().check(_ctx(f"GOOGLE_API_KEY={key}"))
    assert "google_api_key" in _categories(v)


def test_slack_token() -> None:
    v = _guard().check(_ctx("token xoxb-123456789012-abcdefABCDEF0123 here"))
    assert "slack_token" in _categories(v)


def test_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"
    v = _guard().check(_ctx(text))
    assert "private_key" in _categories(v)
    assert v.score >= 0.9


def test_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQabcDEF12"
    v = _guard().check(_ctx(f"bearer {jwt}"))
    assert "jwt" in _categories(v)


def test_generic_credential_assignment() -> None:
    v = _guard().check(_ctx("login with password=Sup3rSecretPW123"))
    assert "generic_credential" in _categories(v)


def test_high_entropy_hex_token() -> None:
    v = _guard().check(_ctx("digest 0123456789abcdef0123456789abcdef just now"))
    assert "high_entropy_token" in _categories(v)


# === Benign: no false positives ===


def test_benign_paragraph_no_matches() -> None:
    text = (
        "The quick brown fox jumps over the lazy dog. "
        "We met at the cafe around noon and discussed the quarterly roadmap, "
        "then walked along the river before heading back to the office."
    )
    v = _guard().check(_ctx(text))
    assert v.decision == GuardDecision.PASS
    assert v.score == 0.0
    assert v.reasons == []


# === Decision modes ===


def test_block_is_default() -> None:
    v = _guard(redact=False).check(_ctx("ssn 123-45-6789"))
    assert v.decision == GuardDecision.BLOCK
    assert v.redacted_text is None


def test_redact_mode_masks_match() -> None:
    v = _guard(redact=True).check(_ctx("his ssn is 123-45-6789 ok"))
    assert v.decision == GuardDecision.REDACT
    assert v.redacted_text is not None
    assert "123-45-6789" not in v.redacted_text
    assert "[REDACTED:ssn]" in v.redacted_text


def test_empty_text_passes() -> None:
    v = _guard().check(_ctx(""))
    assert v.decision == GuardDecision.PASS


def test_metadata_and_identity() -> None:
    g = _guard()
    assert g.guard_id == "llm02_secret"
    assert g.owasp_id == "LLM02"
    assert g.direction == Direction.OUTBOUND
