"""Unit tests for approval-token signing helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from kaval.actions.approvals import (
    APPROVAL_HMAC_SECRET_ENV,
    get_approval_hmac_secret,
    sign_approval_token,
    verify_approval_token_signature,
)
from kaval.models import ActionType, ApprovalToken

_TEST_SECRET = "test-secret-0123456789abcdef0123456789"
_ANOTHER_TEST_SECRET = "other-secret-0123456789abcdef012345678"
_ERROR_MATCH = "KAVAL_APPROVAL_HMAC_SECRET.*openssl rand -hex 32"


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for test payloads."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def build_token() -> ApprovalToken:
    """Create a reusable approval token payload."""
    return ApprovalToken(
        token_id="tok-approval",
        incident_id="inc-approval",
        action=ActionType.RESTART_CONTAINER,
        target="delugevpn",
        approved_by="telegram-user",
        issued_at=ts(14, 30),
        expires_at=ts(14, 35),
        nonce="nonce-approval",
        hmac_signature="",
        used_at=None,
        result=None,
    )


@pytest.mark.parametrize(
    "weak_secret",
    ["local-dev-approval-secret", "too-short-secret"],
)
def test_get_approval_hmac_secret_rejects_weak_explicit_secret(
    weak_secret: str,
) -> None:
    """Explicit approval secrets must not use weak/default values."""
    with pytest.raises(RuntimeError, match=_ERROR_MATCH):
        get_approval_hmac_secret(explicit_secret=weak_secret)


@pytest.mark.parametrize(
    "weak_secret",
    ["local-dev-approval-secret", "too-short-secret"],
)
def test_get_approval_hmac_secret_rejects_weak_env_secret(
    monkeypatch: pytest.MonkeyPatch,
    weak_secret: str,
) -> None:
    """Environment approval secrets must not use weak/default values."""
    monkeypatch.setenv(APPROVAL_HMAC_SECRET_ENV, weak_secret)

    with pytest.raises(RuntimeError, match=_ERROR_MATCH):
        get_approval_hmac_secret()


def test_get_approval_hmac_secret_accepts_strong_explicit_secret() -> None:
    """Explicit approval secrets are accepted when they meet the byte floor."""
    assert get_approval_hmac_secret(explicit_secret=_TEST_SECRET) == _TEST_SECRET


def test_get_approval_hmac_secret_accepts_strong_env_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Environment approval secrets are accepted when they meet the byte floor."""
    monkeypatch.setenv(APPROVAL_HMAC_SECRET_ENV, _TEST_SECRET)

    assert get_approval_hmac_secret() == _TEST_SECRET


def test_sign_and_verify_approval_token() -> None:
    """Signed tokens should verify against the same secret."""
    token = sign_approval_token(build_token(), secret=_TEST_SECRET)

    assert verify_approval_token_signature(token, secret=_TEST_SECRET) is True


def test_verify_approval_token_rejects_tampered_payload() -> None:
    """Changing a signed field should invalidate the approval-token signature."""
    signed_token = sign_approval_token(build_token(), secret=_TEST_SECRET)
    tampered_token = signed_token.model_copy(update={"target": "radarr"})

    assert verify_approval_token_signature(tampered_token, secret=_TEST_SECRET) is False


def test_verify_approval_token_rejects_different_secret() -> None:
    """Changing the approval secret should invalidate the signature."""
    signed_token = sign_approval_token(build_token(), secret=_TEST_SECRET)

    assert (
        verify_approval_token_signature(signed_token, secret=_ANOTHER_TEST_SECRET)
        is False
    )
