"""Unit tests for approval-token signing helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from kaval.actions.approvals import sign_approval_token, verify_approval_token_signature
from kaval.models import ActionType, ApprovalToken


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


def test_sign_and_verify_approval_token() -> None:
    """Signed tokens should verify against the same secret."""
    token = sign_approval_token(build_token(), secret="test-secret")

    assert verify_approval_token_signature(token, secret="test-secret") is True


def test_verify_approval_token_rejects_tampered_payload() -> None:
    """Changing a signed field should invalidate the approval-token signature."""
    signed_token = sign_approval_token(build_token(), secret="test-secret")
    tampered_token = signed_token.model_copy(update={"target": "radarr"})

    assert verify_approval_token_signature(tampered_token, secret="test-secret") is False
