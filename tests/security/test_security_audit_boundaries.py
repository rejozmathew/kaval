"""Consolidated security-audit boundary evidence (P4-22, P4-23, P4-25).

These tests lock in the highest-value, most stable invariants of Kaval's security model so
the Phase 4 audit evidence (see ``docs/security_requirements.md``) becomes part of the
permanent CI suite. They complement, rather than replace, the area-specific suites already
present in ``tests/security/``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kaval.actions.approvals import (
    sign_approval_token,
    verify_approval_token_signature,
)
from kaval.executor.server import ALLOWED_EXECUTOR_ACTIONS
from kaval.models import ActionType, ApprovalToken

_SECRET = "audit-test-secret-0123456789abcdef0123"
_OTHER_SECRET = "other-secret-0123456789abcdef012345678"


def _signed_token(**overrides: object) -> ApprovalToken:
    """Build a signed approval token for the audit-boundary tests."""
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    base = {
        "token_id": "tok-1",
        "incident_id": "inc-1",
        "action": ActionType.RESTART_CONTAINER,
        "target": "container-deluge",
        "approved_by": "admin",
        "issued_at": issued_at,
        "expires_at": issued_at + timedelta(minutes=5),
        "nonce": "nonce-1",
        "hmac_signature": "",
        "used_at": None,
        "result": None,
    }
    base.update(overrides)
    return sign_approval_token(ApprovalToken(**base), secret=_SECRET)


def test_approval_token_signature_verifies_when_untampered() -> None:
    """A correctly signed token verifies against its canonical payload (P4-23)."""
    token = _signed_token()
    assert verify_approval_token_signature(token, secret=_SECRET) is True


def test_approval_token_signature_rejects_target_tampering() -> None:
    """Mutating the target after signing breaks verification (P4-23)."""
    token = _signed_token()
    tampered = token.model_copy(update={"target": "container-other"})
    assert verify_approval_token_signature(tampered, secret=_SECRET) is False


def test_approval_token_signature_rejects_incident_rebinding() -> None:
    """Rebinding the token to another incident breaks verification (P4-23)."""
    token = _signed_token()
    tampered = token.model_copy(update={"incident_id": "inc-evil"})
    assert verify_approval_token_signature(tampered, secret=_SECRET) is False


def test_approval_token_signature_rejects_wrong_secret() -> None:
    """A token signed with a different secret does not verify (P4-23)."""
    token = _signed_token()
    assert verify_approval_token_signature(token, secret=_OTHER_SECRET) is False


def test_executor_allowlist_is_restart_only() -> None:
    """The executor allowlist remains a single bounded action (P4-25)."""
    assert ALLOWED_EXECUTOR_ACTIONS == frozenset({ActionType.RESTART_CONTAINER})
    forbidden = {
        ActionType.PULL_SPECIFIC_IMAGE_TAG,
        ActionType.START_VM,
        ActionType.STOP_VM,
        ActionType.MODIFY_CONFIG_WITH_BACKUP,
    }
    assert ALLOWED_EXECUTOR_ACTIONS.isdisjoint(forbidden)
