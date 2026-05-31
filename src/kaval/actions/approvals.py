"""Deterministic approval-token signing and verification helpers."""

from __future__ import annotations

import hashlib
import hmac
import os

from kaval.models import ApprovalToken

APPROVAL_HMAC_SECRET_ENV = "KAVAL_APPROVAL_HMAC_SECRET"
KNOWN_BAD_APPROVAL_HMAC_SECRET = "local-dev-approval-secret"
MIN_APPROVAL_HMAC_SECRET_BYTES = 32


def _validate_approval_hmac_secret(secret: str) -> str:
    """Return a strong approval-token signing secret or raise a clear error."""
    if (
        secret == KNOWN_BAD_APPROVAL_HMAC_SECRET
        or len(secret.encode("utf-8")) < MIN_APPROVAL_HMAC_SECRET_BYTES
    ):
        msg = (
            f"{APPROVAL_HMAC_SECRET_ENV} must be set to a strong random secret "
            f"of at least {MIN_APPROVAL_HMAC_SECRET_BYTES} bytes and must not use "
            "the known-bad default; generate one with `openssl rand -hex 32`."
        )
        raise RuntimeError(msg)
    return secret


def get_approval_hmac_secret(*, explicit_secret: str | None = None) -> str:
    """Return the configured approval-token signing secret."""
    if explicit_secret is not None:
        return _validate_approval_hmac_secret(explicit_secret)
    secret = os.environ.get(APPROVAL_HMAC_SECRET_ENV)
    if secret:
        return _validate_approval_hmac_secret(secret)
    msg = (
        f"{APPROVAL_HMAC_SECRET_ENV} is required for approval-token validation; "
        "set a strong random value generated with `openssl rand -hex 32`."
    )
    raise RuntimeError(msg)


def approval_token_signature_payload(token: ApprovalToken) -> bytes:
    """Return the canonical byte payload used for ApprovalToken HMAC signing."""
    canonical_payload = "\n".join(
        [
            token.token_id,
            token.incident_id,
            token.action.value,
            token.target,
            token.approved_by,
            token.issued_at.isoformat(),
            token.expires_at.isoformat(),
            token.nonce,
        ]
    )
    return canonical_payload.encode("utf-8")


def compute_approval_token_signature(
    token: ApprovalToken,
    *,
    secret: str | None = None,
) -> str:
    """Compute the deterministic HMAC-SHA256 signature for an approval token."""
    effective_secret = get_approval_hmac_secret(explicit_secret=secret)
    digest = hmac.new(
        effective_secret.encode("utf-8"),
        approval_token_signature_payload(token),
        hashlib.sha256,
    )
    return digest.hexdigest()


def sign_approval_token(
    token: ApprovalToken,
    *,
    secret: str | None = None,
) -> ApprovalToken:
    """Return a copy of an approval token with its HMAC signature populated."""
    return token.model_copy(
        update={
            "hmac_signature": compute_approval_token_signature(
                token,
                secret=secret,
            )
        }
    )


def verify_approval_token_signature(
    token: ApprovalToken,
    *,
    secret: str | None = None,
) -> bool:
    """Return whether the approval token signature matches the canonical payload."""
    expected_signature = compute_approval_token_signature(token, secret=secret)
    return hmac.compare_digest(token.hmac_signature, expected_signature)
