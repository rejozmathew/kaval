"""Typed credential-request contracts for the Phase 2B UAC flow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import model_validator

from kaval.models import KavalModel


class CredentialRequestMode(StrEnum):
    """How the user chose to handle a requested credential."""

    VOLATILE = "volatile"
    VAULT = "vault"
    SKIP = "skip"


class CredentialRequestStatus(StrEnum):
    """Lifecycle states for one credential request."""

    PENDING = "pending"
    AWAITING_INPUT = "awaiting_input"
    SATISFIED = "satisfied"
    SKIPPED = "skipped"
    EXPIRED = "expired"


class CredentialRequest(KavalModel):
    """A persisted request for one service credential."""

    id: str
    incident_id: str
    investigation_id: str | None
    service_id: str
    service_name: str
    credential_key: str
    credential_description: str
    credential_location: str
    reason: str
    status: CredentialRequestStatus
    selected_mode: CredentialRequestMode | None = None
    decided_by: str | None = None
    requested_at: datetime
    expires_at: datetime
    decided_at: datetime | None = None
    satisfied_at: datetime | None = None
    credential_reference: str | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        """Keep request state, timestamps, and selected modes coherent."""
        if self.expires_at <= self.requested_at:
            msg = "expires_at must be later than requested_at"
            raise ValueError(msg)

        if (self.decided_by is None) != (self.decided_at is None):
            msg = "decided_by and decided_at must be set together"
            raise ValueError(msg)

        if self.status == CredentialRequestStatus.PENDING:
            if any(
                (
                    self.selected_mode is not None,
                    self.decided_by is not None,
                    self.decided_at is not None,
                    self.satisfied_at is not None,
                    self.credential_reference is not None,
                )
            ):
                msg = "pending requests cannot include decision or credential fields"
                raise ValueError(msg)
            return self

        if self.status == CredentialRequestStatus.AWAITING_INPUT:
            if self.selected_mode not in {
                CredentialRequestMode.VOLATILE,
                CredentialRequestMode.VAULT,
            }:
                msg = "awaiting_input requests require volatile or vault mode"
                raise ValueError(msg)
            if self.decided_by is None or self.decided_at is None:
                msg = "awaiting_input requests require decision metadata"
                raise ValueError(msg)
            if self.satisfied_at is not None or self.credential_reference is not None:
                msg = "awaiting_input requests cannot include stored credential references"
                raise ValueError(msg)
            return self

        if self.status == CredentialRequestStatus.SATISFIED:
            if self.selected_mode not in {
                CredentialRequestMode.VOLATILE,
                CredentialRequestMode.VAULT,
            }:
                msg = "satisfied requests require volatile or vault mode"
                raise ValueError(msg)
            if self.decided_by is None or self.decided_at is None:
                msg = "satisfied requests require decision metadata"
                raise ValueError(msg)
            if self.satisfied_at is None or self.credential_reference is None:
                msg = "satisfied requests require satisfied_at and credential_reference"
                raise ValueError(msg)
            return self

        if self.status == CredentialRequestStatus.SKIPPED:
            if self.selected_mode != CredentialRequestMode.SKIP:
                msg = "skipped requests must record selected_mode=skip"
                raise ValueError(msg)
            if self.decided_by is None or self.decided_at is None:
                msg = "skipped requests require decision metadata"
                raise ValueError(msg)
            if self.satisfied_at is not None or self.credential_reference is not None:
                msg = "skipped requests cannot include credential references"
                raise ValueError(msg)
            return self

        if self.selected_mode == CredentialRequestMode.SKIP:
            msg = "expired requests cannot record selected_mode=skip"
            raise ValueError(msg)
        if self.satisfied_at is not None or self.credential_reference is not None:
            msg = "expired requests cannot include credential references"
            raise ValueError(msg)
        return self


class VaultConfigRecord(KavalModel):
    """Persistent vault metadata used to derive and verify the unlock key."""

    salt_b64: str
    verifier_token: str
    created_at: datetime
    updated_at: datetime


class VaultCredentialRecord(KavalModel):
    """One encrypted credential persisted in the vault."""

    reference_id: str
    request_id: str
    incident_id: str
    service_id: str
    credential_key: str
    ciphertext: str
    submitted_by: str
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None = None
    last_tested_at: datetime | None = None
    expires_at: datetime | None = None


class VaultStatus(KavalModel):
    """Runtime lock state for the credential vault."""

    initialized: bool
    unlocked: bool
    unlock_expires_at: datetime | None
    stored_credentials: int
