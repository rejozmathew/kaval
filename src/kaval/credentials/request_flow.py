"""Credential-request state management for the Phase 2B UAC flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from kaval.credentials.models import (
    CredentialRequest,
    CredentialRequestMode,
    CredentialRequestStatus,
)
from kaval.database import KavalDatabase
from kaval.discovery.descriptors import LoadedServiceDescriptor, load_service_descriptors
from kaval.models import Service


class CredentialRequestError(RuntimeError):
    """Base error raised by the credential-request manager."""


class CredentialRequestNotFoundError(CredentialRequestError):
    """Raised when the requested credential-request record does not exist."""


class CredentialRequestHintError(CredentialRequestError):
    """Raised when the requested service has no matching credential hint."""


class CredentialRequestConflictError(CredentialRequestError):
    """Raised when a request transition is invalid for its current state."""


def default_services_dir() -> Path:
    """Return the shipped service-descriptor directory."""
    return Path(__file__).resolve().parents[3] / "services"


@dataclass(slots=True)
class CredentialRequestManager:
    """Create, list, and advance credential requests without storing secrets."""

    database: KavalDatabase
    descriptors: tuple[LoadedServiceDescriptor, ...] = ()
    default_request_ttl_seconds: int = 1800
    _descriptors_by_id: dict[str, LoadedServiceDescriptor] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Load default descriptors when the caller does not provide them."""
        if self.default_request_ttl_seconds <= 0:
            msg = "default_request_ttl_seconds must be positive"
            raise ValueError(msg)
        if not self.descriptors:
            self.descriptors = tuple(load_service_descriptors([default_services_dir()]))
        self._descriptors_by_id = {
            f"{descriptor.path.parent.name}/{descriptor.path.stem}": descriptor
            for descriptor in self.descriptors
        }

    def create_request(
        self,
        *,
        incident_id: str,
        service_id: str,
        credential_key: str,
        reason: str,
        investigation_id: str | None = None,
        now: datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> CredentialRequest:
        """Persist a new pending request using descriptor-backed credential hints."""
        service = self.database.get_service(service_id)
        if service is None:
            msg = f"service not found: {service_id}"
            raise CredentialRequestNotFoundError(msg)

        credential_description, credential_location = self._credential_hint(
            service=service,
            credential_key=credential_key,
        )
        requested_at = now or datetime.now(tz=UTC)
        effective_ttl_seconds = (
            self.default_request_ttl_seconds if ttl_seconds is None else ttl_seconds
        )
        if effective_ttl_seconds <= 0:
            msg = "ttl_seconds must be positive"
            raise ValueError(msg)

        credential_request = CredentialRequest(
            id=f"credreq-{uuid4()}",
            incident_id=incident_id,
            investigation_id=investigation_id,
            service_id=service.id,
            service_name=service.name,
            credential_key=credential_key,
            credential_description=credential_description,
            credential_location=credential_location,
            reason=reason,
            status=CredentialRequestStatus.PENDING,
            requested_at=requested_at,
            expires_at=requested_at + timedelta(seconds=effective_ttl_seconds),
        )
        self.database.upsert_credential_request(credential_request)
        return credential_request

    def get_request(
        self,
        request_id: str,
        *,
        now: datetime | None = None,
    ) -> CredentialRequest | None:
        """Fetch one request and apply expiry if needed."""
        credential_request = self.database.get_credential_request(request_id)
        if credential_request is None:
            return None
        return self._refresh_expiry(credential_request, now=now)

    def list_requests(self, *, now: datetime | None = None) -> list[CredentialRequest]:
        """List all persisted credential requests with expiry applied."""
        effective_now = now or datetime.now(tz=UTC)
        return [
            self._refresh_expiry(credential_request, now=effective_now)
            for credential_request in self.database.list_credential_requests()
        ]

    def resolve_choice(
        self,
        *,
        request_id: str,
        mode: CredentialRequestMode,
        decided_by: str,
        now: datetime | None = None,
    ) -> CredentialRequest:
        """Record the user's volatile/vault/skip decision for one request."""
        effective_now = now or datetime.now(tz=UTC)
        credential_request = self.get_request(request_id, now=effective_now)
        if credential_request is None:
            msg = f"credential request not found: {request_id}"
            raise CredentialRequestNotFoundError(msg)
        if credential_request.status == CredentialRequestStatus.EXPIRED:
            msg = "credential request has expired"
            raise CredentialRequestConflictError(msg)
        if credential_request.status in {
            CredentialRequestStatus.SKIPPED,
            CredentialRequestStatus.SATISFIED,
        }:
            msg = "credential request is already complete"
            raise CredentialRequestConflictError(msg)
        if credential_request.status == CredentialRequestStatus.AWAITING_INPUT:
            msg = "credential request already has a selected mode"
            raise CredentialRequestConflictError(msg)

        updated_request = credential_request.model_copy(
            update={
                "status": (
                    CredentialRequestStatus.SKIPPED
                    if mode == CredentialRequestMode.SKIP
                    else CredentialRequestStatus.AWAITING_INPUT
                ),
                "selected_mode": mode,
                "decided_by": decided_by,
                "decided_at": effective_now,
            }
        )
        self.database.upsert_credential_request(updated_request)
        return updated_request

    def mark_satisfied(
        self,
        *,
        request_id: str,
        credential_reference: str,
        now: datetime | None = None,
    ) -> CredentialRequest:
        """Mark an awaiting-input credential request as satisfied."""
        effective_now = now or datetime.now(tz=UTC)
        credential_request = self.get_request(request_id, now=effective_now)
        if credential_request is None:
            msg = f"credential request not found: {request_id}"
            raise CredentialRequestNotFoundError(msg)
        if credential_request.status != CredentialRequestStatus.AWAITING_INPUT:
            msg = "credential request is not ready to accept secret material"
            raise CredentialRequestConflictError(msg)
        if not credential_reference:
            msg = "credential_reference must not be empty"
            raise ValueError(msg)

        updated_request = credential_request.model_copy(
            update={
                "status": CredentialRequestStatus.SATISFIED,
                "satisfied_at": effective_now,
                "credential_reference": credential_reference,
            }
        )
        self.database.upsert_credential_request(updated_request)
        return updated_request

    def _refresh_expiry(
        self,
        credential_request: CredentialRequest,
        *,
        now: datetime | None,
    ) -> CredentialRequest:
        """Convert expired pending/input-waiting requests into explicit expired state."""
        effective_now = now or datetime.now(tz=UTC)
        if credential_request.status not in {
            CredentialRequestStatus.PENDING,
            CredentialRequestStatus.AWAITING_INPUT,
        }:
            return credential_request
        if effective_now < credential_request.expires_at:
            return credential_request

        expired_request = credential_request.model_copy(
            update={
                "status": CredentialRequestStatus.EXPIRED,
                "satisfied_at": None,
                "credential_reference": None,
            }
        )
        self.database.upsert_credential_request(expired_request)
        return expired_request

    def _credential_hint(self, *, service: Service, credential_key: str) -> tuple[str, str]:
        """Resolve one descriptor-backed credential hint for the target service."""
        if service.descriptor_id is None:
            msg = f"service {service.id} does not have a descriptor-backed credential hint"
            raise CredentialRequestHintError(msg)
        descriptor = self._descriptors_by_id.get(service.descriptor_id)
        if descriptor is None:
            msg = f"descriptor not found for service {service.id}: {service.descriptor_id}"
            raise CredentialRequestHintError(msg)
        hint = descriptor.descriptor.credential_hints.get(credential_key)
        if hint is None:
            msg = (
                f"credential hint {credential_key!r} is not defined for service "
                f"{service.id}"
            )
            raise CredentialRequestHintError(msg)
        return hint.description, hint.location
