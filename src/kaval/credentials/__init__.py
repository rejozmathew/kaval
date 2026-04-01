"""Credential handling package."""

from __future__ import annotations

from importlib import import_module
from typing import Any

from kaval.credentials.models import (
    CredentialRequest,
    CredentialRequestMode,
    CredentialRequestStatus,
    VaultStatus,
)

__all__ = [
    "CredentialRequest",
    "CredentialRequestConflictError",
    "CredentialRequestError",
    "CredentialRequestHintError",
    "CredentialRequestManager",
    "CredentialRequestMode",
    "CredentialRequestNotFoundError",
    "CredentialRequestStatus",
    "CredentialMaterialNotFoundError",
    "CredentialMaterialService",
    "CredentialVault",
    "CredentialVaultError",
    "CredentialVaultLockedError",
    "CredentialVaultPassphraseError",
    "ParsedCredentialTelegramCallback",
    "TelegramCredentialRequestHandler",
    "VaultStatus",
    "VolatileCredentialStore",
    "build_credential_request_callback_id",
    "build_credential_request_message",
    "parse_credential_request_callback_id",
]


def __getattr__(name: str) -> Any:
    """Lazily expose submodule symbols without creating import cycles."""
    if name in {
        "CredentialRequestConflictError",
        "CredentialRequestError",
        "CredentialRequestHintError",
        "CredentialRequestManager",
        "CredentialRequestNotFoundError",
    }:
        return getattr(import_module("kaval.credentials.request_flow"), name)
    if name in {
        "CredentialMaterialNotFoundError",
        "CredentialMaterialService",
        "CredentialVault",
        "CredentialVaultError",
        "CredentialVaultLockedError",
        "CredentialVaultPassphraseError",
        "VolatileCredentialStore",
    }:
        return getattr(import_module("kaval.credentials.vault"), name)
    if name in {
        "ParsedCredentialTelegramCallback",
        "TelegramCredentialRequestHandler",
        "build_credential_request_callback_id",
        "build_credential_request_message",
        "parse_credential_request_callback_id",
    }:
        return getattr(import_module("kaval.credentials.telegram"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
