"""Persisted model settings with explicit staged/apply semantics."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from kaval.credentials.vault import CredentialVault
from kaval.investigation.cloud_model import (
    CloudEscalationPolicy,
    CloudModelConfig,
    CloudProvider,
    load_cloud_escalation_policy_from_env,
    load_cloud_model_config_from_env,
)
from kaval.investigation.local_model import (
    LocalModelConfig,
    load_local_model_config_from_env,
)
from kaval.models import KavalModel
from kaval.settings.store import (
    deep_merge,
    load_settings_document,
    normalize_mapping,
    write_settings_document,
)

type SettingsSecretSource = Literal["vault", "env", "unset"]

_LOCAL_API_KEY_REF = "vault:settings:models:local_api_key"
_CLOUD_API_KEY_REF = "vault:settings:models:cloud_api_key"
_ROOT_KEY_MODELS = "models"


class ManagedLocalModelSettings(KavalModel):
    """Persisted non-secret settings for the local model path."""

    enabled: bool = False
    provider: Literal["openai_compatible"] = "openai_compatible"
    model: str | None = None
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 30.0
    api_key_ref: str | None = None

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedLocalModelSettings:
        """Require coherent local-model settings."""
        if self.enabled and (self.model is None or not self.model.strip()):
            msg = "local model name is required when the local model is enabled"
            raise ValueError(msg)
        if not self.base_url.strip():
            msg = "local model base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "local model timeout_seconds must be positive"
            raise ValueError(msg)
        return self


class ManagedCloudModelSettings(KavalModel):
    """Persisted non-secret settings for the cloud model path."""

    enabled: bool = False
    provider: CloudProvider = "anthropic"
    model: str | None = None
    base_url: str = "https://api.anthropic.com"
    timeout_seconds: float = 45.0
    max_output_tokens: int = 1600
    api_key_ref: str | None = None

    @model_validator(mode="after")
    def validate_settings(self) -> ManagedCloudModelSettings:
        """Require coherent cloud-model settings."""
        if self.enabled and (self.model is None or not self.model.strip()):
            msg = "cloud model name is required when the cloud model is enabled"
            raise ValueError(msg)
        if not self.base_url.strip():
            msg = "cloud model base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "cloud model timeout_seconds must be positive"
            raise ValueError(msg)
        if self.max_output_tokens <= 0:
            msg = "cloud model max_output_tokens must be positive"
            raise ValueError(msg)
        return self


class ManagedCloudEscalationSettings(KavalModel):
    """Persisted escalation thresholds and bounded cloud cost controls."""

    finding_count_gt: int = Field(default=3, ge=0)
    local_confidence_lt: float = Field(default=0.6, ge=0.0, le=1.0)
    escalate_on_multiple_domains: bool = True
    escalate_on_changelog_research: bool = True
    escalate_on_user_request: bool = False
    max_cloud_calls_per_day: int = Field(default=20, ge=1)
    max_cloud_calls_per_incident: int = Field(default=3, ge=1)


class ManagedModelSettings(KavalModel):
    """Persisted model-settings document stored beneath ``models`` in YAML."""

    local: ManagedLocalModelSettings = Field(default_factory=ManagedLocalModelSettings)
    cloud: ManagedCloudModelSettings = Field(default_factory=ManagedCloudModelSettings)
    escalation: ManagedCloudEscalationSettings = Field(
        default_factory=ManagedCloudEscalationSettings
    )


def default_settings_path() -> Path:
    """Return the canonical persisted settings path."""
    return Path("/data/kaval.yaml")


@dataclass(slots=True)
class ModelSettingsService:
    """Manage staged and active model settings for the current process."""

    settings_path: Path
    environment: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    _active: ManagedModelSettings = field(init=False, repr=False)
    _staged: ManagedModelSettings = field(init=False, repr=False)
    _root_document: dict[str, object] = field(init=False, repr=False, default_factory=dict)
    _load_error: str | None = field(init=False, default=None)
    _last_applied_at: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        """Load bootstrap defaults and any persisted overrides."""
        bootstrap, bootstrap_error = _build_bootstrap_settings(self.environment)
        root_document, root_error = load_settings_document(self.settings_path)
        persisted, persisted_error = _load_persisted_settings(root_document)
        if persisted is None:
            resolved = bootstrap
        else:
            merged_payload = deep_merge(
                bootstrap.model_dump(mode="json"),
                persisted.model_dump(mode="json"),
            )
            resolved = ManagedModelSettings.model_validate(merged_payload)
        self._active = resolved.model_copy(deep=True)
        self._staged = resolved.model_copy(deep=True)
        self._root_document = root_document
        load_errors = [root_error, persisted_error, bootstrap_error]
        self._load_error = "; ".join(error for error in load_errors if error) or None
        self._last_applied_at = datetime.now(tz=UTC)

    @property
    def load_error(self) -> str | None:
        """Return the most recent persisted-settings load error."""
        return self._load_error

    @property
    def last_applied_at(self) -> datetime | None:
        """Return when the active snapshot was last applied in-process."""
        return self._last_applied_at

    def staged_snapshot(self) -> ManagedModelSettings:
        """Return a defensive copy of the staged settings snapshot."""
        return self._staged.model_copy(deep=True)

    def active_snapshot(self) -> ManagedModelSettings:
        """Return a defensive copy of the active settings snapshot."""
        return self._active.model_copy(deep=True)

    def apply_required(self) -> bool:
        """Return whether staged settings differ from the current active snapshot."""
        return self._staged != self._active

    def apply(self, *, now: datetime | None = None) -> ManagedModelSettings:
        """Promote the staged snapshot into the active in-process runtime."""
        effective_now = now or datetime.now(tz=UTC)
        self._active = self._staged.model_copy(deep=True)
        self._last_applied_at = effective_now
        return self.active_snapshot()

    def update_staged(
        self,
        *,
        local: ManagedLocalModelSettings,
        local_api_key: str | None,
        clear_local_api_key: bool,
        cloud: ManagedCloudModelSettings,
        cloud_api_key: str | None,
        clear_cloud_api_key: bool,
        escalation: ManagedCloudEscalationSettings,
        vault: CredentialVault,
        submitted_by: str = "admin_ui",
        now: datetime | None = None,
    ) -> ManagedModelSettings:
        """Validate, persist, and stage one complete model-settings snapshot."""
        effective_now = now or datetime.now(tz=UTC)
        local_api_key_ref = self._next_secret_reference(
            current_ref=self._staged.local.api_key_ref,
            clear_secret=clear_local_api_key,
            secret_value=local_api_key,
            fallback_ref=_LOCAL_API_KEY_REF,
            service_id="settings.models.local",
            credential_key="api_key",
            vault=vault,
            submitted_by=submitted_by,
            now=effective_now,
        )
        cloud_api_key_ref = self._next_secret_reference(
            current_ref=self._staged.cloud.api_key_ref,
            clear_secret=clear_cloud_api_key,
            secret_value=cloud_api_key,
            fallback_ref=_CLOUD_API_KEY_REF,
            service_id="settings.models.cloud",
            credential_key="api_key",
            vault=vault,
            submitted_by=submitted_by,
            now=effective_now,
        )

        next_snapshot = ManagedModelSettings(
            local=local.model_copy(update={"api_key_ref": local_api_key_ref}),
            cloud=cloud.model_copy(update={"api_key_ref": cloud_api_key_ref}),
            escalation=escalation,
        )
        self._validate_secret_requirements(next_snapshot)

        latest_root_document, latest_root_error = load_settings_document(self.settings_path)
        root_document = (
            latest_root_document
            if latest_root_error is None
            else dict(self._root_document)
        )
        root_document[_ROOT_KEY_MODELS] = next_snapshot.model_dump(
            mode="json",
            exclude_none=True,
        )
        write_settings_document(self.settings_path, root_document)
        self._root_document = root_document
        self._staged = next_snapshot
        self._load_error = None
        return self.staged_snapshot()

    def active_local_configured(self) -> bool:
        """Return whether the active local model path is configured."""
        return self._snapshot_local_configured(self._active)

    def active_cloud_configured(self) -> bool:
        """Return whether the active cloud model path is configured."""
        return self._snapshot_cloud_configured(self._active)

    def local_api_key_source(self, *, scope: Literal["active", "staged"]) -> SettingsSecretSource:
        """Return the configured local API-key source for one snapshot."""
        snapshot = self._select_snapshot(scope)
        if snapshot.local.api_key_ref is not None:
            return "vault"
        if _resolve_local_env_api_key(self.environment) is not None:
            return "env"
        return "unset"

    def cloud_api_key_source(self, *, scope: Literal["active", "staged"]) -> SettingsSecretSource:
        """Return the configured cloud API-key source for one snapshot."""
        snapshot = self._select_snapshot(scope)
        if snapshot.cloud.api_key_ref is not None:
            return "vault"
        if (
            _resolve_cloud_env_api_key(
                self.environment,
                provider=snapshot.cloud.provider,
            )
            is not None
        ):
            return "env"
        return "unset"

    def resolve_local_model_config(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
        vault: CredentialVault,
    ) -> LocalModelConfig | None:
        """Resolve one runtime local-model config from the selected snapshot."""
        snapshot = self._select_snapshot(scope)
        if not self._snapshot_local_configured(snapshot):
            return None
        secret = None
        if snapshot.local.api_key_ref is not None:
            secret = vault.get_secret(snapshot.local.api_key_ref)
        else:
            secret = _resolve_local_env_api_key(self.environment)
        return LocalModelConfig(
            base_url=snapshot.local.base_url,
            model=str(snapshot.local.model),
            api_key=secret,
            timeout_seconds=snapshot.local.timeout_seconds,
        )

    def resolve_cloud_model_config(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
        vault: CredentialVault,
    ) -> CloudModelConfig | None:
        """Resolve one runtime cloud-model config from the selected snapshot."""
        snapshot = self._select_snapshot(scope)
        if not self._snapshot_cloud_configured(snapshot):
            return None
        api_key: str | None
        if snapshot.cloud.api_key_ref is not None:
            api_key = vault.get_secret(snapshot.cloud.api_key_ref)
        else:
            api_key = _resolve_cloud_env_api_key(
                self.environment,
                provider=snapshot.cloud.provider,
            )
        if api_key is None:
            msg = "cloud model api key is required when the cloud model is enabled"
            raise ValueError(msg)
        return CloudModelConfig(
            provider=snapshot.cloud.provider,
            model=str(snapshot.cloud.model),
            api_key=api_key,
            base_url=snapshot.cloud.base_url,
            timeout_seconds=snapshot.cloud.timeout_seconds,
            max_output_tokens=snapshot.cloud.max_output_tokens,
        )

    def resolve_cloud_escalation_policy(
        self,
        *,
        scope: Literal["active", "staged"] = "active",
    ) -> CloudEscalationPolicy:
        """Resolve the cloud-escalation policy for the selected snapshot."""
        snapshot = self._select_snapshot(scope)
        return CloudEscalationPolicy(**snapshot.escalation.model_dump(mode="json"))

    def _select_snapshot(self, scope: Literal["active", "staged"]) -> ManagedModelSettings:
        """Return one internal snapshot by scope."""
        return self._active if scope == "active" else self._staged

    def _snapshot_local_configured(self, snapshot: ManagedModelSettings) -> bool:
        """Return whether one snapshot has a usable local-model configuration."""
        return bool(snapshot.local.enabled and snapshot.local.model)

    def _snapshot_cloud_configured(self, snapshot: ManagedModelSettings) -> bool:
        """Return whether one snapshot has a usable cloud-model configuration."""
        return bool(
            snapshot.cloud.enabled
            and snapshot.cloud.model
            and (
                snapshot.cloud.api_key_ref is not None
                or _resolve_cloud_env_api_key(
                    self.environment,
                    provider=snapshot.cloud.provider,
                )
                is not None
            )
        )

    def _validate_secret_requirements(self, snapshot: ManagedModelSettings) -> None:
        """Ensure enabled providers have either a vault reference or env fallback."""
        if snapshot.cloud.enabled and (
            snapshot.cloud.api_key_ref is None
            and _resolve_cloud_env_api_key(
                self.environment,
                provider=snapshot.cloud.provider,
            )
            is None
        ):
            msg = "cloud model api key must come from the vault or environment bootstrap"
            raise ValueError(msg)

    def _next_secret_reference(
        self,
        *,
        current_ref: str | None,
        clear_secret: bool,
        secret_value: str | None,
        fallback_ref: str,
        service_id: str,
        credential_key: str,
        vault: CredentialVault,
        submitted_by: str,
        now: datetime,
    ) -> str | None:
        """Return the next stable secret reference after one staged update."""
        if clear_secret:
            if secret_value is not None and secret_value.strip():
                msg = "cannot clear and replace the same managed secret in one request"
                raise ValueError(msg)
            if current_ref is not None:
                vault.delete_secret(current_ref)
            return None

        if secret_value is None or not secret_value.strip():
            return current_ref

        next_ref = current_ref or fallback_ref
        vault.upsert_managed_secret(
            reference_id=next_ref,
            secret_value=secret_value.strip(),
            service_id=service_id,
            credential_key=credential_key,
            submitted_by=submitted_by,
            now=now,
        )
        return next_ref


def _build_bootstrap_settings(
    environment: Mapping[str, str],
) -> tuple[ManagedModelSettings, str | None]:
    """Build the env-bootstrap snapshot that seeds staged and active settings."""
    errors: list[str] = []
    local_settings = ManagedLocalModelSettings()
    cloud_settings = ManagedCloudModelSettings()
    escalation_settings = ManagedCloudEscalationSettings()

    try:
        local_config = load_local_model_config_from_env(environment)
        if local_config is not None:
            local_settings = ManagedLocalModelSettings(
                enabled=True,
                model=local_config.model,
                base_url=local_config.base_url,
                timeout_seconds=local_config.timeout_seconds,
            )
    except ValueError as exc:
        errors.append(str(exc))

    try:
        cloud_config = load_cloud_model_config_from_env(environment)
        if cloud_config is not None:
            cloud_settings = ManagedCloudModelSettings(
                enabled=True,
                provider=cloud_config.provider,
                model=cloud_config.model,
                base_url=cloud_config.base_url,
                timeout_seconds=cloud_config.timeout_seconds,
                max_output_tokens=cloud_config.max_output_tokens,
            )
    except ValueError as exc:
        errors.append(str(exc))

    try:
        policy = load_cloud_escalation_policy_from_env(environment)
        escalation_settings = ManagedCloudEscalationSettings(
            finding_count_gt=policy.finding_count_gt,
            local_confidence_lt=policy.local_confidence_lt,
            escalate_on_multiple_domains=policy.escalate_on_multiple_domains,
            escalate_on_changelog_research=policy.escalate_on_changelog_research,
            escalate_on_user_request=policy.escalate_on_user_request,
            max_cloud_calls_per_day=policy.max_cloud_calls_per_day,
            max_cloud_calls_per_incident=policy.max_cloud_calls_per_incident,
        )
    except ValueError as exc:
        errors.append(str(exc))

    load_error = None if not errors else "; ".join(errors)
    return (
        ManagedModelSettings(
            local=local_settings,
            cloud=cloud_settings,
            escalation=escalation_settings,
        ),
        load_error,
    )


def _load_persisted_settings(
    root_document: Mapping[str, object],
) -> tuple[ManagedModelSettings | None, str | None]:
    """Load any persisted settings document and validate the model-settings section."""
    raw_models = root_document.get(_ROOT_KEY_MODELS)
    if raw_models is None:
        return None, None
    if not isinstance(raw_models, Mapping):
        return None, "Persisted models settings must be a mapping."
    try:
        return ManagedModelSettings.model_validate(normalize_mapping(raw_models)), None
    except ValueError as exc:
        return None, f"Persisted models settings were invalid: {exc}"


def _resolve_local_env_api_key(environment: Mapping[str, str]) -> str | None:
    """Resolve the bootstrap local-model API key from the environment."""
    configured = environment.get("KAVAL_LOCAL_MODEL_API_KEY", "").strip()
    if configured:
        return configured
    fallback = environment.get("OLLAMA_API_KEY", "").strip()
    return fallback or None


def _resolve_cloud_env_api_key(
    environment: Mapping[str, str],
    *,
    provider: CloudProvider,
) -> str | None:
    """Resolve the bootstrap cloud-model API key from the environment."""
    configured_env = environment.get("KAVAL_CLOUD_MODEL_API_KEY_ENV", "").strip()
    if configured_env:
        configured = environment.get(configured_env, "").strip()
        return configured or None

    configured_key = environment.get("KAVAL_CLOUD_MODEL_API_KEY", "").strip()
    if configured_key:
        return configured_key

    default_key = (
        environment.get("ANTHROPIC_API_KEY", "").strip()
        if provider == "anthropic"
        else environment.get("OPENAI_API_KEY", "").strip()
    )
    return default_key or None
