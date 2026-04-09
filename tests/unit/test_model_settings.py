"""Unit tests for persisted model settings."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from kaval.credentials import CredentialVault
from kaval.database import KavalDatabase
from kaval.settings.model_config import (
    ManagedCloudEscalationSettings,
    ManagedCloudModelSettings,
    ManagedLocalModelSettings,
    ModelSettingsService,
)


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for model-settings tests."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


def test_model_settings_service_persists_staged_updates_and_requires_apply(
    tmp_path: Path,
) -> None:
    """The model settings service should stage, persist, and later apply updates."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()

    vault = CredentialVault(database_path=database_path, auto_lock_minutes=5)
    vault.unlock("correct horse battery staple", now=ts(10, 0))

    service = ModelSettingsService(
        settings_path=settings_path,
        environment={
            "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
            "KAVAL_CLOUD_MODEL_NAME": "claude-sonnet-4-20250514",
            "ANTHROPIC_API_KEY": "env-cloud-secret",
        },
    )

    assert service.active_snapshot().local.model == "qwen3:8b"
    assert service.active_snapshot().cloud.model == "claude-sonnet-4-20250514"
    assert service.apply_required() is False

    service.update_staged(
        local=ManagedLocalModelSettings(
            enabled=True,
            model="qwen3:14b",
            base_url="http://localhost:11434",
            timeout_seconds=12.0,
        ),
        local_api_key="local-vault-secret",
        clear_local_api_key=False,
        cloud=ManagedCloudModelSettings(
            enabled=True,
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            base_url="https://api.anthropic.com",
            timeout_seconds=25.0,
            max_output_tokens=900,
        ),
        cloud_api_key=None,
        clear_cloud_api_key=False,
        escalation=ManagedCloudEscalationSettings(
            finding_count_gt=4,
            local_confidence_lt=0.55,
            escalate_on_multiple_domains=True,
            escalate_on_changelog_research=True,
            escalate_on_user_request=True,
            max_cloud_calls_per_day=15,
            max_cloud_calls_per_incident=2,
        ),
        vault=vault,
        now=ts(10, 1),
    )

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "local-vault-secret" not in persisted_text
    assert "env-cloud-secret" not in persisted_text
    assert "api_key_ref: vault:settings:models:local_api_key" in persisted_text
    assert service.apply_required() is True
    assert service.active_snapshot().local.model == "qwen3:8b"
    assert service.staged_snapshot().local.model == "qwen3:14b"
    vault.unlock("correct horse battery staple")
    assert service.resolve_local_model_config(scope="staged", vault=vault) is not None
    assert (
        service.resolve_local_model_config(scope="staged", vault=vault).api_key
        == "local-vault-secret"
    )
    assert service.resolve_cloud_model_config(scope="staged", vault=vault) is not None
    assert (
        service.resolve_cloud_model_config(scope="staged", vault=vault).api_key
        == "env-cloud-secret"
    )

    service.apply(now=ts(10, 2))

    assert service.apply_required() is False
    assert service.active_snapshot().local.model == "qwen3:14b"
    assert service.last_applied_at == ts(10, 2)

    reloaded_service = ModelSettingsService(
        settings_path=settings_path,
        environment={
            "KAVAL_LOCAL_MODEL_NAME": "qwen3:8b",
            "KAVAL_CLOUD_MODEL_NAME": "claude-sonnet-4-20250514",
            "ANTHROPIC_API_KEY": "env-cloud-secret",
        },
    )
    assert reloaded_service.active_snapshot().local.model == "qwen3:14b"
    assert reloaded_service.active_snapshot().cloud.max_output_tokens == 900
    assert reloaded_service.active_snapshot().escalation.max_cloud_calls_per_day == 15


def test_model_settings_service_preserves_existing_notification_sections(
    tmp_path: Path,
) -> None:
    """Saving model settings should not clobber unrelated notification config sections."""
    database_path = tmp_path / "kaval.db"
    settings_path = tmp_path / "kaval.yaml"
    database = KavalDatabase(path=database_path)
    database.bootstrap()
    database.close()
    settings_path.write_text(
        "notifications:\n  preserved: true\n",
        encoding="utf-8",
    )

    service = ModelSettingsService(settings_path=settings_path, environment={})

    service.update_staged(
        local=ManagedLocalModelSettings(
            enabled=False,
            base_url="http://localhost:11434",
            timeout_seconds=12.0,
        ),
        local_api_key=None,
        clear_local_api_key=False,
        cloud=ManagedCloudModelSettings(
            enabled=False,
            provider="anthropic",
            base_url="https://api.anthropic.com",
            timeout_seconds=25.0,
            max_output_tokens=900,
        ),
        cloud_api_key=None,
        clear_cloud_api_key=False,
        escalation=ManagedCloudEscalationSettings(),
        vault=CredentialVault(database_path=database_path, auto_lock_minutes=5),
        now=ts(11, 0),
    )

    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "notifications:" in persisted_text
    assert "preserved: true" in persisted_text
