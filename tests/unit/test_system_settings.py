"""Unit tests for persisted system settings."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.settings.system_config import SystemSettingsService


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for system-settings tests."""
    return datetime(2026, 4, 8, hour, minute, tzinfo=UTC)


def test_system_settings_service_persists_staged_log_level_and_requires_apply(
    tmp_path: Path,
) -> None:
    """System settings should stage, persist, and later apply log-level changes."""
    settings_path = tmp_path / "kaval.yaml"
    settings_path.write_text("models:\n  local:\n    enabled: false\n", encoding="utf-8")

    service = SystemSettingsService(
        settings_path=settings_path,
        environment={"KAVAL_CORE_LOG_LEVEL": "warning"},
    )

    assert service.active_snapshot().log_level == "warning"
    assert service.apply_required() is False

    staged = service.update_staged(
        log_level="debug",
        audit_detail_retention_days=120,
        audit_summary_retention_days=400,
    )

    assert staged.log_level == "debug"
    assert staged.audit_detail_retention_days == 120
    assert staged.audit_summary_retention_days == 400
    assert service.apply_required() is True
    persisted_text = settings_path.read_text(encoding="utf-8")
    assert "models:" in persisted_text
    assert "system:" in persisted_text
    assert "log_level: debug" in persisted_text
    assert "audit_detail_retention_days: 120" in persisted_text
    assert "audit_summary_retention_days: 400" in persisted_text

    applied = service.apply(now=ts(11, 0))

    assert applied.log_level == "debug"
    assert applied.audit_detail_retention_days == 120
    assert applied.audit_summary_retention_days == 400
    assert service.apply_required() is False
    assert service.last_applied_at == ts(11, 0)

    reloaded_service = SystemSettingsService(
        settings_path=settings_path,
        environment={"KAVAL_CORE_LOG_LEVEL": "warning"},
    )
    assert reloaded_service.active_snapshot().log_level == "debug"
    assert reloaded_service.active_snapshot().audit_detail_retention_days == 120
    assert reloaded_service.active_snapshot().audit_summary_retention_days == 400


def test_system_settings_service_rejects_summary_retention_shorter_than_detail(
    tmp_path: Path,
) -> None:
    """Staged audit summary retention cannot be shorter than detailed retention."""
    service = SystemSettingsService(
        settings_path=tmp_path / "kaval.yaml",
        environment={},
    )

    with pytest.raises(
        ValueError,
        match=(
            "audit_summary_retention_days must be greater than or equal to "
            "audit_detail_retention_days"
        ),
    ):
        service.update_staged(
            log_level="info",
            audit_detail_retention_days=90,
            audit_summary_retention_days=30,
        )
