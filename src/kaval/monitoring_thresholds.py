"""Shared defaults and validation helpers for bounded monitoring thresholds."""

from __future__ import annotations

TLS_WARNING_DAYS_DEFAULT = 7
RESTART_DELTA_THRESHOLD_DEFAULT = 3
PROBE_TIMEOUT_SECONDS_DEFAULT = 5.0


def monitoring_threshold_defaults(
    check_id: str,
) -> tuple[int | None, int | None, float | None]:
    """Return the built-in threshold defaults for one supported monitoring check."""
    if check_id == "tls_cert":
        return TLS_WARNING_DAYS_DEFAULT, None, None
    if check_id == "restart_storm":
        return None, RESTART_DELTA_THRESHOLD_DEFAULT, None
    if check_id == "endpoint_probe":
        return None, None, PROBE_TIMEOUT_SECONDS_DEFAULT
    return None, None, None


def monitoring_threshold_fields_present(
    *,
    tls_warning_days: int | None,
    restart_delta_threshold: int | None,
    probe_timeout_seconds: float | None,
) -> bool:
    """Return whether any threshold field is explicitly set."""
    return any(
        value is not None
        for value in (
            tls_warning_days,
            restart_delta_threshold,
            probe_timeout_seconds,
        )
    )


def validate_monitoring_threshold_fields(
    check_id: str,
    *,
    tls_warning_days: int | None,
    restart_delta_threshold: int | None,
    probe_timeout_seconds: float | None,
) -> None:
    """Reject threshold fields that do not apply to the selected check."""
    if check_id == "tls_cert":
        if restart_delta_threshold is not None or probe_timeout_seconds is not None:
            raise ValueError("tls_cert thresholds only support tls_warning_days")
        return
    if check_id == "restart_storm":
        if tls_warning_days is not None or probe_timeout_seconds is not None:
            raise ValueError(
                "restart_storm thresholds only support restart_delta_threshold"
            )
        return
    if check_id == "endpoint_probe":
        if tls_warning_days is not None or restart_delta_threshold is not None:
            raise ValueError("endpoint_probe thresholds only support probe_timeout_seconds")
        return
    if monitoring_threshold_fields_present(
        tls_warning_days=tls_warning_days,
        restart_delta_threshold=restart_delta_threshold,
        probe_timeout_seconds=probe_timeout_seconds,
    ):
        raise ValueError(f"{check_id} does not support threshold overrides")


def monitoring_threshold_summary(
    check_id: str,
    *,
    tls_warning_days: int | None,
    restart_delta_threshold: int | None,
    probe_timeout_seconds: float | None,
) -> str | None:
    """Return a compact audit-friendly threshold summary for one check."""
    if check_id == "tls_cert" and tls_warning_days is not None:
        return f"warn_days={tls_warning_days}"
    if check_id == "restart_storm" and restart_delta_threshold is not None:
        return f"restart_delta={restart_delta_threshold}"
    if check_id == "endpoint_probe" and probe_timeout_seconds is not None:
        return f"probe_timeout={probe_timeout_seconds:g}"
    return None
