"""Opt-in self-health notification delivery for Kaval capability issues."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from kaval.models import (
    KavalModel,
    NotificationPayload,
    NotificationSourceType,
    Severity,
)
from kaval.notifications.bus import NotificationDeliveryResult, NotificationDeliveryStatus
from kaval.notifications.grouped import NotificationSender
from kaval.runtime.capability_health import CapabilityHealthStatus
from kaval.runtime.capability_runtime import CapabilityHealthReport, CapabilityLayerReport


class SelfHealthNotificationStatus(StrEnum):
    """Outcomes of attempting to notify on one capability-health issue."""

    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class SelfHealthNotificationPolicy(KavalModel):
    """Minimal Phase 3B policy for capability-health notifications."""

    critical_enabled: bool = True
    degraded_enabled: bool = False

    def enabled_for(self, severity: Severity) -> bool:
        """Return whether the policy allows notifications for this severity."""
        if severity == Severity.CRITICAL:
            return self.critical_enabled
        return self.degraded_enabled


class SelfHealthNotificationIssue(KavalModel):
    """One capability-health problem that can produce a notification."""

    layer: str
    status: CapabilityHealthStatus
    severity: Severity
    title: str
    summary: str
    detail: str
    user_impact: str
    guidance: str

    def signature(self) -> str:
        """Return the dedup signature for this specific issue state."""
        return f"{self.layer}:{self.status.value}:{self.summary}:{self.detail}"


class SelfHealthNotificationResult(KavalModel):
    """The outcome of evaluating and optionally sending one self-health issue."""

    status: SelfHealthNotificationStatus
    issue: SelfHealthNotificationIssue
    payload: NotificationPayload | None = None
    delivery: NotificationDeliveryResult | None = None
    detail: str


@dataclass(slots=True)
class SelfHealthNotificationDispatcher:
    """Send opt-in self-health alerts without mixing them with service incidents."""

    sender: NotificationSender
    policy: SelfHealthNotificationPolicy = field(default_factory=SelfHealthNotificationPolicy)
    _last_sent_signatures: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def dispatch_report(
        self,
        report: CapabilityHealthReport,
        *,
        now: datetime | None = None,
        global_maintenance_active: bool = False,
    ) -> list[SelfHealthNotificationResult]:
        """Evaluate one capability-health report and send any newly eligible alerts."""
        effective_now = now or datetime.now(tz=UTC)
        issues = collect_self_health_issues(report)
        active_signatures = {issue.layer: issue.signature() for issue in issues}
        for layer in list(self._last_sent_signatures):
            if layer not in active_signatures:
                del self._last_sent_signatures[layer]

        results: list[SelfHealthNotificationResult] = []
        for issue in issues:
            if global_maintenance_active and issue.severity != Severity.CRITICAL:
                results.append(
                    SelfHealthNotificationResult(
                        status=SelfHealthNotificationStatus.SUPPRESSED,
                        issue=issue,
                        detail="Non-critical self-health notification suppressed by maintenance.",
                    )
                )
                continue

            if not self.policy.enabled_for(issue.severity):
                results.append(
                    SelfHealthNotificationResult(
                        status=SelfHealthNotificationStatus.SKIPPED,
                        issue=issue,
                        detail="Self-health notification is disabled by policy.",
                    )
                )
                continue

            signature = issue.signature()
            if self._last_sent_signatures.get(issue.layer) == signature:
                results.append(
                    SelfHealthNotificationResult(
                        status=SelfHealthNotificationStatus.SKIPPED,
                        issue=issue,
                        detail="Self-health notification already sent for the current issue state.",
                    )
                )
                continue

            payload = build_self_health_notification_payload(issue=issue, now=effective_now)
            delivery = self.sender.send(payload)
            result_status = _self_health_status_from_delivery(delivery.status)
            if result_status == SelfHealthNotificationStatus.SENT:
                self._last_sent_signatures[issue.layer] = signature

            results.append(
                SelfHealthNotificationResult(
                    status=result_status,
                    issue=issue,
                    payload=payload,
                    delivery=delivery,
                    detail=delivery.detail,
                )
            )

        return results


def collect_self_health_issues(
    report: CapabilityHealthReport,
) -> list[SelfHealthNotificationIssue]:
    """Collect current capability-health problems that can produce notifications."""
    issues: list[SelfHealthNotificationIssue] = []
    for layer in report.layers:
        severity = _severity_for_layer_status(layer)
        if severity is None:
            continue
        issues.append(
            SelfHealthNotificationIssue(
                layer=layer.layer.value,
                status=layer.status,
                severity=severity,
                title=f"Kaval {format_self_health_label(layer.layer.value)} issue",
                summary=layer.summary,
                detail=layer.detail,
                user_impact=layer.user_impact,
                guidance=layer.guidance,
            )
        )
    return issues


def build_self_health_notification_payload(
    *,
    issue: SelfHealthNotificationIssue,
    now: datetime,
) -> NotificationPayload:
    """Build one notification payload for a self-health issue."""
    body_lines = [
        issue.summary,
        "",
        f"Detail: {issue.detail}",
        f"Impact: {issue.user_impact}",
        f"Guidance: {issue.guidance}",
    ]
    return NotificationPayload(
        source_type=NotificationSourceType.FINDING,
        source_id=f"capability:{issue.layer}",
        incident_id=None,
        severity=issue.severity,
        title=issue.title,
        summary=issue.summary,
        body="\n".join(body_lines),
        evidence_lines=[issue.detail],
        recommended_action=None,
        action_buttons=[],
        dedup_key=f"self-health:{issue.layer}:{issue.status.value}",
        created_at=now,
    )


def load_self_health_notification_policy_from_env(
    env: Mapping[str, str] | None = None,
) -> SelfHealthNotificationPolicy:
    """Load the minimal self-health notification policy from the environment."""
    source = env or os.environ
    return SelfHealthNotificationPolicy(
        critical_enabled=_env_bool(
            source,
            "KAVAL_SELF_HEALTH_NOTIFY_CRITICAL",
            True,
        ),
        degraded_enabled=_env_bool(
            source,
            "KAVAL_SELF_HEALTH_NOTIFY_DEGRADED",
            False,
        ),
    )


def format_self_health_label(value: str) -> str:
    """Render one capability-layer identifier for notification copy."""
    return " ".join(
        part.capitalize()
        for part in value.split("_")
    )


def _env_bool(source: Mapping[str, str], key: str, default: bool) -> bool:
    """Read one boolean environment flag with a conservative fallback."""
    raw_value = source.get(key)
    if raw_value is None:
        return default
    normalized = raw_value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _severity_for_layer_status(layer: CapabilityLayerReport) -> Severity | None:
    """Map one capability-layer status to a notification severity."""
    if layer.status == CapabilityHealthStatus.CRITICAL:
        return Severity.CRITICAL
    if layer.status == CapabilityHealthStatus.DEGRADED:
        return Severity.HIGH
    return None


def _self_health_status_from_delivery(
    delivery_status: NotificationDeliveryStatus,
) -> SelfHealthNotificationStatus:
    """Map notification-bus outcomes onto self-health notification results."""
    if delivery_status == NotificationDeliveryStatus.SENT:
        return SelfHealthNotificationStatus.SENT
    if delivery_status == NotificationDeliveryStatus.FAILED:
        return SelfHealthNotificationStatus.FAILED
    return SelfHealthNotificationStatus.SKIPPED
