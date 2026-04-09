"""Severity-based incident notification routing for Phase 3B."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import Field

from kaval.models import (
    Incident,
    Investigation,
    KavalModel,
    NotificationPayload,
    NotificationSourceType,
    Severity,
)
from kaval.notifications.bus import NotificationDeliveryResult, NotificationDeliveryStatus
from kaval.notifications.formatter import format_incident_notification
from kaval.notifications.grouped import (
    IncidentNotificationDispatcher,
    IncidentNotificationDispatchStatus,
    NotificationSender,
)


class IncidentAlertRoute(StrEnum):
    """Supported alert-routing behaviors for incident notifications."""

    IMMEDIATE = "immediate"
    IMMEDIATE_WITH_DEDUP = "immediate_with_dedup"
    HOURLY_DIGEST = "hourly_digest"
    SUMMARY = "summary"
    DASHBOARD_ONLY = "dashboard_only"


class IncidentAlertRoutingStatus(StrEnum):
    """User-visible outcomes of severity-based incident routing."""

    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"
    QUEUED = "queued"
    HELD = "held"
    SUPPRESSED = "suppressed"
    DASHBOARD_ONLY = "dashboard_only"


class IncidentAlertRoutingPolicy(KavalModel):
    """Default Phase 3B routing policy for service-health incidents."""

    critical: IncidentAlertRoute = IncidentAlertRoute.IMMEDIATE
    high: IncidentAlertRoute = IncidentAlertRoute.IMMEDIATE_WITH_DEDUP
    medium: IncidentAlertRoute = IncidentAlertRoute.HOURLY_DIGEST
    low: IncidentAlertRoute = IncidentAlertRoute.DASHBOARD_ONLY
    dedup_window_minutes: int = Field(default=15, gt=0)
    digest_window_minutes: int = Field(default=60, gt=0)

    def route_for(self, severity: Severity) -> IncidentAlertRoute:
        """Return the configured routing behavior for one incident severity."""
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.medium,
            Severity.LOW: self.low,
        }[severity]

    def dedup_window(self) -> timedelta:
        """Return the grouped-notification dedup window."""
        return timedelta(minutes=self.dedup_window_minutes)

    def digest_window(self) -> timedelta:
        """Return the batching interval for digest-bound incidents."""
        return timedelta(minutes=self.digest_window_minutes)


class PendingDigestIncident(KavalModel):
    """One incident currently queued for a later digest summary."""

    incident_id: str
    dedup_key: str
    severity: Severity
    title: str
    summary: str
    queued_at: datetime
    last_updated_at: datetime
    payload: NotificationPayload


class PendingIncidentDigest(KavalModel):
    """One pending digest bucket containing medium-severity incidents."""

    bucket_start: datetime
    deliver_after: datetime
    incidents: list[PendingDigestIncident] = Field(default_factory=list)


class AlertMaintenanceWindow(KavalModel):
    """One active maintenance window affecting notification routing."""

    service_id: str | None = None
    expires_at: datetime


class QuietHoursHeldIncident(KavalModel):
    """One non-critical incident held until quiet hours end."""

    incident_id: str
    dedup_key: str
    severity: Severity
    title: str
    summary: str
    held_at: datetime
    last_updated_at: datetime
    deliver_after: datetime
    original_route: IncidentAlertRoute
    payload: NotificationPayload


class IncidentAlertRoutingContext(KavalModel):
    """Runtime context that influences incident notification routing."""

    quiet_hours_until: datetime | None = None
    maintenance_windows: list[AlertMaintenanceWindow] = Field(default_factory=list)
    is_kaval_self_health: bool = False

    def quiet_hours_active(self, *, now: datetime) -> bool:
        """Return whether quiet-hours holding should apply right now."""
        return self.quiet_hours_until is not None and now < self.quiet_hours_until

    def maintenance_active_for_incident(
        self,
        *,
        incident: Incident,
        now: datetime,
    ) -> bool:
        """Return whether maintenance suppression should apply to this incident."""
        if self.is_kaval_self_health and incident.severity == Severity.CRITICAL:
            return False

        active_windows = [
            window
            for window in self.maintenance_windows
            if window.expires_at > now
        ]
        if any(window.service_id is None for window in active_windows):
            return True

        if not incident.affected_services:
            return False

        maintenance_service_ids = {
            window.service_id
            for window in active_windows
            if window.service_id is not None
        }
        return all(
            service_id in maintenance_service_ids
            for service_id in incident.affected_services
        )


class IncidentAlertRoutingResult(KavalModel):
    """The outcome of routing one incident through the alerting policy."""

    route: IncidentAlertRoute
    status: IncidentAlertRoutingStatus
    payload: NotificationPayload
    detail: str
    delivery: NotificationDeliveryResult | None = None
    digest_bucket_start: datetime | None = None
    digest_deliver_after: datetime | None = None
    quiet_hours_deliver_after: datetime | None = None


@dataclass(slots=True)
class IncidentAlertRouter:
    """Route incident notifications by severity without widening the payload contract."""

    sender: NotificationSender
    policy: IncidentAlertRoutingPolicy = field(default_factory=IncidentAlertRoutingPolicy)
    _grouped_dispatcher: IncidentNotificationDispatcher = field(init=False, repr=False)
    _pending_digest_buckets: dict[
        datetime,
        dict[str, PendingDigestIncident],
    ] = field(default_factory=dict, init=False, repr=False)
    _quiet_hours_holds: dict[str, QuietHoursHeldIncident] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Initialize the deduped high-severity path."""
        self._grouped_dispatcher = IncidentNotificationDispatcher(
            sender=self.sender,
            dedup_window=self.policy.dedup_window(),
        )

    def reconfigure(
        self,
        *,
        sender: NotificationSender,
        policy: IncidentAlertRoutingPolicy,
    ) -> None:
        """Update the runtime sender and policy without discarding queued state."""
        self.sender = sender
        self.policy = policy
        self._grouped_dispatcher = IncidentNotificationDispatcher(
            sender=sender,
            dedup_window=policy.dedup_window(),
        )

    def route(
        self,
        *,
        incident: Incident,
        investigation: Investigation,
        now: datetime | None = None,
        context: IncidentAlertRoutingContext | None = None,
    ) -> IncidentAlertRoutingResult:
        """Apply the Phase 3B severity-routing policy to one incident."""
        effective_now = now or datetime.now(tz=UTC)
        routing_context = context or IncidentAlertRoutingContext()
        payload = format_incident_notification(
            incident=incident,
            investigation=investigation,
            now=effective_now,
        )
        route = self.policy.route_for(incident.severity)

        if routing_context.maintenance_active_for_incident(
            incident=incident,
            now=effective_now,
        ):
            return IncidentAlertRoutingResult(
                route=route,
                status=IncidentAlertRoutingStatus.SUPPRESSED,
                payload=payload,
                detail="Incident notification suppressed by active maintenance.",
            )

        if (
            route != IncidentAlertRoute.DASHBOARD_ONLY
            and incident.severity != Severity.CRITICAL
            and routing_context.quiet_hours_active(now=effective_now)
            and routing_context.quiet_hours_until is not None
        ):
            held_incident = self._queue_quiet_hours_hold(
                incident=incident,
                payload=payload,
                route=route,
                held_until=routing_context.quiet_hours_until,
                now=effective_now,
            )
            return IncidentAlertRoutingResult(
                route=route,
                status=IncidentAlertRoutingStatus.HELD,
                payload=payload,
                detail="Incident notification held until quiet hours end.",
                quiet_hours_deliver_after=held_incident.deliver_after,
            )

        if route == IncidentAlertRoute.IMMEDIATE:
            delivery = self.sender.send(payload)
            return IncidentAlertRoutingResult(
                route=route,
                status=_routing_status_from_delivery(delivery.status),
                payload=payload,
                detail=delivery.detail,
                delivery=delivery,
            )

        if route == IncidentAlertRoute.IMMEDIATE_WITH_DEDUP:
            dispatch = self._grouped_dispatcher.dispatch(
                incident=incident,
                investigation=investigation,
                now=effective_now,
            )
            return IncidentAlertRoutingResult(
                route=route,
                status=_routing_status_from_grouped_dispatch(dispatch.status),
                payload=dispatch.payload,
                detail=dispatch.detail,
                delivery=dispatch.delivery,
            )

        if route == IncidentAlertRoute.HOURLY_DIGEST:
            bucket_start = _digest_bucket_start(
                now=effective_now,
                digest_window=self.policy.digest_window(),
            )
            deliver_after = bucket_start + self.policy.digest_window()
            bucket = self._pending_digest_buckets.setdefault(bucket_start, {})
            existing = bucket.get(payload.dedup_key)
            if existing is None:
                bucket[payload.dedup_key] = PendingDigestIncident(
                    incident_id=incident.id,
                    dedup_key=payload.dedup_key,
                    severity=incident.severity,
                    title=incident.title,
                    summary=payload.summary,
                    queued_at=effective_now,
                    last_updated_at=effective_now,
                    payload=payload,
                )
            else:
                bucket[payload.dedup_key] = existing.model_copy(
                    update={
                        "severity": incident.severity,
                        "title": incident.title,
                        "summary": payload.summary,
                        "last_updated_at": effective_now,
                        "payload": payload,
                    }
                )
            return IncidentAlertRoutingResult(
                route=route,
                status=IncidentAlertRoutingStatus.QUEUED,
                payload=payload,
                detail="Incident queued for the hourly digest path.",
                digest_bucket_start=bucket_start,
                digest_deliver_after=deliver_after,
            )

        return IncidentAlertRoutingResult(
            route=route,
            status=IncidentAlertRoutingStatus.DASHBOARD_ONLY,
            payload=payload,
            detail="Incident is dashboard-only for the current severity policy.",
        )

    def list_pending_digests(self) -> list[PendingIncidentDigest]:
        """Return pending hourly-digest buckets in delivery order."""
        digests = [
            PendingIncidentDigest(
                bucket_start=bucket_start,
                deliver_after=bucket_start + self.policy.digest_window(),
                incidents=sorted(
                    bucket.values(),
                    key=lambda incident: (
                        _severity_rank(incident.severity),
                        incident.title,
                    ),
                ),
            )
            for bucket_start, bucket in self._pending_digest_buckets.items()
        ]
        return sorted(digests, key=lambda digest: digest.bucket_start)

    def list_quiet_hours_holds(self) -> list[QuietHoursHeldIncident]:
        """Return quiet-hours-held incidents in delivery order."""
        return sorted(
            self._quiet_hours_holds.values(),
            key=lambda incident: (
                incident.deliver_after,
                _severity_rank(incident.severity),
                incident.title,
            ),
        )

    def flush_due_notifications(
        self,
        *,
        now: datetime | None = None,
    ) -> list[IncidentAlertRoutingResult]:
        """Send any due digest or quiet-hours summary notifications."""
        effective_now = now or datetime.now(tz=UTC)
        results: list[IncidentAlertRoutingResult] = []

        due_digest_starts = [
            bucket_start
            for bucket_start in self._pending_digest_buckets
            if bucket_start + self.policy.digest_window() <= effective_now
        ]
        for bucket_start in sorted(due_digest_starts):
            digest = PendingIncidentDigest(
                bucket_start=bucket_start,
                deliver_after=bucket_start + self.policy.digest_window(),
                incidents=sorted(
                    self._pending_digest_buckets[bucket_start].values(),
                    key=lambda incident: (
                        _severity_rank(incident.severity),
                        incident.title,
                    ),
                ),
            )
            results.append(
                self._send_due_group(
                    incidents=digest.incidents,
                    route=IncidentAlertRoute.HOURLY_DIGEST,
                    now=effective_now,
                    summary_key=f"digest:{bucket_start.isoformat()}",
                    summary_title=f"{len(digest.incidents)} active incidents",
                    detail_prefix="Hourly digest delivery",
                )
            )
            del self._pending_digest_buckets[bucket_start]

        due_hold_keys = [
            dedup_key
            for dedup_key, hold in self._quiet_hours_holds.items()
            if hold.deliver_after <= effective_now
        ]
        if due_hold_keys:
            held_incidents = sorted(
                (
                    self._quiet_hours_holds[dedup_key]
                    for dedup_key in due_hold_keys
                ),
                key=lambda incident: (
                    _severity_rank(incident.severity),
                    incident.title,
                ),
            )
            results.append(
                self._send_due_group(
                    incidents=held_incidents,
                    route=IncidentAlertRoute.SUMMARY,
                    now=effective_now,
                    summary_key=f"quiet-hours:{effective_now.isoformat()}",
                    summary_title=f"{len(held_incidents)} incidents after quiet hours",
                    detail_prefix="Quiet-hours release",
                )
            )
            for dedup_key in due_hold_keys:
                del self._quiet_hours_holds[dedup_key]

        return results

    def _queue_quiet_hours_hold(
        self,
        *,
        incident: Incident,
        payload: NotificationPayload,
        route: IncidentAlertRoute,
        held_until: datetime,
        now: datetime,
    ) -> QuietHoursHeldIncident:
        """Record one non-critical incident for later quiet-hours delivery."""
        existing = self._quiet_hours_holds.get(payload.dedup_key)
        if existing is None:
            held_incident = QuietHoursHeldIncident(
                incident_id=incident.id,
                dedup_key=payload.dedup_key,
                severity=incident.severity,
                title=incident.title,
                summary=payload.summary,
                held_at=now,
                last_updated_at=now,
                deliver_after=held_until,
                original_route=route,
                payload=payload,
            )
        else:
            held_incident = existing.model_copy(
                update={
                    "severity": incident.severity,
                    "title": incident.title,
                    "summary": payload.summary,
                    "last_updated_at": now,
                    "deliver_after": held_until,
                    "original_route": route,
                    "payload": payload,
                }
            )
        self._quiet_hours_holds[payload.dedup_key] = held_incident
        return held_incident

    def _send_due_group(
        self,
        *,
        incidents: Sequence[PendingDigestIncident | QuietHoursHeldIncident],
        route: IncidentAlertRoute,
        now: datetime,
        summary_key: str,
        summary_title: str,
        detail_prefix: str,
    ) -> IncidentAlertRoutingResult:
        """Deliver one due backlog group as either an incident or a summary payload."""
        if len(incidents) == 1:
            payload = incidents[0].payload
            delivery = self.sender.send(payload)
            return IncidentAlertRoutingResult(
                route=incidents[0].original_route
                if isinstance(incidents[0], QuietHoursHeldIncident)
                else route,
                status=_routing_status_from_delivery(delivery.status),
                payload=payload,
                detail=f"{detail_prefix} sent one incident notification.",
                delivery=delivery,
            )

        payload = _build_multi_issue_summary_payload(
            incidents=incidents,
            source_id=summary_key,
            title=summary_title,
            now=now,
        )
        delivery = self.sender.send(payload)
        return IncidentAlertRoutingResult(
            route=IncidentAlertRoute.SUMMARY,
            status=_routing_status_from_delivery(delivery.status),
            payload=payload,
            detail=f"{detail_prefix} sent a multi-issue summary notification.",
            delivery=delivery,
        )


def _digest_bucket_start(*, now: datetime, digest_window: timedelta) -> datetime:
    """Return the stable digest bucket start for one routing timestamp."""
    utc_now = now.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    bucket_size_seconds = int(digest_window.total_seconds())
    seconds_since_epoch = int((utc_now - epoch).total_seconds())
    bucket_offset_seconds = (
        seconds_since_epoch // bucket_size_seconds
    ) * bucket_size_seconds
    return epoch + timedelta(seconds=bucket_offset_seconds)


def _routing_status_from_delivery(
    delivery_status: NotificationDeliveryStatus,
) -> IncidentAlertRoutingStatus:
    """Map immediate-delivery outcomes onto routing outcomes."""
    if delivery_status == NotificationDeliveryStatus.SENT:
        return IncidentAlertRoutingStatus.SENT
    if delivery_status == NotificationDeliveryStatus.FAILED:
        return IncidentAlertRoutingStatus.FAILED
    return IncidentAlertRoutingStatus.SKIPPED


def _routing_status_from_grouped_dispatch(
    dispatch_status: IncidentNotificationDispatchStatus,
) -> IncidentAlertRoutingStatus:
    """Map grouped-dispatch outcomes onto routing outcomes."""
    if dispatch_status == IncidentNotificationDispatchStatus.SENT:
        return IncidentAlertRoutingStatus.SENT
    if dispatch_status == IncidentNotificationDispatchStatus.FAILED:
        return IncidentAlertRoutingStatus.FAILED
    return IncidentAlertRoutingStatus.SKIPPED


def _severity_rank(severity: Severity) -> int:
    """Return a stable sort order for queued digest incidents."""
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }[severity]


def _build_multi_issue_summary_payload(
    *,
    incidents: Sequence[PendingDigestIncident | QuietHoursHeldIncident],
    source_id: str,
    title: str,
    now: datetime,
) -> NotificationPayload:
    """Build one summary payload without collapsing the underlying incidents."""
    highest_severity = min(
        incidents,
        key=lambda incident: _severity_rank(incident.severity),
    ).severity
    summary_lines = [
        f"{incident.title} ({incident.severity.value.title()})"
        for incident in incidents
    ]
    body_lines = [
        "Multiple unrelated incidents are active:",
        *[f"- {line}" for line in summary_lines],
        "",
        "Each incident remains separate in Kaval and should be reviewed individually.",
    ]
    return NotificationPayload(
        source_type=NotificationSourceType.INCIDENT,
        source_id=source_id,
        incident_id=None,
        severity=highest_severity,
        title=title,
        summary=summary_lines[0],
        body="\n".join(body_lines),
        evidence_lines=summary_lines,
        recommended_action=None,
        action_buttons=[],
        dedup_key=source_id,
        created_at=now,
    )
