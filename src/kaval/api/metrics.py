"""Prometheus exposition helpers for the Kaval API."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from kaval.api.schemas import (
    ServiceDetailAdapterConfigurationState,
    ServiceDetailAdapterResponse,
)
from kaval.integrations.webhooks import WebhookSourceType, WebhookStoredPayload
from kaval.integrations.webhooks.state import WebhookEventStateRecord
from kaval.models import (
    ActionType,
    ApprovalToken,
    EvidenceKind,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    Investigation,
    InvestigationStatus,
    ModelUsed,
    Service,
    ServiceInsightLevel,
    ServiceStatus,
    Severity,
)

_ACTIVE_FINDING_STATUSES = {
    FindingStatus.NEW,
    FindingStatus.GROUPED,
    FindingStatus.INVESTIGATING,
}
_ACTIVE_INCIDENT_STATUSES = {
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.AWAITING_APPROVAL,
    IncidentStatus.REMEDIATING,
}
_ADAPTER_METRIC_STATUSES = (
    "configured",
    "healthy",
    "degraded",
    "unknown",
    "locked",
    "unconfigured",
)
_ACTION_RESULT_STATUSES = ("success", "failed", "pending", "expired")
_APPROVAL_TOKEN_STATUSES = ("active", "used", "expired")
_HISTOGRAM_BUCKETS = (60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0, 21600.0)


@dataclass(frozen=True, slots=True)
class MetricSample:
    """One Prometheus sample line."""

    metric_name: str
    value: float
    labels: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class MetricFamily:
    """One Prometheus metric family."""

    name: str
    help_text: str
    metric_type: str
    samples: tuple[MetricSample, ...]


@dataclass(frozen=True, slots=True)
class MetricLabelPolicy:
    """Allowed labels and bounded values for one metric family."""

    base_label_names: tuple[str, ...] = ()
    allowed_label_values: dict[str, frozenset[str]] = field(default_factory=dict)
    histogram: bool = False


def render_prometheus_metrics(
    *,
    services: Sequence[Service],
    findings: Sequence[Finding],
    incidents: Sequence[Incident],
    investigations: Sequence[Investigation],
    adapter_statuses: Sequence[ServiceDetailAdapterResponse],
    known_adapter_ids: Sequence[str],
    approval_tokens: Sequence[ApprovalToken],
    webhook_payloads: Sequence[WebhookStoredPayload],
    webhook_event_states: Sequence[WebhookEventStateRecord],
    database_size_bytes: int,
    uptime_seconds: float,
    now: datetime,
) -> str:
    """Render the current Kaval state in Prometheus exposition format."""
    families = (
        _services_total_family(services),
        _services_insight_family(services),
        _active_findings_family(findings),
        _active_incidents_family(incidents),
        _incident_mttr_family(incidents),
        _investigations_total_family(investigations),
        _investigation_duration_family(investigations),
        _investigation_cloud_calls_family(investigations),
        _investigation_cloud_cost_estimate_family(investigations),
        _adapters_total_family(adapter_statuses),
        _adapter_inspections_family(
            adapter_statuses=adapter_statuses,
            known_adapter_ids=known_adapter_ids,
        ),
        _actions_total_family(approval_tokens=approval_tokens, now=now),
        _approval_tokens_total_family(approval_tokens=approval_tokens, now=now),
        _webhooks_received_family(webhook_payloads),
        _webhooks_matched_family(findings),
        _webhooks_duplicate_family(webhook_event_states),
        _single_value_family(
            name="kaval_database_size_bytes",
            help_text="SQLite database size in bytes.",
            metric_type="gauge",
            value=float(database_size_bytes),
        ),
        _single_value_family(
            name="kaval_uptime_seconds",
            help_text="Kaval API process uptime in seconds.",
            metric_type="gauge",
            value=max(uptime_seconds, 0.0),
        ),
    )
    _validate_metric_families(
        families=families,
        policies=_build_metric_label_policies(known_adapter_ids=known_adapter_ids),
    )
    return _render_metric_families(families)


def _services_total_family(services: Sequence[Service]) -> MetricFamily:
    """Build service-count metrics keyed by service status."""
    counts = Counter(service.status.value for service in services)
    return MetricFamily(
        name="kaval_services_total",
        help_text="Count of services grouped by current status.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_services_total",
                value=float(counts[status.value]),
                labels=(("status", status.value),),
            )
            for status in ServiceStatus
        ),
    )


def _services_insight_family(services: Sequence[Service]) -> MetricFamily:
    """Build service-count metrics keyed by current insight level."""
    counts = Counter(
        int(
            service.insight.level
            if service.insight is not None
            else ServiceInsightLevel.DISCOVERED
        )
        for service in services
    )
    return MetricFamily(
        name="kaval_services_insight_level",
        help_text="Count of services grouped by current insight level.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_services_insight_level",
                value=float(counts[int(level)]),
                labels=(("level", str(int(level))),),
            )
            for level in ServiceInsightLevel
        ),
    )


def _active_findings_family(findings: Sequence[Finding]) -> MetricFamily:
    """Build active-finding metrics keyed by severity."""
    counts = Counter(
        finding.severity.value
        for finding in findings
        if finding.status in _ACTIVE_FINDING_STATUSES
    )
    return MetricFamily(
        name="kaval_findings_active_total",
        help_text="Count of active findings grouped by severity.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_findings_active_total",
                value=float(counts[severity.value]),
                labels=(("severity", severity.value),),
            )
            for severity in Severity
        ),
    )


def _active_incidents_family(incidents: Sequence[Incident]) -> MetricFamily:
    """Build active-incident metrics keyed by incident status."""
    counts = Counter(
        incident.status.value
        for incident in incidents
        if incident.status in _ACTIVE_INCIDENT_STATUSES
    )
    return MetricFamily(
        name="kaval_incidents_active_total",
        help_text="Count of active incidents grouped by status.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_incidents_active_total",
                value=float(counts[status.value]),
                labels=(("status", status.value),),
            )
            for status in IncidentStatus
        ),
    )


def _incident_mttr_family(incidents: Sequence[Incident]) -> MetricFamily:
    """Build an MTTR histogram from resolved incident records."""
    observations = [
        incident.mttr_seconds
        for incident in incidents
        if incident.mttr_seconds is not None
    ]
    return _histogram_family(
        name="kaval_incident_mttr_seconds",
        help_text="Histogram of resolved incident MTTR values in seconds.",
        observations_by_labels={(): observations},
    )


def _investigations_total_family(
    investigations: Sequence[Investigation],
) -> MetricFamily:
    """Build investigation counts keyed by status and model usage."""
    counts = Counter(
        (investigation.status.value, investigation.model_used.value)
        for investigation in investigations
    )
    samples: list[MetricSample] = []
    for status in InvestigationStatus:
        for model in ModelUsed:
            samples.append(
                MetricSample(
                    metric_name="kaval_investigations_total",
                    value=float(counts[(status.value, model.value)]),
                    labels=(
                        ("status", status.value),
                        ("model", model.value),
                    ),
                )
            )
    return MetricFamily(
        name="kaval_investigations_total",
        help_text="Count of investigations grouped by status and model usage.",
        metric_type="gauge",
        samples=tuple(samples),
    )


def _investigation_duration_family(
    investigations: Sequence[Investigation],
) -> MetricFamily:
    """Build an investigation-duration histogram keyed by model usage."""
    observations_by_labels: dict[tuple[tuple[str, str], ...], list[float]] = {}
    for model in ModelUsed:
        observations_by_labels[(("model", model.value),)] = []
    for investigation in investigations:
        if investigation.completed_at is None:
            continue
        duration = (investigation.completed_at - investigation.started_at).total_seconds()
        observations_by_labels[(("model", investigation.model_used.value),)].append(duration)
    return _histogram_family(
        name="kaval_investigation_duration_seconds",
        help_text="Histogram of completed investigation durations in seconds.",
        observations_by_labels=observations_by_labels,
    )


def _investigation_cloud_calls_family(
    investigations: Sequence[Investigation],
) -> MetricFamily:
    """Build the aggregate cloud-call counter from persisted investigations."""
    cloud_calls = sum(
        investigation.cloud_model_calls
        for investigation in investigations
    )
    return _single_value_family(
        name="kaval_investigation_cloud_calls_total",
        help_text="Total persisted cloud model calls across investigations.",
        metric_type="counter",
        value=float(cloud_calls),
    )


def _investigation_cloud_cost_estimate_family(
    investigations: Sequence[Investigation],
) -> MetricFamily:
    """Build the aggregate persisted cloud-cost estimate metric."""
    estimated_cost = sum(
        investigation.estimated_cloud_cost_usd
        for investigation in investigations
    )
    return _single_value_family(
        name="kaval_investigation_cloud_cost_estimate",
        help_text="Total persisted estimated cloud-model cost across investigations.",
        metric_type="gauge",
        value=float(estimated_cost),
    )


def _adapters_total_family(
    adapter_statuses: Sequence[ServiceDetailAdapterResponse],
) -> MetricFamily:
    """Build aggregate adapter-binding counts grouped by current status."""
    counts = Counter(_adapter_metric_status(status) for status in adapter_statuses)
    return MetricFamily(
        name="kaval_adapters_total",
        help_text="Count of adapter bindings grouped by current status.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_adapters_total",
                value=float(counts[status]),
                labels=(("status", status),),
            )
            for status in _ADAPTER_METRIC_STATUSES
        ),
    )


def _adapter_inspections_family(
    *,
    adapter_statuses: Sequence[ServiceDetailAdapterResponse],
    known_adapter_ids: Sequence[str],
) -> MetricFamily:
    """Build adapter-binding counts keyed by adapter identifier and status."""
    counts = Counter(
        (status.adapter_id, _adapter_metric_status(status))
        for status in adapter_statuses
    )
    samples: list[MetricSample] = []
    for adapter_id in sorted(set(known_adapter_ids)):
        for status in _ADAPTER_METRIC_STATUSES:
            samples.append(
                MetricSample(
                    metric_name="kaval_adapter_inspections_total",
                    value=float(counts[(adapter_id, status)]),
                    labels=(
                        ("adapter", adapter_id),
                        ("status", status),
                    ),
                )
            )
    return MetricFamily(
        name="kaval_adapter_inspections_total",
        help_text="Count of adapter bindings grouped by adapter identifier and status.",
        metric_type="gauge",
        samples=tuple(samples),
    )


def _actions_total_family(
    *,
    approval_tokens: Sequence[ApprovalToken],
    now: datetime,
) -> MetricFamily:
    """Build action counts derived from approval-token lifecycle state."""
    counts = Counter(
        (token.action.value, _action_result_status(token, now=now))
        for token in approval_tokens
    )
    samples: list[MetricSample] = []
    for action in ActionType:
        for result in _ACTION_RESULT_STATUSES:
            samples.append(
                MetricSample(
                    metric_name="kaval_actions_total",
                    value=float(counts[(action.value, result)]),
                    labels=(
                        ("type", action.value),
                        ("result", result),
                    ),
                )
            )
    return MetricFamily(
        name="kaval_actions_total",
        help_text="Count of action attempts grouped by action type and result.",
        metric_type="gauge",
        samples=tuple(samples),
    )


def _approval_tokens_total_family(
    *,
    approval_tokens: Sequence[ApprovalToken],
    now: datetime,
) -> MetricFamily:
    """Build approval-token counts keyed by current lifecycle state."""
    counts = Counter(_approval_token_status(token, now=now) for token in approval_tokens)
    return MetricFamily(
        name="kaval_approval_tokens_total",
        help_text="Count of approval tokens grouped by lifecycle state.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_approval_tokens_total",
                value=float(counts[status]),
                labels=(("status", status),),
            )
            for status in _APPROVAL_TOKEN_STATUSES
        ),
    )


def _webhooks_received_family(
    webhook_payloads: Sequence[WebhookStoredPayload],
) -> MetricFamily:
    """Build retained-webhook counts keyed by source."""
    counts = Counter(payload.source_id for payload in webhook_payloads)
    return MetricFamily(
        name="kaval_webhooks_received_total",
        help_text="Count of retained webhook payloads grouped by source.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_webhooks_received_total",
                value=float(counts[source.value]),
                labels=(("source", source.value),),
            )
            for source in WebhookSourceType
        ),
    )


def _webhooks_matched_family(findings: Sequence[Finding]) -> MetricFamily:
    """Build matched-webhook counts keyed by source."""
    counts = Counter(_matched_webhook_sources(findings))
    return MetricFamily(
        name="kaval_webhooks_matched_total",
        help_text="Count of webhook-derived findings that matched one or more services.",
        metric_type="gauge",
        samples=tuple(
            MetricSample(
                metric_name="kaval_webhooks_matched_total",
                value=float(counts[source.value]),
                labels=(("source", source.value),),
            )
            for source in WebhookSourceType
        ),
    )


def _webhooks_duplicate_family(
    webhook_event_states: Sequence[WebhookEventStateRecord],
) -> MetricFamily:
    """Build duplicate-webhook counts keyed by source."""
    counts: defaultdict[str, int] = defaultdict(int)
    for state_record in webhook_event_states:
        counts[state_record.source_id] += state_record.duplicate_count
    return MetricFamily(
        name="kaval_webhooks_duplicate_total",
        help_text="Count of suppressed duplicate webhooks grouped by source.",
        metric_type="counter",
        samples=tuple(
            MetricSample(
                metric_name="kaval_webhooks_duplicate_total",
                value=float(counts[source.value]),
                labels=(("source", source.value),),
            )
            for source in WebhookSourceType
        ),
    )


def _single_value_family(
    *,
    name: str,
    help_text: str,
    metric_type: str,
    value: float,
) -> MetricFamily:
    """Build one single-sample metric family."""
    return MetricFamily(
        name=name,
        help_text=help_text,
        metric_type=metric_type,
        samples=(MetricSample(metric_name=name, value=value),),
    )


def _histogram_family(
    *,
    name: str,
    help_text: str,
    observations_by_labels: Mapping[tuple[tuple[str, str], ...], Sequence[float]],
) -> MetricFamily:
    """Build one Prometheus histogram family from grouped observations."""
    samples: list[MetricSample] = []
    for labels, observations in sorted(observations_by_labels.items()):
        ordered = sorted(observations)
        for bucket in _HISTOGRAM_BUCKETS:
            bucket_labels = labels + (("le", _format_label_value(bucket)),)
            samples.append(
                MetricSample(
                    metric_name=f"{name}_bucket",
                    value=float(sum(observation <= bucket for observation in ordered)),
                    labels=bucket_labels,
                )
            )
        samples.append(
            MetricSample(
                metric_name=f"{name}_bucket",
                value=float(len(ordered)),
                labels=labels + (("le", "+Inf"),),
            )
        )
        samples.append(
            MetricSample(
                metric_name=f"{name}_sum",
                value=float(sum(ordered)),
                labels=labels,
            )
        )
        samples.append(
            MetricSample(
                metric_name=f"{name}_count",
                value=float(len(ordered)),
                labels=labels,
            )
        )
    return MetricFamily(
        name=name,
        help_text=help_text,
        metric_type="histogram",
        samples=tuple(samples),
    )


def _matched_webhook_sources(findings: Sequence[Finding]) -> list[str]:
    """Return webhook source identifiers for findings that represent matched events."""
    matched_sources: list[str] = []
    for finding in findings:
        for evidence in finding.evidence:
            if evidence.kind is not EvidenceKind.EVENT:
                continue
            if not isinstance(evidence.data, dict):
                continue
            source_id = evidence.data.get("source_id")
            matching_outcome = evidence.data.get("matching_outcome")
            if not isinstance(source_id, str):
                continue
            if matching_outcome not in {"single", "multi"}:
                continue
            matched_sources.append(source_id)
            break
    return matched_sources


def _adapter_metric_status(adapter_status: ServiceDetailAdapterResponse) -> str:
    """Return the bounded metrics label for one adapter status snapshot."""
    if (
        adapter_status.configuration_state
        == ServiceDetailAdapterConfigurationState.UNCONFIGURED
    ):
        return "unconfigured"
    if adapter_status.configuration_state == ServiceDetailAdapterConfigurationState.LOCKED:
        return "locked"
    if adapter_status.health_state.value == "unknown":
        return "configured"
    return adapter_status.health_state.value


def _approval_token_status(token: ApprovalToken, *, now: datetime) -> str:
    """Return the current approval-token lifecycle label."""
    if token.used_at is not None:
        return "used"
    if token.expires_at <= now:
        return "expired"
    return "active"


def _action_result_status(token: ApprovalToken, *, now: datetime) -> str:
    """Return the bounded action-result label for one approval token."""
    if token.result is not None:
        if token.result.casefold().startswith("success"):
            return "success"
        return "failed"
    if token.expires_at <= now:
        return "expired"
    return "pending"


def _render_metric_families(families: Sequence[MetricFamily]) -> str:
    """Render metric families to the Prometheus text exposition format."""
    lines: list[str] = []
    for family in families:
        lines.append(f"# HELP {family.name} {_escape_help_text(family.help_text)}")
        lines.append(f"# TYPE {family.name} {family.metric_type}")
        for sample in family.samples:
            lines.append(_render_sample(sample))
    return "\n".join(lines) + "\n"


def _render_sample(sample: MetricSample) -> str:
    """Render one Prometheus sample line."""
    if not sample.labels:
        return f"{sample.metric_name} {_format_metric_value(sample.value)}"
    rendered_labels = ",".join(
        f'{key}="{_escape_label_value(value)}"'
        for key, value in sample.labels
    )
    return f"{sample.metric_name}{{{rendered_labels}}} {_format_metric_value(sample.value)}"


def _escape_help_text(value: str) -> str:
    """Escape Prometheus help text."""
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _escape_label_value(value: str) -> str:
    """Escape a Prometheus label value."""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _format_metric_value(value: float) -> str:
    """Render one numeric metric value."""
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


def _format_label_value(value: float) -> str:
    """Render one histogram bucket boundary label."""
    if value.is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")


def _build_metric_label_policies(
    *,
    known_adapter_ids: Sequence[str],
) -> dict[str, MetricLabelPolicy]:
    """Return the explicit bounded-label policy for every metric family."""
    histogram_bounds = frozenset(
        ["+Inf", *(_format_label_value(bucket) for bucket in _HISTOGRAM_BUCKETS)]
    )
    known_adapters = frozenset(sorted(set(known_adapter_ids)))
    return {
        "kaval_services_total": MetricLabelPolicy(
            base_label_names=("status",),
            allowed_label_values={
                "status": frozenset(status.value for status in ServiceStatus),
            },
        ),
        "kaval_services_insight_level": MetricLabelPolicy(
            base_label_names=("level",),
            allowed_label_values={
                "level": frozenset(str(int(level)) for level in ServiceInsightLevel),
            },
        ),
        "kaval_findings_active_total": MetricLabelPolicy(
            base_label_names=("severity",),
            allowed_label_values={
                "severity": frozenset(severity.value for severity in Severity),
            },
        ),
        "kaval_incidents_active_total": MetricLabelPolicy(
            base_label_names=("status",),
            allowed_label_values={
                "status": frozenset(status.value for status in IncidentStatus),
            },
        ),
        "kaval_incident_mttr_seconds": MetricLabelPolicy(
            allowed_label_values={"le": histogram_bounds},
            histogram=True,
        ),
        "kaval_investigations_total": MetricLabelPolicy(
            base_label_names=("status", "model"),
            allowed_label_values={
                "status": frozenset(status.value for status in InvestigationStatus),
                "model": frozenset(model.value for model in ModelUsed),
            },
        ),
        "kaval_investigation_duration_seconds": MetricLabelPolicy(
            base_label_names=("model",),
            allowed_label_values={
                "model": frozenset(model.value for model in ModelUsed),
                "le": histogram_bounds,
            },
            histogram=True,
        ),
        "kaval_investigation_cloud_calls_total": MetricLabelPolicy(),
        "kaval_investigation_cloud_cost_estimate": MetricLabelPolicy(),
        "kaval_adapters_total": MetricLabelPolicy(
            base_label_names=("status",),
            allowed_label_values={
                "status": frozenset(_ADAPTER_METRIC_STATUSES),
            },
        ),
        "kaval_adapter_inspections_total": MetricLabelPolicy(
            base_label_names=("adapter", "status"),
            allowed_label_values={
                "adapter": known_adapters,
                "status": frozenset(_ADAPTER_METRIC_STATUSES),
            },
        ),
        "kaval_actions_total": MetricLabelPolicy(
            base_label_names=("type", "result"),
            allowed_label_values={
                "type": frozenset(action.value for action in ActionType),
                "result": frozenset(_ACTION_RESULT_STATUSES),
            },
        ),
        "kaval_approval_tokens_total": MetricLabelPolicy(
            base_label_names=("status",),
            allowed_label_values={
                "status": frozenset(_APPROVAL_TOKEN_STATUSES),
            },
        ),
        "kaval_webhooks_received_total": MetricLabelPolicy(
            base_label_names=("source",),
            allowed_label_values={
                "source": frozenset(source.value for source in WebhookSourceType),
            },
        ),
        "kaval_webhooks_matched_total": MetricLabelPolicy(
            base_label_names=("source",),
            allowed_label_values={
                "source": frozenset(source.value for source in WebhookSourceType),
            },
        ),
        "kaval_webhooks_duplicate_total": MetricLabelPolicy(
            base_label_names=("source",),
            allowed_label_values={
                "source": frozenset(source.value for source in WebhookSourceType),
            },
        ),
        "kaval_database_size_bytes": MetricLabelPolicy(),
        "kaval_uptime_seconds": MetricLabelPolicy(),
    }


def _validate_metric_families(
    *,
    families: Sequence[MetricFamily],
    policies: Mapping[str, MetricLabelPolicy],
) -> None:
    """Reject metric samples that drift outside the bounded label policy."""
    for family in families:
        policy = policies.get(family.name)
        if policy is None:
            raise ValueError(f"missing label policy for metric family {family.name}")
        for sample in family.samples:
            _validate_metric_sample(
                family=family,
                sample=sample,
                policy=policy,
            )


def _validate_metric_sample(
    *,
    family: MetricFamily,
    sample: MetricSample,
    policy: MetricLabelPolicy,
) -> None:
    """Validate one sample against the allowed metric-name and label policy."""
    allowed_metric_names = {family.name}
    if policy.histogram:
        allowed_metric_names = {
            f"{family.name}_bucket",
            f"{family.name}_sum",
            f"{family.name}_count",
        }
    if sample.metric_name not in allowed_metric_names:
        raise ValueError(
            f"unexpected sample name {sample.metric_name} for family {family.name}"
        )

    expected_labels = policy.base_label_names
    if policy.histogram and sample.metric_name.endswith("_bucket"):
        expected_labels = (*expected_labels, "le")
    sample_label_names = tuple(key for key, _ in sample.labels)
    if sample_label_names != expected_labels:
        raise ValueError(
            f"unexpected label keys for {sample.metric_name}: {sample_label_names}"
        )

    for key, value in sample.labels:
        allowed_values = policy.allowed_label_values.get(key)
        if allowed_values is None:
            raise ValueError(f"unexpected label key {key} on {sample.metric_name}")
        if value not in allowed_values:
            raise ValueError(
                f"unexpected label value {key}={value!r} on {sample.metric_name}"
            )
