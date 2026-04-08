"""Deterministic service matching for normalized webhook events."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from kaval.integrations.webhooks.models import (
    WebhookEvent,
    WebhookMatchingOutcome,
    WebhookProcessingStatus,
)
from kaval.models import Service

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_STRUCTURED_TAG_KEYWORDS = (
    "service",
    "host",
    "hostname",
    "url",
    "instance",
    "container",
    "job",
    "app",
    "application",
    "node",
    "pod",
    "target",
    "monitor",
)
_STRUCTURED_TAG_EXCLUSIONS = (
    "generator",
    "dashboard",
    "panel",
    "silence",
    "external",
    "runbook",
    "annotation:summary",
    "annotation:description",
    "annotation:message",
)
_FUZZY_STOPWORDS = {
    "service",
    "server",
    "container",
    "system",
    "media",
    "web",
    "home",
    "stack",
}


class WebhookServiceMatchMethod(StrEnum):
    """Matching rules evaluated for normalized webhook events."""

    EXACT = "exact"
    TAG = "tag"
    FUZZY = "fuzzy"
    UNMATCHED = "unmatched"


@dataclass(frozen=True, slots=True)
class WebhookServiceMatchResult:
    """The deterministic service-matching result for one webhook event."""

    event: WebhookEvent
    method: WebhookServiceMatchMethod
    explanations: tuple[str, ...]


@dataclass(slots=True)
class WebhookServiceMatcher:
    """Match normalized webhook events to known services without side effects."""

    def match(
        self,
        *,
        event: WebhookEvent,
        services: list[Service],
    ) -> WebhookServiceMatchResult:
        """Return the highest-confidence deterministic match outcome for one event."""
        profiles = _build_service_profiles(services)
        exact_match = _match_exact(event=event, profiles=profiles)
        if exact_match is not None:
            return _build_result(
                event=event,
                method=WebhookServiceMatchMethod.EXACT,
                matched_service_ids=exact_match.matched_service_ids,
                explanations=exact_match.explanations,
            )

        tag_match = _match_tags(event=event, profiles=profiles)
        if tag_match is not None:
            return _build_result(
                event=event,
                method=WebhookServiceMatchMethod.TAG,
                matched_service_ids=tag_match.matched_service_ids,
                explanations=tag_match.explanations,
            )

        fuzzy_match = _match_fuzzy(event=event, profiles=profiles)
        if fuzzy_match is not None:
            return _build_result(
                event=event,
                method=WebhookServiceMatchMethod.FUZZY,
                matched_service_ids=fuzzy_match.matched_service_ids,
                explanations=fuzzy_match.explanations,
            )

        return WebhookServiceMatchResult(
            event=event.model_copy(
                update={
                    "matching_outcome": WebhookMatchingOutcome.UNMATCHED,
                    "matched_service_ids": [],
                }
            ),
            method=WebhookServiceMatchMethod.UNMATCHED,
            explanations=("no deterministic service match evidence was found",),
        )


@dataclass(frozen=True, slots=True)
class _ServiceProfile:
    """Exact, structured-tag, and fuzzy match data for one service."""

    service: Service
    exact_aliases: frozenset[str]
    tag_targets: frozenset[str]
    fuzzy_tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CandidateMatch:
    """Matched services plus deterministic explanation strings."""

    matched_service_ids: tuple[str, ...]
    explanations: tuple[str, ...]


def _build_result(
    *,
    event: WebhookEvent,
    method: WebhookServiceMatchMethod,
    matched_service_ids: tuple[str, ...],
    explanations: tuple[str, ...],
) -> WebhookServiceMatchResult:
    """Return the event updated with its deterministic match outcome."""
    matching_outcome = (
        WebhookMatchingOutcome.SINGLE
        if len(matched_service_ids) == 1
        else WebhookMatchingOutcome.MULTI
    )
    return WebhookServiceMatchResult(
        event=event.model_copy(
            update={
                "matching_outcome": matching_outcome,
                "matched_service_ids": list(matched_service_ids),
                "processing_status": WebhookProcessingStatus.MATCHED,
            }
        ),
        method=method,
        explanations=explanations,
    )


def _build_service_profiles(services: list[Service]) -> list[_ServiceProfile]:
    """Return deterministic service match profiles ordered by service ID."""
    return [
        _ServiceProfile(
            service=service,
            exact_aliases=frozenset(_exact_aliases(service)),
            tag_targets=frozenset(_tag_targets(service)),
            fuzzy_tokens=frozenset(_fuzzy_tokens(service)),
        )
        for service in sorted(services, key=lambda item: item.id)
    ]


def _match_exact(
    *,
    event: WebhookEvent,
    profiles: list[_ServiceProfile],
) -> _CandidateMatch | None:
    """Return exact unique matches from normalized service hints, if any."""
    alias_index = _unique_index(profiles, attribute_name="exact_aliases")
    explanations_by_service: dict[str, list[str]] = {}
    seen_evidence: set[tuple[str, str]] = set()
    for hint in event.service_hints:
        normalized_hint = _normalize_value(hint)
        if normalized_hint is None or normalized_hint not in alias_index:
            continue
        service_id = alias_index[normalized_hint]
        evidence_key = (service_id, normalized_hint)
        if evidence_key in seen_evidence:
            continue
        seen_evidence.add(evidence_key)
        explanations_by_service.setdefault(service_id, []).append(
            f"exact hint '{hint}' matched {service_id}"
        )
    return _candidate_match_from_evidence(
        service_ids=tuple(sorted(explanations_by_service)),
        explanations_by_service=explanations_by_service,
    )


def _match_tags(
    *,
    event: WebhookEvent,
    profiles: list[_ServiceProfile],
) -> _CandidateMatch | None:
    """Return structured-tag matches from normalized webhook tags, if any."""
    target_index = _unique_index(profiles, attribute_name="tag_targets")
    explanations_by_service: dict[str, list[str]] = {}
    for candidate in _event_tag_candidates(event.tags):
        if candidate not in target_index:
            continue
        service_id = target_index[candidate]
        explanations_by_service.setdefault(service_id, []).append(
            f"structured tag value '{candidate}' matched {service_id}"
        )
    return _candidate_match_from_evidence(
        service_ids=tuple(sorted(explanations_by_service)),
        explanations_by_service=explanations_by_service,
    )


def _match_fuzzy(
    *,
    event: WebhookEvent,
    profiles: list[_ServiceProfile],
) -> _CandidateMatch | None:
    """Return a single deterministic fuzzy text match when only one service wins."""
    searchable_text = "\n".join(part for part in (event.title, event.body) if part)
    slug_text = _slugify(searchable_text)
    if not slug_text:
        return None
    text_tokens = {token for token in slug_text.split("-") if token}

    scores: dict[str, list[str]] = {}
    for profile in profiles:
        for token in profile.fuzzy_tokens:
            if token in text_tokens or f"-{token}-" in f"-{slug_text}-":
                scores.setdefault(profile.service.id, []).append(token)
    if not scores:
        return None

    ranked = sorted(
        (
            (len(tokens), service_id, tuple(sorted(set(tokens))))
            for service_id, tokens in scores.items()
        ),
        key=lambda item: (-item[0], item[1]),
    )
    top_score, top_service_id, top_tokens = ranked[0]
    if top_score <= 0:
        return None
    if len(ranked) > 1 and ranked[1][0] == top_score:
        return None
    return _CandidateMatch(
        matched_service_ids=(top_service_id,),
        explanations=(
            f"fuzzy text tokens {', '.join(top_tokens)} matched {top_service_id}",
        ),
    )


def _candidate_match_from_evidence(
    *,
    service_ids: tuple[str, ...],
    explanations_by_service: dict[str, list[str]],
) -> _CandidateMatch | None:
    """Build a candidate match from collected evidence grouped by service ID."""
    if not service_ids:
        return None
    explanations: list[str] = []
    for service_id in service_ids:
        explanations.extend(explanations_by_service[service_id])
    return _CandidateMatch(
        matched_service_ids=service_ids,
        explanations=tuple(explanations),
    )


def _unique_index(
    profiles: list[_ServiceProfile],
    *,
    attribute_name: str,
) -> dict[str, str]:
    """Return the subset of aliases or targets owned by exactly one service."""
    counts: dict[str, int] = {}
    owners: dict[str, str] = {}
    for profile in profiles:
        values = getattr(profile, attribute_name)
        for value in values:
            counts[value] = counts.get(value, 0) + 1
            owners.setdefault(value, profile.service.id)
    return {
        value: owners[value]
        for value, count in counts.items()
        if count == 1
    }


def _exact_aliases(service: Service) -> set[str]:
    """Return exact service aliases safe for deterministic webhook matching."""
    aliases: set[str] = set()
    for candidate in (
        service.name,
        service.id.removeprefix("svc-"),
        service.descriptor_id,
        *(service.lifecycle.previous_names),
        *(service.lifecycle.previous_descriptor_ids),
    ):
        normalized = _normalize_value(candidate)
        if normalized is None:
            continue
        aliases.add(normalized)
        if "/" in normalized:
            aliases.add(normalized.rsplit("/", maxsplit=1)[-1])
    return aliases


def _tag_targets(service: Service) -> set[str]:
    """Return structured targets appropriate for tag-based webhook matching."""
    targets: set[str] = set()
    for endpoint in service.endpoints:
        _add_candidate_values(targets, endpoint.host)
        _add_candidate_values(targets, endpoint.url)
        if endpoint.host is not None and endpoint.port is not None:
            targets.add(f"{endpoint.host.casefold()}:{endpoint.port}")
    for dns_target in service.dns_targets:
        _add_candidate_values(targets, dns_target.host)
    return targets


def _fuzzy_tokens(service: Service) -> set[str]:
    """Return conservative fuzzy-match tokens derived from service identity."""
    tokens: set[str] = set()
    raw_candidates = [
        service.name,
        service.id.removeprefix("svc-"),
        service.descriptor_id.rsplit("/", maxsplit=1)[-1]
        if service.descriptor_id is not None
        else None,
        *(service.lifecycle.previous_names),
    ]
    for candidate in raw_candidates:
        if candidate is None:
            continue
        slug = _slugify(candidate)
        if len(slug) >= 3:
            tokens.add(slug)
        for segment in slug.split("-"):
            if (
                len(segment) >= 4
                and segment not in _FUZZY_STOPWORDS
            ):
                tokens.add(segment)
    return tokens


def _event_tag_candidates(tags: dict[str, str]) -> tuple[str, ...]:
    """Return structured candidate values extracted from webhook tags."""
    ordered: list[str] = []
    seen: set[str] = set()
    for key, raw_value in sorted(tags.items()):
        normalized_key = key.casefold()
        if not any(token in normalized_key for token in _STRUCTURED_TAG_KEYWORDS):
            continue
        if any(token in normalized_key for token in _STRUCTURED_TAG_EXCLUSIONS):
            continue
        for candidate in _extract_tag_candidates(raw_value):
            if candidate in seen:
                continue
            seen.add(candidate)
            ordered.append(candidate)
    return tuple(ordered)


def _extract_tag_candidates(raw_value: str) -> tuple[str, ...]:
    """Expand one tag value into structured candidates suitable for matching."""
    candidates: list[str] = []
    for part in raw_value.split(","):
        normalized = _normalize_value(part)
        if normalized is None:
            continue
        candidates.append(normalized)
        candidates.extend(_derived_host_candidates(normalized))
    return tuple(dict.fromkeys(candidates))


def _add_candidate_values(values: set[str], raw_value: str | None) -> None:
    """Add a raw value plus any structured URL/host variants to one target set."""
    normalized = _normalize_value(raw_value)
    if normalized is None:
        return
    values.add(normalized)
    values.update(_derived_host_candidates(normalized))


def _derived_host_candidates(value: str) -> set[str]:
    """Return host-like candidates derived from a URL or host:port-style string."""
    candidates: set[str] = set()
    parsed = urlsplit(value if "://" in value else f"//{value}")
    if parsed.hostname is None:
        return candidates
    candidates.add(parsed.hostname.casefold())
    if parsed.port is not None:
        candidates.add(f"{parsed.hostname.casefold()}:{parsed.port}")
    return candidates


def _normalize_value(value: str | None) -> str | None:
    """Trim and case-fold a possible match value."""
    if value is None:
        return None
    normalized = value.strip().casefold()
    return normalized or None


def _slugify(value: str) -> str:
    """Normalize free text into stable lowercase comparison tokens."""
    return _NON_ALNUM_RE.sub("-", value.casefold()).strip("-")
