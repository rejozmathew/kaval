"""Typed Docker Hub client for Tier 2 image metadata research."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, cast
from urllib import error, parse, request

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kaval.models import KavalModel

type RequestTransport = Callable[[request.Request, float], bytes]


class DockerHubError(RuntimeError):
    """Base error for Docker Hub client failures."""


class DockerHubOfflineError(DockerHubError):
    """Raised when Docker Hub metadata research is unavailable offline."""


class DockerHubNotFoundError(DockerHubError):
    """Raised when a repository or tag cannot be found."""


class DockerHubTransportError(DockerHubError):
    """Raised when the Docker Hub HTTP transport fails."""


class DockerHubResponseError(DockerHubError):
    """Raised when the Docker Hub response shape is invalid."""


class DockerHubImageReference(KavalModel):
    """A normalized Docker Hub image reference."""

    namespace: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def repository_path(self) -> str:
        """Return the canonical namespace/repository identifier."""
        return f"{self.namespace}/{self.repository}"

    @property
    def html_url(self) -> str:
        """Return the canonical Docker Hub browser URL for the repository."""
        if self.namespace == "library":
            return f"https://hub.docker.com/_/{self.repository}"
        return f"https://hub.docker.com/r/{self.namespace}/{self.repository}"

    @property
    def tags_url(self) -> str:
        """Return the canonical Docker Hub tags browser URL."""
        return f"{self.html_url}/tags"


class DockerHubTagImage(KavalModel):
    """One architecture-specific image variant published under a tag."""

    digest: str | None = None
    architecture: str | None = None
    os: str | None = None
    size: int | None = None


class DockerHubRepository(KavalModel):
    """Stable repository metadata consumed by later Tier 2 research."""

    namespace: str
    repository: str
    description: str | None = None
    full_description: str | None = None
    is_private: bool = False
    star_count: int = 0
    pull_count: int = 0
    last_updated: datetime | None = None
    status: int | None = None
    source_url: str


class DockerHubTag(KavalModel):
    """Stable metadata for one Docker Hub repository tag."""

    name: str
    full_size: int | None = None
    last_updated: datetime | None = None
    tag_last_pushed: datetime | None = None
    tag_last_pulled: datetime | None = None
    images: list[DockerHubTagImage] = Field(default_factory=list)


class DockerHubTagFeed(KavalModel):
    """A deterministic page of Docker Hub tags for one repository."""

    repository: DockerHubImageReference
    source_url: str
    fetched_at: datetime
    next_page_url: str | None = None
    tags: list[DockerHubTag] = Field(default_factory=list)


class _DockerHubPayloadModel(BaseModel):
    """Tolerant parser for Docker Hub API payloads."""

    model_config = ConfigDict(extra="ignore")


class _DockerHubRepositoryPayload(_DockerHubPayloadModel):
    """The subset of repository metadata consumed by Kaval."""

    namespace: str
    name: str
    description: str | None = None
    full_description: str | None = None
    is_private: bool = False
    star_count: int = 0
    pull_count: int = 0
    last_updated: datetime | None = None
    status: int | None = None


class _DockerHubTagImagePayload(_DockerHubPayloadModel):
    """One image record nested under a Docker Hub tag response."""

    digest: str | None = None
    architecture: str | None = None
    os: str | None = None
    size: int | None = None


class _DockerHubTagPayload(_DockerHubPayloadModel):
    """The subset of tag metadata consumed by Kaval."""

    name: str
    full_size: int | None = None
    last_updated: datetime | None = None
    tag_last_pushed: datetime | None = None
    tag_last_pulled: datetime | None = None
    images: list[_DockerHubTagImagePayload] = Field(default_factory=list)


class _DockerHubTagListPayload(_DockerHubPayloadModel):
    """The paginated tag listing returned by Docker Hub."""

    next: str | None = None
    results: list[_DockerHubTagPayload] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DockerHubClientConfig:
    """Immutable runtime configuration for the Docker Hub client."""

    base_url: str = "https://hub.docker.com/v2"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"
    offline_mode: bool = False

    def __post_init__(self) -> None:
        """Normalize and validate the configured Docker Hub endpoint."""
        normalized_base_url = self.base_url.rstrip("/")
        if not normalized_base_url:
            msg = "base_url must not be empty"
            raise ValueError(msg)
        if self.timeout_seconds <= 0:
            msg = "timeout_seconds must be positive"
            raise ValueError(msg)
        if not self.user_agent.strip():
            msg = "user_agent must not be empty"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)

    def endpoint(self, path: str, query: Mapping[str, str] | None = None) -> str:
        """Build one fully qualified Docker Hub API endpoint URL."""
        trimmed_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


@dataclass(frozen=True, slots=True)
class DockerHubClient:
    """Minimal public Docker Hub client used by Tier 2 research."""

    config: DockerHubClientConfig = DockerHubClientConfig()
    transport: RequestTransport | None = None

    def fetch_repository(
        self,
        reference: DockerHubImageReference | str,
    ) -> DockerHubRepository:
        """Fetch one public Docker Hub repository metadata record."""
        image_reference = parse_dockerhub_reference(reference)
        response_payload = self._get_json(
            (
                f"/namespaces/{_quoted_segment(image_reference.namespace)}"
                f"/repositories/{_quoted_segment(image_reference.repository)}"
            )
        )
        return decode_repository_payload(response_payload)

    def fetch_tags(
        self,
        reference: DockerHubImageReference | str,
        *,
        page_size: int = 10,
        fetched_at: datetime | None = None,
    ) -> DockerHubTagFeed:
        """Fetch one page of public Docker Hub tags for a repository."""
        if page_size <= 0:
            msg = "page_size must be positive"
            raise ValueError(msg)

        image_reference = parse_dockerhub_reference(reference)
        response_payload = self._get_json(
            (
                f"/namespaces/{_quoted_segment(image_reference.namespace)}"
                f"/repositories/{_quoted_segment(image_reference.repository)}/tags"
            ),
            query={"page_size": str(page_size), "page": "1"},
        )
        if not isinstance(response_payload, Mapping):
            raise DockerHubResponseError("Docker Hub tag list response was not an object")
        try:
            parsed_payload = _DockerHubTagListPayload.model_validate(response_payload)
        except ValidationError as exc:
            raise DockerHubResponseError("Docker Hub tag list payload shape was invalid") from exc

        return DockerHubTagFeed(
            repository=image_reference.model_copy(update={"tag": None, "digest": None}),
            source_url=image_reference.tags_url,
            fetched_at=fetched_at or datetime.now(tz=UTC),
            next_page_url=parsed_payload.next,
            tags=[
                decode_tag_payload(item.model_dump(mode="python"))
                for item in parsed_payload.results
            ],
        )

    def fetch_tag(
        self,
        reference: DockerHubImageReference | str,
        *,
        tag_name: str | None = None,
    ) -> DockerHubTag:
        """Fetch one public Docker Hub tag record."""
        image_reference = parse_dockerhub_reference(reference)
        resolved_tag = tag_name.strip() if tag_name is not None else image_reference.tag
        if not resolved_tag:
            msg = "tag_name must be provided when the reference does not include a tag"
            raise ValueError(msg)

        response_payload = self._get_json(
            (
                f"/namespaces/{_quoted_segment(image_reference.namespace)}"
                f"/repositories/{_quoted_segment(image_reference.repository)}"
                f"/tags/{_quoted_segment(resolved_tag)}"
            )
        )
        return decode_tag_payload(response_payload)

    def _build_request(self, path: str, query: Mapping[str, str] | None = None) -> request.Request:
        """Build a public Docker Hub request with stable headers."""
        if self.config.offline_mode:
            raise DockerHubOfflineError("Docker Hub research skipped: offline mode enabled.")

        return request.Request(
            self.config.endpoint(path, query),
            headers={
                "Accept": "application/json",
                "User-Agent": self.config.user_agent,
            },
            method="GET",
        )

    def _get_json(self, path: str, query: Mapping[str, str] | None = None) -> object:
        """Fetch one JSON payload from Docker Hub."""
        http_request = self._build_request(path, query)
        response_body = self._transport()(http_request, self.config.timeout_seconds)
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DockerHubResponseError("Docker Hub API returned non-JSON content") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


def parse_dockerhub_reference(reference: DockerHubImageReference | str) -> DockerHubImageReference:
    """Normalize Docker Hub image input from image refs or Docker Hub URLs."""
    if isinstance(reference, DockerHubImageReference):
        return reference

    candidate = reference.strip()
    if not candidate:
        msg = "Docker Hub reference must not be empty"
        raise ValueError(msg)

    if "://" in candidate:
        return _parse_dockerhub_url(candidate)
    return _parse_image_reference(candidate)


def decode_repository_payload(payload: object) -> DockerHubRepository:
    """Decode one Docker Hub repository payload into the stable contract."""
    if not isinstance(payload, Mapping):
        raise DockerHubResponseError("Docker Hub repository payload was not an object")
    try:
        parsed_payload = _DockerHubRepositoryPayload.model_validate(payload)
    except ValidationError as exc:
        raise DockerHubResponseError("Docker Hub repository payload shape was invalid") from exc

    reference = DockerHubImageReference(
        namespace=parsed_payload.namespace,
        repository=parsed_payload.name,
    )
    return DockerHubRepository(
        namespace=parsed_payload.namespace,
        repository=parsed_payload.name,
        description=parsed_payload.description,
        full_description=parsed_payload.full_description,
        is_private=parsed_payload.is_private,
        star_count=parsed_payload.star_count,
        pull_count=parsed_payload.pull_count,
        last_updated=parsed_payload.last_updated,
        status=parsed_payload.status,
        source_url=reference.html_url,
    )


def decode_tag_payload(payload: object) -> DockerHubTag:
    """Decode one Docker Hub tag payload into the stable contract."""
    if not isinstance(payload, Mapping):
        raise DockerHubResponseError("Docker Hub tag payload was not an object")
    try:
        parsed_payload = _DockerHubTagPayload.model_validate(payload)
    except ValidationError as exc:
        raise DockerHubResponseError("Docker Hub tag payload shape was invalid") from exc

    return DockerHubTag(
        name=parsed_payload.name,
        full_size=parsed_payload.full_size,
        last_updated=parsed_payload.last_updated,
        tag_last_pushed=parsed_payload.tag_last_pushed,
        tag_last_pulled=parsed_payload.tag_last_pulled,
        images=[
            DockerHubTagImage(
                digest=image.digest,
                architecture=image.architecture,
                os=image.os,
                size=image.size,
            )
            for image in parsed_payload.images
        ],
    )


def _parse_dockerhub_url(reference: str) -> DockerHubImageReference:
    """Parse a Docker Hub repository URL into a normalized image reference."""
    parsed = parse.urlsplit(reference)
    if parsed.netloc.casefold() != "hub.docker.com":
        msg = "repository URL must point to hub.docker.com"
        raise ValueError(msg)

    parts = [part for part in parsed.path.split("/") if part]
    if not parts:
        msg = "Docker Hub URL must include a repository path"
        raise ValueError(msg)

    if parts[0] == "r" and len(parts) >= 3:
        return DockerHubImageReference(namespace=parts[1], repository=parts[2])
    if parts[0] == "_" and len(parts) >= 2:
        return DockerHubImageReference(namespace="library", repository=parts[1])

    msg = "unsupported Docker Hub repository URL"
    raise ValueError(msg)


def _parse_image_reference(reference: str) -> DockerHubImageReference:
    """Parse a Docker-style image reference and ensure it points to Docker Hub."""
    digest: str | None = None
    if "@" in reference:
        reference, digest = reference.split("@", maxsplit=1)

    tag: str | None = None
    last_colon = reference.rfind(":")
    last_slash = reference.rfind("/")
    if last_colon > last_slash:
        reference, tag = reference[:last_colon], reference[last_colon + 1 :]

    parts = [part for part in reference.split("/") if part]
    if not parts:
        msg = "image reference must include a repository name"
        raise ValueError(msg)

    if len(parts) == 1:
        namespace = "library"
        repository = parts[0]
    elif len(parts) == 2:
        first_segment = parts[0].casefold()
        if _looks_like_registry_host(parts[0]):
            if first_segment not in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
                msg = "image reference does not point to Docker Hub"
                raise ValueError(msg)
            namespace = "library"
            repository = parts[1]
        else:
            namespace, repository = parts
    else:
        registry = parts[0].casefold()
        if registry not in {"docker.io", "index.docker.io", "registry-1.docker.io"}:
            msg = "image reference does not point to Docker Hub"
            raise ValueError(msg)
        remaining = parts[1:]
        if len(remaining) == 1:
            namespace = "library"
            repository = remaining[0]
        elif len(remaining) == 2:
            namespace, repository = remaining
        else:
            msg = "Docker Hub references support only namespace/repository paths"
            raise ValueError(msg)

    if not namespace or not repository:
        msg = "image reference must include namespace and repository details"
        raise ValueError(msg)

    return DockerHubImageReference(
        namespace=namespace,
        repository=repository,
        tag=tag.strip() if tag else None,
        digest=digest.strip() if digest else None,
    )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one public Docker Hub API request."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except error.HTTPError as exc:
        if exc.code == 404:
            raise DockerHubNotFoundError("Docker Hub repository or tag was not found") from exc
        raise DockerHubTransportError(
            f"Docker Hub API request failed with HTTP {exc.code}"
        ) from exc
    except (TimeoutError, OSError, error.URLError) as exc:
        raise DockerHubOfflineError(
            "Docker Hub research unavailable: network is offline or unreachable."
        ) from exc


def _quoted_segment(value: str) -> str:
    """Quote one path segment for safe inclusion in Docker Hub API URLs."""
    return parse.quote(value, safe="")


def _looks_like_registry_host(value: str) -> bool:
    """Return whether the segment looks like a registry host rather than a namespace."""
    return "." in value or ":" in value or value == "localhost"


__all__ = [
    "DockerHubClient",
    "DockerHubClientConfig",
    "DockerHubError",
    "DockerHubImageReference",
    "DockerHubNotFoundError",
    "DockerHubOfflineError",
    "DockerHubRepository",
    "DockerHubResponseError",
    "DockerHubTag",
    "DockerHubTagFeed",
    "DockerHubTagImage",
    "DockerHubTransportError",
    "decode_repository_payload",
    "decode_tag_payload",
    "parse_dockerhub_reference",
]
