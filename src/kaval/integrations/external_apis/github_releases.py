"""Typed GitHub releases client for Tier 2 changelog research."""

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


class GitHubReleasesError(RuntimeError):
    """Base error for GitHub releases client failures."""


class GitHubReleasesOfflineError(GitHubReleasesError):
    """Raised when Tier 2 GitHub research is unavailable offline."""


class GitHubReleasesNotFoundError(GitHubReleasesError):
    """Raised when a repository or release tag cannot be found."""


class GitHubReleasesTransportError(GitHubReleasesError):
    """Raised when the GitHub API transport fails."""


class GitHubReleasesResponseError(GitHubReleasesError):
    """Raised when the GitHub API response is invalid."""


class GitHubRepositoryReference(KavalModel):
    """A normalized GitHub repository reference."""

    owner: str
    name: str

    @property
    def full_name(self) -> str:
        """Return the canonical owner/name repository identifier."""
        return f"{self.owner}/{self.name}"

    @property
    def html_url(self) -> str:
        """Return the canonical browser URL for the repository."""
        return f"https://github.com/{self.full_name}"

    @property
    def releases_url(self) -> str:
        """Return the canonical browser URL for the repository releases page."""
        return f"{self.html_url}/releases"


class GitHubRelease(KavalModel):
    """The stable GitHub release metadata used by investigation research."""

    id: int
    tag_name: str
    name: str | None = None
    body: str | None = None
    html_url: str
    draft: bool = False
    prerelease: bool = False
    created_at: datetime | None = None
    published_at: datetime | None = None


class GitHubReleaseFeed(KavalModel):
    """A deterministic snapshot of public releases for one repository."""

    repository: GitHubRepositoryReference
    source_url: str
    fetched_at: datetime
    releases: list[GitHubRelease] = Field(default_factory=list)


class _GitHubPayloadModel(BaseModel):
    """Tolerant parser for GitHub API payloads."""

    model_config = ConfigDict(extra="ignore")


class _GitHubReleasePayload(_GitHubPayloadModel):
    """The subset of GitHub release fields used by Kaval."""

    id: int
    tag_name: str
    name: str | None = None
    body: str | None = None
    html_url: str
    draft: bool = False
    prerelease: bool = False
    created_at: datetime | None = None
    published_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class GitHubReleasesClientConfig:
    """Immutable runtime configuration for the GitHub releases client."""

    base_url: str = "https://api.github.com"
    timeout_seconds: float = 10.0
    user_agent: str = "kaval/0.1"
    api_version: str = "2022-11-28"
    offline_mode: bool = False

    def __post_init__(self) -> None:
        """Normalize and validate the configured API endpoint."""
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
        if not self.api_version.strip():
            msg = "api_version must not be empty"
            raise ValueError(msg)
        object.__setattr__(self, "base_url", normalized_base_url)

    def endpoint(self, path: str, query: Mapping[str, str] | None = None) -> str:
        """Build one fully qualified GitHub API endpoint URL."""
        trimmed_path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


@dataclass(frozen=True, slots=True)
class GitHubReleasesClient:
    """Minimal public GitHub releases client used by Tier 2 research."""

    config: GitHubReleasesClientConfig = GitHubReleasesClientConfig()
    transport: RequestTransport | None = None

    def fetch_releases(
        self,
        repository: GitHubRepositoryReference | str,
        *,
        limit: int = 10,
        fetched_at: datetime | None = None,
    ) -> GitHubReleaseFeed:
        """Fetch recent public releases for a repository."""
        if limit <= 0:
            msg = "limit must be positive"
            raise ValueError(msg)

        repo = parse_repository_reference(repository)
        response_payload = self._get_json(
            f"/repos/{_quoted_segment(repo.owner)}/{_quoted_segment(repo.name)}/releases",
            query={"per_page": str(limit), "page": "1"},
        )
        if not isinstance(response_payload, list):
            raise GitHubReleasesResponseError("GitHub releases response was not a list")

        releases = [decode_release_payload(item) for item in response_payload]
        return GitHubReleaseFeed(
            repository=repo,
            source_url=repo.releases_url,
            fetched_at=fetched_at or datetime.now(tz=UTC),
            releases=releases,
        )

    def fetch_release_by_tag(
        self,
        repository: GitHubRepositoryReference | str,
        *,
        tag_name: str,
    ) -> GitHubRelease:
        """Fetch one public release by its tag name."""
        normalized_tag = tag_name.strip()
        if not normalized_tag:
            msg = "tag_name must not be empty"
            raise ValueError(msg)

        repo = parse_repository_reference(repository)
        response_payload = self._get_json(
            (
                f"/repos/{_quoted_segment(repo.owner)}/{_quoted_segment(repo.name)}"
                f"/releases/tags/{_quoted_segment(normalized_tag)}"
            )
        )
        return decode_release_payload(response_payload)

    def _build_request(self, path: str, query: Mapping[str, str] | None = None) -> request.Request:
        """Build a public GitHub API request with stable headers."""
        if self.config.offline_mode:
            raise GitHubReleasesOfflineError(
                "GitHub release research skipped: offline mode enabled."
            )

        return request.Request(
            self.config.endpoint(path, query),
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": self.config.user_agent,
                "X-GitHub-Api-Version": self.config.api_version,
            },
            method="GET",
        )

    def _get_json(self, path: str, query: Mapping[str, str] | None = None) -> object:
        """Fetch one JSON payload from the GitHub API."""
        http_request = self._build_request(path, query)
        response_body = self._transport()(http_request, self.config.timeout_seconds)
        try:
            return json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubReleasesResponseError("GitHub API returned non-JSON content") from exc

    def _transport(self) -> RequestTransport:
        """Return the configured transport or the production default transport."""
        return self.transport or _default_transport


def parse_repository_reference(
    repository: GitHubRepositoryReference | str,
) -> GitHubRepositoryReference:
    """Normalize repository input from owner/name or GitHub URL forms."""
    if isinstance(repository, GitHubRepositoryReference):
        return repository

    candidate = repository.strip()
    if not candidate:
        msg = "repository reference must not be empty"
        raise ValueError(msg)

    if "://" in candidate:
        parsed = parse.urlsplit(candidate)
        if parsed.netloc.casefold() != "github.com":
            msg = "repository URL must point to github.com"
            raise ValueError(msg)
        path_parts = [part for part in parsed.path.split("/") if part]
    else:
        path_parts = [part for part in candidate.split("/") if part]

    if len(path_parts) < 2:
        msg = "repository reference must include owner and repository name"
        raise ValueError(msg)

    owner = path_parts[0].strip()
    name = path_parts[1].strip()
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        msg = "repository reference must include owner and repository name"
        raise ValueError(msg)

    return GitHubRepositoryReference(owner=owner, name=name)


def decode_release_payload(payload: object) -> GitHubRelease:
    """Decode one GitHub release payload into the stable internal contract."""
    if not isinstance(payload, Mapping):
        raise GitHubReleasesResponseError("GitHub release entry was not an object")
    try:
        parsed_payload = _GitHubReleasePayload.model_validate(payload)
    except ValidationError as exc:
        raise GitHubReleasesResponseError("GitHub release payload shape was invalid") from exc

    return GitHubRelease(
        id=parsed_payload.id,
        tag_name=parsed_payload.tag_name,
        name=parsed_payload.name,
        body=parsed_payload.body,
        html_url=parsed_payload.html_url,
        draft=parsed_payload.draft,
        prerelease=parsed_payload.prerelease,
        created_at=parsed_payload.created_at,
        published_at=parsed_payload.published_at,
    )


def _default_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Send one public GitHub API request."""
    try:
        with request.urlopen(http_request, timeout=timeout_seconds) as response:
            return cast(bytes, response.read())
    except error.HTTPError as exc:
        if exc.code == 404:
            raise GitHubReleasesNotFoundError("GitHub repository or release was not found") from exc
        raise GitHubReleasesTransportError(
            f"GitHub API request failed with HTTP {exc.code}"
        ) from exc
    except (TimeoutError, OSError, error.URLError) as exc:
        raise GitHubReleasesOfflineError(
            "GitHub release research unavailable: network is offline or unreachable."
        ) from exc


def _quoted_segment(value: str) -> str:
    """Quote one path segment for safe inclusion in GitHub API URLs."""
    return parse.quote(value, safe="")


__all__ = [
    "GitHubRelease",
    "GitHubReleaseFeed",
    "GitHubReleasesClient",
    "GitHubReleasesClientConfig",
    "GitHubReleasesError",
    "GitHubReleasesNotFoundError",
    "GitHubReleasesOfflineError",
    "GitHubReleasesResponseError",
    "GitHubReleasesTransportError",
    "GitHubRepositoryReference",
    "decode_release_payload",
    "parse_repository_reference",
]
