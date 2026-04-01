"""Unit tests for the Phase 2B Docker Hub client."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib import request

import pytest

from kaval.integrations.external_apis.dockerhub import (
    DockerHubClient,
    DockerHubClientConfig,
    DockerHubOfflineError,
    DockerHubResponseError,
    decode_repository_payload,
    decode_tag_payload,
    parse_dockerhub_reference,
)

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "dockerhub"


def load_fixture(name: str) -> object:
    """Load a JSON fixture used by Docker Hub tests."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a deterministic UTC timestamp for Docker Hub assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_client_config_builds_stable_v2_endpoint() -> None:
    """The Docker Hub client should normalize the documented v2 namespace endpoint."""
    config = DockerHubClientConfig(base_url="https://hub.docker.com/v2/")

    assert config.endpoint(
        "/namespaces/jc21/repositories/nginx-proxy-manager/tags",
        {"page_size": "2", "page": "1"},
    ) == (
        "https://hub.docker.com/v2/namespaces/jc21/repositories/nginx-proxy-manager/tags"
        "?page_size=2&page=1"
    )


def test_parse_dockerhub_reference_accepts_images_and_hub_urls() -> None:
    """References should normalize from Docker image and browser URL forms."""
    from_image = parse_dockerhub_reference("jc21/nginx-proxy-manager:2.12.1")
    from_library_image = parse_dockerhub_reference("docker.io/nginx:1.25")
    from_url = parse_dockerhub_reference("https://hub.docker.com/r/jc21/nginx-proxy-manager")

    assert from_image.repository_path == "jc21/nginx-proxy-manager"
    assert from_image.tag == "2.12.1"
    assert from_library_image.repository_path == "library/nginx"
    assert from_url.repository_path == "jc21/nginx-proxy-manager"


def test_decode_repository_and_tag_payloads_map_fixture_to_stable_contract() -> None:
    """Docker Hub fixtures should parse into the stable repository and tag contracts."""
    repository = decode_repository_payload(load_fixture("repository_npm.json"))
    tag = decode_tag_payload(load_fixture("tag_npm_2.12.1.json"))

    assert repository.repository == "nginx-proxy-manager"
    assert repository.pull_count == 987654
    assert repository.last_updated == ts(18, 20)
    assert tag.name == "2.12.1"
    assert tag.images[0].architecture == "amd64"
    assert tag.images[0].digest == "sha256:npm-2121-amd64"


def test_fetch_repository_raises_explicit_offline_error_when_disabled() -> None:
    """Offline mode should skip Docker Hub research before any transport call."""
    client = DockerHubClient(
        config=DockerHubClientConfig(offline_mode=True),
        transport=_unexpected_transport,
    )

    with pytest.raises(DockerHubOfflineError, match="offline mode enabled"):
        client.fetch_repository("jc21/nginx-proxy-manager")


def test_fetch_tags_raises_response_error_for_invalid_shape() -> None:
    """Tag list responses must be objects with the expected pagination fields."""
    client = DockerHubClient(
        transport=lambda http_request, timeout_seconds: b"[1, 2, 3]"
    )

    with pytest.raises(DockerHubResponseError, match="was not an object"):
        client.fetch_tags("jc21/nginx-proxy-manager")


def test_fetch_tag_uses_embedded_image_tag_when_available() -> None:
    """Tag lookups should accept the tag already present on the image reference."""
    response_body = json.dumps(load_fixture("tag_npm_2.12.1.json")).encode("utf-8")

    def transport(http_request: request.Request, timeout_seconds: float) -> bytes:
        del http_request, timeout_seconds
        return response_body

    client = DockerHubClient(transport=transport)

    tag = client.fetch_tag("jc21/nginx-proxy-manager:2.12.1")

    assert tag.name == "2.12.1"


def _unexpected_transport(http_request: request.Request, timeout_seconds: float) -> bytes:
    """Fail if offline-mode tests accidentally hit a transport path."""
    del http_request, timeout_seconds
    raise AssertionError("transport should not be called")
