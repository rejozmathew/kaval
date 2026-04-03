"""Read-only Docker discovery client and typed snapshot models."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Mapping, TypeVar
from urllib import error, parse, request

from pydantic import BaseModel, ConfigDict, Field


class DockerDiscoveryModel(BaseModel):
    """Base model for tolerant Docker API parsing."""

    model_config = ConfigDict(extra="ignore")


class DockerMount(DockerDiscoveryModel):
    """A read-only view of a container mount."""

    type: str | None = Field(default=None, alias="Type")
    source: str | None = Field(default=None, alias="Source")
    destination: str | None = Field(default=None, alias="Destination")
    mode: str | None = Field(default=None, alias="Mode")
    writable: bool = Field(default=False, alias="RW")

    @property
    def read_only(self) -> bool:
        """Return whether the mount is read-only."""
        return not self.writable


class DockerHealthLogEntry(DockerDiscoveryModel):
    """A single health-check log entry from Docker."""

    start: str | None = Field(default=None, alias="Start")
    end: str | None = Field(default=None, alias="End")
    exit_code: int | None = Field(default=None, alias="ExitCode")
    output: str | None = Field(default=None, alias="Output")


class DockerHealth(DockerDiscoveryModel):
    """Container health-check status."""

    status: str | None = Field(default=None, alias="Status")
    failing_streak: int | None = Field(default=None, alias="FailingStreak")
    log: list[DockerHealthLogEntry] = Field(default_factory=list, alias="Log")


class DockerContainerState(DockerDiscoveryModel):
    """Container state details from Docker inspect."""

    status: str | None = Field(default=None, alias="Status")
    running: bool | None = Field(default=None, alias="Running")
    restarting: bool | None = Field(default=None, alias="Restarting")
    exit_code: int | None = Field(default=None, alias="ExitCode")
    started_at: str | None = Field(default=None, alias="StartedAt")
    finished_at: str | None = Field(default=None, alias="FinishedAt")
    health: DockerHealth | None = Field(default=None, alias="Health")


class DockerPortBinding(DockerDiscoveryModel):
    """A published container port binding."""

    container_port: int
    protocol: str
    host_ip: str | None = None
    host_port: int | None = None


class DockerNetworkAttachment(DockerDiscoveryModel):
    """A network attachment from Docker inspect."""

    name: str
    network_id: str | None = Field(default=None, alias="NetworkID")
    endpoint_id: str | None = Field(default=None, alias="EndpointID")
    gateway: str | None = Field(default=None, alias="Gateway")
    ip_address: str | None = Field(default=None, alias="IPAddress")
    aliases: list[str] = Field(default_factory=list, alias="Aliases")


class DockerImageSummary(DockerDiscoveryModel):
    """Metadata for a discovered Docker image."""

    id: str = Field(alias="Id")
    repo_tags: list[str] = Field(default_factory=list, alias="RepoTags")
    repo_digests: list[str] = Field(default_factory=list, alias="RepoDigests")
    created: str | None = Field(default=None, alias="Created")


class DockerContainerSnapshot(DockerDiscoveryModel):
    """A read-only snapshot of a Docker container."""

    id: str = Field(alias="Id")
    name: str
    image: str = Field(alias="ConfigImage")
    image_id: str = Field(alias="Image")
    command: list[str] = Field(default_factory=list)
    state: DockerContainerState
    restart_count: int = Field(alias="RestartCount")
    env_names: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    mounts: list[DockerMount] = Field(default_factory=list)
    networks: list[DockerNetworkAttachment] = Field(default_factory=list)
    ports: list[DockerPortBinding] = Field(default_factory=list)
    image_details: DockerImageSummary | None = None


class DockerDiscoverySnapshot(DockerDiscoveryModel):
    """A complete read-only Docker discovery snapshot."""

    discovered_at: datetime
    containers: list[DockerContainerSnapshot] = Field(default_factory=list)
    images: list[DockerImageSummary] = Field(default_factory=list)


class DockerEventActor(DockerDiscoveryModel):
    """Event actor details returned by the Docker events API."""

    id: str | None = Field(default=None, alias="ID")
    attributes: dict[str, str] = Field(default_factory=dict, alias="Attributes")


class DockerContainerEvent(DockerDiscoveryModel):
    """One container event returned by the Docker events API."""

    status: str | None = None
    id: str | None = None
    from_image: str | None = Field(default=None, alias="from")
    type: str | None = Field(default=None, alias="Type")
    action: str | None = Field(default=None, alias="Action")
    actor: DockerEventActor = Field(default_factory=DockerEventActor, alias="Actor")
    scope: str | None = None
    time: int | None = None
    time_nano: int | None = Field(default=None, alias="timeNano")

    @property
    def container_id(self) -> str | None:
        """Return the container identifier carried by the event."""
        return self.actor.id or self.id


DockerModelT = TypeVar("DockerModelT", bound=DockerDiscoveryModel)


class DockerDiscoveryError(RuntimeError):
    """Base error for Docker discovery failures."""


class DockerTransportError(DockerDiscoveryError):
    """Raised when the Docker HTTP transport fails."""


def build_container_snapshot(
    inspect_payload: Mapping[str, object],
    image_payload: Mapping[str, object] | None = None,
) -> DockerContainerSnapshot:
    """Convert Docker inspect payloads into a typed container snapshot."""
    config = _mapping(inspect_payload.get("Config"))
    state = DockerContainerState.model_validate(_mapping(inspect_payload.get("State")))
    labels = _string_map(config.get("Labels"))
    env_names = _env_names(config.get("Env"))
    mounts = _model_list(inspect_payload.get("Mounts"), DockerMount)
    network_settings = _mapping(inspect_payload.get("NetworkSettings"))
    networks = _network_attachments(_mapping(network_settings.get("Networks")))
    ports = _port_bindings(_mapping(network_settings.get("Ports")))

    command = []
    raw_command = inspect_payload.get("Args")
    if isinstance(raw_command, list):
        command = [item for item in raw_command if isinstance(item, str)]

    snapshot = DockerContainerSnapshot(
        Id=_string_value(inspect_payload.get("Id")),
        name=_container_name(inspect_payload.get("Name")),
        ConfigImage=_string_value(config.get("Image")),
        Image=_string_value(inspect_payload.get("Image")),
        command=command,
        state=state,
        RestartCount=_int_value(inspect_payload.get("RestartCount")),
        env_names=env_names,
        labels=labels,
        mounts=mounts,
        networks=networks,
        ports=ports,
        image_details=(
            DockerImageSummary.model_validate(image_payload) if image_payload is not None else None
        ),
    )
    return snapshot


def build_discovery_snapshot(
    inspect_payloads: list[Mapping[str, object]],
    image_payloads: Mapping[str, Mapping[str, object]],
    *,
    discovered_at: datetime | None = None,
) -> DockerDiscoverySnapshot:
    """Convert Docker inspect payloads into a full discovery snapshot."""
    containers = [
        build_container_snapshot(
            inspect_payload,
            image_payloads.get(_string_value(inspect_payload.get("Image"))),
        )
        for inspect_payload in inspect_payloads
    ]
    images = [
        DockerImageSummary.model_validate(payload)
        for payload in image_payloads.values()
    ]
    return DockerDiscoverySnapshot(
        discovered_at=discovered_at or datetime.now(tz=UTC),
        containers=containers,
        images=images,
    )


@dataclass(frozen=True, slots=True)
class DockerClientConfig:
    """Configuration for the read-only Docker HTTP client."""

    base_url: str
    api_version: str = "v1.43"
    api_key: str | None = None
    timeout_seconds: float = 10.0

    def endpoint(self, path: str, query: Mapping[str, str] | None = None) -> str:
        """Return a versioned Docker endpoint URL."""
        trimmed_base = self.base_url.rstrip("/")
        trimmed_path = path if path.startswith("/") else f"/{path}"
        url = f"{trimmed_base}/{self.api_version}{trimmed_path}"
        if query is None:
            return url
        return f"{url}?{parse.urlencode(query)}"


class DockerDiscoveryClient:
    """A minimal read-only Docker HTTP API client."""

    def __init__(self, config: DockerClientConfig) -> None:
        """Store immutable client configuration."""
        self._config = config

    def fetch_discovery_snapshot(self) -> DockerDiscoverySnapshot:
        """Fetch container and image discovery data through the Docker HTTP API."""
        containers = self._get_json("/containers/json", {"all": "1"})
        if not isinstance(containers, list):
            raise DockerTransportError("Docker list containers response was not a list")

        inspect_payloads: list[Mapping[str, object]] = []
        image_payloads: dict[str, Mapping[str, object]] = {}
        for container in containers:
            if not isinstance(container, Mapping):
                continue
            container_id = _string_value(container.get("Id"))
            inspect_payload = self._get_json(f"/containers/{container_id}/json")
            if not isinstance(inspect_payload, Mapping):
                raise DockerTransportError(
                    f"Docker inspect response for {container_id} was not an object"
                )
            inspect_payloads.append(inspect_payload)

            image_id = _string_value(inspect_payload.get("Image"))
            if image_id not in image_payloads:
                image_payload = self._get_json(f"/images/{parse.quote(image_id, safe='')}/json")
                if not isinstance(image_payload, Mapping):
                    raise DockerTransportError(
                        f"Docker image inspect response for {image_id} was not an object"
                    )
                image_payloads[image_id] = image_payload

        return build_discovery_snapshot(inspect_payloads, image_payloads)

    def fetch_container_logs(
        self,
        container_id: str,
        *,
        tail_lines: int = 200,
    ) -> str:
        """Fetch recent container logs through the Docker HTTP API."""
        if tail_lines <= 0:
            msg = "tail_lines must be positive"
            raise ValueError(msg)
        return self._get_text(
            f"/containers/{parse.quote(container_id, safe='')}/logs",
            {
                "stdout": "1",
                "stderr": "1",
                "tail": str(tail_lines),
                "timestamps": "0",
            },
        )

    def fetch_container_events(
        self,
        *,
        since: datetime,
        until: datetime | None = None,
    ) -> list[DockerContainerEvent]:
        """Fetch read-only container events through the Docker HTTP API."""
        query = {
            "filters": json.dumps({"type": ["container"]}, separators=(",", ":")),
            "since": _docker_event_timestamp(since),
        }
        if until is not None:
            query["until"] = _docker_event_timestamp(until)
        payload = self._get_text("/events", query)
        return parse_docker_event_stream(payload)

    def _get_json(
        self,
        path: str,
        query: Mapping[str, str] | None = None,
    ) -> object:
        """GET a JSON document from the Docker HTTP API."""
        headers = {"accept": "application/json"}
        if self._config.api_key is not None:
            headers["x-api-key"] = self._config.api_key
        docker_request = request.Request(
            self._config.endpoint(path, query),
            method="GET",
            headers=headers,
        )

        try:
            with request.urlopen(docker_request, timeout=self._config.timeout_seconds) as response:
                if response.getcode() != HTTPStatus.OK:
                    raise DockerTransportError(
                        f"unexpected Docker response status: {response.getcode()}"
                    )
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise DockerTransportError(f"Docker API request failed with HTTP {exc.code}") from exc
        except error.URLError as exc:
            raise DockerTransportError(f"failed to reach Docker API: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise DockerTransportError("Docker API response was not valid JSON") from exc

        return payload

    def _get_text(
        self,
        path: str,
        query: Mapping[str, str] | None = None,
    ) -> str:
        """GET a plain-text document from the Docker HTTP API."""
        headers = {"accept": "text/plain"}
        if self._config.api_key is not None:
            headers["x-api-key"] = self._config.api_key
        docker_request = request.Request(
            self._config.endpoint(path, query),
            method="GET",
            headers=headers,
        )

        try:
            with request.urlopen(docker_request, timeout=self._config.timeout_seconds) as response:
                if response.getcode() != HTTPStatus.OK:
                    raise DockerTransportError(
                        f"unexpected Docker response status: {response.getcode()}"
                    )
                raw_payload = response.read()
                if not isinstance(raw_payload, bytes):
                    raise DockerTransportError("Docker API response was not valid UTF-8 text")
                payload = raw_payload.decode("utf-8")
        except error.HTTPError as exc:
            raise DockerTransportError(f"Docker API request failed with HTTP {exc.code}") from exc
        except error.URLError as exc:
            raise DockerTransportError(f"failed to reach Docker API: {exc.reason}") from exc

        return payload


def _mapping(value: object) -> Mapping[str, object]:
    """Return a mapping view for loose JSON values."""
    if isinstance(value, Mapping):
        return value
    return {}


def _string_value(value: object) -> str:
    """Coerce a JSON value to a string."""
    if isinstance(value, str):
        return value
    raise DockerTransportError("expected Docker payload field to be a string")


def _int_value(value: object) -> int:
    """Coerce a JSON value to an integer."""
    if isinstance(value, int):
        return value
    raise DockerTransportError("expected Docker payload field to be an integer")


def _string_map(value: object) -> dict[str, str]:
    """Return a dict[str, str] from a loose JSON value."""
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and isinstance(item, str):
            result[key] = item
    return result


def _env_names(value: object) -> list[str]:
    """Return environment variable names without their values."""
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        name, _, _ = item.partition("=")
        if name:
            names.append(name)
    return names


def _model_list(value: object, model_type: type[DockerModelT]) -> list[DockerModelT]:
    """Validate a list of Docker models."""
    if not isinstance(value, list):
        return []
    models: list[DockerModelT] = []
    for item in value:
        if isinstance(item, Mapping):
            models.append(model_type.model_validate(item))
    return models


def parse_docker_event_stream(payload: str) -> list[DockerContainerEvent]:
    """Parse the Docker events API newline-delimited JSON format."""
    events: list[DockerContainerEvent] = []
    for line in payload.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise DockerTransportError("Docker events response was not valid JSON") from exc
        if not isinstance(item, Mapping):
            raise DockerTransportError("Docker events response item was not an object")
        events.append(DockerContainerEvent.model_validate(item))
    return events


def _docker_event_timestamp(value: datetime) -> str:
    """Convert one event boundary timestamp to Docker's integer seconds token."""
    return str(int(value.astimezone(UTC).timestamp()))


def _network_attachments(value: Mapping[str, object]) -> list[DockerNetworkAttachment]:
    """Build a stable list of Docker network attachments."""
    attachments: list[DockerNetworkAttachment] = []
    for name in sorted(value):
        raw_attachment = value[name]
        if not isinstance(raw_attachment, Mapping):
            continue
        attachments.append(DockerNetworkAttachment(name=name, **raw_attachment))
    return attachments


def _port_bindings(value: Mapping[str, object]) -> list[DockerPortBinding]:
    """Build a stable list of published port bindings."""
    bindings: list[DockerPortBinding] = []
    for port_spec in sorted(value):
        port_value = value[port_spec]
        container_port, protocol = _split_port_spec(port_spec)
        if not isinstance(port_value, list):
            bindings.append(
                DockerPortBinding(
                    container_port=container_port,
                    protocol=protocol,
                    host_ip=None,
                    host_port=None,
                )
            )
            continue
        for entry in port_value:
            if not isinstance(entry, Mapping):
                continue
            host_port: int | None = None
            raw_host_port = entry.get("HostPort")
            if isinstance(raw_host_port, str) and raw_host_port.isdigit():
                host_port = int(raw_host_port)
            bindings.append(
                DockerPortBinding(
                    container_port=container_port,
                    protocol=protocol,
                    host_ip=entry.get("HostIp") if isinstance(entry.get("HostIp"), str) else None,
                    host_port=host_port,
                )
            )
    return bindings


def _split_port_spec(port_spec: str) -> tuple[int, str]:
    """Split a Docker port key like `7878/tcp` into typed pieces."""
    port_text, _, protocol = port_spec.partition("/")
    if not port_text.isdigit() or not protocol:
        raise DockerTransportError(f"invalid Docker port specification: {port_spec}")
    return int(port_text), protocol


def _container_name(value: object) -> str:
    """Normalize Docker inspect container names to a plain service-style name."""
    raw_name = _string_value(value)
    return raw_name[1:] if raw_name.startswith("/") else raw_name
