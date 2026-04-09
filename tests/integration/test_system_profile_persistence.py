"""Integration tests for persisting the Operational Memory system profile."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from kaval.database import KavalDatabase
from kaval.discovery.dependency_mapper import build_dependency_graph
from kaval.discovery.descriptors import load_service_descriptors
from kaval.discovery.docker import build_discovery_snapshot
from kaval.discovery.unraid import build_discovery_snapshot as build_unraid_discovery_snapshot
from kaval.discovery.unraid import decode_graphql_data
from kaval.models import ChangeType, PluginImpactService, PluginProfile
from kaval.runtime import CapabilityRuntimeSignalSource, DiscoveryPipelineRuntimeSignal
from kaval.system_profile import build_system_profile, persist_system_profile

DOCKER_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "docker"
UNRAID_FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "unraid"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def load_docker_fixture(name: str) -> dict[str, object]:
    """Load a Docker fixture for system-profile persistence tests."""
    return json.loads((DOCKER_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def load_unraid_fixture(name: str) -> dict[str, object]:
    """Load an Unraid fixture for system-profile persistence tests."""
    return json.loads((UNRAID_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def ts(hour: int, minute: int = 0) -> datetime:
    """Build a UTC timestamp for deterministic assertions."""
    return datetime(2026, 3, 31, hour, minute, tzinfo=UTC)


def test_system_profile_persists_to_sqlite(tmp_path: Path) -> None:
    """The built system profile should round-trip through the existing singleton row."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            load_docker_fixture("container_inspect_abc123.json"),
            load_docker_fixture("container_inspect_def456.json"),
        ],
        {
            "sha256:img-radarr": load_docker_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_docker_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
    )
    unraid_snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )
    services = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    ).services
    profile = build_system_profile(
        unraid_snapshot,
        docker_snapshot,
        services=services,
        now=ts(23, 10),
    )

    persist_system_profile(database, profile)

    assert database.get_system_profile() == profile
    runtime_signal = database.get_capability_runtime_signal(
        CapabilityRuntimeSignalSource.DISCOVERY_PIPELINE
    )
    assert isinstance(runtime_signal, DiscoveryPipelineRuntimeSignal)
    assert runtime_signal.last_succeeded_at == profile.last_updated
    assert runtime_signal.unraid_api_reachable is True
    assert runtime_signal.docker_api_reachable is True


def test_persist_system_profile_emits_plugin_update_changes(tmp_path: Path) -> None:
    """Plugin facet diffs should persist deterministic plugin-update timeline entries."""
    database = KavalDatabase(path=tmp_path / "kaval.db")
    database.bootstrap()
    descriptors = load_service_descriptors([SERVICES_DIR])
    docker_snapshot = build_discovery_snapshot(
        [
            load_docker_fixture("container_inspect_abc123.json"),
            load_docker_fixture("container_inspect_def456.json"),
        ],
        {
            "sha256:img-radarr": load_docker_fixture("image_inspect_sha256_img-radarr.json"),
            "sha256:img-delugevpn": load_docker_fixture("image_inspect_sha256_img-delugevpn.json"),
        },
    )
    unraid_snapshot = build_unraid_discovery_snapshot(
        decode_graphql_data(load_unraid_fixture("discovery_response.json"))
    )
    services = build_dependency_graph(
        docker_snapshot,
        descriptors,
        unraid_snapshot=unraid_snapshot,
    ).services
    base_profile = build_system_profile(
        unraid_snapshot,
        docker_snapshot,
        services=services,
        now=ts(23, 10),
    )
    previous_profile = base_profile.model_copy(
        update={
            "plugins": [
                PluginProfile(
                    name="community.applications",
                    version="2026.03.01",
                    enabled=True,
                    update_available=False,
                    impacted_services=[
                        PluginImpactService(
                            service_id="svc-radarr",
                            service_name="Radarr",
                            descriptor_id="arr/radarr",
                        )
                    ],
                ),
                PluginProfile(
                    name="gpu.stats",
                    version="1.0.0",
                    enabled=True,
                    update_available=False,
                    impacted_services=[
                        PluginImpactService(
                            service_id="svc-plex",
                            service_name="Plex",
                            descriptor_id="media/plex",
                        )
                    ],
                ),
            ]
        }
    )
    current_profile = base_profile.model_copy(
        update={
            "last_updated": ts(23, 20),
            "plugins": [
                PluginProfile(
                    name="community.applications",
                    version="2026.04.01",
                    enabled=False,
                    update_available=True,
                    impacted_services=[
                        PluginImpactService(
                            service_id="svc-radarr",
                            service_name="Radarr",
                            descriptor_id="arr/radarr",
                        )
                    ],
                ),
                PluginProfile(
                    name="new.plugin",
                    version="1.2.3",
                    enabled=True,
                    update_available=False,
                ),
            ],
        }
    )

    persist_system_profile(database, previous_profile)
    persist_system_profile(database, current_profile)

    plugin_changes = [
        change
        for change in database.list_changes()
        if change.type == ChangeType.PLUGIN_UPDATE
    ]

    assert len(plugin_changes) == 4
    changes_by_description = {change.description: change for change in plugin_changes}

    installed_change = changes_by_description["Plugin new.plugin was installed."]
    assert installed_change.old_value is None
    assert installed_change.new_value == "version=1.2.3; state=enabled; up_to_date; impacts=0"

    removed_change = changes_by_description[
        "Plugin gpu.stats was removed. Impacted services: Plex."
    ]
    assert removed_change.old_value == "version=1.0.0; state=enabled; up_to_date; impacts=1"
    assert removed_change.new_value is None

    version_change = changes_by_description[
        "Plugin community.applications changed version. Impacted services: Radarr."
    ]
    assert version_change.old_value == "2026.03.01"
    assert version_change.new_value == "2026.04.01"

    state_change = changes_by_description[
        "Plugin community.applications changed state. Impacted services: Radarr."
    ]
    assert state_change.old_value == "enabled; up_to_date"
    assert state_change.new_value == "disabled; update_available"
