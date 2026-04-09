"""Contract tests for shipped service descriptors."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pytest

from kaval.discovery.descriptors import load_service_descriptors
from kaval.models import DescriptorSource, DnsRecordType

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"

EXPECTED_DESCRIPTOR_IDS = {
    "adguard_home",
    "authentik",
    "authelia",
    "calibre_web",
    "caddy",
    "cloudflared",
    "emby",
    "grafana",
    "delugevpn",
    "home_assistant",
    "jellyfin",
    "keycloak",
    "loki",
    "mariadb",
    "minio",
    "nextcloud",
    "nginx_proxy_manager",
    "nzbget",
    "pihole",
    "plex",
    "portainer",
    "postgres",
    "prowlarr",
    "prometheus",
    "qbittorrent",
    "radarr",
    "redis",
    "sabnzbd",
    "seafile",
    "sonarr",
    "traefik",
    "transmission",
    "uptime_kuma",
    "watchtower",
    "zigbee2mqtt",
}


@lru_cache(maxsize=1)
def shipped_descriptors():
    """Load the shipped descriptor catalog once for contract assertions."""
    return load_service_descriptors([SERVICES_DIR])


def descriptor_ids() -> list[str]:
    """Return the shipped descriptor ids in stable order for parametrized checks."""
    return sorted(item.descriptor.id for item in shipped_descriptors())


def descriptor_by_id(descriptor_id: str):
    """Return one shipped descriptor by its stable id."""
    return next(
        item for item in shipped_descriptors() if item.descriptor.id == descriptor_id
    )


def test_shipped_service_descriptors_load_from_services_tree() -> None:
    """The shipped service catalog should load cleanly from disk."""
    loaded_descriptors = shipped_descriptors()

    assert len(loaded_descriptors) == 35
    assert {item.descriptor.id for item in loaded_descriptors} == EXPECTED_DESCRIPTOR_IDS
    assert all(item.descriptor.source == DescriptorSource.SHIPPED for item in loaded_descriptors)
    assert all(item.descriptor.verified is True for item in loaded_descriptors)
    assert all(item.descriptor.generated_at is None for item in loaded_descriptors)


def test_shipped_descriptors_live_under_expected_service_categories() -> None:
    """Each shipped descriptor should live under a non-auto-generated category path."""
    loaded_descriptors = shipped_descriptors()

    assert all(item.path.parent.name != "auto_generated" for item in loaded_descriptors)
    assert {item.path.parent.name for item in loaded_descriptors} == {
        "arr",
        "automation",
        "cloud",
        "databases",
        "downloads",
        "identity",
        "media",
        "monitoring",
        "networking",
        "system",
    }


def test_shipped_pihole_descriptor_declares_dns_target() -> None:
    """The shipped catalog should include explicit DNS metadata where intended."""
    loaded_descriptors = shipped_descriptors()
    pihole = next(item for item in loaded_descriptors if item.descriptor.id == "pihole")

    assert len(pihole.descriptor.dns_targets) == 1
    assert pihole.descriptor.dns_targets[0].host == "pi.hole"
    assert pihole.descriptor.dns_targets[0].record_type == DnsRecordType.A


def test_shipped_radarr_descriptor_declares_read_only_inspection_surfaces() -> None:
    """The shipped Radarr descriptor should declare deep inspection declaratively."""
    loaded_descriptors = shipped_descriptors()
    radarr = next(item for item in loaded_descriptors if item.descriptor.id == "radarr")

    assert [surface.id for surface in radarr.descriptor.inspection.surfaces] == [
        "health_api",
        "system_status",
        "download_clients",
        "indexers",
        "queue_status",
        "queue_details",
    ]
    assert all(surface.read_only is True for surface in radarr.descriptor.inspection.surfaces)
    assert (
        radarr.descriptor.inspection.surfaces[0].confidence_effect is not None
    )
    assert radarr.descriptor.credential_hints["api_key"].prompt is not None


def test_shipped_authentik_descriptor_declares_bearer_token_inspection_surfaces() -> None:
    """The shipped Authentik descriptor should expose its read-only API surfaces."""
    loaded_descriptors = shipped_descriptors()
    authentik = next(
        item for item in loaded_descriptors if item.descriptor.id == "authentik"
    )

    assert [surface.id for surface in authentik.descriptor.inspection.surfaces] == [
        "applications",
        "providers",
        "outposts",
        "outpost_health",
        "system_health",
    ]
    assert all(
        surface.auth.value == "token"
        for surface in authentik.descriptor.inspection.surfaces
    )
    assert authentik.descriptor.credential_hints["api_token"].prompt is not None


def test_shipped_npm_descriptor_declares_token_auth_inspection_surfaces() -> None:
    """The shipped NPM descriptor should expose the API surfaces the adapter consumes."""
    loaded_descriptors = shipped_descriptors()
    npm = next(
        item for item in loaded_descriptors if item.descriptor.id == "nginx_proxy_manager"
    )

    assert [surface.id for surface in npm.descriptor.inspection.surfaces] == [
        "proxy_hosts",
        "certificates",
    ]
    assert all(surface.auth.value == "token" for surface in npm.descriptor.inspection.surfaces)
    assert npm.descriptor.credential_hints["identity"].prompt is not None
    assert npm.descriptor.credential_hints["secret"].prompt is not None


def test_shipped_cloudflared_descriptor_declares_cloudflare_surfaces() -> None:
    """The shipped cloudflared descriptor should declare approved Cloudflare surfaces."""
    loaded_descriptors = shipped_descriptors()
    cloudflared = next(
        item for item in loaded_descriptors if item.descriptor.id == "cloudflared"
    )

    assert [surface.id for surface in cloudflared.descriptor.inspection.surfaces] == [
        "dns_records",
        "ssl_mode",
        "tunnel_status",
        "origin_certificates",
    ]
    assert all(
        surface.auth.value == "token"
        for surface in cloudflared.descriptor.inspection.surfaces
    )
    assert cloudflared.descriptor.credential_hints["api_token"].prompt is not None
    assert cloudflared.descriptor.credential_hints["zone_name"].prompt is not None
    assert cloudflared.descriptor.credential_hints["account_id"].prompt is not None
    assert cloudflared.descriptor.credential_hints["tunnel_id"].prompt is not None


def test_shipped_pihole_descriptor_declares_read_only_api_surfaces() -> None:
    """The shipped Pi-hole descriptor should expose its deep-inspection surfaces."""
    loaded_descriptors = shipped_descriptors()
    pihole = next(item for item in loaded_descriptors if item.descriptor.id == "pihole")

    assert [surface.id for surface in pihole.descriptor.inspection.surfaces] == [
        "upstream_dns",
        "blocklist_status",
        "dhcp_config",
    ]
    assert all(surface.auth.value == "token" for surface in pihole.descriptor.inspection.surfaces)
    assert pihole.descriptor.credential_hints["password"].prompt is not None


@pytest.mark.parametrize("descriptor_id", descriptor_ids())
def test_each_shipped_descriptor_has_operator_quality_metadata(
    descriptor_id: str,
) -> None:
    """Each shipped descriptor should carry baseline metadata for operator review."""
    descriptor = descriptor_by_id(descriptor_id).descriptor

    assert descriptor.project_url is not None
    assert descriptor.icon is not None
    assert descriptor.investigation_context is not None
    assert descriptor.investigation_context.strip()
    assert descriptor.log_signals.errors or descriptor.log_signals.warnings
    assert descriptor.common_failure_modes


@pytest.mark.parametrize("descriptor_id", descriptor_ids())
def test_each_shipped_descriptor_failure_modes_and_path_are_consistent(
    descriptor_id: str,
) -> None:
    """Each shipped descriptor should map cleanly to its file and declared signals."""
    loaded_descriptor = descriptor_by_id(descriptor_id)
    descriptor = loaded_descriptor.descriptor
    declared_signals = {
        *descriptor.log_signals.errors,
        *descriptor.log_signals.warnings,
    }

    assert loaded_descriptor.path == SERVICES_DIR / descriptor.category / f"{descriptor.id}.yaml"
    for failure_mode in descriptor.common_failure_modes:
        assert failure_mode.trigger in declared_signals
        assert failure_mode.check_first
