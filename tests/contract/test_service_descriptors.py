"""Contract tests for shipped service descriptors."""

from __future__ import annotations

from pathlib import Path

from kaval.discovery.descriptors import load_service_descriptors
from kaval.models import DescriptorSource, DnsRecordType

SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"

EXPECTED_DESCRIPTOR_IDS = {
    "authentik",
    "cloudflared",
    "delugevpn",
    "home_assistant",
    "jellyfin",
    "mariadb",
    "nextcloud",
    "nginx_proxy_manager",
    "pihole",
    "plex",
    "prowlarr",
    "qbittorrent",
    "radarr",
    "sonarr",
    "uptime_kuma",
}


def test_shipped_service_descriptors_load_from_services_tree() -> None:
    """The shipped service catalog should load cleanly from disk."""
    loaded_descriptors = load_service_descriptors([SERVICES_DIR])

    assert len(loaded_descriptors) == 15
    assert {item.descriptor.id for item in loaded_descriptors} == EXPECTED_DESCRIPTOR_IDS
    assert all(item.descriptor.source == DescriptorSource.SHIPPED for item in loaded_descriptors)
    assert all(item.descriptor.verified is True for item in loaded_descriptors)


def test_shipped_descriptors_live_under_expected_service_categories() -> None:
    """Each shipped descriptor should live under a non-auto-generated category path."""
    loaded_descriptors = load_service_descriptors([SERVICES_DIR])

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
    }


def test_shipped_pihole_descriptor_declares_dns_target() -> None:
    """The shipped catalog should include explicit DNS metadata where intended."""
    loaded_descriptors = load_service_descriptors([SERVICES_DIR])
    pihole = next(item for item in loaded_descriptors if item.descriptor.id == "pihole")

    assert len(pihole.descriptor.dns_targets) == 1
    assert pihole.descriptor.dns_targets[0].host == "pi.hole"
    assert pihole.descriptor.dns_targets[0].record_type == DnsRecordType.A
