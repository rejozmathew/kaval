"""Unit tests for the Phase 1 service descriptor schema and loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from kaval.discovery.descriptors import (
    DescriptorLoadError,
    discover_descriptor_files,
    load_service_descriptor,
    load_service_descriptors,
)
from kaval.models import DescriptorSource, DnsRecordType

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "descriptors"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def test_load_service_descriptor_from_yaml_fixture() -> None:
    """A valid YAML descriptor should load into the strict descriptor model."""
    loaded = load_service_descriptor(FIXTURES_DIR / "radarr.yaml")

    assert loaded.descriptor.id == "radarr"
    assert loaded.descriptor.source == DescriptorSource.SHIPPED
    assert loaded.descriptor.match.image_patterns[0] == "lscr.io/linuxserver/radarr*"
    assert loaded.descriptor.endpoints["health_api"].auth_header == "X-Api-Key"
    assert loaded.descriptor.credential_hints["api_key"].description == "Radarr API Key"


def test_discover_descriptor_files_ignores_gitkeep_and_loads_yaml(tmp_path: Path) -> None:
    """Descriptor discovery should recurse for YAML files and ignore placeholders."""
    descriptor_dir = tmp_path / "services" / "arr"
    descriptor_dir.mkdir(parents=True)
    (descriptor_dir / ".gitkeep").write_text("", encoding="utf-8")
    (descriptor_dir / "radarr.yaml").write_text(
        (FIXTURES_DIR / "radarr.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    discovered = discover_descriptor_files([tmp_path / "services"])

    assert discovered == [descriptor_dir / "radarr.yaml"]


def test_load_service_descriptors_rejects_duplicate_ids(tmp_path: Path) -> None:
    """Descriptor catalogs should fail fast on duplicate descriptor identifiers."""
    descriptor_root = tmp_path / "services"
    arr_dir = descriptor_root / "arr"
    downloads_dir = descriptor_root / "downloads"
    arr_dir.mkdir(parents=True)
    downloads_dir.mkdir(parents=True)
    fixture_text = (FIXTURES_DIR / "radarr.yaml").read_text(encoding="utf-8")
    (arr_dir / "radarr.yaml").write_text(fixture_text, encoding="utf-8")
    (downloads_dir / "radarr-copy.yaml").write_text(fixture_text, encoding="utf-8")

    with pytest.raises(DescriptorLoadError, match="duplicate descriptor ids"):
        load_service_descriptors([descriptor_root])


def test_shipped_pihole_descriptor_exposes_dns_target_metadata() -> None:
    """The shipped Pi-hole descriptor should declare its explicit DNS target."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    pihole = next(item for item in descriptors if item.descriptor.id == "pihole")

    assert len(pihole.descriptor.dns_targets) == 1
    assert pihole.descriptor.dns_targets[0].host == "pi.hole"
    assert pihole.descriptor.dns_targets[0].record_type == DnsRecordType.A
    assert pihole.descriptor.dns_targets[0].expected_values == []
