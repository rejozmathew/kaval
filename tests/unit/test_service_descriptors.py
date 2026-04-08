"""Unit tests for the Phase 1 service descriptor schema and loader."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from kaval.discovery.descriptors import (
    DescriptorLoadError,
    build_auto_generated_descriptor_path,
    build_service_descriptor_community_export,
    discover_descriptor_files,
    load_auto_generated_service_descriptors,
    load_service_descriptor,
    load_service_descriptors,
    loaded_descriptor_identifier,
    write_auto_generated_descriptor,
    write_user_descriptor,
)
from kaval.models import DescriptorSource, DnsRecordType, DnsTarget

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "descriptors"
SERVICES_DIR = Path(__file__).resolve().parents[2] / "services"


def test_load_service_descriptor_from_yaml_fixture() -> None:
    """A valid YAML descriptor should load into the strict descriptor model."""
    loaded = load_service_descriptor(FIXTURES_DIR / "radarr.yaml")

    assert loaded.descriptor.id == "radarr"
    assert loaded.descriptor.source == DescriptorSource.SHIPPED
    assert loaded.descriptor.match.image_patterns[0] == "lscr.io/linuxserver/radarr*"
    assert loaded.descriptor.endpoints["health_api"].auth_header == "X-Api-Key"
    assert len(loaded.descriptor.inspection.surfaces) == 6
    assert loaded.descriptor.inspection.surfaces[0].id == "health_api"
    assert loaded.descriptor.inspection.surfaces[2].id == "download_clients"
    assert loaded.descriptor.inspection.surfaces[5].id == "queue_details"
    assert loaded.descriptor.inspection.surfaces[0].confidence_effect is not None
    assert loaded.descriptor.credential_hints["api_key"].description == "Radarr API Key"
    assert loaded.descriptor.credential_hints["api_key"].prompt is not None


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


def test_load_service_descriptor_rejects_procedural_inspection_fields(
    tmp_path: Path,
) -> None:
    """Inspection declarations must reject procedural adapter logic in YAML."""
    descriptor_path = tmp_path / "radarr.yaml"
    fixture_text = (FIXTURES_DIR / "radarr.yaml").read_text(encoding="utf-8")
    descriptor_path.write_text(
        fixture_text.replace(
            '      version_range: ">=3.0"\n',
            '      version_range: ">=3.0"\n'
            "      selectors:\n"
            '        - ".health-table"\n',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(DescriptorLoadError, match="descriptor validation failed"):
        load_service_descriptor(descriptor_path)


def test_load_service_descriptors_prefers_user_overrides_and_skips_auto_generated(
    tmp_path: Path,
) -> None:
    """Active loads should prefer user overrides while ignoring quarantined drafts."""
    descriptor_root = tmp_path / "services"
    shipped_dir = descriptor_root / "arr"
    auto_generated_dir = descriptor_root / "auto_generated" / "arr"
    shipped_dir.mkdir(parents=True)
    auto_generated_dir.mkdir(parents=True)
    shipped_path = shipped_dir / "radarr.yaml"
    fixture_text = (FIXTURES_DIR / "radarr.yaml").read_text(encoding="utf-8")
    shipped_path.write_text(fixture_text, encoding="utf-8")
    (auto_generated_dir / "radarr.yaml").write_text(
        fixture_text.replace("source: shipped", "source: auto_generated", 1),
        encoding="utf-8",
    )

    loaded_shipped = load_service_descriptor(shipped_path)
    write_user_descriptor(
        services_dir=descriptor_root,
        descriptor=loaded_shipped.descriptor.model_copy(
            update={
                "name": "Radarr Override",
                "source": DescriptorSource.USER,
            }
        ),
    )

    loaded_descriptors = load_service_descriptors([descriptor_root])

    assert len(loaded_descriptors) == 1
    assert loaded_descriptor_identifier(loaded_descriptors[0]) == "arr/radarr"
    assert loaded_descriptors[0].descriptor.name == "Radarr Override"
    assert loaded_descriptors[0].descriptor.source == DescriptorSource.USER
    assert loaded_descriptors[0].path == descriptor_root / "user" / "arr" / "radarr.yaml"


def test_write_auto_generated_descriptor_uses_quarantine_tree(tmp_path: Path) -> None:
    """Generated descriptors should persist under services/auto_generated only."""
    descriptor_root = tmp_path / "services"
    loaded = load_service_descriptor(FIXTURES_DIR / "radarr.yaml")

    saved = write_auto_generated_descriptor(
        services_dir=descriptor_root,
        descriptor=loaded.descriptor.model_copy(
            update={
                "id": "custom_app",
                "name": "Custom App",
                "category": "custom",
                "source": DescriptorSource.AUTO_GENERATED,
                "verified": False,
            }
        ),
    )

    assert saved.path == build_auto_generated_descriptor_path(
        descriptor_root,
        saved.descriptor,
    )
    assert saved.path == descriptor_root / "auto_generated" / "custom" / "custom_app.yaml"
    assert saved.path.read_text(encoding="utf-8").find("source: auto_generated") != -1


def test_load_auto_generated_service_descriptors_only_reads_quarantine_tree(
    tmp_path: Path,
) -> None:
    """Quarantine loads should read only auto-generated descriptor drafts."""
    descriptor_root = tmp_path / "services"
    shipped_dir = descriptor_root / "arr"
    auto_generated_dir = descriptor_root / "auto_generated" / "custom"
    shipped_dir.mkdir(parents=True)
    auto_generated_dir.mkdir(parents=True)
    fixture_text = (FIXTURES_DIR / "radarr.yaml").read_text(encoding="utf-8")
    (shipped_dir / "radarr.yaml").write_text(fixture_text, encoding="utf-8")
    (auto_generated_dir / "custom_app.yaml").write_text(
        fixture_text
        .replace("id: radarr", "id: custom_app", 1)
        .replace("name: Radarr", "name: Custom App", 1)
        .replace("category: arr", "category: custom", 1)
        .replace("source: shipped", "source: auto_generated", 1)
        .replace("verified: true", "verified: false", 1),
        encoding="utf-8",
    )

    loaded_descriptors = load_auto_generated_service_descriptors([descriptor_root])

    assert len(loaded_descriptors) == 1
    assert loaded_descriptor_identifier(loaded_descriptors[0]) == "custom/custom_app"
    assert loaded_descriptors[0].path == auto_generated_dir / "custom_app.yaml"


def test_build_service_descriptor_community_export_omits_local_fields() -> None:
    """Community export should strip provenance and local-risk descriptor sections."""
    loaded = load_service_descriptor(FIXTURES_DIR / "radarr.yaml")
    export = build_service_descriptor_community_export(
        loaded.descriptor.model_copy(
            update={
                "source": DescriptorSource.USER,
                "verified": True,
                "generated_at": datetime(2026, 4, 8, 9, 30, tzinfo=UTC),
                "dns_targets": [
                    DnsTarget(
                        host="radarr.example.com",
                        record_type=DnsRecordType.A,
                        expected_values=["server.example.com"],
                    )
                ],
            }
        )
    )

    assert export.target_path == "services/arr/radarr.yaml"
    assert export.omitted_fields == (
        "source",
        "verified",
        "generated_at",
        "dns_targets",
        "inspection",
        "credential_hints",
    )
    assert "source:" not in export.yaml_text
    assert "verified:" not in export.yaml_text
    assert "generated_at:" not in export.yaml_text
    assert "dns_targets:" not in export.yaml_text
    assert "inspection:" not in export.yaml_text
    assert "credential_hints:" not in export.yaml_text


def test_shipped_pihole_descriptor_exposes_dns_target_metadata() -> None:
    """The shipped Pi-hole descriptor should declare its explicit DNS target."""
    descriptors = load_service_descriptors([SERVICES_DIR])
    pihole = next(item for item in descriptors if item.descriptor.id == "pihole")

    assert len(pihole.descriptor.dns_targets) == 1
    assert pihole.descriptor.dns_targets[0].host == "pi.hole"
    assert pihole.descriptor.dns_targets[0].record_type == DnsRecordType.A
    assert pihole.descriptor.dns_targets[0].expected_values == []
