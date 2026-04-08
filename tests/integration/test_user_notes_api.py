"""Integration tests for the Phase 3B user-notes API surface."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from kaval.api import create_app


def test_memory_notes_api_supports_full_lifecycle(tmp_path: Path) -> None:
    """The note API should support create, update, version history, archive, and delete."""
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        create_response = client.post(
            "/api/v1/memory/notes",
            json={
                "service_id": "svc-delugevpn",
                "note": "Restart DelugeVPN only after checking the VPN tunnel.",
                "safe_for_model": True,
            },
        )
        assert create_response.status_code == 201
        created_note = create_response.json()
        note_id = created_note["id"]
        assert created_note["service_id"] == "svc-delugevpn"
        assert created_note["safe_for_model"] is True

        list_response = client.get("/api/v1/memory/notes", params={"service_id": "svc-delugevpn"})
        assert list_response.status_code == 200
        assert [note["id"] for note in list_response.json()] == [note_id]

        update_response = client.patch(
            f"/api/v1/memory/notes/{note_id}",
            json={
                "note": "Restart DelugeVPN only after checking the VPN tunnel and DNS route.",
                "safe_for_model": False,
                "stale": True,
            },
        )
        assert update_response.status_code == 200
        updated_note = update_response.json()
        assert updated_note["note"].endswith("DNS route.")
        assert updated_note["safe_for_model"] is False
        assert updated_note["stale"] is True

        versions_response = client.get(f"/api/v1/memory/notes/{note_id}/versions")
        assert versions_response.status_code == 200
        versions_payload = versions_response.json()
        assert [
            (version["version_number"], version["current"])
            for version in versions_payload
        ] == [(1, False), (2, True)]
        assert versions_payload[0]["note"]["note"] == created_note["note"]
        assert versions_payload[1]["note"]["note"] == updated_note["note"]

        archive_response = client.post(f"/api/v1/memory/notes/{note_id}/archive")
        assert archive_response.status_code == 200
        archived_version = archive_response.json()
        assert archived_version["version_number"] == 2
        assert archived_version["archived"] is True
        assert archived_version["current"] is True

        active_notes_response = client.get("/api/v1/memory/notes")
        legacy_notes_response = client.get("/api/v1/user-notes")
        assert active_notes_response.status_code == 200
        assert legacy_notes_response.status_code == 200
        assert active_notes_response.json() == []
        assert legacy_notes_response.json() == []

        archived_versions_response = client.get(f"/api/v1/memory/notes/{note_id}/versions")
        assert archived_versions_response.status_code == 200
        assert [
            (version["version_number"], version["current"], version["archived"])
            for version in archived_versions_response.json()
        ] == [(1, False, False), (2, True, True)]

        delete_response = client.delete(f"/api/v1/memory/notes/{note_id}")
        assert delete_response.status_code == 204
        assert delete_response.text == ""

        deleted_versions_response = client.get(f"/api/v1/memory/notes/{note_id}/versions")
        assert deleted_versions_response.status_code == 404
        assert deleted_versions_response.json() == {
            "detail": f"user note not found: {note_id}"
        }


def test_memory_notes_api_rejects_empty_patch_and_missing_note_actions(tmp_path: Path) -> None:
    """The note API should validate PATCH bodies and missing-note mutations."""
    app = create_app(database_path=tmp_path / "kaval.db")

    with TestClient(app) as client:
        empty_patch_response = client.patch("/api/v1/memory/notes/note-missing", json={})
        assert empty_patch_response.status_code == 422

        missing_patch_response = client.patch(
            "/api/v1/memory/notes/note-missing",
            json={"note": "Updated note."},
        )
        assert missing_patch_response.status_code == 404
        assert missing_patch_response.json() == {
            "detail": "user note not found: note-missing"
        }

        missing_archive_response = client.post("/api/v1/memory/notes/note-missing/archive")
        assert missing_archive_response.status_code == 404
        assert missing_archive_response.json() == {
            "detail": "user note not found: note-missing"
        }

        missing_delete_response = client.delete("/api/v1/memory/notes/note-missing")
        assert missing_delete_response.status_code == 404
        assert missing_delete_response.json() == {
            "detail": "user note not found: note-missing"
        }
