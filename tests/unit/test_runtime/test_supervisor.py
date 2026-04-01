"""Unit tests for the packaged runtime supervisor helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from kaval.runtime import supervisor
from kaval.runtime.supervisor import SupervisorConfig


def test_prepare_runtime_directory_sets_group_permissions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The shared runtime directory should be sgid and group-writable."""
    chown_calls: list[tuple[str, int, int]] = []

    def fake_chown(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        uid: int,
        gid: int,
    ) -> None:
        chown_calls.append((os.fspath(path), uid, gid))

    monkeypatch.setattr(supervisor.os, "chown", fake_chown)
    runtime_dir = tmp_path / "run" / "kaval"

    supervisor.prepare_runtime_directory(runtime_dir, group_gid=4321)

    assert runtime_dir.exists()
    assert chown_calls == [(os.fspath(runtime_dir), 0, 4321)]
    assert runtime_dir.stat().st_mode & 0o7777 == 0o2770


def test_build_child_process_specs_uses_socket_and_docker_groups(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supervisor should keep Core off the Docker group and add it only to Executor."""

    class _Group:
        def __init__(self, gid: int) -> None:
            self.gr_gid = gid

    class _Passwd:
        def __init__(self, uid: int, gid: int) -> None:
            self.pw_uid = uid
            self.pw_gid = gid

    monkeypatch.setattr(supervisor.grp, "getgrnam", lambda _: _Group(2001))
    monkeypatch.setattr(
        supervisor.pwd,
        "getpwnam",
        lambda name: _Passwd(1001, 1001) if name == "kaval" else _Passwd(1002, 1002),
    )
    monkeypatch.setattr(supervisor, "docker_socket_group_id", lambda _: 3001)
    specs = supervisor.build_child_process_specs(
        SupervisorConfig(docker_socket_path=tmp_path / "docker.sock")
    )

    assert [spec.name for spec in specs] == ["kaval-core", "kaval-executor"]
    assert specs[0].identity.supplementary_gids == (2001,)
    assert specs[1].identity.supplementary_gids == (2001, 3001)
