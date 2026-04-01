"""Minimal two-process supervisor for the packaged Kaval container."""

from __future__ import annotations

import grp
import os
import pwd
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

_CORE_USER = "kaval"
_EXECUTOR_USER = "kaval-exec"
_SOCKET_GROUP = "kaval-ipc"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """UNIX identity information for one supervised child process."""

    uid: int
    gid: int
    supplementary_gids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ChildProcessSpec:
    """Configuration for one supervised child process."""

    name: str
    argv: tuple[str, ...]
    identity: ProcessIdentity


@dataclass(frozen=True, slots=True)
class SupervisorConfig:
    """Filesystem and user configuration for the packaged runtime."""

    runtime_dir: Path = Path("/run/kaval")
    docker_socket_path: Path = Path("/var/run/docker.sock")
    socket_group_name: str = _SOCKET_GROUP

    @classmethod
    def from_env(cls) -> "SupervisorConfig":
        """Build supervisor settings from the packaged runtime environment."""
        return cls(
            runtime_dir=Path(os.environ.get("KAVAL_RUNTIME_DIR", "/run/kaval")),
            docker_socket_path=Path(
                os.environ.get("KAVAL_DOCKER_SOCKET", "/var/run/docker.sock")
            ),
        )


def prepare_runtime_directory(path: Path, *, group_gid: int) -> None:
    """Create the shared executor-socket runtime directory with group access."""
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, 0, group_gid)
    os.chmod(path, 0o2770)


def docker_socket_group_id(socket_path: Path) -> int:
    """Return the actual GID of the mounted Docker daemon socket."""
    return socket_path.stat().st_gid


def build_child_process_specs(config: SupervisorConfig) -> tuple[ChildProcessSpec, ...]:
    """Return the supervised core/executor process specifications."""
    socket_group_gid = grp.getgrnam(config.socket_group_name).gr_gid
    docker_group_gid = docker_socket_group_id(config.docker_socket_path)
    core_entry = pwd.getpwnam(_CORE_USER)
    executor_entry = pwd.getpwnam(_EXECUTOR_USER)
    return (
        ChildProcessSpec(
            name="kaval-core",
            argv=("kaval-core",),
            identity=ProcessIdentity(
                uid=core_entry.pw_uid,
                gid=core_entry.pw_gid,
                supplementary_gids=(socket_group_gid,),
            ),
        ),
        ChildProcessSpec(
            name="kaval-executor",
            argv=("kaval-executor",),
            identity=ProcessIdentity(
                uid=executor_entry.pw_uid,
                gid=executor_entry.pw_gid,
                supplementary_gids=(socket_group_gid, docker_group_gid),
            ),
        ),
    )


def _drop_privileges(identity: ProcessIdentity) -> None:
    """Switch the current process to the requested uid/gid combination."""
    os.setgroups(list(identity.supplementary_gids))
    os.setgid(identity.gid)
    os.setuid(identity.uid)


def _start_child_process(spec: ChildProcessSpec) -> subprocess.Popen[bytes]:
    """Spawn one supervised child process with the configured UNIX identity."""
    return subprocess.Popen(
        spec.argv,
        preexec_fn=lambda: _drop_privileges(spec.identity),
    )


def run_supervisor(config: SupervisorConfig) -> int:
    """Run the two-process packaged runtime until one child exits."""
    if os.getuid() != 0:
        msg = "kaval-supervisor must start as root so it can drop privileges per child process"
        raise RuntimeError(msg)

    socket_group_gid = grp.getgrnam(config.socket_group_name).gr_gid
    prepare_runtime_directory(config.runtime_dir, group_gid=socket_group_gid)
    child_specs = build_child_process_specs(config)
    processes = {
        spec.name: _start_child_process(spec)
        for spec in child_specs
    }
    try:
        while True:
            for name, process in processes.items():
                exit_code = process.poll()
                if exit_code is not None:
                    _stop_remaining_processes(processes, exclude=name)
                    return exit_code
            time.sleep(0.5)
    except KeyboardInterrupt:
        _stop_remaining_processes(processes)
        return 0


def _stop_remaining_processes(
    processes: dict[str, subprocess.Popen[bytes]],
    *,
    exclude: str | None = None,
) -> None:
    """Terminate all supervised children except an optional already-exited one."""
    for name, process in processes.items():
        if name == exclude or process.poll() is not None:
            continue
        process.send_signal(signal.SIGTERM)
    deadline = time.monotonic() + 5.0
    for name, process in processes.items():
        if name == exclude or process.poll() is not None:
            continue
        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)


def main() -> int:
    """Launch the packaged two-process runtime."""
    return run_supervisor(SupervisorConfig.from_env())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
