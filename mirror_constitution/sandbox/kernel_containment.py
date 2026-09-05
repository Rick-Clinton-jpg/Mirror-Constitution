"""Wrap a real agent subprocess invocation in kernel-enforced containment,
independent of and underneath the governor's own tool-call mediation.

    prlimit  -- hard resource limits: CPU time, address-space size, open
                file descriptors, process/thread count, no core dumps.
    unshare  -- new PID, network, UTS, IPC, and mount namespaces. The new
                network namespace has no configured interfaces (not even
                a routable loopback), so the agent has no path to any
                real network even if it tried; the new PID namespace
                means it cannot see or signal any real host process.
    (shell)  -- makes the new mount namespace's root filesystem read-only
                (after first marking it private, so the remount can never
                propagate back to the host's real root).
    setpriv  -- drops to an unprivileged uid/gid, clears supplementary
                groups, and clears both the inheritable and bounding
                capability sets, then sets no_new_privs so none of this
                can be regained even via a setuid binary.

The agent process itself then self-installs a seccomp-bpf syscall filter
(``kernel_lockdown.lockdown_agent_process``) once it has finished
importing everything it needs -- see that module. None of this depends on
the governor's own mediation code being bug-free: an agent that bypassed
the stdin/stdout pipe protocol entirely and tried raw syscalls is stopped
here, by the kernel, not by our Python.
"""

from __future__ import annotations

import shlex
import shutil
from dataclasses import dataclass

REQUIRED_TOOLS = ("prlimit", "unshare", "setpriv", "sh")


class KernelContainmentUnavailable(RuntimeError):
    """One or more required system tools (util-linux's prlimit/unshare/
    setpriv, or /bin/sh) are missing, so hardened execution cannot
    proceed. Raised instead of silently falling back to an unhardened
    subprocess launch.
    """


def available() -> bool:
    return all(shutil.which(tool) for tool in REQUIRED_TOOLS)


def require_available() -> None:
    missing = [tool for tool in REQUIRED_TOOLS if not shutil.which(tool)]
    if missing:
        raise KernelContainmentUnavailable(
            f"kernel containment requires these tools on PATH: {missing}"
        )


@dataclass(frozen=True)
class HardenedProcessConfig:
    uid: int = 65534
    gid: int = 65534
    cpu_seconds: int = 5
    memory_bytes: int = 256 * 1024 * 1024
    nofile: int = 64
    nproc: int = 32


def build_hardened_argv(
    python_executable: str,
    script_path: str,
    config: HardenedProcessConfig = HardenedProcessConfig(),
) -> list[str]:
    """Return the full argv chain: prlimit -> unshare(new namespaces) ->
    read-only root -> setpriv -> python script_path.

    Raises ``KernelContainmentUnavailable`` if a required tool is missing.
    """
    require_available()

    inner_shell = (
        "mount --make-rprivate / && "
        "mount -o remount,bind,ro / && "
        "exec setpriv "
        f"--reuid {config.uid} --regid {config.gid} --clear-groups "
        "--inh-caps=-all --bounding-set=-all --no-new-privs -- "
        f"{shlex.quote(python_executable)} {shlex.quote(script_path)}"
    )

    return [
        "prlimit",
        f"--cpu={config.cpu_seconds}",
        f"--as={config.memory_bytes}",
        f"--nofile={config.nofile}",
        f"--nproc={config.nproc}",
        "--core=0",
        "--",
        "unshare",
        "--pid",
        "--net",
        "--uts",
        "--ipc",
        "--mount",
        "--fork",
        "--",
        "sh",
        "-c",
        inner_shell,
    ]
