"""Self-applied seccomp-bpf syscall filter for a real agent process.

Call ``lockdown_agent_process()`` only after every import the rest of the
process will ever need has already happened. Once the filter is loaded,
any syscall outside the fixed allow-list below kills the process
immediately (SIGSYS) -- including further imports, opening a file,
opening a socket, ptrace, or any namespace/mount syscall. The allow-list
is exactly what a process that talks to its parent over already-open
stdin/stdout pipes and then exits needs, plus the handful of syscalls
CPython's own runtime uses for buffering, memory management, and
shutdown. This holds even if the agent's own Python code is buggy or
compromised: the kernel enforces it, independent of the governor's own
mediation logic.
"""

from __future__ import annotations

import os
import sys

import pyseccomp as seccomp

_ALLOWED_SYSCALLS = (
    "read", "write", "close",                # the stdin/stdout pipe protocol
    "exit", "exit_group", "rt_sigreturn",     # process shutdown
    "fstat", "lseek", "ioctl",                # CPython's own stdio buffering
    "brk", "mmap", "munmap",                  # CPython's own memory management
    "sigaltstack", "rseq",                    # CPython/glibc startup housekeeping
)

_installed = False


def lockdown_agent_process() -> None:
    """Install the seccomp filter on the calling process. Idempotent."""
    global _installed
    if _installed:
        return

    filt = seccomp.SyscallFilter(defaction=seccomp.KILL)
    for name in _ALLOWED_SYSCALLS:
        filt.add_rule(seccomp.ALLOW, name)
    filt.load()
    _installed = True


def exit_locked_down(code: int = 0) -> None:
    """The only safe way to end a process after ``lockdown_agent_process``:
    CPython's normal interpreter shutdown (atexit handlers, finalizers,
    buffer teardown) issues syscalls outside the allow-list above and gets
    the process SIGKILLed by the filter. ``os._exit`` skips all of that and
    goes straight to the kernel's exit_group syscall, which is allowed.
    Always flush stdout first -- there is no finalizer left to do it after.
    """
    sys.stdout.flush()
    os._exit(code)
