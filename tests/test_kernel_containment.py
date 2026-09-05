"""Prove the kernel containment layer, independent of the governor's own
tool-call mediation: these two agent scripts never call
``agent_runtime.request`` at all -- they attempt a raw filesystem write
and a raw network connection directly, exactly what a compromised or
buggy agent might try if the governor's mediation code had a bug. If
kernel containment is doing real work, both are stopped by the kernel
before the governor's Python ever gets a say.
"""

import os
import tempfile

import pytest

from mirror_constitution.sandbox.governor_process import AgentKilledByKernel, RealGovernor
from mirror_constitution.sandbox.kernel_containment import available as containment_available

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
AGENTS_DIR = os.path.join(EXAMPLES_DIR, "sandbox_agents")

pytestmark = pytest.mark.skipif(
    not containment_available(),
    reason="kernel containment requires prlimit/unshare/setpriv/sh on PATH",
)


def _governor(tmp_path) -> RealGovernor:
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    return RealGovernor(str(tmp_path), trace_path, mirror_port=1)


def test_raw_filesystem_escape_is_killed_by_the_kernel(tmp_path):
    marker = "/tmp/raw-escape-proof.txt"
    if os.path.exists(marker):
        os.remove(marker)

    gov = _governor(tmp_path)
    try:
        with pytest.raises(AgentKilledByKernel):
            gov.run_agent(
                "raw-escape-agent",
                os.path.join(AGENTS_DIR, "raw_fs_escape_agent.py"),
            )
    finally:
        gov.close()

    # The write never reached the real host filesystem.
    assert not os.path.exists(marker)


def test_raw_network_escape_is_killed_by_the_kernel(tmp_path):
    gov = _governor(tmp_path)
    try:
        with pytest.raises(AgentKilledByKernel):
            gov.run_agent(
                "raw-network-agent",
                os.path.join(AGENTS_DIR, "raw_network_escape_agent.py"),
            )
    finally:
        gov.close()


def test_unhardened_mode_lets_the_raw_escape_through(tmp_path):
    # Contrast case: with no governor-level hardening and no self-applied
    # seccomp filter, the same style of raw filesystem write actually
    # succeeds -- proving the previous two tests are exercising real
    # enforcement, not something that would have failed regardless.
    marker = "/tmp/raw-escape-proof.txt"
    if os.path.exists(marker):
        os.remove(marker)

    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)
    try:
        gov.run_agent(
            "raw-escape-agent-unhardened",
            os.path.join(AGENTS_DIR, "raw_fs_escape_agent_unlocked.py"),
        )
    finally:
        gov.close()

    assert os.path.exists(marker)
    os.remove(marker)


def test_kernel_containment_required_by_default(tmp_path, monkeypatch):
    import shutil

    import mirror_constitution.sandbox.kernel_containment as kc

    monkeypatch.setattr(shutil, "which", lambda tool: None)
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    with pytest.raises(kc.KernelContainmentUnavailable):
        RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=True)
