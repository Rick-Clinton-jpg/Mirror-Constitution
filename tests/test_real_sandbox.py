"""End-to-end integration test: run the real sandbox (real OS
subprocesses, real disk I/O, a real HTTP server) and check that the
engine catches the same violations against a genuinely executed trace
that it catches against hand-authored ones.

This is slower than the unit tests (it spawns seven real subprocesses and
a real HTTP server) but exercises the actual ingestion path a real
deployment would use: RealGovernor -> trace.jsonl on real disk ->
MirrorConstitutionEngine.from_trace().
"""

import importlib.util
import json
import os
import sys

import pytest

from mirror_constitution.engine import MirrorConstitutionEngine
from mirror_constitution.sandbox.kernel_containment import available as containment_available

pytestmark = pytest.mark.skipif(
    not containment_available(), reason="requires working Linux namespaces and seccomp"
)

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _load_run_real_sandbox():
    spec = importlib.util.spec_from_file_location(
        "run_real_sandbox", os.path.join(EXAMPLES_DIR, "run_real_sandbox.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_sandbox_produces_the_expected_breach(tmp_path):
    run_real_sandbox = _load_run_real_sandbox()

    trace_path = run_real_sandbox.run(str(tmp_path))
    assert os.path.exists(trace_path)

    with open(trace_path, "r", encoding="utf-8") as f:
        raw_lines = [line for line in f if line.strip()]
    assert len(raw_lines) > 0  # the trace was actually written by real execution

    report = MirrorConstitutionEngine.from_trace(trace_path).run()
    status = report.article_status()

    # Article I: escalate-agent's ungated exec:shell request is reflected
    # (zero real capability gained, recorded as a mirror state), and
    # ops-agent's dual-authorized network:egress request is a real grant
    # with a matching authorized_grant -- both clean under the check.
    assert status["I_authority_monotonicity"] is True
    # Article II: no strand-crossing was set up in this scenario, nothing to fail.
    assert status["II_mirror_weave"] is None
    # Article III: the real HTTP round trips to the real Answered Mirror
    # produced genuinely different responses for the same query. (The
    # reflected capability request's synthetic facts don't trip this --
    # they're recorded as disclosed_grant, an intentional reflection, not
    # an undisclosed leak.)
    assert status["III_confidentiality_monotonicity"] is False
    # Article IV: no evidence records were part of this scenario.
    assert status["IV_evaluator_trust_integrity"] is None
    # Article V: two real, separately-invoked agent processes exchanged
    # real messages via a real shared file on disk.
    assert status["V_channel_non_emergence"] is False
    # Article VI: the real delegation request handed over more than the
    # sandbox's declared root authority.
    assert status["VI_chainmail_non_expanding_delegation"] is False

    assert not report.passed()


def test_reflected_capability_request_looks_identical_to_a_real_grant(tmp_path):
    """The whole point of reflection: the agent-facing response for the
    ungated exec:shell request and the dual-authorized network:egress
    request must be indistinguishable, even though only one is real. Only
    the trace tells them apart.
    """
    run_real_sandbox = _load_run_real_sandbox()
    trace_path = run_real_sandbox.run(str(tmp_path))

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    reflected = next(
        e
        for e in events
        if e.get("type") == "transition" and e["action"].startswith("reflected:request_capability")
    )
    real_grant = next(
        e
        for e in events
        if e.get("type") == "transition" and e["action"] == "request_capability"
    )

    assert reflected["authorized_grant"] == []
    assert real_grant["authorized_grant"] == ["network:egress"]

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    reflected_dst = dst_states[reflected["dst"]]
    assert reflected_dst["is_mirror"] is True
    assert reflected_dst["apparent_success"] is not None
    assert "exec:shell" not in reflected_dst["capabilities"]  # never actually gained


def test_wrong_token_escalation_is_reflected_not_granted(tmp_path):
    """escalate_agent_wrong_token.py presents a token that is simply
    incorrect (not missing). This is a distinct case from no token at all:
    it proves the real governor, running against a genuine subprocess,
    rejects an invalid token rather than treating any non-empty string as
    good enough.
    """
    run_real_sandbox = _load_run_real_sandbox()
    trace_path = run_real_sandbox.run(str(tmp_path))

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    wrong_token_transition = next(
        e
        for e in events
        if e.get("type") == "transition" and e.get("agent_id") == "escalate-agent-wrong-token"
    )
    assert wrong_token_transition["action"] == "reflected:request_capability:exec:shell"
    assert wrong_token_transition["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[wrong_token_transition["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]
