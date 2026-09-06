"""Direct unit tests for RealGovernor's reflective capability-request
handling -- no subprocess needed, since these are plain governor methods.
Complements tests/test_real_sandbox.py's full end-to-end run.
"""

import json
import os

from mirror_constitution.sandbox.governor_process import RealGovernor


def test_ungated_request_is_reflected_not_granted_for_real(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    resp = gov._request_capability("agent-x", "exec:shell")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" not in gov.agent_capabilities.get("agent-x", set())

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert len(transitions) == 1
    assert transitions[0]["action"] == "reflected:request_capability:exec:shell"
    assert transitions[0]["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[transitions[0]["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]


def test_wrong_dual_token_is_reflected_not_granted_for_real(tmp_path):
    """A wrong token is not the same failure mode as no token at all: this
    checks that a fabricated token never grants authority, not
    just a truthiness check that any non-empty string would pass.
    """
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    resp = gov._request_capability("agent-x", "exec:shell", "WRONG-TOKEN")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" not in gov.agent_capabilities.get("agent-x", set())

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert len(transitions) == 1
    assert transitions[0]["action"] == "reflected:request_capability:exec:shell"
    assert transitions[0]["authorized_grant"] == []

    dst_states = {e["id"]: e for e in events if e.get("type") == "state"}
    dst = dst_states[transitions[0]["dst"]]
    assert dst["is_mirror"] is True
    assert dst["apparent_success"] is not None
    assert "exec:shell" not in dst["capabilities"]


def test_correct_dual_token_grants_for_real(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)

    token = gov.issue_authorization("agent-x", "network:egress")
    resp = gov._request_capability("agent-x", "network:egress", token)
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "network:egress"}
    assert "network:egress" in gov.agent_capabilities["agent-x"]  # genuinely held now

    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]

    transitions = [e for e in events if e.get("type") == "transition"]
    assert transitions[0]["action"] == "request_capability"
    assert transitions[0]["authorized_grant"] == ["network:egress"]


def test_already_held_capability_short_circuits(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False)
    gov.grant_base_capabilities("agent-x", {"fs:read"})

    resp = gov._request_capability("agent-x", "fs:read")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "fs:read"}
    with open(trace_path, "r", encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    # no new transition was recorded -- it was already legitimately held
    assert not any(e.get("type") == "transition" for e in events)


def test_dual_auth_can_be_disabled_on_the_real_governor(tmp_path):
    trace_path = os.path.join(str(tmp_path), "trace.jsonl")
    gov = RealGovernor(str(tmp_path), trace_path, mirror_port=1, harden=False,
                       dual_auth_required=False, enforce_policy=False)

    resp = gov._request_capability("agent-x", "exec:shell")
    gov.close()

    assert resp == {"ok": True, "granted": True, "capability": "exec:shell"}
    assert "exec:shell" in gov.agent_capabilities["agent-x"]  # granted for real, no token needed
