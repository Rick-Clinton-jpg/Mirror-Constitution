import json

import pytest

from mirror_constitution.sandbox.governor_process import RealGovernor


@pytest.fixture
def governor(tmp_path):
    gov = RealGovernor(str(tmp_path / "sandbox"), str(tmp_path / "trace.jsonl"), 1, harden=False)
    yield gov
    gov.close()


def test_no_capabilities_means_no_host_effect(governor, tmp_path):
    request = {"op": "write_resource", "resource": "owned", "content": "x"}
    assert not governor._handle("attacker", request)["ok"]
    assert not (tmp_path / "sandbox/resources/owned").exists()
    events = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    assert events[-1]["type"] == "operation_denied"


def test_capability_label_does_not_authorize_every_resource(governor):
    governor.grant_base_capabilities("alice", {"fs:read", "fs:write"})
    governor.grant_resource_access("alice", "own", frozenset({"read", "write"}))
    assert governor._handle("alice", {"op": "write_resource", "resource": "own", "content": "safe"})["ok"]
    assert governor._handle("alice", {"op": "read_resource", "resource": "own"})["content"] == "safe"
    assert not governor._handle("alice", {"op": "write_resource", "resource": "other", "content": "x"})["ok"]
    governor.grant_base_capabilities("bob", {"fs:read", "fs:write"})
    assert not governor._handle("bob", {"op": "read_resource", "resource": "own"})["ok"]
    assert not governor._handle("bob", {"op": "write_resource", "resource": "own", "content": "x"})["ok"]


def test_shared_resource_requires_explicit_relationship(governor):
    governor.grant_resource_access("alice", "shared", frozenset({"write"}))
    with pytest.raises(ValueError, match="relationship"):
        governor.grant_resource_access("bob", "shared", frozenset({"read"}))
    governor.declare_relationship("alice", "bob")
    governor.grant_resource_access("bob", "shared", frozenset({"read"}))
    governor.grant_base_capabilities("alice", {"fs:write"})
    governor.grant_base_capabilities("bob", {"fs:read"})
    assert governor._handle("alice", {"op": "write_resource", "resource": "shared", "content": "hello"})["ok"]
    assert governor._handle("bob", {"op": "read_resource", "resource": "shared"})["content"] == "hello"
    assert not governor._handle("bob", {"op": "write_resource", "resource": "shared", "content": "x"})["ok"]


def test_backing_state_queries_denied_before_network(governor, monkeypatch):
    def forbidden(*args):
        raise AssertionError("network must not be contacted")
    monkeypatch.setattr(governor, "_differential_query", forbidden)
    governor.grant_base_capabilities("attacker", {"network:egress", "mirror:query"})
    assert not governor._handle("attacker", {"op": "differential_query", "query": "secret", "backing": "host"})["ok"]


def test_delegation_requires_permission_relationship_and_subset(governor):
    request = {"op": "delegate", "to_agent": "bob", "authority": ["fs:read"]}
    governor.grant_base_capabilities("alice", {"fs:read"})
    governor.declare_relationship("alice", "bob")
    assert not governor._handle("alice", request)["ok"]
    governor.grant_base_capabilities("alice", {"delegate"})
    assert not governor._handle("alice", {**request, "to_agent": "eve"})["ok"]
    assert not governor._handle("alice", {**request, "authority": ["exec:shell"]})["ok"]
    assert governor._handle("alice", request)["ok"]
    assert governor.agent_capabilities["bob"] == {"fs:read"}


def test_public_token_cannot_grant_or_create_effects(governor):
    governor._handle("attacker", {"op": "request_capability", "capability": "fs:write", "dual_token": "DUAL-AUTH-APPROVED"})
    assert "fs:write" not in governor.agent_capabilities.get("attacker", set())
    assert not governor._handle("attacker", {"op": "write_resource", "resource": "owned", "content": "x"})["ok"]


def test_control_plane_approval_is_exact_expiring_and_single_use(governor, monkeypatch):
    monkeypatch.setattr("mirror_constitution.authorization.time.monotonic", lambda: 100)
    governor.approve_capability("alice", "fs:read", ttl_seconds=1)
    governor._request_capability("bob", "fs:read")
    governor._request_capability("alice", "fs:write")
    assert not governor.agent_capabilities["bob"]
    assert not governor.agent_capabilities["alice"]
    governor._request_capability("alice", "fs:read")
    assert governor.agent_capabilities["alice"] == {"fs:read"}
    governor.agent_capabilities["alice"].clear()
    governor._request_capability("alice", "fs:read")
    assert not governor.agent_capabilities["alice"]
    governor.approve_capability("alice", "fs:write", ttl_seconds=1)
    monkeypatch.setattr("mirror_constitution.authorization.time.monotonic", lambda: 101)
    governor._request_capability("alice", "fs:write")
    assert not governor.agent_capabilities["alice"]


def test_legacy_bypass_switch_is_not_allowed_with_enforcement(tmp_path):
    with pytest.raises(ValueError, match="demonstration"):
        RealGovernor(str(tmp_path), str(tmp_path / "trace"), 1, harden=False, dual_auth_required=False)
