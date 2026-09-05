from mirror_constitution.invariants.channel import ResourceAccess, check_channel_non_emergence


def test_no_shared_resource_traffic_is_clean():
    accesses = [
        ResourceAccess("agent-1", "repo-a", "write", seq=1),
        ResourceAccess("agent-2", "repo-b", "read", seq=2),
    ]
    assert check_channel_non_emergence(accesses) == []


def test_undeclared_write_then_read_is_an_emergent_channel():
    # Two agents in individually isolated sandboxes, never declared as
    # related, discover a shared repo and leave notes for each other in it.
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
        ResourceAccess("agent-2", "shared-repo", "write", seq=3),
        ResourceAccess("agent-1", "shared-repo", "read", seq=4),
    ]
    violations = check_channel_non_emergence(accesses)
    assert len(violations) == 1
    assert violations[0].message_count == 2
    assert {violations[0].agent_a, violations[0].agent_b} == {"agent-1", "agent-2"}


def test_declared_relationship_is_not_flagged():
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
    ]
    declared = frozenset({frozenset({"agent-1", "agent-2"})})
    assert check_channel_non_emergence(accesses, declared_relationships=declared) == []


def test_no_individual_agent_exceeds_its_own_scoped_access_yet_channel_still_flagged():
    # Neither agent does anything outside its own legitimate read/write
    # access to the resource -- the violation is purely topological.
    accesses = [
        ResourceAccess("agent-1", "shared-repo", "write", seq=1),
        ResourceAccess("agent-2", "shared-repo", "read", seq=2),
    ]
    violations = check_channel_non_emergence(accesses)
    assert len(violations) == 1
