from mirror_constitution.invariants.chainmail import (
    DelegationEdge,
    check_non_expanding_delegation,
)


def test_non_expanding_chain_is_clean():
    chain = [
        DelegationEdge("root", "mid", frozenset({"read:file"})),
        DelegationEdge("mid", "leaf", frozenset({"read:file"})),
    ]
    assert check_non_expanding_delegation(chain, root_authority=frozenset({"read:file"})) == []


def test_expansion_mid_chain_is_flagged():
    # "middle management" agent issues an assignment granting authority it
    # never legitimately held itself.
    chain = [
        DelegationEdge("root", "mid", frozenset({"read:file"})),
        DelegationEdge("mid", "leaf", frozenset({"read:file", "exec:shell"})),
    ]
    violations = check_non_expanding_delegation(
        chain, root_authority=frozenset({"read:file"})
    )
    assert len(violations) == 1
    assert violations[0].expanded_authority == frozenset({"exec:shell"})


def test_expansion_at_root_is_flagged():
    chain = [DelegationEdge("root", "mid", frozenset({"exec:shell"}))]
    violations = check_non_expanding_delegation(chain, root_authority=frozenset())
    assert len(violations) == 1
