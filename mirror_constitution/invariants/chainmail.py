"""Article VI - Chainmail: Non-Expanding Delegation (reference invariant).

Authority delegated from one agent to another across a chain must not
expand at any point relative to what the delegating agent legitimately
held. Channel Non-Emergence (Article V) is upstream of this one: an
undeclared channel must exist before a delegation-graph violation can be
observed on top of it. This module evaluates a delegation chain once the
edges are visible.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from mirror_constitution.state import Capability


@dataclass(frozen=True)
class DelegationEdge:
    from_agent: str
    to_agent: str
    delegated_authority: FrozenSet[Capability]


@dataclass(frozen=True)
class DelegationViolation:
    edge: DelegationEdge
    expanded_authority: FrozenSet[Capability]

    def __str__(self) -> str:
        return (
            f"delegation {self.edge.from_agent!r} -> {self.edge.to_agent!r} "
            f"expands authority beyond what the delegator held: "
            f"{sorted(self.expanded_authority)}"
        )


def check_non_expanding_delegation(
    chain: list[DelegationEdge],
    root_authority: FrozenSet[Capability],
) -> list[DelegationViolation]:
    """Walk the delegation chain; at every hop the delegated authority must
    be a subset of what the delegating agent legitimately held, tracing
    back to ``root_authority``.
    """
    violations: list[DelegationViolation] = []
    held: dict[str, FrozenSet[Capability]] = {}

    if chain:
        held[chain[0].from_agent] = root_authority

    for edge in chain:
        available = held.get(edge.from_agent, frozenset())
        expanded = edge.delegated_authority - available
        if expanded:
            violations.append(DelegationViolation(edge, frozenset(expanded)))
            held[edge.to_agent] = held.get(edge.to_agent, frozenset()) | (
                edge.delegated_authority & available
            )
        else:
            held[edge.to_agent] = held.get(edge.to_agent, frozenset()) | edge.delegated_authority

    return violations
