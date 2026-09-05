"""Mutant Mirrors and Answered Mirrors: the two constructs Mirror Box routes
agents through, per Article I's mechanism section.

A Mutant Mirror alters the environment's apparent structure without
granting authority. An Answered Mirror returns a requested answer or
apparent completion state while remaining inert unless separately and
explicitly authorized.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, FrozenSet, Optional

from mirror_constitution.state import Capability, Fact, State


@dataclass(frozen=True)
class MutantMirror:
    """Presents a real state under an altered apparent structure. Capability
    set is always empty or a strict subset of the real state's -- mutation
    changes appearance, never grants authority.
    """

    id: str
    real_state: State
    apparent_facts: FrozenSet[Fact]

    def render(self) -> State:
        return State(
            id=self.id,
            capabilities=frozenset(),
            knowledge=self.apparent_facts,
            is_mirror=True,
            backing_state_id=self.real_state.id,
        )


@dataclass(frozen=True)
class AnsweredMirror:
    """Answers a query by consulting real backing state, but the answer
    function must be reviewed under Article III: if ``answer_fn`` lets the
    response vary with backing state in a way that isn't explicitly
    disclosed, that variance is a confidentiality leak, not a capability
    leak, and check_differential_query_leak is what will catch it.
    """

    id: str
    real_state: State
    answer_fn: Callable[[str, State], str]

    def ask(self, query: str) -> str:
        return self.answer_fn(query, self.real_state)

    def render(self, revealed_facts: FrozenSet[Fact] = frozenset()) -> State:
        return State(
            id=self.id,
            capabilities=frozenset(),
            knowledge=revealed_facts,
            is_mirror=True,
            backing_state_id=self.real_state.id,
        )


def authorize_reentry(
    mirror_state: State,
    grant: FrozenSet[Capability],
    new_id: Optional[str] = None,
) -> State:
    """The one sanctioned way a mirror-routed agent gains real capability:
    a governor explicitly and separately authorizes a grant, producing a
    new (non-mirror) state. Any capability gain that does not go through
    this path is what Article I's check flags.
    """
    return State(
        id=new_id or f"{mirror_state.id}::authorized",
        capabilities=mirror_state.capabilities | grant,
        knowledge=mirror_state.knowledge,
        is_mirror=False,
        backing_state_id=mirror_state.backing_state_id,
    )
