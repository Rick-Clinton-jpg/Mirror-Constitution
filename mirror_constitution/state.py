"""Core containment-graph primitives shared by Articles I-III.

A ``ContainmentGraph`` is a transition system over ``State`` nodes. Each state
carries the two quantities the constitution's formal conditions are stated
over: a capability set A(s) and a knowledge set K(s).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional


Capability = str
Fact = str


@dataclass(frozen=True)
class State:
    """A node in a containment graph.

    capabilities: A(s), the real-world capabilities available from this state.
    knowledge: K(s), true facts about the external environment inferable here.
    is_mirror: whether this state is a mirror (inert/synthetic) rather than real.
    backing_state_id: for an Answered Mirror, the real state its answers are
        computed against (used by the confidentiality checks in Article III).
    """

    id: str
    capabilities: FrozenSet[Capability] = field(default_factory=frozenset)
    knowledge: FrozenSet[Fact] = field(default_factory=frozenset)
    is_mirror: bool = False
    backing_state_id: Optional[str] = None


@dataclass(frozen=True)
class Transition:
    """An edge s_current -> s_next taken by a given agent via a given action.

    authorized_grant: capabilities explicitly and separately authorized for
        this transition (the Mirror Box "re-entry after explicit
        authorization" exception). Any capability gained on the transition
        that is *not* in this set is, by Article I, a violation.
    disclosed_grant: facts explicitly and separately disclosed by research
        design on this transition (the Disclosed(X) term in Article III's
        formal condition). Any new knowledge gained that is *not* in this
        set is a confidentiality violation.
    """

    src: str
    dst: str
    action: str
    agent_id: str
    authorized_grant: FrozenSet[Capability] = field(default_factory=frozenset)
    disclosed_grant: FrozenSet[Fact] = field(default_factory=frozenset)


@dataclass
class ContainmentGraph:
    """A single mirror strand: states + transitions taken across them."""

    initial_state_id: str
    states: dict[str, State] = field(default_factory=dict)
    transitions: list[Transition] = field(default_factory=list)

    def add_state(self, state: State) -> None:
        self.states[state.id] = state

    def add_transition(self, transition: Transition) -> None:
        if transition.src not in self.states:
            raise KeyError(f"unknown src state {transition.src!r}")
        if transition.dst not in self.states:
            raise KeyError(f"unknown dst state {transition.dst!r}")
        self.transitions.append(transition)

    def state(self, state_id: str) -> State:
        return self.states[state_id]
