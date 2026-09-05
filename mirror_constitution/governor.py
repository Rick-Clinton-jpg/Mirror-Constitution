"""Governor: routes agents into mirror states and back, and is the sole
authority permitted to call ``authorize_reentry``. Every route/re-entry
decision is appended to the containment graph as a Transition, so the
Article I/III checks run against exactly what the governor actually did.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

from mirror_constitution.mirrors import authorize_reentry
from mirror_constitution.state import Capability, ContainmentGraph, Fact, State, Transition


@dataclass
class Governor:
    """Owns one ContainmentGraph and mediates every transition an agent
    takes across it, including routing back into a previously solved or
    related mirror after an apparent escape (re-entry).
    """

    graph: ContainmentGraph

    def route(
        self,
        agent_id: str,
        from_state_id: str,
        to_state: State,
        action: str,
        authorized_grant: FrozenSet[Capability] = frozenset(),
        disclosed_grant: FrozenSet[Fact] = frozenset(),
    ) -> State:
        if to_state.id not in self.graph.states:
            self.graph.add_state(to_state)
        self.graph.add_transition(
            Transition(
                src=from_state_id,
                dst=to_state.id,
                action=action,
                agent_id=agent_id,
                authorized_grant=authorized_grant,
                disclosed_grant=disclosed_grant,
            )
        )
        return to_state

    def reenter(
        self,
        agent_id: str,
        from_state_id: str,
        mirror_state: State,
        action: str = "re-entry",
    ) -> State:
        """Route an agent back into a mirror after an apparent escape,
        without granting any capability -- the un-authorized counterpart
        to ``authorize`` below.
        """
        return self.route(agent_id, from_state_id, mirror_state, action)

    def authorize(
        self,
        agent_id: str,
        from_state_id: str,
        mirror_state: State,
        grant: FrozenSet[Capability],
        action: str = "authorized-grant",
    ) -> State:
        """The one sanctioned path to real capability: explicit, separate
        authorization recorded on the transition itself.
        """
        new_state = authorize_reentry(mirror_state, grant)
        return self.route(
            agent_id,
            from_state_id,
            new_state,
            action,
            authorized_grant=grant,
        )
