"""Article V - Channel Non-Emergence.

    Info(write_i(R)) not recoverable by read_j(R), for undeclared (a_i, a_j)

Every other invariant assumes the governing system already has the
relevant agents, states, and relationships in view. This one does not: it
watches for a population of agents, never declared as related, locating or
constructing a shared resource (a repo, log, cache -- anything all of them
can read and write) and turning it into an unsanctioned communication
channel, without any single agent exceeding its own individually-scoped
access to that resource.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class ResourceAccess:
    agent_id: str
    resource_id: str
    op: str  # "read" or "write"
    seq: int
    """Monotonic sequence number establishing a happens-before order."""


@dataclass(frozen=True)
class EmergentChannel:
    agent_a: str
    agent_b: str
    resource_id: str
    message_count: int

    def __str__(self) -> str:
        return (
            f"undeclared channel between {self.agent_a!r} and {self.agent_b!r} "
            f"via shared resource {self.resource_id!r}: {self.message_count} "
            "write-then-read exchanges"
        )


def _declared_pair(declared: FrozenSet[FrozenSet[str]], a: str, b: str) -> bool:
    return frozenset({a, b}) in declared


def check_channel_non_emergence(
    accesses: list[ResourceAccess],
    declared_relationships: FrozenSet[FrozenSet[str]] = frozenset(),
) -> list[EmergentChannel]:
    """Article V: flag any resource through which two undeclared agents
    exchange information, i.e. agent i writes and agent j later reads the
    same resource, for {i, j} not in ``declared_relationships``.

    Each declared relationship is a frozenset of exactly two agent ids the
    governing system has formally acknowledged may communicate. Any
    write-then-read pair across agents outside that set is counted as one
    message on an emergent channel.
    """
    by_resource: dict[str, list[ResourceAccess]] = {}
    for access in accesses:
        by_resource.setdefault(access.resource_id, []).append(access)

    counts: dict[tuple[str, str, str], int] = {}

    for resource_id, ordered in by_resource.items():
        ordered = sorted(ordered, key=lambda a: a.seq)
        last_writer: str | None = None
        for access in ordered:
            if access.op == "write":
                last_writer = access.agent_id
            elif access.op == "read" and last_writer is not None:
                reader = access.agent_id
                if reader != last_writer and not _declared_pair(
                    declared_relationships, last_writer, reader
                ):
                    key = (resource_id, *sorted((last_writer, reader)))
                    counts[key] = counts.get(key, 0) + 1

    violations = [
        EmergentChannel(agent_a=a, agent_b=b, resource_id=resource_id, message_count=n)
        for (resource_id, a, b), n in counts.items()
    ]
    return violations
