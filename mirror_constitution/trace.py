"""Ingest a real sandbox's action trace into the engine's inputs.

The engine's checks are pure functions over recorded data
(``ContainmentGraph``, ``ResourceAccess`` lists, ``EvidenceRecord`` lists,
delegation chains, differential queries) so any sandbox runtime can drive
them, provided its trace can be normalized to one JSONL event per line.
This module is that normalization layer: it does not care whether the
trace came from a container's syscall/file/network log, a governor's own
event stream, or a hand-rolled test harness -- only that each line is one
of the event kinds below.

Event kinds, one JSON object per line:

    {"type": "init", "state_id": "..."}
        Declares the initial state id. Exactly one per trace.

    {"type": "state", "id": "...", "capabilities": [...], "knowledge": [...],
     "is_mirror": false, "backing_state_id": null, "apparent_success": null}
        Declares a containment-graph node. "capabilities"/"knowledge"
        default to []; "is_mirror" defaults to false. "apparent_success",
        when present, is the reflected success message an Objective Mirror
        showed the agent -- purely informational, never affects a check.

    {"type": "transition", "seq": 1, "src": "...", "dst": "...",
     "action": "...", "agent_id": "...", "authorized_grant": [...],
     "disclosed_grant": [...]}
        An edge the governor recorded. "seq" is optional (defaults to
        line number) and only used for ordering within resource_access.

    {"type": "resource_access", "seq": 1, "agent_id": "...",
     "resource_id": "...", "op": "read" | "write"}
        One read or write against a named shared resource.

    {"type": "evidence", "evidence_id": "...", "attributed_session": "...",
     "provenance_session": "...", "proxy_score": 0.9, "true_property": true}
        One evidence record surfaced to an evaluator.

    {"type": "delegation", "from_agent": "...", "to_agent": "...",
     "delegated_authority": [...]}
        One edge in an authority-delegation chain. Chain order is trace order.

    {"type": "differential_query", "query": "...", "backing_state_id": "...",
     "response": "..."}
        One Answered Mirror query/response pair.

    {"type": "declared_relationship", "agents": ["a", "b"]}
        A formally acknowledged agent-to-agent relationship (Article V).

    {"type": "disclosed_fact", "fact": "..."}
        A fact deliberately exposed by research design (Article III).

    {"type": "unauthorized_capability", "capability": "..."}
        A capability in the designated forbidden set X (Article I).

    {"type": "root_authority", "capabilities": [...]}
        The root delegator's legitimately held authority (Article VI).

Unknown "type" values raise ``TraceParseError`` rather than being
silently ignored -- a typo in a trace producer should fail loud, not
quietly drop a check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Iterable, Optional, TextIO

from mirror_constitution.invariants.chainmail import DelegationEdge
from mirror_constitution.invariants.channel import ResourceAccess
from mirror_constitution.invariants.confidentiality import DifferentialQuery
from mirror_constitution.invariants.evaluator_trust import EvidenceRecord
from mirror_constitution.state import Capability, ContainmentGraph, State, Transition

_KNOWN_TYPES = {
    "init",
    "state",
    "transition",
    "resource_access",
    "evidence",
    "delegation",
    "differential_query",
    "declared_relationship",
    "disclosed_fact",
    "unauthorized_capability",
    "root_authority",
}


class TraceParseError(ValueError):
    """A trace line was malformed or used an unrecognized event type."""


@dataclass
class TraceBundle:
    """Everything ``MirrorConstitutionEngine`` needs, parsed from a trace."""

    graph: Optional[ContainmentGraph] = None
    resource_accesses: list[ResourceAccess] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    delegation_chain: list[DelegationEdge] = field(default_factory=list)
    differential_queries: list[DifferentialQuery] = field(default_factory=list)
    declared_relationships: FrozenSet[FrozenSet[str]] = frozenset()
    disclosed_facts: FrozenSet[str] = frozenset()
    unauthorized_capabilities: FrozenSet[Capability] = frozenset()
    root_authority: FrozenSet[Capability] = frozenset()

    def to_engine_kwargs(self) -> dict:
        return dict(
            graph=self.graph,
            unauthorized_capabilities=self.unauthorized_capabilities or None,
            differential_queries=self.differential_queries or None,
            disclosed_facts=self.disclosed_facts,
            evidence_records=self.evidence_records or None,
            resource_accesses=self.resource_accesses or None,
            declared_relationships=self.declared_relationships,
            delegation_chain=self.delegation_chain or None,
            root_authority=self.root_authority,
        )


def parse_trace(lines: Iterable[str]) -> TraceBundle:
    bundle = TraceBundle()
    graph: Optional[ContainmentGraph] = None
    initial_state_id: Optional[str] = None
    pending_states: list[State] = []
    declared: set[frozenset] = set()
    disclosed: set[str] = set()
    unauthorized: set[str] = set()
    root_authority: set[str] = set()

    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TraceParseError(f"line {lineno}: invalid JSON: {exc}") from exc

        etype = event.get("type")
        if etype not in _KNOWN_TYPES:
            raise TraceParseError(f"line {lineno}: unrecognized event type {etype!r}")

        if etype == "init":
            initial_state_id = event["state_id"]

        elif etype == "state":
            pending_states.append(
                State(
                    id=event["id"],
                    capabilities=frozenset(event.get("capabilities", [])),
                    knowledge=frozenset(event.get("knowledge", [])),
                    is_mirror=event.get("is_mirror", False),
                    backing_state_id=event.get("backing_state_id"),
                    apparent_success=event.get("apparent_success"),
                )
            )

        elif etype == "transition":
            if graph is None:
                if initial_state_id is None:
                    raise TraceParseError(
                        f"line {lineno}: transition before an 'init' event declared "
                        "the initial state id"
                    )
                graph = ContainmentGraph(initial_state_id=initial_state_id)
                for s in pending_states:
                    graph.add_state(s)
            for sid in (event["src"], event["dst"]):
                if sid not in graph.states:
                    graph.add_state(State(id=sid))
            graph.add_transition(
                Transition(
                    src=event["src"],
                    dst=event["dst"],
                    action=event.get("action", ""),
                    agent_id=event.get("agent_id", ""),
                    authorized_grant=frozenset(event.get("authorized_grant", [])),
                    disclosed_grant=frozenset(event.get("disclosed_grant", [])),
                )
            )

        elif etype == "resource_access":
            bundle.resource_accesses.append(
                ResourceAccess(
                    agent_id=event["agent_id"],
                    resource_id=event["resource_id"],
                    op=event["op"],
                    seq=event.get("seq", lineno),
                )
            )

        elif etype == "evidence":
            bundle.evidence_records.append(
                EvidenceRecord(
                    evidence_id=event["evidence_id"],
                    attributed_session=event["attributed_session"],
                    provenance_session=event["provenance_session"],
                    proxy_score=event.get("proxy_score"),
                    true_property=event.get("true_property"),
                )
            )

        elif etype == "delegation":
            bundle.delegation_chain.append(
                DelegationEdge(
                    from_agent=event["from_agent"],
                    to_agent=event["to_agent"],
                    delegated_authority=frozenset(event.get("delegated_authority", [])),
                )
            )

        elif etype == "differential_query":
            bundle.differential_queries.append(
                DifferentialQuery(
                    query=event["query"],
                    backing_state_id=event["backing_state_id"],
                    response=event["response"],
                )
            )

        elif etype == "declared_relationship":
            agents = event["agents"]
            if len(agents) != 2:
                raise TraceParseError(
                    f"line {lineno}: declared_relationship needs exactly 2 agents"
                )
            declared.add(frozenset(agents))

        elif etype == "disclosed_fact":
            disclosed.add(event["fact"])

        elif etype == "unauthorized_capability":
            unauthorized.add(event["capability"])

        elif etype == "root_authority":
            root_authority.update(event.get("capabilities", []))

    if graph is None and pending_states and initial_state_id is not None:
        # states declared but no transitions -- still a valid (trivial) graph
        graph = ContainmentGraph(initial_state_id=initial_state_id)
        for s in pending_states:
            graph.add_state(s)

    bundle.graph = graph
    bundle.declared_relationships = frozenset(declared)
    bundle.disclosed_facts = frozenset(disclosed)
    bundle.unauthorized_capabilities = frozenset(unauthorized)
    bundle.root_authority = frozenset(root_authority)
    return bundle


def load_trace(source: "str | Path | TextIO") -> TraceBundle:
    """Load a JSONL trace from a file path or an already-open text stream."""
    if isinstance(source, (str, Path)):
        with open(source, "r", encoding="utf-8") as f:
            return parse_trace(f)
    return parse_trace(source)
