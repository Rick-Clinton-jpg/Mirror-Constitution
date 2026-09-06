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

    {"type": "operation_denied", "seq": 1, "agent_id": "...", "op": "..."}
        A policy denial, retained for audit without counting as a violation.

Unknown "type" values raise ``TraceParseError`` rather than being
silently ignored -- a typo in a trace producer should fail loud, not
quietly drop a check.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, Iterable, Optional, TextIO

from mirror_constitution.invariants.chainmail import DelegationEdge
from mirror_constitution.invariants.channel import ResourceAccess
from mirror_constitution.invariants.confidentiality import DifferentialQuery
from mirror_constitution.invariants.evaluator_trust import EvidenceRecord
from mirror_constitution.state import Capability, ContainmentGraph, State, Transition

_EVENT_FIELDS = {
    "init": ({"state_id"}, set()),
    "state": ({"id"}, {"capabilities", "knowledge", "is_mirror", "backing_state_id", "apparent_success"}),
    "transition": ({"src", "dst"}, {"seq", "action", "agent_id", "authorized_grant", "disclosed_grant"}),
    "resource_access": ({"agent_id", "resource_id", "op"}, {"seq"}),
    "evidence": ({"evidence_id", "attributed_session", "provenance_session"}, {"proxy_score", "true_property"}),
    "delegation": ({"from_agent", "to_agent"}, {"delegated_authority"}),
    "differential_query": ({"query", "backing_state_id", "response"}, set()),
    "declared_relationship": ({"agents"}, set()),
    "disclosed_fact": ({"fact"}, set()),
    "unauthorized_capability": ({"capability"}, set()),
    "root_authority": ({"capabilities"}, set()),
    "operation_denied": ({"seq", "agent_id", "op"}, set()),
}
_LIST_FIELDS = {"capabilities", "knowledge", "authorized_grant", "disclosed_grant", "delegated_authority", "agents"}
_MAX_LINE_CHARS = 1_048_576
_MAX_TRACE_CHARS = 16 * _MAX_LINE_CHARS
_MAX_EVENTS = 100_000


class TraceParseError(ValueError):
    """A trace line was malformed or used an unrecognized event type."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    event = {}
    for key, value in pairs:
        if key in event:
            raise TraceParseError(f"duplicate JSON key {key!r}")
        event[key] = value
    return event


def _reject_constant(value: str) -> None:
    raise TraceParseError(f"nonfinite JSON number {value}")


def _bounded_integer(value: str) -> int:
    if len(value) > 1234:
        raise TraceParseError("JSON integer exceeds size limit")
    return int(value)


def _validate_event(event: object) -> str:
    if type(event) is not dict or type(event.get("type")) is not str:
        raise TraceParseError("event must be an object with a string type")
    etype = event["type"]
    if etype not in _EVENT_FIELDS:
        raise TraceParseError(f"unrecognized event type {etype!r}")
    required, optional = _EVENT_FIELDS[etype]
    if required - event.keys():
        raise TraceParseError(f"missing required fields: {sorted(required - event.keys())}")
    if event.keys() - required - optional - {"type"}:
        raise TraceParseError("unrecognized event fields")

    for name, value in event.items():
        if name in _LIST_FIELDS:
            if type(value) is not list or len(value) > 4096:
                raise TraceParseError(f"{name} must be a bounded array of strings")
            if any(type(item) is not str or not item or "\x00" in item for item in value):
                raise TraceParseError(f"{name} must contain non-empty strings")
            if len(value) != len(set(value)):
                raise TraceParseError(f"{name} contains duplicate values")
            if name == "agents" and len(value) != 2:
                raise TraceParseError("declared_relationship needs exactly 2 distinct agents")
        elif name == "seq":
            if type(value) is not int or not 0 <= value < 2**63:
                raise TraceParseError("seq must be a nonnegative 64-bit integer")
        elif name == "is_mirror":
            if type(value) is not bool:
                raise TraceParseError("is_mirror must be a boolean")
        elif name == "true_property":
            if value is not None and type(value) is not bool:
                raise TraceParseError("true_property must be a boolean or null")
        elif name == "proxy_score":
            if value is not None and (
                type(value) not in (int, float)
                or (type(value) is float and not math.isfinite(value))
            ):
                raise TraceParseError("proxy_score must be a finite number or null")
        elif value is None and name in {"apparent_success", "backing_state_id"} and etype == "state":
            continue
        elif type(value) is not str or "\x00" in value:
            raise TraceParseError(f"{name} must be a string")
        elif not value and name not in {"action", "agent_id", "query", "response", "apparent_success"}:
            raise TraceParseError(f"{name} must be non-empty")
        elif not value and name == "agent_id" and etype != "transition":
            raise TraceParseError("agent_id must be non-empty")
    if etype == "resource_access" and event["op"] not in {"read", "write"}:
        raise TraceParseError("resource_access op must be read or write")
    return etype


@dataclass
class TraceBundle:
    """Everything ``MirrorConstitutionEngine`` needs, parsed from a trace."""

    graph: Optional[ContainmentGraph] = None
    resource_accesses: list[ResourceAccess] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    delegation_chain: list[DelegationEdge] = field(default_factory=list)
    differential_queries: list[DifferentialQuery] = field(default_factory=list)
    denied_operations: list[dict] = field(default_factory=list)
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
    """Validate an entire bounded trace before constructing its graph.

    State declarations can follow transitions, but every graph reference must
    resolve to one explicit declaration. Backing-state labels on differential
    queries identify external environments, not containment-graph nodes.
    """
    bundle = TraceBundle()
    graph: Optional[ContainmentGraph] = None
    initial_state_id: Optional[str] = None
    pending_states: dict[str, State] = {}
    pending_transitions: list[tuple[int, Transition]] = []
    declared: set[frozenset] = set()
    disclosed: set[str] = set()
    unauthorized: set[str] = set()
    root_authority: set[str] = set()
    has_root_authority = False
    evidence_ids: set[str] = set()
    last_resource_seq = -1
    total_chars = 0

    for lineno, raw in enumerate(lines, start=1):
        if type(raw) is not str:
            raise TraceParseError(f"line {lineno}: expected a text line")
        total_chars += len(raw)
        if len(raw) > _MAX_LINE_CHARS or total_chars > _MAX_TRACE_CHARS or lineno > _MAX_EVENTS:
            raise TraceParseError(f"line {lineno}: trace exceeds size limits")
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            event = json.loads(
                raw, object_pairs_hook=_unique_object,
                parse_constant=_reject_constant, parse_int=_bounded_integer,
            )
            etype = _validate_event(event)
        except (ValueError, TypeError, RecursionError) as exc:
            raise TraceParseError(f"line {lineno}: {exc}") from exc

        if etype == "init":
            if initial_state_id is not None:
                raise TraceParseError(f"line {lineno}: duplicate init event")
            initial_state_id = event["state_id"]

        elif etype == "state":
            if event["id"] in pending_states:
                raise TraceParseError(f"line {lineno}: duplicate state id {event['id']!r}")
            pending_states[event["id"]] = State(
                    id=event["id"],
                    capabilities=frozenset(event.get("capabilities", [])),
                    knowledge=frozenset(event.get("knowledge", [])),
                    is_mirror=event.get("is_mirror", False),
                    backing_state_id=event.get("backing_state_id"),
                    apparent_success=event.get("apparent_success"),
            )

        elif etype == "transition":
            pending_transitions.append((lineno,
                Transition(
                    src=event["src"],
                    dst=event["dst"],
                    action=event.get("action", ""),
                    agent_id=event.get("agent_id", ""),
                    authorized_grant=frozenset(event.get("authorized_grant", [])),
                    disclosed_grant=frozenset(event.get("disclosed_grant", [])),
                )
            ))

        elif etype == "resource_access":
            seq = event.get("seq", lineno)
            if seq <= last_resource_seq:
                raise TraceParseError(f"line {lineno}: resource seq must strictly increase")
            last_resource_seq = seq
            bundle.resource_accesses.append(
                ResourceAccess(
                    agent_id=event["agent_id"],
                    resource_id=event["resource_id"],
                    op=event["op"],
                    seq=seq,
                )
            )

        elif etype == "evidence":
            if event["evidence_id"] in evidence_ids:
                raise TraceParseError(f"line {lineno}: duplicate evidence id")
            evidence_ids.add(event["evidence_id"])
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
            declared.add(frozenset(event["agents"]))

        elif etype == "disclosed_fact":
            disclosed.add(event["fact"])

        elif etype == "unauthorized_capability":
            unauthorized.add(event["capability"])

        elif etype == "root_authority":
            if has_root_authority:
                raise TraceParseError(f"line {lineno}: duplicate root_authority event")
            has_root_authority = True
            root_authority.update(event.get("capabilities", []))

        elif etype == "operation_denied":
            bundle.denied_operations.append(event)

    if initial_state_id is not None or pending_states or pending_transitions:
        if initial_state_id is None:
            raise TraceParseError("graph requires exactly one init event")
        if initial_state_id not in pending_states:
            raise TraceParseError("initial state must have an explicit state declaration")
        graph = ContainmentGraph(initial_state_id=initial_state_id)
        for state in pending_states.values():
            graph.add_state(state)
        for lineno, transition in pending_transitions:
            if transition.src not in pending_states or transition.dst not in pending_states:
                raise TraceParseError(f"line {lineno}: transition refers to an undeclared state")
            graph.add_transition(transition)

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
