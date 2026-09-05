"""Executable defense-in-depth strands for frontier-agent boundaries.

The weave deliberately evaluates every strand for every action.  A strand
cannot silently disappear: a rejection *or an exception* blocks the action,
and an action proceeds only when every configured strand explicitly allows it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, Mapping


class StrandStatus(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    ERROR = "error"


@dataclass(frozen=True)
class StrandResult:
    name: str
    status: StrandStatus
    reason: str


@dataclass(frozen=True)
class WeaveDecision:
    """The complete, auditable result of evaluating one action."""

    allowed: bool
    strands: tuple[StrandResult, ...]

    @property
    def blockers(self) -> tuple[StrandResult, ...]:
        return tuple(result for result in self.strands if result.status is not StrandStatus.ALLOW)


StrandGuard = Callable[[Mapping[str, object]], bool | tuple[bool, str]]


def _freeze(value: object, active: set[int] | None = None) -> object:
    """Copy JSON-like input into recursively immutable containers.

    A shallow ``MappingProxyType`` is insufficient here: a hostile strand
    could mutate a nested list or dictionary and change what subsequent
    strands authorize. Cycles and non-data objects are rejected rather than
    handed to policy code with surprising behavior.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value

    active = set() if active is None else active
    identity = id(value)
    if identity in active:
        raise ValueError("cyclic action data")

    active.add(identity)
    try:
        if isinstance(value, Mapping):
            if not all(isinstance(key, str) for key in value):
                raise TypeError("action mapping keys must be strings")
            return MappingProxyType({key: _freeze(item, active) for key, item in value.items()})
        if isinstance(value, (list, tuple)):
            return tuple(_freeze(item, active) for item in value)
        if isinstance(value, (set, frozenset)):
            return frozenset(_freeze(item, active) for item in value)
    finally:
        active.remove(identity)

    raise TypeError(f"unsupported action value: {type(value).__name__}")


class LivingWeave:
    """Run independent guard code as a fail-closed defensive weave.

    Guards receive an immutable-by-contract action mapping and return either a
    boolean or ``(allowed, reason)``.  All guards run, even after one blocks or
    crashes, so one faulty strand cannot suppress the evidence or protection
    supplied by the others.
    """

    def __init__(self) -> None:
        self._strands: dict[str, StrandGuard] = {}

    def add_strand(self, name: str, guard: StrandGuard) -> None:
        if not name or name in self._strands:
            raise ValueError(f"strand name must be non-empty and unique: {name!r}")
        if not callable(guard):
            raise TypeError("strand guard must be callable")
        self._strands[name] = guard

    def evaluate(self, action: Mapping[str, object]) -> WeaveDecision:
        if not self._strands:
            return WeaveDecision(
                allowed=False,
                strands=(
                    StrandResult("weave", StrandStatus.ERROR, "no defensive strands configured"),
                ),
            )

        # One guard must not rewrite even nested data observed by later guards.
        try:
            frozen_action = _freeze(action)
        except Exception as exc:
            return WeaveDecision(
                allowed=False,
                strands=(
                    StrandResult("input", StrandStatus.ERROR, type(exc).__name__),
                ),
            )
        assert isinstance(frozen_action, Mapping)
        results: list[StrandResult] = []
        for name, guard in self._strands.items():
            try:
                raw = guard(frozen_action)
                if isinstance(raw, bool):
                    allowed, reason = raw, "explicit allow" if raw else "explicit block"
                else:
                    allowed, reason = raw
                    if not isinstance(allowed, bool) or not isinstance(reason, str):
                        raise TypeError("expected bool or (bool, str)")
                status = StrandStatus.ALLOW if allowed else StrandStatus.BLOCK
                results.append(StrandResult(name, status, reason))
            except BaseException as exc:
                # Guard failures are data, not authorization.  Keep weaving so
                # every remaining independent defense still gets its vote.
                # This boundary intentionally includes SystemExit; a strand
                # does not own the lifecycle of the process running the weave.
                results.append(
                    # Avoid invoking an untrusted exception's ``__str__`` while
                    # handling the original failure.
                    StrandResult(name, StrandStatus.ERROR, type(exc).__name__)
                )

        return WeaveDecision(
            allowed=all(result.status is StrandStatus.ALLOW for result in results),
            strands=tuple(results),
        )
