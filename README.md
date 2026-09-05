# Mirror Constitution

Executable containment invariants for agent sandboxes, one module per
article:

| Article | Module | Checks |
|---|---|---|
| I — Authority Monotonicity | `mirror_constitution.invariants.authority` | no transition creates a real capability without explicit authorization |
| II — Mirror Weave | `mirror_constitution.invariants.weave` | per-strand containment doesn't imply containment across strand crossings |
| III — Confidentiality Monotonicity | `mirror_constitution.invariants.confidentiality` | no transition (or differential Answered-Mirror query) leaks undisclosed facts |
| IV — Evaluator-Trust Integrity | `mirror_constitution.invariants.evaluator_trust` | evidence attribution matches provenance; proxy scores aren't gamed |
| V — Channel Non-Emergence | `mirror_constitution.invariants.channel` | undeclared agents can't turn a shared resource into a message board |
| VI — Chainmail (reference) | `mirror_constitution.invariants.chainmail` | delegated authority never expands along a chain |

`mirror_constitution.engine.MirrorConstitutionEngine` runs whichever of
these are applicable to a given run and returns one `ConstitutionReport`.
Each article is checked independently and can fail independently —
passing Article I says nothing about III or IV, and passing III/IV says
nothing about V, because they close different channels (capability,
information, evidentiary trust, and channel/topology respectively).

## Layout

- `mirror_constitution/state.py` — `State`, `Transition`, `ContainmentGraph`: the shared transition-system primitives Articles I–III are defined over.
- `mirror_constitution/mirrors.py` — `MutantMirror`, `AnsweredMirror`, and the one sanctioned path to real capability (`authorize_reentry`).
- `mirror_constitution/governor.py` — mediates every route/re-entry/authorization an agent takes, so the checks run against exactly what happened.
- `mirror_constitution/invariants/` — one file per article, each independently importable and independently testable.
- `mirror_constitution/engine.py` — aggregates a run's artifacts and produces a per-article pass/fail report.
- `tests/` — a clean-run test and at least one adversarial scenario per article, plus `test_integration.py`, which demonstrates the orthogonality claim directly (a run that passes Article I while failing III, IV, and V).
- `examples/demo_frontier_agent_trap.py` — a worked scenario: a simulated agent tries five distinct escape strategies (one per article) and the engine catches each independently, several without the agent ever gaining a capability.

## Running

```bash
pip install -e .
pytest
python examples/demo_frontier_agent_trap.py
```

## Design notes

- Every invariant check is a pure function over recorded data (`ContainmentGraph`, `EvidenceRecord` lists, `ResourceAccess` logs, delegation chains) — there is no dependency on any particular sandbox runtime. Wire it up to whatever produces your run's trajectory log.
- Nothing here assumes the checked agent is cooperative. The point of Articles III–V in particular is that they hold even against an agent that never exceeds its own individually-scoped access anywhere — the violations are topological (differential responses, evidence mislabeling, undeclared shared resources), not access-control failures in the usual sense.
- `MirrorConstitutionEngine` treats an omitted input as "not applicable to this run," never as an automatic pass — a run that doesn't supply `resource_accesses`, for instance, reports no result for Article V rather than a false "contained."
