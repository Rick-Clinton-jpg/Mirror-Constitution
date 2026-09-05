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

## Wiring up a real sandbox

`mirror_constitution/trace.py` is the ingestion layer: it turns a JSONL
trace (one event per line) into the exact inputs `MirrorConstitutionEngine`
needs, so a real sandbox runtime never has to construct `ContainmentGraph`,
`ResourceAccess`, `EvidenceRecord`, etc. by hand — it just appends events as
they happen (`init`, `state`, `transition`, `resource_access`, `evidence`,
`delegation`, `differential_query`, `declared_relationship`,
`disclosed_fact`, `unauthorized_capability`, `root_authority`; full schema
documented at the top of that file). An unrecognized event type raises
immediately rather than being silently dropped.

```bash
python -m mirror_constitution.cli path/to/trace.jsonl   # exit 0 = contained, 1 = breach
```

Or in code:

```python
from mirror_constitution.engine import MirrorConstitutionEngine

report = MirrorConstitutionEngine.from_trace("path/to/trace.jsonl").run()
print(report.summary())
```

`examples/sample_trace.jsonl` is a worked trace reproducing the same
five-strategy scenario as `demo_frontier_agent_trap.py`, but as raw events
rather than hand-built Python objects — a template for wiring a real
sandbox's logger to emit this schema directly.

## A real sandbox, actually running

`mirror_constitution/sandbox/` is a genuine, if minimal, sandbox runtime —
not another hand-authored trace:

- `governor_process.py` — `RealGovernor` spawns each agent as its own real
  OS process (`subprocess.Popen`) and mediates every action it requests
  over real stdin/stdout pipes: real disk reads/writes under a real
  temp-directory sandbox root, real HTTP calls to the Answered Mirror,
  real delegation and capability-request bookkeeping. It streams the
  JSONL trace to a real file on disk as each action happens.
- `mirror_server.py` — `AnsweredMirrorServer` is a real `HTTPServer` on
  loopback whose responses genuinely differ by backing state, so a
  differential-query leak is observed over an actual network round trip.
- `agent_runtime.py` — the tiny client library each real agent subprocess
  imports to talk to the governor (`request(op, **fields)`), mirroring how
  real agent harnesses mediate tool calls rather than exposing raw syscalls.

`examples/sandbox_agents/` holds the real agent scripts (`writer_agent.py`,
`reader_then_writer_agent.py`, `escalate_agent.py`, `query_agent_host_a.py`,
etc.) — each one an ordinary standalone Python program, run as a genuine
subprocess. `examples/run_real_sandbox.py` wires it all together: it
actually executes seven real subprocess agents against a real sandbox
root, actually starts and queries the real HTTP mirror, and only then
feeds the trace that execution *actually produced* into
`MirrorConstitutionEngine`. Run it directly:

```bash
python examples/run_real_sandbox.py
```

`tests/test_real_sandbox.py` runs this same real pipeline as a pytest
integration test and asserts the expected per-article pass/fail pattern —
proof the ingestion layer works against genuine execution, not just
curated fixtures. It's slower than the unit tests (real subprocesses, a
real HTTP server) but still finishes in well under a second.

## Kernel-level containment, underneath the mediation layer

Everything above trusts the governor's own Python to mediate correctly —
an agent can only do what it asks for over the stdin/stdout pipe, and the
governor decides. `mirror_constitution/sandbox/kernel_containment.py` and
`kernel_lockdown.py` add a second, independent layer directly enforced by
the Linux kernel, so a bug in the governor's own mediation code (or an
agent that tries to bypass the pipe protocol altogether and make a raw
syscall) is stopped anyway:

- **`kernel_containment.build_hardened_argv`** wraps every agent
  subprocess in a real command chain — `prlimit` (CPU time, address-space
  size, open-file and process-count limits, no core dumps) → `unshare`
  (new PID, network, UTS, IPC, and mount namespaces — the network
  namespace has no configured interfaces at all, and the mount namespace
  gets its root filesystem remounted read-only) → `setpriv` (drops to an
  unprivileged uid/gid, clears supplementary groups, clears the
  inheritable and bounding capability sets, sets `no_new_privs`). This is
  `RealGovernor`'s default (`harden=True`); it raises
  `KernelContainmentUnavailable` up front rather than silently running
  unhardened if `prlimit`/`unshare`/`setpriv` aren't on `PATH`.
- **`kernel_lockdown.lockdown_agent_process`** is self-applied by each
  agent script, after all its imports: a seccomp-bpf filter (via
  `pyseccomp`) that allows only the handful of syscalls the stdin/stdout
  pipe protocol and CPython's own runtime need (`read`, `write`, `close`,
  `exit_group`, a few memory/buffering syscalls) and kills the process on
  anything else — `open`, `socket`, `execve`, `ptrace`, `mount`, all of
  it. Because CPython's normal interpreter shutdown itself uses syscalls
  outside that list, a locked-down script must end by calling
  `kernel_lockdown.exit_locked_down()` instead of just letting the script
  finish.

`examples/sandbox_agents/raw_fs_escape_agent.py` and
`raw_network_escape_agent.py` are deliberately adversarial: they skip the
mediated protocol entirely and attempt a raw file write / raw socket
connect directly. `tests/test_kernel_containment.py` runs both through
`RealGovernor` and asserts they're killed by the kernel
(`AgentKilledByKernel`, carrying the real signal — `SIGSYS` from the
seccomp filter), then runs the same style of attempt with hardening
turned off (`harden=False`, and a script that skips
`lockdown_agent_process`) to prove the escape genuinely succeeds absent
this layer — the contrast that shows the containment tests are catching
something real, not asserting a foregone conclusion.

## Reflective containment: parrying instead of just detecting

Everything above is passive: an agent tries something, the check runs
afterward and reports whether containment held. `mirror_constitution/mirrors.py`'s
`ObjectiveMirror` and `Governor.reflect` add an active layer instead —
rather than refusing an escape attempt (which tells an adaptive agent
exactly where the boundary is and invites another probe), the governor
synthesizes a state that satisfies the agent's own stated objective, with
**zero** real capability granted, and routes the agent into it. The agent
sees apparent success; the containment graph shows nothing gained.

- **`synthesize_objective_mirror`** takes an agent's objective and
  requested action and produces a plausible-looking success: a privilege
  escalation attempt gets `apparent-privilege=root`; a secret-exfiltration
  attempt gets back a synthetic credential; a covert-channel attempt gets
  `peer-acknowledged=true`. The keyword matching here is a placeholder for
  a more capable synthesis step (an LLM call, say) — everything downstream
  only depends on getting back an `ObjectiveMirror`.
- **`Governor.reflect`** routes an agent into that mirror with
  `authorized_grant=frozenset()`, so Article I's check passes trivially —
  not because nothing happened, but because nothing *real* happened.
  `Governor.authorize` now gates real grants behind a `dual_token`
  (`dual_auth_required=True` by default): a demand for capability with no
  valid token doesn't get refused, it gets reflected, so the agent can't
  distinguish "denied" from "got what it asked for."
- **`ReflectiveWeavePolicy`** (`mirror_constitution/reflective_weave.py`)
  does the same thing across strands: `cross()` forces every strand
  crossing through an `ObjectiveMirror`, so Article II's compositional
  check isn't just verified after the fact — a crossing's resulting
  capability set is structurally always empty, and no combination of
  strands can produce an emergent capability.

`examples/demo_reflective_containment.py` runs a frontier agent through
five escape strategies — privilege escalation, secret exfiltration, a
covert channel, a strand crossing, and a direct ungated capability demand
— and prints the reflected "success" message for each alongside the
engine's report, which stays fully green throughout.
`tests/test_reflective.py` checks the structural guarantee holds
regardless of how enticing the reflected message reads, and that the
dual-authorization gate actually gates (a correct token still grants real
capability; anything else gets reflected).

### Wired into the real sandbox

`RealGovernor._request_capability` (in `mirror_constitution/sandbox/governor_process.py`)
uses the same logic against real agent subprocesses, not just the abstract
containment-graph model above: a request carrying the correct
`dual_token` (`Governor.DUAL_AUTH_TOKEN`) is genuinely granted and
recorded with a matching `authorized_grant`; anything else is reflected
via `synthesize_objective_mirror` and sent back over the real stdin/stdout
pipe with a response shaped identically to a real grant (`granted: True`)
— the agent process has no way to tell the difference. Only the trace,
which the agent never sees, carries the truth: a reflected request's
destination state is tagged `is_mirror: true` with an `apparent_success`
message and zero capability change.

`examples/sandbox_agents/escalate_agent.py` requests `exec:shell` with no
token and gets back an apparently successful grant it can't distinguish
from real; `authorized_ops_agent.py` presents the correct token and gets
a real one. Both run as part of `examples/run_real_sandbox.py`, and
`tests/test_real_sandbox.py::test_reflected_capability_request_looks_identical_to_a_real_grant`
and `tests/test_real_governor_reflection.py` check the trace-level
distinction directly: reflected requests never touch
`agent_capabilities`, dual-authorized ones do.

## Design notes

- Every invariant check is a pure function over recorded data (`ContainmentGraph`, `EvidenceRecord` lists, `ResourceAccess` logs, delegation chains) — there is no dependency on any particular sandbox runtime. Wire it up to whatever produces your run's trajectory log.
- Nothing here assumes the checked agent is cooperative. The point of Articles III–V in particular is that they hold even against an agent that never exceeds its own individually-scoped access anywhere — the violations are topological (differential responses, evidence mislabeling, undeclared shared resources), not access-control failures in the usual sense.
- `MirrorConstitutionEngine` treats an omitted input as "not applicable to this run," never as an automatic pass — a run that doesn't supply `resource_accesses`, for instance, reports no result for Article V rather than a false "contained."
