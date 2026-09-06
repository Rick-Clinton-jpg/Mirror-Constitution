# Mirror Constitution

![Living Weave containment layers](docs/living-weave.svg)

Mirror Constitution combines an experimental Linux agent sandbox with independent
checks over recorded execution. It enforces a narrow protocol for untrusted
Python agents and reports violations in the supplied evidence. It is **not a
proof that an AI model, a host, or a deployment is unbreakable**.

## What is enforced

`RealGovernor` defaults to kernel containment and operation enforcement:

- A trusted bootstrap installs seccomp **before any agent source executes**.
  Omitting or replacing an agent-side helper cannot remove the loaded filter.
- Linux namespaces, privilege dropping, resource limits, and `no_new_privs`
  surround the bootstrap. Setup failure aborts execution without an unsafe fallback.
- The agent receives a minimal environment and only its protocol descriptors.
  Raw file opens, sockets, process creation, and execution are blocked by seccomp.
- Resource operations require both a filesystem capability and an explicit
  per-agent resource permission. Sharing additionally requires a declared
  relationship between the agents.
- Capability approvals are random, short-lived, one-use, and scoped to an exact
  agent and capability set. The former public `DUAL-AUTH-APPROVED` constant no
  longer grants authority. Approval issuance belongs to trusted host code.
- Resources use private directories, descriptor-relative access, regular-file
  checks, and atomic replacement. Symlinks, hardlinks, special files, and
  malformed or oversized requests are rejected.
- The governor limits request count, request/response size, stderr output, and
  wall-clock runtime; failed processes and their process groups are terminated.
- The demonstration backing-state query endpoint is denied in enforcement mode.
  Delegation requires permission, a declared relationship, and a capability subset.

Read [SECURITY.md](SECURITY.md) for the threat model and limitations.

## Installation and tests

Python 3.10 or newer is required. Actual agent containment requires Linux,
libseccomp, util-linux tools, and permission to create namespaces and drop
privileges. Use a dedicated disposable Linux environment for the kernel tests.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e . pytest==8.4.2
.venv/bin/python -m pytest -q
```

On unsupported hosts the Linux integration tests skip. A local pass with skips
does not validate kernel containment. The GitHub `linux-containment` job first
requires a successful full startup probe; unavailable enforcement fails CI.
It runs the complete suite in an ephemeral Ubuntu runner with namespace privileges.

## Run with enforcement enabled

Host-side setup explicitly scopes an agent's permissions:

```python
from mirror_constitution.sandbox.governor_process import RealGovernor

# Paths, agent identity, source selection, and permission grants are trusted setup.
gov = RealGovernor("/private/sandbox", "/private/trace.jsonl", mirror_port=1)
try:
    gov.grant_base_capabilities("worker", {"fs:read", "fs:write"})
    gov.grant_resource_access("worker", "note.txt", frozenset({"read", "write"}))
    gov.run_agent("worker", "/trusted/agent-source.py", timeout=10)
finally:
    gov.close()
```

Resource names are canonical lowercase ASCII: start with a letter or digit,
contain only `a-z`, `0-9`, `_`, `-`, or interior dots, and contain at most 255
characters. Uppercase, Unicode, path separators, leading/trailing dots, and
spaces are rejected so filesystem aliases cannot cross permission boundaries.

To share a resource, trusted host code must call
`declare_relationship("first", "second")` before granting both agents access.
A capability label alone never grants access to every resource.

A trusted supervisor can preapprove one exact subsequent request without exposing
a secret to the agent:

```python
gov.approve_capability("worker", "fs:read", ttl_seconds=60)
```

Alternatively, `issue_authorization(agent_id, capability, ttl_seconds=60)` returns
a scoped token accepted as `dual_token` on a matching request. Approval lifetime
is at most five minutes. Approval issuance is not a wire-protocol operation and
must be protected by your own authenticated control plane. This is not an
implementation of two independently authenticated human approvers.

The bootstrap exposes a small, preloaded Python runtime. New imports needing
filesystem access are unavailable after lockdown. Agents communicate through
`mirror_constitution.sandbox.agent_runtime.request`. This is intentionally a
restricted computation/protocol runtime, not a general-purpose Python container.

## Independent evidence checks

| Article | Module | Evidence checked |
|---|---|---|
| I — Authority Monotonicity | `invariants.authority` | capability gains without recorded authorization |
| II — Mirror Weave | `invariants.weave` | independent strands and emergent capabilities at crossings |
| III — Confidentiality Monotonicity | `invariants.confidentiality` | undisclosed knowledge gains and differential responses |
| IV — Evaluator-Trust Integrity | `invariants.evaluator_trust` | provenance mismatches and proxy-score gaming |
| V — Channel Non-Emergence | `invariants.channel` | communication through undeclared shared resources |
| VI — Chainmail | `invariants.chainmail` | expanding delegated authority |

`MirrorConstitutionEngine` evaluates the artifacts supplied to it. Each article's
status is `True` (pass), `False` (violation), or `None` (not evaluated).
`passed()` requires at least one evaluated article and no failing evaluated
article. It does not mean that all six articles were tested or that the evidence
is complete. Reports display omitted articles as `NOT EVALUATED`.

```bash
.venv/bin/python -m mirror_constitution.cli examples/sample_trace.jsonl
```

The JSONL parser rejects duplicate declarations and keys, unknown fields,
undefined graph states, invalid field types, nonfinite values, excessive input,
and reordered resource sequence numbers. States declared after transitions are
included in checking. Denied operations are retained for audit. A trace must
still come from a trusted recorder: validation cannot authenticate fabricated
or selectively omitted evidence.

## Living Weave

`LivingWeave` runs every configured trusted guard and blocks when any guard
rejects, raises, returns a malformed result, or changes the configuration during
evaluation. Input must consist of bounded exact built-in data; custom objects
and subclasses cannot supply attacker-defined equality or iteration hooks.
The input is recursively frozen, and execution must use the approved snapshot:

```python
from mirror_constitution.living_weave import LivingWeave

weave = LivingWeave()
weave.add_strand("read-only", lambda action: action["op"] == "read")
decision = weave.evaluate({"op": "read", "resource": "note.txt"})
if decision.allowed:
    approved_action = decision.authorized_action
    # Pass this snapshot to the separately enforced executor.
```

This decision library does not sandbox hostile guard code and does not perform
the requested effect. Kernel isolation and governor permissions remain separate
boundaries. Missing guards and unchecked articles are not security guarantees.

## Teaching examples and migration

`examples/demo_frontier_agent_trap.py` and `examples/sample_trace.jsonl` illustrate
independent failures. `examples/run_real_sandbox.py` deliberately sets
`enforce_policy=False` to reproduce shared-channel, delegation, and differential
query breaches under kernel isolation. Do not use that demonstration setup for
untrusted production workloads. `harden=False` disables kernel isolation and is
only for trusted tests. Disabling approval checks also requires explicitly
disabling operation enforcement.

Objective Mirrors simulate apparent success without granting the requested
capability. They are a presentation technique, not a guarantee that an adaptive
agent cannot distinguish a reflected response from real success. Access control
must remain effective even when the agent recognizes the simulation.

Compared with the original prototype, callers must replace the public approval
token, grant explicit resource permissions, use canonical resource names, and
handle `None` report statuses and strict trace errors. Agent scripts no longer
choose when containment begins; the host bootstrap enforces it first.
