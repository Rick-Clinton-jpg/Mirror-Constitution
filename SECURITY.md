# Security model

## Boundary and trusted components

The adversary may choose agent Python source and send arbitrary protocol bytes.
It may try to omit lockdown, forge approval tokens, manipulate resource names,
replay requests, or exhaust its process and the governor's protocol handling.
The host assigns the agent identity; an agent cannot choose its identity through
a request field.

The trusted computing base includes the Linux kernel, libseccomp, CPython and
preloaded modules, system tools, trusted bootstrap, governor, approval issuer,
configuration, and filesystem paths holding these components. These must not be
writable by the agent. The configured sandbox root and trace parent must be on
trusted local storage with ordinary POSIX semantics. Do not place them on hostile
FUSE/network filesystems. Host administrator compromise, kernel exploits,
hardware side channels, hostile supervisor code, and changes made outside this
boundary are outside this implementation's guarantees.

The mandatory bootstrap prevents agent source from running before the filter.
Python guard functions are trusted code. Giving hostile code access to the
supervisor's own Python process, approval registry, credentials, or live objects
would bypass the model; a Python object convention is not process isolation.

## Enforcement profile

The agent can compute in bounded memory and exchange bounded messages over
stdin/stdout. Its environment is rebuilt from an allowlist. The syscall filter
allows a small runtime set, anonymous mappings, reads from descriptor 0, and
writes to descriptors 1 and 2. Raw opens, network calls, subprocess creation,
execution, and changes to the protection mechanism are denied. The supported
profile must pass the actual startup probe on the target Linux environment.

Capabilities are server-side labels. Resource effects also require explicit
access lists. Declared sharing is intentional information flow; permission to
share does not make the shared content safe. Backing-state queries have no
production disclosure policy and are disabled under enforcement.

Approval issuance must be authenticated and authorized outside the agent.
Tokens contain 256 bits of randomness, expire within five minutes, are bound to
one agent and exact capability set, and are consumed once. A pending approval
can be used by that agent for the approved action; it does not authenticate a
particular model's intent. The implementation does not provide a human approval
UI, two-person identity verification, or distributed revocation.

## Evidence and validation limits

The tests demonstrate specific attacks failing under specific environments.
They do not prove absence of other vulnerabilities, containment against every
model, or correctness under all kernels and Python versions. Read each CI run's
result; skipped kernel tests provide no kernel-enforcement evidence.

Offline invariant checks trust the provenance and completeness of their inputs.
Strict parsing rejects ambiguous and missing references but cannot detect a
forged plausible trace or all omitted events. Protect the recorder and storage;
external durable, authenticated logging is a deployment responsibility.
Reports explicitly distinguish checks that were not evaluated. A passing subset
must not be represented as complete containment certification.

The resource/pipe bounds constrain one invocation. Fleet-wide quotas, disk
capacity, concurrent supervisor use, service rate limiting, and operational
recovery require additional deployment controls. The prototype's supervisor is
intended for sequential execution with trusted configuration updates.

## Demonstration switches

`enforce_policy=False` permits intentional policy breaches for detector demos.
`harden=False` removes the kernel boundary. Neither setting is appropriate for
untrusted live workloads. Synthetic reflected success never substitutes for an
enforced denial of real capability or effects.
