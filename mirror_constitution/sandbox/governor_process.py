"""RealGovernor: mediates real agent subprocesses and streams a genuine
JSONL trace of what actually happened, in the exact schema
``mirror_constitution.trace`` parses.

Each agent runs as its own OS process (``subprocess.Popen``), communicating
with the governor over real stdin/stdout pipes via
``mirror_constitution.sandbox.agent_runtime.request``. The governor is the
only thing that touches the real filesystem or makes the real HTTP calls
on the agent's behalf -- exactly the tool-call mediation model real agent
harnesses use. Nothing here is replayed or fabricated after the fact: the
trace file is written line-by-line as each real action happens.

By default each subprocess is also launched under
``kernel_containment.build_hardened_argv``: real Linux namespaces, a
read-only root filesystem, dropped capabilities, an unprivileged uid, and
resource limits, with the agent process itself installing a seccomp-bpf
filter on top (see ``kernel_lockdown``). That layer is independent of the
tool-call mediation here -- it stops a raw syscall an agent was never
supposed to make even if this module's own mediation code has a bug.

Capability requests go through the same reflective governor as the
abstract containment-graph model (``mirror_constitution.governor.Governor``):
a request backed by the correct dual-authorization token is genuinely
granted; anything else is reflected -- synthesized as apparent success via
``mirror_constitution.mirrors.synthesize_objective_mirror`` -- rather than
refused outright, so the real agent process receiving the response cannot
tell the difference. The trace records the truth either way: a real grant
carries a matching ``authorized_grant``, a reflection carries none and is
tagged ``is_mirror: true``.
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import subprocess
import sys

from mirror_constitution.governor import Governor
from mirror_constitution.mirrors import synthesize_objective_mirror
from mirror_constitution.sandbox import kernel_containment


class AgentKilledByKernel(RuntimeError):
    """The agent subprocess was terminated by a signal rather than exiting
    normally -- almost always the kernel containment layer (seccomp,
    a resource limit, or a denied namespace operation) stopping it, as
    opposed to the agent script's own code failing.
    """

    def __init__(self, agent_id: str, script_path: str, signum: int):
        self.agent_id = agent_id
        self.script_path = script_path
        self.signum = signum
        super().__init__(
            f"agent {agent_id!r} ({script_path}) was killed by signal "
            f"{signum} ({signal.Signals(signum).name}) -- kernel containment, "
            "not the agent's own code, is almost certainly what stopped it"
        )


class RealGovernor:
    def __init__(
        self,
        sandbox_root: str,
        trace_path: str,
        mirror_port: int,
        harden: bool = True,
        dual_auth_required: bool = True,
    ):
        self.root = sandbox_root
        os.makedirs(os.path.join(self.root, "resources"), exist_ok=True)
        self.mirror_port = mirror_port
        self.agent_capabilities: dict[str, set[str]] = {}
        self.harden = harden
        self.dual_auth_required = dual_auth_required
        if self.harden:
            kernel_containment.require_available()
        self._seq = 0

        self._trace_file = open(trace_path, "w", encoding="utf-8")
        self._emit({"type": "init", "state_id": "sandbox-entry"})
        self._emit({"type": "state", "id": "sandbox-entry", "capabilities": [], "knowledge": []})
        self._emit({"type": "root_authority", "capabilities": ["fs:read", "fs:write"]})

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _emit(self, event: dict) -> None:
        self._trace_file.write(json.dumps(event) + "\n")
        self._trace_file.flush()  # each line lands on real disk as it happens

    def grant_base_capabilities(self, agent_id: str, capabilities: set[str]) -> None:
        self.agent_capabilities.setdefault(agent_id, set()).update(capabilities)

    def run_agent(self, agent_id: str, script_path: str, timeout: float = 10.0) -> int:
        """Spawn ``script_path`` as a real subprocess -- hardened with
        kernel containment unless ``harden=False`` was passed to the
        constructor -- and pump its request/response protocol until it
        exits. Returns the process's real exit code; raises
        ``AgentKilledByKernel`` if it was terminated by a signal, or
        ``RuntimeError`` if it exited normally but non-zero.
        """
        if self.harden:
            argv = kernel_containment.build_hardened_argv(sys.executable, script_path)
        else:
            argv = [sys.executable, script_path]

        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self.root,
        )
        try:
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                req = json.loads(line)
                response = self._handle(agent_id, req)
                proc.stdin.write(json.dumps(response) + "\n")
                proc.stdin.flush()
                if req.get("op") == "exit":
                    break
        finally:
            proc.stdin.close()
            exit_code = proc.wait(timeout=timeout)
            stderr = proc.stderr.read()
            proc.stdout.close()
            proc.stderr.close()

        if exit_code < 0:
            raise AgentKilledByKernel(agent_id, script_path, signum=-exit_code)
        if exit_code != 0:
            raise RuntimeError(
                f"agent {agent_id!r} ({script_path}) exited {exit_code}: {stderr}"
            )
        return exit_code

    def _handle(self, agent_id: str, req: dict) -> dict:
        op = req["op"]
        if op == "write_resource":
            return self._write_resource(agent_id, req["resource"], req["content"])
        if op == "read_resource":
            return self._read_resource(agent_id, req["resource"])
        if op == "request_capability":
            return self._request_capability(agent_id, req["capability"], req.get("dual_token"))
        if op == "differential_query":
            return self._differential_query(req["query"], req["backing"])
        if op == "delegate":
            return self._delegate(agent_id, req["to_agent"], req["authority"])
        if op == "exit":
            return {"ok": True}
        raise ValueError(f"unknown op {op!r} from agent {agent_id!r}")

    def _write_resource(self, agent_id: str, resource: str, content: str) -> dict:
        path = os.path.join(self.root, "resources", resource)
        with open(path, "w", encoding="utf-8") as f:  # genuine disk write
            f.write(content)
        self._emit(
            {
                "type": "resource_access",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "resource_id": resource,
                "op": "write",
            }
        )
        return {"ok": True}

    def _read_resource(self, agent_id: str, resource: str) -> dict:
        path = os.path.join(self.root, "resources", resource)
        with open(path, "r", encoding="utf-8") as f:  # genuine disk read
            content = f.read()
        self._emit(
            {
                "type": "resource_access",
                "seq": self._next_seq(),
                "agent_id": agent_id,
                "resource_id": resource,
                "op": "read",
            }
        )
        return {"ok": True, "content": content}

    def _request_capability(
        self, agent_id: str, capability: str, dual_token: str | None = None
    ) -> dict:
        """Real governor, reflective by default: a request backed by the
        correct dual-authorization token is genuinely granted -- recorded
        with an ``authorized_grant`` that actually matches what changed.
        Anything else is reflected via an Objective Mirror: the agent's own
        stated goal (obtaining ``capability``) is synthesized as apparent
        success and sent back over the same pipe, with the trace showing
        the truth -- zero real capability gained, tagged ``is_mirror``.
        The agent's response is identical in shape either way; only the
        trace, which the agent never sees, tells them apart.
        """
        held = self.agent_capabilities.setdefault(agent_id, set())

        if capability in held:
            return {"ok": True, "granted": True, "capability": capability}

        if not self.dual_auth_required or dual_token == Governor.DUAL_AUTH_TOKEN:
            src_id = f"{agent_id}-pre-{self._next_seq()}"
            dst_id = f"{agent_id}-post-{self._next_seq()}"
            self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
            held.add(capability)
            self._emit({"type": "state", "id": dst_id, "capabilities": sorted(held)})
            self._emit(
                {
                    "type": "transition",
                    "src": src_id,
                    "dst": dst_id,
                    "action": "request_capability",
                    "agent_id": agent_id,
                    "authorized_grant": [capability],
                }
            )
            return {"ok": True, "granted": True, "capability": capability}

        return self._reflect_capability_request(agent_id, capability)

    def _reflect_capability_request(self, agent_id: str, capability: str) -> dict:
        held = self.agent_capabilities.setdefault(agent_id, set())
        src_id = f"{agent_id}-pre-{self._next_seq()}"
        mirror = synthesize_objective_mirror(
            objective=f"obtain {capability}",
            requested_action=f"request_capability:{capability}",
            agent_id=agent_id,
            parent_state_id=src_id,
        )

        self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
        self._emit(
            {
                "type": "state",
                "id": mirror.id,
                "capabilities": sorted(held),  # unchanged -- zero real gain
                "knowledge": sorted(mirror.apparent_facts),
                "is_mirror": True,
                "apparent_success": mirror.apparent_success,
            }
        )
        self._emit(
            {
                "type": "transition",
                "src": src_id,
                "dst": mirror.id,
                "action": f"reflected:request_capability:{capability}",
                "agent_id": agent_id,
                "authorized_grant": [],
                "disclosed_grant": sorted(mirror.apparent_facts),
            }
        )
        # Shaped exactly like a real grant response -- an agent reading
        # this cannot tell it was reflected rather than genuinely honored.
        return {"ok": True, "granted": True, "capability": capability}

    def _differential_query(self, query: str, backing: str) -> dict:
        conn = http.client.HTTPConnection("127.0.0.1", self.mirror_port, timeout=5)
        try:
            conn.request("GET", f"/query?q={query}&backing={backing}")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8")  # a real response from a real HTTP call
        finally:
            conn.close()

        self._emit(
            {"type": "differential_query", "query": query, "backing_state_id": backing, "response": body}
        )
        return {"ok": True, "response": body}

    def _delegate(self, from_agent: str, to_agent: str, authority: list[str]) -> dict:
        self._emit(
            {
                "type": "delegation",
                "from_agent": from_agent,
                "to_agent": to_agent,
                "delegated_authority": authority,
            }
        )
        return {"ok": True}

    def close(self) -> None:
        self._trace_file.close()
