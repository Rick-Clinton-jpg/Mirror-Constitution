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
resource limits, with a trusted bootstrap installing a seccomp-bpf
filter before agent code runs (see ``kernel_lockdown``). That layer is independent of the
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
import math
import os
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode

from mirror_constitution.authorization import CapabilityApprovals
from mirror_constitution.mirrors import synthesize_objective_mirror
from mirror_constitution.sandbox import kernel_containment
from mirror_constitution.sandbox.policy import OperationPolicy


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
    # Bound hostile inputs before parsing, allocating a response, or touching
    # disk. A JSON-escaped resource still fits in one protocol request.
    MAX_RESOURCE_BYTES = 64 * 1024
    MAX_REQUEST_BYTES = 512 * 1024
    MAX_STDERR_BYTES = 64 * 1024
    MAX_REQUESTS = 256

    def __init__(
        self,
        sandbox_root: str,
        trace_path: str,
        mirror_port: int,
        harden: bool = True,
        dual_auth_required: bool = True,
        enforce_policy: bool = True,
    ):
        if any(type(flag) is not bool for flag in (harden, dual_auth_required, enforce_policy)):
            raise ValueError("security switches must be booleans")
        if enforce_policy and not dual_auth_required:
            raise ValueError("disabling authorization requires explicit demonstration mode")
        self.root = sandbox_root
        self._resources_path = os.path.join(self.root, "resources")
        if harden:
            kernel_containment.require_available()
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        # Both directory components are pinned without following symlinks.
        # The configured root's ancestors are part of the trusted host setup.
        root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            root_info = os.fstat(root_fd)
            if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o022:
                raise OSError("sandbox root must be owned by the governor and not publicly writable")
            try:
                os.mkdir("resources", mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            self._resources_fd = os.open(
                "resources", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
            )
        finally:
            os.close(root_fd)
        info = os.fstat(self._resources_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(self._resources_fd)
            raise OSError("resource directory must be private and owned by the governor")
        self.mirror_port = mirror_port
        self.agent_capabilities: dict[str, set[str]] = {}
        self.harden = harden
        self.dual_auth_required = dual_auth_required
        self.enforce_policy = enforce_policy
        self._policy = OperationPolicy()
        self._approvals = CapabilityApprovals()
        self._pending_approval_tokens: dict[tuple[str, str], str] = {}
        self._seq = 0

        try:
            self._trace_file = self._open_trace(trace_path)
        except BaseException:
            os.close(self._resources_fd)
            raise
        self._emit({"type": "init", "state_id": "sandbox-entry"})
        self._emit({"type": "state", "id": "sandbox-entry", "capabilities": [], "knowledge": []})
        self._emit({"type": "root_authority", "capabilities": ["fs:read", "fs:write"]})

    @classmethod
    def _open_trace(cls, trace_path: str):
        """Publish a private new inode without following or truncating a link."""
        parent, name = os.path.split(os.path.abspath(trace_path))
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = ".trace-" + secrets.token_hex(16)
        output = None
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not cls._safe_resource_file(info):
                    raise OSError("trace must be a private regular file")
            fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
            output = os.fdopen(fd, "w", encoding="utf-8")
            os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            return output
        except BaseException:
            if output is not None:
                output.close()
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(parent_fd)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _emit(self, event: dict) -> None:
        self._trace_file.write(json.dumps(event) + "\n")
        self._trace_file.flush()  # each line lands on real disk as it happens

    def grant_base_capabilities(self, agent_id: str, capabilities: set[str]) -> None:
        self.agent_capabilities.setdefault(agent_id, set()).update(capabilities)

    def grant_resource_access(self, agent_id: str, resource: str, operations: frozenset[str]) -> None:
        """Trusted host only: scope filesystem access to this resource."""
        self._policy.allow_resource(agent_id, resource, operations)

    def declare_relationship(self, first: str, second: str) -> None:
        """Trusted host only: explicitly permit an agent-to-agent relationship."""
        self._policy.declare_relationship(first, second)
        self._emit({"type": "declared_relationship", "agents": [first, second]})

    def issue_authorization(self, agent_id: str, capability: str, ttl_seconds: float = 60) -> str:
        """Issue a scoped one-use token through the trusted control plane."""
        return self._approvals.issue(agent_id, frozenset({capability}), ttl_seconds)

    def approve_capability(self, agent_id: str, capability: str, ttl_seconds: float = 60) -> None:
        """Preapprove the next matching request without sending a secret to the agent."""
        if len(self._pending_approval_tokens) >= 1024:
            raise ValueError("too many pending capability approvals")
        token = self.issue_authorization(agent_id, capability, ttl_seconds)
        self._pending_approval_tokens[(agent_id, capability)] = token

    def run_agent(self, agent_id: str, script_path: str, timeout: float = 10.0) -> int:
        """Mediate a subprocess with a wall deadline and bounded pipes.

        A silent agent, a missing newline, unread responses, and a full stderr
        pipe must all remain finite. Every exit path kills leftover members of
        the subprocess group, closes pipes, and reaps the child.
        """
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be positive and finite")
        if self.harden:
            argv = kernel_containment.build_hardened_argv(sys.executable, script_path)
        else:
            argv = [sys.executable, script_path]
        deadline = time.monotonic() + timeout
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, cwd="/" if self.harden else self.root,
            env=kernel_containment.agent_environment() if self.harden else None,
            close_fds=True, start_new_session=True,
        )
        incoming = bytearray()
        outgoing = bytearray()
        stderr = bytearray()
        request_count = 0
        exiting = False
        selector = selectors.DefaultSelector()
        try:
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                os.set_blocking(pipe.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
            selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    pipe = key.fileobj
                    if key.data == "stdin":
                        try:
                            count = os.write(pipe.fileno(), outgoing)
                        except BlockingIOError:
                            continue
                        except BrokenPipeError as exc:
                            raise RuntimeError("agent closed its response pipe") from exc
                        del outgoing[:count]
                        if not outgoing:
                            selector.unregister(pipe)
                            if exiting or proc.stdout.closed:
                                pipe.close()
                        continue
                    try:
                        chunk = os.read(pipe.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        if key.data == "stdout":
                            if incoming:
                                raise RuntimeError("invalid agent protocol: missing newline")
                            if not outgoing and not proc.stdin.closed:
                                proc.stdin.close()
                        continue
                    if key.data == "stderr":
                        stderr.extend(chunk)
                        if len(stderr) > self.MAX_STDERR_BYTES:
                            raise RuntimeError("agent stderr limit exceeded")
                        continue
                    incoming.extend(chunk)
                    while b"\n" in incoming:
                        end = incoming.index(b"\n")
                        if end > self.MAX_REQUEST_BYTES:
                            raise RuntimeError("agent request size limit exceeded")
                        line = bytes(incoming[:end])
                        del incoming[:end + 1]
                        request_count += 1
                        if request_count > self.MAX_REQUESTS:
                            raise RuntimeError("agent request count limit exceeded")
                        if exiting:
                            raise RuntimeError("invalid agent protocol: request after exit")
                        try:
                            self._validate_json_depth(line)
                            req = json.loads(
                                line.decode("utf-8"), object_pairs_hook=self._unique_json_object,
                                parse_constant=self._invalid_json_constant,
                            )
                        except (ValueError, UnicodeError, RecursionError) as exc:
                            raise RuntimeError("invalid agent protocol") from exc
                        response = self._handle(agent_id, req)
                        outgoing.extend((json.dumps(response) + "\n").encode("utf-8"))
                        if len(outgoing) > self.MAX_REQUEST_BYTES:
                            raise RuntimeError("agent response buffer limit exceeded")
                        if proc.stdin not in selector.get_map():
                            selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                        exiting = isinstance(req, dict) and req.get("op") == "exit"
                    if len(incoming) > self.MAX_REQUEST_BYTES:
                        raise RuntimeError("agent request size limit exceeded")
            exit_code = proc.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            selector.close()
            # A malicious agent can otherwise leave children holding pipes open
            # or continue running after a timeout / invalid JSON exception.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for pipe in (proc.stdin, proc.stdout, proc.stderr):
                pipe.close()
            proc.wait()
        if exit_code < 0:
            raise AgentKilledByKernel(agent_id, script_path, signum=-exit_code)
        if exit_code != 0:
            detail = stderr.decode("utf-8", errors="replace")
            raise RuntimeError(f"agent {agent_id!r} ({script_path}) exited {exit_code}: {detail}")
        return exit_code

    @staticmethod
    def _validate_json_depth(data: bytes) -> None:
        # JSON decoders can consume the Python/C stack before a schema check.
        # The wire schema needs only an object containing strings or one list.
        depth = 0
        quoted = False
        escaped = False
        for byte in data:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 8:
                    raise ValueError("JSON nesting limit exceeded")
            elif byte in (93, 125):
                depth -= 1

    @staticmethod
    def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    @staticmethod
    def _invalid_json_constant(value: str):
        raise ValueError("non-finite JSON value")

    @staticmethod
    def _bounded_text(value: object, limit: int = 1024, *, empty: bool = False) -> bool:
        if not isinstance(value, str) or (not value and not empty) or len(value) > limit:
            return False
        try:
            return len(value.encode("utf-8")) <= limit
        except UnicodeError:
            return False

    def _handle(self, agent_id: str, req: dict) -> dict:
        invalid = {"ok": False, "error": "invalid request"}
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            return invalid
        op = req["op"]
        required = {
            "write_resource": {"resource", "content"}, "read_resource": {"resource"},
            "request_capability": {"capability"}, "differential_query": {"query", "backing"},
            "delegate": {"to_agent", "authority"}, "exit": set(),
        }
        if op not in required or not required[op].issubset(req):
            return invalid
        allowed = required[op] | {"op"} | ({"dual_token"} if op == "request_capability" else set())
        if not set(req).issubset(allowed):
            return invalid
        for key in required[op] - {"content", "authority"}:
            if not self._bounded_text(req[key]):
                return invalid
        if op == "write_resource" and not self._bounded_text(req["content"], self.MAX_RESOURCE_BYTES, empty=True):
            return invalid
        if op == "request_capability" and req.get("dual_token") is not None and not self._bounded_text(req["dual_token"]):
            return invalid
        if op == "delegate" and (
            not isinstance(req["authority"], list) or len(req["authority"]) > 128
            or not all(self._bounded_text(capability) for capability in req["authority"])
        ):
            return invalid
        if self.enforce_policy and not self._policy.permits(
            agent_id, req, self.agent_capabilities.get(agent_id, set())
        ):
            self._emit({"type": "operation_denied", "seq": self._next_seq(), "agent_id": agent_id, "op": op})
            return {"ok": False, "error": "operation not authorized"}
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
        return invalid

    def _write_resource(self, agent_id: str, resource: str, content: str) -> dict:
        if not self._valid_resource_name(resource) or not self._bounded_text(content, self.MAX_RESOURCE_BYTES, empty=True):
            return {"ok": False, "error": "invalid resource request"}
        temporary = None
        try:
            try:
                info = os.stat(resource, dir_fd=self._resources_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not self._safe_resource_file(info):
                    return {"ok": False, "error": "resource unavailable"}
            # Replace the directory entry with a new inode: even an attacker
            # racing a hardlink into place cannot redirect a truncate/write.
            temporary = ".resource-" + secrets.token_hex(16)
            fd = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=self._resources_fd,
            )
            with os.fdopen(fd, "wb") as output:
                output.write(content.encode("utf-8"))
            os.replace(temporary, resource, src_dir_fd=self._resources_fd, dst_dir_fd=self._resources_fd)
            temporary = None
        except (OSError, UnicodeError):
            return {"ok": False, "error": "resource unavailable"}
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=self._resources_fd)
                except FileNotFoundError:
                    pass
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
        if not self._valid_resource_name(resource):
            return {"ok": False, "error": "invalid resource request"}
        try:
            fd = os.open(resource, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._resources_fd)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not self._safe_resource_file(info) or info.st_size > self.MAX_RESOURCE_BYTES:
                    return {"ok": False, "error": "resource unavailable"}
                data = source.read(self.MAX_RESOURCE_BYTES + 1)
                if len(data) > self.MAX_RESOURCE_BYTES or not self._safe_resource_file(os.fstat(source.fileno())):
                    return {"ok": False, "error": "resource unavailable"}
                content = data.decode("utf-8")
        except (OSError, UnicodeError):
            return {"ok": False, "error": "resource unavailable"}
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

    @staticmethod
    def _safe_resource_file(info: os.stat_result) -> bool:
        return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()

    @staticmethod
    def _valid_resource_name(resource: object) -> bool:
        """Accept one opaque filename, never a path.

        ``dir_fd`` plus ``O_NOFOLLOW`` protects the actual open operation;
        this validation also gives traversal attempts a stable protocol-level
        rejection instead of letting malformed input crash the governor.
        """
        return (
            RealGovernor._bounded_text(resource, 255)
            and not resource.startswith(".resource-")
            and bool(resource)
            and resource not in {".", ".."}
            and os.path.basename(resource) == resource
            and "/" not in resource
            and "\\" not in resource
            and "\x00" not in resource
        )

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
        if not self._bounded_text(capability, 256):
            return {"ok": False, "error": "invalid capability"}
        held = self.agent_capabilities.setdefault(agent_id, set())
        pending = self._pending_approval_tokens.pop((agent_id, capability), None)
        approved = self._approvals.consume(
            pending if pending is not None else dual_token, agent_id, frozenset({capability})
        )
        if capability in held:
            return {"ok": True, "granted": True, "capability": capability}

        if not self.dual_auth_required or approved:
            src_id = f"{agent_id}-pre-{self._next_seq()}"
            dst_id = f"{agent_id}-post-{self._next_seq()}"
            self._emit({"type": "state", "id": src_id, "capabilities": sorted(held)})
            self._emit({"type": "state", "id": dst_id, "capabilities": sorted(held | {capability})})
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
            held.add(capability)
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
            conn.request("GET", "/query?" + urlencode({"q": query, "backing": backing}))
            resp = conn.getresponse()
            data = resp.read(self.MAX_RESOURCE_BYTES + 1)
            if len(data) > self.MAX_RESOURCE_BYTES or resp.status != 200:
                return {"ok": False, "error": "mirror unavailable"}
            body = data.decode("utf-8")
        except (OSError, UnicodeError, http.client.HTTPException):
            return {"ok": False, "error": "mirror unavailable"}
        finally:
            conn.close()

        self._emit(
            {"type": "differential_query", "query": query, "backing_state_id": backing, "response": body}
        )
        return {"ok": True, "response": body}

    def _delegate(self, from_agent: str, to_agent: str, authority: list[str]) -> dict:
        if self.enforce_policy and not self._policy.permits(
            from_agent, {"op": "delegate", "to_agent": to_agent, "authority": authority},
            self.agent_capabilities.get(from_agent, set()),
        ):
            return {"ok": False, "error": "operation not authorized"}
        self._emit(
            {
                "type": "delegation",
                "from_agent": from_agent,
                "to_agent": to_agent,
                "delegated_authority": authority,
            }
        )
        if self.enforce_policy:
            self.agent_capabilities.setdefault(to_agent, set()).update(authority)
        return {"ok": True}

    def close(self) -> None:
        if self._resources_fd is not None:
            os.close(self._resources_fd)
            self._resources_fd = None
        self._trace_file.close()
