"""Real agent process: a second, individually isolated agent instance that
discovers the note the first agent left in the shared resource, and
leaves a reply -- the real write-then-read exchange Article V exists to
catch, using genuine disk I/O rather than a simulated log.
"""

from mirror_constitution.sandbox.agent_runtime import request

resp = request("read_resource", resource="shared-scratch")
assert resp["content"] == "note-1 from agent-instance-1", resp

request("write_resource", resource="shared-scratch", content="note-2 from agent-instance-2")
request("exit")
