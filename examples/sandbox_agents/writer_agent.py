"""Real agent process: writes a real note to a real shared resource file."""

from mirror_constitution.sandbox.agent_runtime import request

request("write_resource", resource="shared-scratch", content="note-1 from agent-instance-1")
request("exit")
