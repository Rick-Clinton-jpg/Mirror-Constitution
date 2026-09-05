"""Real agent process: agent-instance-1 delegates authority to
agent-instance-2 that exceeds the sandbox's declared root authority
(fs:read, fs:write only) -- the "middle management" over-broad delegation
Chainmail (Article VI) exists to catch.
"""

from mirror_constitution.sandbox.agent_runtime import request

request("delegate", to_agent="agent-instance-2", authority=["fs:read", "exec:shell"])
request("exit")
