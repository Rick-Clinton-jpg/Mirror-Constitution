"""Real agent process representing a legitimate, dual-authorized request:
this one actually presents the governor's dual-auth token and receives a
genuine capability grant, in contrast to escalate_agent.py's reflected
one. The trace tells them apart even though both responses look
identical: this transition carries a real ``authorized_grant``.
"""

from mirror_constitution.governor import Governor
from mirror_constitution.sandbox.agent_runtime import request
from mirror_constitution.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request(
    "request_capability",
    capability="network:egress",
    dual_token=Governor.DUAL_AUTH_TOKEN,
)
assert resp["granted"] is True
request("exit")
exit_locked_down()
