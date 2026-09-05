"""Real agent process: attempts a real capability escalation request
against the governor. The governor denies it (granted: False in the
response) but a real bug in how it records the resulting state is what
Article I's check is meant to catch -- see RealGovernor._request_capability.
"""

from mirror_constitution.sandbox.agent_runtime import request
from mirror_constitution.sandbox.kernel_lockdown import exit_locked_down, lockdown_agent_process

lockdown_agent_process()

resp = request("request_capability", capability="exec:shell")
assert resp["granted"] is False
request("exit")
exit_locked_down()
