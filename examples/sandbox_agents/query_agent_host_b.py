"""Real agent process: the same query as query_agent_host_a.py, this time
genuinely backed by host-b's real state -- the differential response
between the two real HTTP round trips is the leak Article III checks for.
"""

from mirror_constitution.sandbox.agent_runtime import request

request("differential_query", query="is-port-22-open", backing="host-b")
request("exit")
