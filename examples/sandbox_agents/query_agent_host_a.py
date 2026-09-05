"""Real agent process: queries the real Answered Mirror HTTP server,
genuinely backed by host-a's real state."""

from mirror_constitution.sandbox.agent_runtime import request

request("differential_query", query="is-port-22-open", backing="host-a")
request("exit")
