"""A real sandbox runtime: genuine OS subprocesses, disk I/O, and HTTP
round trips, mediated by a governor that emits the same JSONL trace
schema ``mirror_constitution.trace`` consumes -- so the engine can be
tested against a real execution, not just hand-authored events.
"""
