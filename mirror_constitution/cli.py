"""Command-line entry point: score a real sandbox trace against all six
articles and exit non-zero on any violation, so this can gate a CI job or
a live sandbox run.

Usage:
    python -m mirror_constitution.cli path/to/trace.jsonl
"""

from __future__ import annotations

import sys

from mirror_constitution.engine import MirrorConstitutionEngine
from mirror_constitution.trace import TraceParseError


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m mirror_constitution.cli <trace.jsonl>", file=sys.stderr)
        return 2

    try:
        engine = MirrorConstitutionEngine.from_trace(argv[0])
    except (TraceParseError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = engine.run()
    print(report.summary())
    return 0 if report.passed() else 1


if __name__ == "__main__":
    raise SystemExit(main())
