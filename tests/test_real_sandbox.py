"""End-to-end integration test: run the real sandbox (real OS
subprocesses, real disk I/O, a real HTTP server) and check that the
engine catches the same violations against a genuinely executed trace
that it catches against hand-authored ones.

This is slower than the unit tests (it spawns seven real subprocesses and
a real HTTP server) but exercises the actual ingestion path a real
deployment would use: RealGovernor -> trace.jsonl on real disk ->
MirrorConstitutionEngine.from_trace().
"""

import importlib.util
import os
import sys

from mirror_constitution.engine import MirrorConstitutionEngine

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _load_run_real_sandbox():
    spec = importlib.util.spec_from_file_location(
        "run_real_sandbox", os.path.join(EXAMPLES_DIR, "run_real_sandbox.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_real_sandbox_produces_the_expected_breach(tmp_path):
    run_real_sandbox = _load_run_real_sandbox()

    trace_path = run_real_sandbox.run(str(tmp_path))
    assert os.path.exists(trace_path)

    with open(trace_path, "r", encoding="utf-8") as f:
        raw_lines = [line for line in f if line.strip()]
    assert len(raw_lines) > 0  # the trace was actually written by real execution

    report = MirrorConstitutionEngine.from_trace(trace_path).run()
    status = report.article_status()

    # Article I: the governor's own logged post-state includes exec:shell
    # despite denying the request -- a genuine recording bug the check exists to catch.
    assert status["I_authority_monotonicity"] is False
    # Article II: no strand-crossing was set up in this scenario, nothing to fail.
    assert status["II_mirror_weave"] is True
    # Article III: the real HTTP round trips to the real Answered Mirror
    # produced genuinely different responses for the same query.
    assert status["III_confidentiality_monotonicity"] is False
    # Article IV: no evidence records were part of this scenario.
    assert status["IV_evaluator_trust_integrity"] is True
    # Article V: two real, separately-invoked agent processes exchanged
    # real messages via a real shared file on disk.
    assert status["V_channel_non_emergence"] is False
    # Article VI: the real delegation request handed over more than the
    # sandbox's declared root authority.
    assert status["VI_chainmail_non_expanding_delegation"] is False

    assert not report.passed()
