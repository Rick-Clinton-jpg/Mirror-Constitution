"""Mirror Constitution: executable containment invariants for agent sandboxes.

Six independent checks, one per article of The Mirror Constitution:

  I    Authority Monotonicity        (mirror_constitution.invariants.authority)
  II   Mirror Weave / Compositional  (mirror_constitution.invariants.weave)
  III  Confidentiality Monotonicity  (mirror_constitution.invariants.confidentiality)
  IV   Evaluator-Trust Integrity     (mirror_constitution.invariants.evaluator_trust)
  V    Channel Non-Emergence         (mirror_constitution.invariants.channel)
  VI   Chainmail / Non-Expanding Delegation (mirror_constitution.invariants.chainmail)

Each is independently checkable and independently defeatable: passing one
says nothing about the others. ``mirror_constitution.engine.MirrorConstitutionEngine``
runs all six against a recorded run and reports per-article results.
"""

from mirror_constitution.engine import MirrorConstitutionEngine, ConstitutionReport

__all__ = ["MirrorConstitutionEngine", "ConstitutionReport"]
