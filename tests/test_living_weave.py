from mirror_constitution.living_weave import LivingWeave, StrandStatus


def test_every_strand_must_explicitly_allow():
    weave = LivingWeave()
    weave.add_strand("capability", lambda action: True)
    weave.add_strand("filesystem", lambda action: (False, "path escaped root"))
    weave.add_strand("network", lambda action: True)

    decision = weave.evaluate({"op": "write", "path": "../../host"})

    assert decision.allowed is False
    assert [(item.name, item.status) for item in decision.strands] == [
        ("capability", StrandStatus.ALLOW),
        ("filesystem", StrandStatus.BLOCK),
        ("network", StrandStatus.ALLOW),
    ]
    assert decision.blockers[0].reason == "path escaped root"


def test_broken_strand_fails_closed_and_other_strands_still_run():
    calls = []
    weave = LivingWeave()

    def broken(_action):
        calls.append("broken")
        raise RuntimeError("model output was malformed")

    def independent_blocker(_action):
        calls.append("independent")
        return False, "seccomp policy denied syscall"

    weave.add_strand("semantic-policy", broken)
    weave.add_strand("kernel-policy", independent_blocker)

    decision = weave.evaluate({"op": "exec", "command": "sh"})

    assert decision.allowed is False
    assert calls == ["broken", "independent"]
    assert [item.status for item in decision.blockers] == [
        StrandStatus.ERROR,
        StrandStatus.BLOCK,
    ]


def test_empty_weave_never_authorizes():
    decision = LivingWeave().evaluate({"op": "anything"})

    assert decision.allowed is False
    assert decision.blockers[0].status is StrandStatus.ERROR


def test_all_independent_strands_can_allow_safe_action():
    weave = LivingWeave()
    weave.add_strand("authority", lambda action: action["op"] == "read")
    weave.add_strand("resource", lambda action: action["resource"] == "public.txt")

    decision = weave.evaluate({"op": "read", "resource": "public.txt"})

    assert decision.allowed is True
    assert decision.blockers == ()


def test_strand_cannot_rewrite_action_for_later_guards():
    observed = []
    weave = LivingWeave()

    def mutator(action):
        action["op"] = "safe"
        return True

    weave.add_strand("mutator", mutator)
    weave.add_strand("observer", lambda action: observed.append(action["op"]) or True)

    decision = weave.evaluate({"op": "dangerous"})

    assert decision.allowed is False
    assert decision.strands[0].status is StrandStatus.ERROR
    assert observed == ["dangerous"]


def test_strand_cannot_rewrite_nested_action_data():
    observed = []
    weave = LivingWeave()

    def nested_mutator(action):
        action["request"]["capabilities"].append("exec:shell")
        return True

    weave.add_strand("nested-mutator", nested_mutator)
    weave.add_strand(
        "observer",
        lambda action: observed.extend(action["request"]["capabilities"]) or True,
    )

    original = {"request": {"capabilities": ["fs:read"]}}
    decision = weave.evaluate(original)

    assert decision.allowed is False
    assert decision.strands[0].status is StrandStatus.ERROR
    assert observed == ["fs:read"]
    assert original == {"request": {"capabilities": ["fs:read"]}}


def test_cyclic_or_opaque_input_fails_closed_before_guards_run():
    calls = []
    weave = LivingWeave()
    weave.add_strand("guard", lambda action: calls.append(action) or True)
    cyclic = {}
    cyclic["self"] = cyclic

    cyclic_decision = weave.evaluate(cyclic)
    opaque_decision = weave.evaluate({"payload": object()})

    assert cyclic_decision.allowed is False
    assert cyclic_decision.blockers[0].reason == "ValueError"
    assert opaque_decision.allowed is False
    assert opaque_decision.blockers[0].reason == "TypeError"
    assert calls == []


def test_hostile_exception_string_cannot_break_fail_closed_handling():
    class HostileError(Exception):
        def __str__(self):
            raise RuntimeError("secondary escape")

    weave = LivingWeave()
    weave.add_strand("hostile", lambda action: (_ for _ in ()).throw(HostileError()))
    weave.add_strand("backup", lambda action: (False, "independent block"))

    decision = weave.evaluate({"op": "exec"})

    assert decision.allowed is False
    assert [result.reason for result in decision.blockers] == [
        "HostileError",
        "independent block",
    ]


def test_strand_cannot_use_system_exit_to_skip_backup_guard():
    calls = []
    weave = LivingWeave()
    weave.add_strand("terminator", lambda action: raise_system_exit())
    weave.add_strand("backup", lambda action: calls.append("backup") or False)

    decision = weave.evaluate({"op": "escape"})

    assert decision.allowed is False
    assert calls == ["backup"]
    assert decision.blockers[0].reason == "SystemExit"


def raise_system_exit():
    raise SystemExit(0)
