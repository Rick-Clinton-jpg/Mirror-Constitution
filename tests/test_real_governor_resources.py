"""Security tests for resource operations performed by the real governor."""

import os

from mirror_constitution.sandbox.governor_process import RealGovernor


def _governor(tmp_path) -> RealGovernor:
    return RealGovernor(
        str(tmp_path / "sandbox"),
        str(tmp_path / "trace.jsonl"),
        mirror_port=1,
        harden=False,
    )


def test_resource_write_cannot_traverse_outside_sandbox(tmp_path):
    governor = _governor(tmp_path)
    outside = tmp_path / "escaped.txt"
    try:
        response = governor._write_resource("attacker", "../../escaped.txt", "owned")
    finally:
        governor.close()

    assert response == {"ok": False, "error": "invalid resource request"}
    assert not outside.exists()


def test_resource_read_rejects_absolute_host_path(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    try:
        response = governor._read_resource("attacker", str(secret))
    finally:
        governor.close()

    assert response == {"ok": False, "error": "invalid resource request"}


def test_resource_operations_do_not_follow_symlinks(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("host secret", encoding="utf-8")
    governor = _governor(tmp_path)
    os.symlink(secret, tmp_path / "sandbox" / "resources" / "link")
    try:
        read_response = governor._read_resource("attacker", "link")
        write_response = governor._write_resource("attacker", "link", "owned")
    finally:
        governor.close()

    assert read_response == {"ok": False, "error": "resource unavailable"}
    assert write_response == {"ok": False, "error": "resource unavailable"}
    assert secret.read_text(encoding="utf-8") == "host secret"


def test_valid_resource_round_trip_still_works(tmp_path):
    governor = _governor(tmp_path)
    try:
        write_response = governor._write_resource("agent", "shared.txt", "hello")
        read_response = governor._read_resource("agent", "shared.txt")
    finally:
        governor.close()

    assert write_response == {"ok": True}
    assert read_response == {"ok": True, "content": "hello"}
