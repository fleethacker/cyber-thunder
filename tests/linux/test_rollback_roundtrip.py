"""Round trips for the fixes whose rollback is not a plain file restore: directory modes, a removed
package, a disabled unit, and the listener fix that stops the unit. Also the capture refusing an
unreadable file, and rollback reporting a restore command that failed."""
from __future__ import annotations

import copy

import pytest

from cyberthunder.transport.base import CommandResult, TransportError

from .conftest import collect_and_detect
from .test_remediate import _by_check, _finding_open


def _fix_for(adapter, finding):
    return next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)


def _apply(adapter, target, transport, tmp_path, key):
    _, findings = collect_and_detect(adapter, target, transport, tmp_path / "pre")
    finding = _by_check(findings)[key]
    fix = _fix_for(adapter, finding)
    before = adapter.capture_before_state(target, transport, fix, finding, tmp_path / "before")
    result = adapter.apply(target, transport, fix, finding, before)
    assert result.ok, result.output
    return finding, fix, before


def test_ww_dirs_rollback_restores_modes(adapter, sim_target, sim_transport, tmp_path):
    key = "linux:dir_perms_world_writable_system_owned"
    ww_before = copy.deepcopy(sim_transport.state["ww_dirs"])
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, key)
    assert not _finding_open(adapter, sim_target, sim_transport, tmp_path / "mid", key)

    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert rb.ok, rb.output
    assert "/var/log/acd-seed-dir" in rb.output
    assert sim_transport.state["ww_dirs"] == ww_before
    assert _finding_open(adapter, sim_target, sim_transport, tmp_path / "post", key)


def test_ww_dirs_rollback_refuses_paths_outside_root(adapter, sim_target, sim_transport, tmp_path):
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path,
                                  "linux:dir_perms_world_writable_system_owned")
    before.extra["path_modes"] += "777 /etc\n"
    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert not rb.ok and "/etc" in rb.output


def test_pkg_remove_rollback_reinstalls(adapter, sim_target, sim_transport, tmp_path):
    pkg = {"name": "telnet-server", "epoch": None, "version": "0.17", "release": "85.el9", "arch": "x86_64"}
    sim_transport.state["packages"].append(dict(pkg))
    sim_transport._save()
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, "RHEL-09-215040")
    assert not sim_transport._installed("telnet-server")

    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert rb.ok, rb.output
    assert "reinstalled telnet-server-0.17-85.el9.x86_64" in rb.output
    assert sim_transport._installed("telnet-server") == pkg
    assert "telnet-server" not in sim_transport.state["removed_packages"]
    assert _finding_open(adapter, sim_target, sim_transport, tmp_path / "post", "RHEL-09-215040")


def test_pkg_remove_rollback_fails_when_mirror_lacks_package(adapter, sim_target, sim_transport, tmp_path):
    sim_transport.state["packages"].append(
        {"name": "telnet-server", "epoch": None, "version": "0.17", "release": "85.el9", "arch": "x86_64"})
    sim_transport._save()
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, "RHEL-09-215040")
    sim_transport.state["mirror_packages"].clear()
    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert not rb.ok and "dnf" in rb.output


def test_disable_unit_rollback_restores_unit_files_and_quarantine(adapter, sim_target, sim_transport, tmp_path):
    s = sim_transport.state
    unit_before = dict(s["units"]["kworkerd.service"])
    files_before = copy.deepcopy(s["files"])
    quarantine_before = copy.deepcopy(s["quarantine"])
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, "hunt:linux:rogue_unit")
    assert s["units"]["kworkerd.service"]["enabled"] == "masked"

    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert rb.ok, rb.output
    assert s["units"]["kworkerd.service"] == unit_before
    assert s["files"] == files_before
    assert s["quarantine"] == quarantine_before
    assert _finding_open(adapter, sim_target, sim_transport, tmp_path / "post", "hunt:linux:rogue_unit")


def test_listener_fix_verifies(adapter, sim_target, sim_transport, tmp_path):
    key = "hunt:linux:unexpected_listener"
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, key)
    assert fix.fix_ref == "hunt:linux:disable_unit"
    verify = adapter.verify(sim_target, sim_transport, fix, finding)
    assert verify.ok and verify.rule_passed, verify.evidence
    assert [l["port"] for l in sim_transport.state["listeners"]] == [22]


def test_disable_unit_is_a_service_change(adapter):
    fix = next(e for e in adapter.fixes() if e.fix_ref == "hunt:linux:disable_unit")
    assert fix.disruption == "medium"
    assert fix.restarts_services


class _Unreadable:
    """Wraps the simulated host so one file cannot be read, as when sudo cat needs a password."""

    def __init__(self, inner, path):
        self.inner, self.path = inner, path

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def read_file(self, path):
        if path == self.path:
            raise TransportError("sudo: a password is required")
        return self.inner.read_file(path)


def test_unreadable_file_stops_capture(adapter, sim_target, sim_transport, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)["RHEL-09-255045"]
    fix = _fix_for(adapter, finding)
    t = _Unreadable(sim_transport, "/etc/ssh/sshd_config")
    with pytest.raises(TransportError, match="sshd_config"):
        adapter.capture_before_state(sim_target, t, fix, finding, tmp_path / "before")


def test_rollback_refuses_tampered_capture(adapter, sim_target, sim_transport, tmp_path):
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, "RHEL-09-255045")
    info = before.extra["files"]["/etc/ssh/sshd_config"]
    (tmp_path / "before" / "files" / info["local"]).write_bytes(b"")
    applied = sim_transport.state["files"]["/etc/ssh/sshd_config"]["content"]
    rb = adapter.rollback(sim_target, sim_transport, fix, before)
    assert not rb.ok and "sha256" in rb.output
    assert sim_transport.state["files"]["/etc/ssh/sshd_config"]["content"] == applied


class _FailingChown:
    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def run(self, command, **kw):
        if command.startswith("chown "):
            return CommandResult(command, 1, "", "chown: changing ownership: Operation not permitted")
        return self.inner.run(command, **kw)


def test_rollback_reports_failed_restore_command(adapter, sim_target, sim_transport, tmp_path):
    finding, fix, before = _apply(adapter, sim_target, sim_transport, tmp_path, "RHEL-09-255045")
    rb = adapter.rollback(sim_target, _FailingChown(sim_transport), fix, before)
    assert not rb.ok and "chown" in rb.output
