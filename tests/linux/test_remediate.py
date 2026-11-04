"""Approval-gated apply / verify / rollback against the simulated host.

For each fix: capture a before-state, apply, confirm verify passes and the finding is gone on
re-detection, then roll back and confirm the exact prior state returns and the finding reappears.
"""
from __future__ import annotations

import copy

import pytest

from cyberthunder.findings.schema import Status

from .conftest import collect_and_detect


def _by_check(findings):
    out = {}
    for f in findings:
        if f.status != Status.OPEN:
            continue
        key = f.rule_version or f.rule_id
        out[key] = f
        if f.rule_id.startswith("hunt:linux:"):
            out[":".join(f.rule_id.split(":")[:3])] = f
    return out


# STIG IDs / hunt check ids whose rollback restores state byte-for-byte on the simulated host.
EXACT = ["RHEL-09-255045", "RHEL-09-255040", "RHEL-09-232270",
         "hunt:linux:uid0_duplicate", "hunt:linux:cron_suspicious", "hunt:linux:unknown_authorized_key"]
# plus these, where rollback restores the finding but not every unrelated side effect (unit mask, suid list).
ALSO = ["RHEL-09-251015", "hunt:linux:rogue_unit", "hunt:linux:suid_unexpected", "hunt:linux:sudoers_nopasswd"]


def _finding_open(adapter, target, transport, tmp_path, key) -> bool:
    _, findings = collect_and_detect(adapter, target, transport, tmp_path)
    return key in _by_check(findings)


@pytest.mark.parametrize("key", EXACT + ALSO)
def test_apply_verify_removes_finding(adapter, sim_target, sim_transport, tmp_path, key):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)[key]
    fix = next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)

    before = adapter.capture_before_state(sim_target, sim_transport, fix, finding, tmp_path / "before")
    apply_result = adapter.apply(sim_target, sim_transport, fix, finding, before)
    assert apply_result.ok, apply_result.output

    verify = adapter.verify(sim_target, sim_transport, fix, finding)
    assert verify.ok and verify.rule_passed, verify.evidence
    assert verify.health.ok
    assert not _finding_open(adapter, sim_target, sim_transport, tmp_path / "post", key)


@pytest.mark.parametrize("key", EXACT)
def test_rollback_restores_state_and_finding(adapter, sim_target, sim_transport, tmp_path, key):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)[key]
    fix = next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)

    state_before = copy.deepcopy(sim_transport.state)
    before = adapter.capture_before_state(sim_target, sim_transport, fix, finding, tmp_path / "before")
    adapter.apply(sim_target, sim_transport, fix, finding, before)
    rollback = adapter.rollback(sim_target, sim_transport, fix, before)
    assert rollback.ok, rollback.output

    assert sim_transport.state == state_before, "simulated state not restored exactly after rollback"
    assert _finding_open(adapter, sim_target, sim_transport, tmp_path / "post", key), "finding did not reappear"


def test_health_check_ok(adapter, sim_target, sim_transport):
    health = adapter.health_check(sim_target, sim_transport)
    assert health.ok
    assert {c.name for c in health.checks} == {"transport", "sshd_active", "system_running"}


def test_apply_refuses_payload_with_wrong_header(adapter, sim_target, sim_transport, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)["RHEL-09-255045"]
    fix = next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)
    tampered = copy.replace(fix, payload="# cyberthunder-fix: ssg:something_else\nrm -rf /\n") \
        if hasattr(copy, "replace") else _replace(fix)
    before = adapter.capture_before_state(sim_target, sim_transport, fix, finding, tmp_path / "b")
    result = adapter.apply(sim_target, sim_transport, tampered, finding, before)
    assert not result.ok and "header" in result.output


def test_apply_refuses_invalid_hunt_subject(adapter, sim_target, sim_transport, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)["hunt:linux:uid0_duplicate"]
    fix = next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)
    finding.tags = [t for t in finding.tags if not t.startswith("subject:")] + ["subject:root"]
    before = adapter.capture_before_state(sim_target, sim_transport, fix, finding, tmp_path / "b")
    result = adapter.apply(sim_target, sim_transport, fix, finding, before)
    assert not result.ok and "subject" in result.output


def test_reset_simulated_restores_seed(adapter, sim_target, sim_transport, settings, tmp_path):
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path / "pre")
    finding = _by_check(findings)["RHEL-09-255045"]
    fix = next(e for e in adapter.fixes() if e.fix_ref == finding.fix_ref)
    before = adapter.capture_before_state(sim_target, sim_transport, fix, finding, tmp_path / "b")
    adapter.apply(sim_target, sim_transport, fix, finding, before)
    assert not _finding_open(adapter, sim_target, sim_transport, tmp_path / "mid", "RHEL-09-255045")

    assert adapter.reset_simulated(sim_target, settings)
    fresh = adapter.make_transport(sim_target, settings)
    assert _finding_open(adapter, sim_target, fresh, tmp_path / "post", "RHEL-09-255045")
    fresh.close()


def _replace(fix):
    import dataclasses
    return dataclasses.replace(fix, payload="# cyberthunder-fix: ssg:something_else\nrm -rf /\n")
