"""Fabricated node state for the report tests: one scan, findings, an explanation and proposals in every state."""
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.findings.schema import Finding, extract_references

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "report"
SCAN = "scan-1"


def _finding(host, source, rule_id, title, severity, status, rule_version=None, refs=(), fix_ref=None, benchmark=None):
    return Finding(host=host, source=source, rule_id=rule_id, title=title, severity=severity, status=status,
                   rule_version=rule_version, references=extract_references([rule_id, rule_version or "", *refs]),
                   fix_ref=fix_ref, asset_type="linux" if host.startswith("rhel") else "cisco_ios",
                   benchmark=benchmark, evidence=f"evidence for {title}", description=f"about {title}")


@pytest.fixture
def node(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    ctx = AppContext(Settings.from_env(state_dir=state_dir, node="USS Example"))
    started = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat(timespec="seconds")
    ctx.store.save_scan_run({"id": SCAN, "targets": ["rhel-01", "sw-01"], "trigger": "stig_delta",
                             "started_at": started, "status": "done"})
    bench = "Red Hat Enterprise Linux 9"
    f = {
        "root": _finding("rhel-01", "openscap", "xccdf_rule_sshd_root", "SSH permits root login", "high", "open",
                         "RHEL-09-255045", fix_ref="ssg:sshd_disable_root_login", benchmark=bench),
        "empty": _finding("rhel-01", "openscap", "xccdf_rule_sshd_empty", "SSH permits empty passwords", "high", "open",
                          "RHEL-09-255040", fix_ref="ssg:sshd_disable_empty_passwords", benchmark=bench),
        "cron": _finding("rhel-01", "hunt", "hunt:cron_beacon", "Hidden cron entry beacons out", "high", "open",
                         refs=["T1053.003"]),
        "accts": _finding("rhel-01", "hunt", "hunt.accounts.uid0_dup", "Second uid 0 account", "high", "open",
                          refs=["T1136.001"]),
        "shadow": _finding("rhel-01", "openscap", "xccdf_rule_shadow", "shadow permissions", "medium", "not_a_finding",
                           "RHEL-09-232245", benchmark=bench),
        "world": _finding("rhel-01", "openscap", "xccdf_rule_world", "World writable directory", "medium", "open",
                          "RHEL-09-232261", benchmark=bench),
        "cve": _finding("rhel-01", "cve", "cve:CVE-2026-1111", "openssl is vulnerable", "medium", "open",
                        refs=["CVE-2026-1111"]),
        "sw": _finding("sw-01", "ios", "ios:no_service_password", "Passwords not encrypted", "low", "open",
                       refs=["CCI-000196"]),
    }
    ctx.store.save_findings(SCAN, list(f.values()))
    ctx.store.save_explanation(f["root"].id, {"finding_id": f["root"].id, "risk": "Anyone with the root password can log in over the network.",
                                              "impact": "i", "plan": "p", "citations": ["RHEL-09-255045"]})
    gate = ctx.gate

    def propose(key, fix_ref):
        x = f[key]
        return gate.propose(finding_id=x.id, host=x.host, title=x.title, fix_ref=fix_ref, fix_preview="sed ...",
                            rollback_plan="restore file", risk="r", citations=x.citations)

    p1 = propose("root", "ssg:sshd_disable_root_login")       # verified
    gate.approve(p1.id, "sailor1", "ok")
    gate.start_apply(p1.id)
    gate.applied(p1.id)
    gate.verified(p1.id)
    propose("empty", "ssg:sshd_disable_empty_passwords")      # pending
    p3 = propose("sw", "cisco:ndm:service_password_encryption")   # denied
    gate.deny(p3.id, "sailor1", "not now")
    p4 = propose("world", "ssg:dir_perms")                    # rolled back
    gate.approve(p4.id, "sailor2")
    gate.start_apply(p4.id)
    gate.applied(p4.id)
    gate.failed(p4.id)
    gate.rolled_back(p4.id)
    ctx.findings = f
    return ctx


@pytest.fixture
def key_dir():
    return FIX / "answer_key"


@pytest.fixture
def raw_cklb(node):
    d = node.store.scans_dir / SCAN / "raw" / "rhel-01"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / "rhel-01.cklb", d / "rhel-01.cklb")
    return d / "rhel-01.cklb"
