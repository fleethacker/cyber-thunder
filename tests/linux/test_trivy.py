"""parse_trivy on a static Trivy rootfs report."""
from __future__ import annotations

from cyberthunder.inventory.targets import Target
from cyberthunder.parsers.trivy import parse_trivy


def _target():
    return Target(id="t1", name="host", asset_type="linux", transport="fixture", options={"fixture_dir": "."})


def test_parse_trivy_four_vulns(fixtures_linux):
    findings = parse_trivy(fixtures_linux / "trivy_rootfs.json", target=_target())
    assert len(findings) == 4
    by_id = {f.rule_id: f for f in findings}

    ssh = by_id["cve:CVE-2024-6387:openssh-server"]
    assert ssh.severity.value == "high"
    assert ssh.title == "CVE-2024-6387 in openssh-server 8.7p1-38.el9"
    assert ssh.fix_text == "update openssh-server to 8.7p1-38.el9_4.1"
    assert ssh.fix_ref == "patch:openssh-server"
    assert ssh.ref_ids("cve") == ["CVE-2024-6387"]
    assert "pkg:openssh-server" in ssh.tags and "fixed:8.7p1-38.el9_4.1" in ssh.tags

    assert by_id["cve:CVE-2024-3094:xz-libs"].severity.value == "high"      # CRITICAL -> high
    assert by_id["cve:CVE-2023-38545:libcurl"].severity.value == "medium"
    assert by_id["cve:CVE-2023-38545:libcurl"].fix_text == "no fixed version"
    assert by_id["cve:CVE-2021-3999:glibc"].severity.value == "low"
    assert set(by_id["cve:CVE-2021-3999:glibc"].ref_ids("other")) >= {"CWE-193", "CWE-787"}


def test_every_cve_finding_has_a_citation(fixtures_linux):
    for f in parse_trivy(fixtures_linux / "trivy_rootfs.json", target=_target()):
        assert f.ref_ids("cve"), f"{f.rule_id} has no CVE citation"


def test_cve_module_empty_without_trivy_artifact(adapter, sim_target, sim_transport, tmp_path):
    collected = adapter.collect(sim_target, sim_transport, tmp_path / "c")
    assert "trivy" not in collected.artifacts        # simulated host reports trivy not installed
    assert adapter.cve(sim_target, collected) == []
