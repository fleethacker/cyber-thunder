from __future__ import annotations


import pytest

from cyberthunder.ingest.bulletin import BulletinError, match, parse_bulletin, rpm_vercmp, rpmvercmp
from tests.ingest.conftest import INGEST_FIXTURES, add_targets, write_collected

VULN = [{"name": "openssh", "epoch": None, "version": "8.7p1", "release": "34.el9", "arch": "x86_64"},
        {"name": "openssh-server", "epoch": "0", "version": "8.7p1", "release": "34.el9", "arch": "x86_64"},
        {"name": "bash", "epoch": None, "version": "5.1.8", "release": "9.el9", "arch": "x86_64"}]
PATCHED = [{"name": "openssh", "epoch": None, "version": "8.7p1", "release": "38.el9_4.1", "arch": "x86_64"},
           {"name": "openssh-server", "epoch": None, "version": "8.7p1", "release": "43.el9", "arch": "x86_64"}]


@pytest.mark.parametrize("a,b,want", [
    ("1.0-1", "1.0-2", -1),
    ("1.10", "1.9", 1),
    ("2:1.0", "1:9.9", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0a", "1.0b", -1),
    ("1.0", "1.0.1", -1),
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0", 0),           # release only compared when both sides have one
    ("1.01", "1.1", 0),             # leading zeros ignored
    ("1.0^git1", "1.0", 1),
    ("1.0^git1", "1.0.1", -1),
    ("8.7p1-34.el9", "8.7p1-38.el9_4.1", -1),
    ("1.a", "1.1", -1),             # numeric segment beats alpha
])
def test_rpm_vercmp_table(a, b, want):
    assert rpm_vercmp(a, b) == want
    assert rpm_vercmp(b, a) == -want


def test_rpmvercmp_tilde_both():
    assert rpmvercmp("1.0~rc1", "1.0~rc2") == -1


def test_parse_bulletin_validation():
    b = parse_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes())
    assert b.id == "2026-A-0123" and b.severity == "high" and b.cves == ["CVE-2024-6387"]
    with pytest.raises(BulletinError):
        parse_bulletin(b"{not json")
    with pytest.raises(BulletinError):
        parse_bulletin({"id": "2026-A-0001", "affected": [{"versions_below": "1"}]})
    with pytest.raises(BulletinError):
        parse_bulletin({"id": "LOCAL-7", "affected": []})       # no IAVM id and nothing to cite


def test_match_pure():
    b = parse_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes())
    cols = {"web01": {"asset_type": "linux", "raw": {"packages": VULN}, "facts": {"os_name": "Rocky Linux"}},
            "web02": {"asset_type": "linux", "raw": {"packages": PATCHED}, "facts": {"os_name": "Rocky Linux"}}}
    fs = match(b, cols)
    assert sorted(f.rule_id for f in fs) == ["iavm:2026-A-0123:openssh", "iavm:2026-A-0123:openssh-server"]
    f = fs[0]
    assert f.host == "web01" and f.source == "iavm" and f.severity.value == "high" and f.is_open
    assert "CVE-2024-6387" in f.citations and "2026-A-0123" in f.citations
    assert f.fix_text == "update openssh to >= 8.7p1-38.el9_4.1" and f.fix_ref == "patch:openssh"
    assert f.tags == ["bulletin", "pkg:openssh"]


def test_match_product_and_cpe():
    b = parse_bulletin({"id": "2026-B-0042", "title": "EL 9 kernel", "severity": "medium", "cves": ["CVE-2026-0001"],
                        "affected": [{"product": "Rocky Linux", "versions_below": "9.5"},
                                     {"cpe": "cpe:/o:redhat:enterprise_linux:9"}]})
    cols = {"a": {"facts": {"os_name": "Rocky Linux", "os_version": "9.4"}, "raw": {}},
            "b": {"facts": {"os_name": "Rocky Linux", "os_version": "9.5"}, "raw": {}},
            "c": {"facts": {"os_name": "Red Hat Enterprise Linux", "os_version": "9.6"}, "raw": {}}}
    hits = {(f.host, f.rule_id) for f in match(b, cols)}
    assert hits == {("a", "iavm:2026-B-0042:Rocky Linux"), ("c", "iavm:2026-B-0042:enterprise linux")}


def test_ingest_bulletin_persists_scan_run(ctx):
    add_targets(ctx, "web01", "web02")
    write_collected(ctx.store, "scan-old", "web01", VULN)
    write_collected(ctx.store, "scan-old", "web02", PATCHED)
    res = ctx.ingest.ingest_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes(), actor="it1.jones")
    assert res["hosts_affected"] == ["web01"] and sorted(res["hosts_checked"]) == ["web01", "web02"]
    assert len(res["findings"]) == 2
    run = ctx.store.load_scan_run(res["scan_id"])
    assert run["trigger"] == "bulletin" and run["targets"] == ["web01"] and run["findings_count"] == 2
    saved = ctx.store.load_findings(res["scan_id"])
    assert {f.scan_id for f in saved} == {res["scan_id"]}
    stored = ctx.store.read_json(ctx.store.ingest_dir / "bulletins" / "2026-A-0123.json")
    assert stored["hosts_affected"] == ["web01"]
    assert ctx.ingest.history()["bulletins"][0]["id"] == "2026-A-0123"
    rec = [r for r in ctx.audit.records() if r["action"] == "ingest.bulletin"][-1]
    assert rec["details"]["findings"] == 2 and rec["actor"] == "it1.jones"
    assert ctx.audit.verify().ok


def test_latest_collected_prefers_newest_run(ctx):
    from cyberthunder.ingest.bulletin import latest_collected
    write_collected(ctx.store, "scan-a", "web01", VULN)
    ctx.store.save_scan_run({"id": "scan-a", "started_at": "2026-11-04T10:00:00+00:00", "targets": ["web01"]})
    write_collected(ctx.store, "scan-b", "web01", PATCHED)
    ctx.store.save_scan_run({"id": "scan-b", "started_at": "2026-11-04T11:00:00+00:00", "targets": ["web01"]})
    assert latest_collected(ctx.store)["web01"]["raw"]["packages"] == PATCHED


def test_no_match_means_no_scan_run(ctx):
    add_targets(ctx, "web02")
    write_collected(ctx.store, "scan-old", "web02", PATCHED)
    res = ctx.ingest.ingest_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes())
    assert res["scan_id"] is None and res["findings"] == []


OPENSSL_E1 = [{"name": "openssl", "epoch": "1", "version": "3.0.7", "release": "24.el9", "arch": "x86_64"}]


def test_epochless_bulletin_matches_package_with_epoch():
    b = parse_bulletin({"id": "2026-A-0200", "title": "OpenSSL", "cves": ["CVE-2026-0002"],
                        "affected": [{"package": "openssl", "versions_below": "3.0.7-25.el9"}]})
    cols = {"h": {"raw": {"packages": OPENSSL_E1}, "facts": {}}}
    fs = match(b, cols)
    assert [f.rule_id for f in fs] == ["iavm:2026-A-0200:openssl"]
    patched = [dict(OPENSSL_E1[0], release="25.el9")]
    assert match(b, {"h": {"raw": {"packages": patched}, "facts": {}}}) == []


def test_bulletin_epoch_is_compared_when_stated():
    b = parse_bulletin({"id": "2026-A-0201", "title": "OpenSSL", "cves": ["CVE-2026-0003"],
                        "affected": [{"package": "openssl", "versions_below": "2:3.0.7-25.el9"}]})
    assert len(match(b, {"h": {"raw": {"packages": OPENSSL_E1}, "facts": {}}})) == 1
    b = parse_bulletin({"id": "2026-A-0202", "title": "OpenSSL", "cves": ["CVE-2026-0004"],
                        "affected": [{"package": "openssl", "versions_below": "0:9.9-1"}]})
    assert match(b, {"h": {"raw": {"packages": OPENSSL_E1}, "facts": {}}}) == []


def test_cpe_uses_vendor_alias_and_version():
    ubuntu = parse_bulletin({"id": "2026-A-0300", "title": "Ubuntu kernel", "cves": ["CVE-2026-0005"],
                             "affected": [{"cpe": "cpe:/o:canonical:ubuntu_linux:22.04"}]})
    rhel9 = parse_bulletin({"id": "2026-A-0301", "title": "RHEL 9", "cves": ["CVE-2026-0006"],
                            "affected": [{"cpe": "cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*"}]})
    cols = {"u22": {"facts": {"os_name": "Ubuntu", "os_version": "22.04"}, "raw": {}},
            "u24": {"facts": {"os_name": "Ubuntu", "os_version": "24.04"}, "raw": {}},
            "el8": {"facts": {"os_name": "Red Hat Enterprise Linux", "os_version": "8.10"}, "raw": {}},
            "el9": {"facts": {"os_name": "Red Hat Enterprise Linux", "os_version": "9.4"}, "raw": {}}}
    assert {f.host for f in match(ubuntu, cols)} == {"u22"}
    assert {f.host for f in match(rhel9, cols)} == {"el9"}


def test_bulletin_skips_hosts_out_of_scope(ctx):
    add_targets(ctx, "web01", "web02")
    write_collected(ctx.store, "scan-old", "web01", VULN)
    write_collected(ctx.store, "scan-old", "web02", VULN)
    ctx.inventory.remove("web01")
    res = ctx.ingest.ingest_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes())
    assert res["hosts_affected"] == ["web02"] and res["hosts_checked"] == ["web02"]
    rec = [r for r in ctx.audit.records() if r["action"] == "ingest.bulletin"][-1]
    assert rec["details"]["skipped_out_of_scope"] == ["web01"]


def test_bulletin_findings_survive_next_full_scan(ctx):
    from cyberthunder import demo
    demo.load(ctx, "it1.jones")
    ctx.scanner.start(background=False)
    res = ctx.ingest.ingest_bulletin((INGEST_FIXTURES / "iavm_openssh.json").read_bytes())
    ids = {f["id"] for f in res["findings"]}
    assert ids
    run = ctx.scanner.start(background=False)
    ctx.ingest.rematch_all(run.id)
    current = {f.id for f in ctx.store.current_findings()}
    assert ids <= current
    rec = [r for r in ctx.audit.records() if r["action"] == "ingest.bulletin_rematch"][-1]
    assert rec["details"]["scan_id"] == run.id and rec["details"]["findings"] >= len(ids)
    assert ctx.audit.verify().ok
