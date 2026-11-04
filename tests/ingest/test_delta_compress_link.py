from __future__ import annotations

import json
import sys
import zipfile

import pytest

from cyberthunder.ingest import compress
from cyberthunder.ingest import delta as dl
from cyberthunder.ingest.link import Link, LinkState, transfer_seconds


def test_load_benchmark_keys_by_stig_id(bench_pair):
    old, _ = bench_pair
    bid, rel, rules = dl.load_benchmark(old)
    assert bid == "xccdf_org.ssgproject.content_benchmark_RHEL-9"
    assert rel == "0.1.76"
    assert {"RHEL-09-255045", "RHEL-09-255100", "RHEL-09-211010"} <= set(rules)
    assert "xccdf_org.ssgproject.content_rule_na_thing" in rules     # no STIG ID: keyed by rule id


def test_diff_counts_and_rescan_ids(bench_pair):
    old, new = bench_pair
    rep = dl.diff(dl.load_benchmark(old), dl.load_benchmark(new))
    assert (rep.old_release, rep.new_release) == ("0.1.76", "0.1.77")
    assert rep.counts == {"added": 1, "removed": 1, "changed": 2, "unchanged": 1, "total": 4}
    assert [r.stig_id for r in rep.rules_added] == ["RHEL-09-211020"]
    assert [r.rule_id for r in rep.rules_removed] == ["xccdf_org.ssgproject.content_rule_na_thing"]
    changes = {r.stig_id: r.change for r in rep.rules_changed}
    assert changes == {"RHEL-09-255045": "title", "RHEL-09-255100": "fix"}
    for rid in ("RHEL-09-211020", "SV-258000r926000_rule", "RHEL-09-255045",
                "xccdf_org.ssgproject.content_rule_sshd_disable_root_login", "RHEL-09-255100"):
        assert rid in rep.rescan_rule_ids
    assert "RHEL-09-211010" not in rep.rescan_rule_ids


def test_whitespace_only_edit_is_not_a_change(tmp_path, bench_pair):
    old, _ = bench_pair
    p = tmp_path / "ws-xccdf.xml"
    p.write_text(old.read_text(encoding="utf-8").replace("then restart sshd.", "then   restart\n  sshd."), encoding="utf-8")
    rep = dl.diff(dl.load_benchmark(old), dl.load_benchmark(p))
    assert rep.counts["changed"] == 0


def test_full_import_when_no_old():
    from tests.ingest.conftest import SAMPLE
    rep = dl.diff(None, dl.load_benchmark(SAMPLE))
    assert rep.old_release is None
    assert rep.counts["added"] == rep.counts["total"] == 4


def test_zip_member_is_used(tmp_path, bench_pair):
    _, new = bench_pair
    z = tmp_path / "U_RHEL_9_V2R2_STIG.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("U_RHEL_9_V2R2_STIG/README.txt", "not this one")
        zf.writestr("U_RHEL_9_V2R2_STIG/U_RHEL_9_STIG_V2R2_Manual-xccdf.xml", new.read_bytes())
    bid, rel, rules = dl.load_benchmark(z)
    assert rel == "0.1.77" and "RHEL-09-211020" in rules
    assert dl.read_benchmark_xml(z) == new.read_bytes()


def test_zip_without_xccdf_rejected(tmp_path):
    z = tmp_path / "x.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("readme.txt", "x")
    with pytest.raises(dl.BenchmarkError):
        dl.load_benchmark(z)


def test_compress_roundtrip_and_fallback(monkeypatch):
    data = b"PermitRootLogin no\n" * 200
    for m in ("lzma", "zlib"):
        packed, used = compress.encode(data, m)
        assert used == m and compress.decode(packed, m) == data and len(packed) < len(data)
    monkeypatch.delenv("CT_COMPRESSOR", raising=False)
    assert compress.encode(data, "external")[1] == "lzma"
    monkeypatch.setenv("CT_COMPRESSOR", "definitely-not-a-real-compressor-binary")
    assert compress.encode(data, "external")[1] == "lzma"
    with pytest.raises(ValueError):
        compress.encode(data, "bogus")


def test_external_compressor_used_when_it_works(monkeypatch, tmp_path):
    script = tmp_path / "squeeze.py"
    script.write_text("import sys, zlib\nsys.stdout.buffer.write(zlib.compress(sys.stdin.buffer.read()))\n",
                      encoding="utf-8")
    monkeypatch.setenv("CT_COMPRESSOR", f'"{sys.executable}" "{script}"')
    packed, used = compress.encode(b"abc" * 100, "external")
    assert used == "external" and compress.decode(packed, "zlib") == b"abc" * 100


def test_delta_payload_and_ratio(bench_pair):
    old, new = bench_pair
    newb = dl.load_benchmark(new)
    rep = dl.diff(dl.load_benchmark(old), newb)
    payload = compress.delta_payload(rep, newb[2])
    doc = json.loads(payload)
    keys = sorted(r["key"] for r in doc["rules"])
    assert keys == ["RHEL-09-211020", "RHEL-09-255045", "RHEL-09-255100"]
    assert doc["removed"] == ["xccdf_org.ssgproject.content_rule_na_thing"]
    assert any("ClientAliveCountMax" in (r.get("fix_text") or "") for r in doc["rules"])
    sizes = compress.compare(new.read_bytes(), payload)
    assert sizes["full_bytes"] == len(new.read_bytes())
    assert sizes["compressed_bytes"] < sizes["full_bytes"]
    assert sizes["ratio"] > 1 and sizes["method"] == "lzma"


def test_transfer_seconds_at_56k():
    st = LinkState(kbps=56, latency_ms=500, connected=True)
    assert transfer_seconds(7000, st) == pytest.approx(7000 * 8 / 56000 + 0.5)
    assert transfer_seconds(0, st) == 0.5
    with pytest.raises(ValueError):
        transfer_seconds(1, LinkState(kbps=0))


def test_link_defaults_persist_and_audit(ctx):
    link = Link(ctx.store, ctx.settings, ctx.audit)
    assert link.state().kbps == 56.0 and link.connected
    st = link.set(actor="it2.smith", kbps=9.6, latency_ms=600, connected="false")
    assert (st.kbps, st.latency_ms, st.connected) == (9.6, 600, False)
    assert Link(ctx.store, ctx.settings).state().kbps == 9.6
    rec = list(ctx.audit.records())[-1]
    assert rec["action"] == "link.change" and rec["actor"] == "it2.smith"
    assert rec["details"]["changed"]["connected"] == {"from": True, "to": False}
    with pytest.raises(ValueError):
        link.set(actor="x", kbps=-1)
    with pytest.raises(ValueError):
        link.set(actor="x", connected="maybe")
