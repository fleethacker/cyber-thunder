from __future__ import annotations

import json

import pytest

from cyberthunder.ingest.outbox import LinkDisconnected
from cyberthunder.ingest.service import IngestError
from tests.ingest.conftest import INGEST_FIXTURES, write_collected


def test_ingest_stig_full_then_delta(ctx, bench_pair):
    old, new = bench_pair
    first = ctx.ingest.ingest_stig(old, actor="it2.smith")
    assert first["full_import"] and first["old_release"] is None and first["counts"]["added"] == 4
    cat = ctx.store.ingest_dir / "catalog" / "xccdf_org.ssgproject.content_benchmark_RHEL-9.xml"
    assert cat.read_bytes() == old.read_bytes()

    rep = ctx.ingest.ingest_stig(new.read_bytes(), "new-xccdf.xml", actor="it2.smith")
    assert not rep["full_import"]
    assert rep["old_release"] == "0.1.76" and rep["new_release"] == "0.1.77"
    assert rep["counts"]["added"] == 1 and rep["counts"]["changed"] == 2 and rep["counts"]["removed"] == 1
    assert cat.read_bytes() == new.read_bytes()
    s, t = rep["sizes"], rep["transfer"]
    assert s["ratio"] > 1 and s["compressed_bytes"] < s["full_bytes"]
    assert t["link"]["kbps"] == 56.0
    assert t["full_seconds"] == pytest.approx(s["full_bytes"] * 8 / 56000 + 0.5, abs=1e-3)
    assert t["delta_seconds"] < t["full_seconds"]
    stored = ctx.ingest.get_delta(rep["id"])
    assert stored["rescan_rule_ids"] == rep["rescan_rule_ids"]
    hist = ctx.ingest.history()["deltas"]
    assert len(hist) == 2
    recs = [r for r in ctx.audit.records() if r["action"] == "ingest.stig"]
    assert len(recs) == 2 and recs[-1]["subject"] == rep["id"]


def test_ingest_stig_with_explicit_old(ctx, bench_pair):
    old, new = bench_pair
    rep = ctx.ingest.ingest_stig(new, old=old)
    assert rep["counts"]["changed"] == 2


def test_rescan_for_delta_without_scanner(ctx, bench_pair, monkeypatch):
    old, new = bench_pair
    rep = ctx.ingest.ingest_stig(new, old=old)

    def _absent(*args, **kwargs):
        raise NotImplementedError("scanner not available in this build")

    monkeypatch.setattr(ctx.scanner, "start", _absent)
    with pytest.raises(IngestError, match="scanner"):
        ctx.ingest.rescan_for_delta(rep["id"], "it2.smith")


def test_rescan_for_delta_passes_rule_filter(ctx, bench_pair):
    old, new = bench_pair
    rep = ctx.ingest.ingest_stig(new, old=old)
    seen = {}

    class FakeScanner:
        def start(self, target_ids=None, **kw):
            seen.update(kw, target_ids=target_ids)
            return "run"

    ctx.scanner = FakeScanner()
    assert ctx.ingest.rescan_for_delta(rep["id"], "it2.smith") == "run"
    assert seen["trigger"] == "stig_delta" and seen["requested_by"] == "it2.smith"
    assert set(seen["rule_filter"]) == set(rep["rescan_rule_ids"])


def test_outbox_enqueue_list_sync(ctx):
    ob = ctx.ingest.outbox
    e = ob.enqueue("report", "commander one-pager.json", b'{"open": 3}', {"scan_id": "s1"}, actor="it2.smith")
    assert e["bytes"] == 11 and (ctx.store.outbox_dir / e["id"]).exists()
    assert (ctx.store.outbox_dir / (e["id"] + ".meta.json")).exists()
    ob.enqueue("poam", "poam.csv", b"x" * 7000)
    lst = ob.list()
    assert len(lst["pending"]) == 2 and lst["synced"] == []
    res = ob.sync(actor="it2.smith")
    assert res["sent"] == 2 and res["bytes"] == 7011
    assert res["seconds"] == pytest.approx(11 * 8 / 56000 + 0.5 + 7000 * 8 / 56000 + 0.5, abs=2e-3)
    lst = ob.list()
    assert lst["pending"] == [] and len(lst["synced"]) == 2
    assert (ctx.store.synced_dir / e["id"]).read_bytes() == b'{"open": 3}'


def test_outbox_disconnected_and_reconnect_flush(ctx):
    svc = ctx.ingest
    svc.set_link(actor="it2.smith", connected=False)
    svc.outbox.enqueue("report", "r1.json", b"{}")
    with pytest.raises(LinkDisconnected):
        svc.outbox.sync()
    assert len(svc.outbox.list()["pending"]) == 1
    blocked = [r for r in ctx.audit.records() if r["action"] == "outbox.sync"][-1]
    assert blocked["outcome"] == "blocked"
    svc.set_link(actor="it2.smith", connected=True)
    assert svc.link.last_flush["sent"] == 1
    assert svc.outbox.list()["pending"] == []
    # staying connected does not flush again
    svc.set_link(actor="it2.smith", kbps=19.2)
    assert svc.link.last_flush is None


def test_outbox_force_while_disconnected(ctx):
    svc = ctx.ingest
    svc.set_link(actor="x", connected=False)
    svc.outbox.enqueue("report", "r.json", b"{}")
    res = svc.outbox.sync(force=True, actor="x")
    assert res["sent"] == 1 and res["forced"]
    assert svc.outbox.list()["synced"][0]["forced"] is True


def test_audit_chain_verifies_after_everything(ctx, bench_pair):
    old, new = bench_pair
    svc = ctx.ingest
    svc.ingest_stig(old)
    svc.ingest_stig(new)
    svc.set_link(actor="x", connected=False)
    svc.outbox.enqueue("report", "r.json", b"{}")
    svc.set_link(actor="x", connected=True)
    actions = {r["action"] for r in ctx.audit.records()}
    assert {"ingest.stig", "link.change", "outbox.enqueue", "outbox.sync"} <= actions
    assert ctx.audit.verify().ok


def _cli(state_dir, *args) -> int:
    from cyberthunder.cli import main
    return main(["--state-dir", str(state_dir), "--actor", "it2.smith", *args])


def test_cli_smoke(state_dir, bench_pair, capsys, monkeypatch):
    monkeypatch.delenv("CT_COMPRESSOR", raising=False)
    old, new = bench_pair
    assert _cli(state_dir, "ingest", "stig", str(new), "--old", str(old)) == 0
    out = capsys.readouterr().out
    assert "added 1, changed 2, removed 1" in out and "kbps" in out
    assert _cli(state_dir, "ingest", "history") == 0
    assert json.loads(capsys.readouterr().out)["deltas"]

    from cyberthunder.store import StateStore
    write_collected(StateStore(state_dir), "scan-x", "web01",
                    [{"name": "openssh", "epoch": None, "version": "8.7p1", "release": "34.el9", "arch": "x86_64"}])
    assert _cli(state_dir, "ingest", "bulletin", str(INGEST_FIXTURES / "iavm_openssh.json")) == 0
    assert json.loads(capsys.readouterr().out)["hosts_affected"] == ["web01"]

    assert _cli(state_dir, "link", "set", "--kbps", "9.6", "--connected", "false") == 0
    assert json.loads(capsys.readouterr().out)["connected"] is False
    assert _cli(state_dir, "link", "show") == 0
    assert json.loads(capsys.readouterr().out)["kbps"] == 9.6
    assert _cli(state_dir, "outbox", "sync") == 2
    capsys.readouterr()
    assert _cli(state_dir, "outbox", "list") == 0
    assert "pending: 0" in capsys.readouterr().out
    assert _cli(state_dir, "ingest", "stig") == 2
