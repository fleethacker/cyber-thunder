"""Ingest, outbox, reports and demo: 501 when the service is absent, delegation when present."""
from __future__ import annotations

import json
import types

import pytest

from cyberthunder.api import util
from tests.api.conftest import ACTOR, SSH_ROOT, add_target, scan_and_wait

API = "/api/v1"


class FakeIngest:
    def __init__(self, ctx):
        self.ctx = ctx
        self.link = {"kbps": 56.0, "latency_ms": 500, "connected": True}
        self.deltas = []
        self.pending = [{"name": "commander.html", "kind": "commander", "bytes": 4096, "created_at": "t"}]
        self.seen_path = None
        self.content = self

    def import_stig(self, path, actor, override_reason=None):
        return self.ingest_stig(path, actor)

    def link_state(self):
        return dict(self.link)

    def set_link(self, changes, actor):
        self.link.update(changes)
        self.ctx.audit.append("link.change", actor, changes)
        return dict(self.link)

    def ingest_stig(self, path, actor):
        self.seen_path = path
        d = {"id": "delta-1", "benchmark_id": "RHEL_9_STIG", "old_release": "V2R1", "new_release": "V2R2",
             "rules_added": [], "rules_removed": [], "rules_changed": [], "counts": {"changed": 1},
             "sizes": {"full_bytes": 3_000_000, "delta_bytes": 40_000, "compressed_bytes": 9_000, "ratio": 0.003},
             "transfer": {"full_s": 428.6, "delta_s": 1.3, "kbps": 56.0}, "rescan_rule_ids": [SSH_ROOT]}
        self.deltas.append(d)
        return d

    def history(self):
        return {"deltas": self.deltas, "bulletins": []}

    def ingest_bulletin(self, bulletin, actor):
        f = self.ctx.store.load_findings()[0]
        return {"bulletin_id": bulletin["id"], "hosts_affected": [f.host], "findings": [f], "scan_id": None}

    def outbox(self):
        return {"connected": self.link["connected"], "pending": self.pending, "synced": []}

    def sync(self, actor):
        n = len(self.pending)
        self.pending = []
        return {"sent": n, "bytes": 4096, "seconds": 0.6}


class FakeReports:
    def commander(self, scan_id, fmt):
        return "# Commander summary" if fmt == "md" else "<h1>Commander summary</h1>"

    def poam_csv(self, scan_id):
        return "id,weakness\r\n1,SSH root login\r\n"

    def checklist(self, scan_id, host):
        return {"title": "RHEL 9", "target_data": {"host_name": host}, "stigs": []}

    def fleet(self, fmt):
        return "<h1>Path to fleet</h1>"

    def friction(self, fmt):
        return "# Friction"

    def score(self, scan_id):
        return {"seeded": 2, "found": 2, "share": 1.0, "items": []}

    def queue(self, kind, scan_id, host, actor):
        return {"name": f"{kind}.html", "kind": kind, "bytes": 10, "created_at": "t"}


def test_absent_services_are_501(client):
    cases = [
        ("get", "/ingest/link", None), ("put", "/ingest/link", {"kbps": 9.6}), ("post", "/ingest/stig", {"path": "x"}),
        ("post", "/ingest/stig/d1/rescan", None), ("post", "/ingest/bulletin", {"id": "b"}),
        ("get", "/ingest/history", None), ("get", "/outbox", None), ("post", "/outbox/sync", None),
        ("get", "/reports/commander", None), ("get", "/reports/poam.csv", None),
        ("get", "/reports/checklist.cklb", None), ("get", "/reports/fleet", None), ("get", "/reports/friction", None),
        ("get", "/reports/score", None), ("post", "/reports/queue", {"kind": "poam"}),
        ("post", "/demo/load", None), ("post", "/demo/reset", None), ("put", "/demo", {"simulate_verify_fail_next": True}),
    ]
    for method, path, body in cases:
        kw = {"headers": ACTOR}
        if body is not None:
            kw["json"] = body
        r = getattr(client, method)(API + path, **kw)
        assert r.status_code == 501, (path, r.status_code, r.text)
        assert r.json()["detail"].endswith("not available on this build"), path
    d = client.get(f"{API}/demo").json()
    assert d == {"available": False, "loaded": False, "targets": [], "simulate_verify_fail_next": False}


@pytest.fixture
def ingest(ctx):
    ctx.ingest = FakeIngest(ctx)
    return ctx.ingest


def test_link_and_outbox(client, ingest):
    assert client.get(f"{API}/ingest/link").json()["kbps"] == 56.0
    assert client.put(f"{API}/ingest/link", json={}, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/ingest/link", json={"kbps": -1}, headers=ACTOR).status_code == 400
    r = client.put(f"{API}/ingest/link", json={"connected": False}, headers=ACTOR)
    assert r.json()["connected"] is False
    assert client.get(f"{API}/status").json()["outbox"]["pending"] == 1
    assert client.post(f"{API}/outbox/sync", headers=ACTOR).status_code == 409
    client.put(f"{API}/ingest/link", json={"connected": True}, headers=ACTOR)
    assert client.post(f"{API}/outbox/sync", headers=ACTOR).json()["sent"] == 1
    assert client.get(f"{API}/outbox").json()["pending"] == []


def test_stig_upload_multipart_and_path(client, ingest, ctx, tmp_path):
    payload = b"<?xml version='1.0'?>\r\n<Benchmark id='RHEL_9_STIG'/>\r\n"
    r = client.post(f"{API}/ingest/stig", files={"file": ("../../evil name.xml", payload, "application/xml")},
                    headers=ACTOR)
    assert r.status_code == 200, r.text
    assert r.json()["sizes"]["ratio"] == 0.003
    saved = ingest.seen_path
    assert saved.read_bytes() == payload and saved.name == "evil_name.xml"
    assert ctx.store.ingest_dir in saved.parents

    src = tmp_path / "U_RHEL_9_V2R2.xml"
    src.write_bytes(payload)
    assert client.post(f"{API}/ingest/stig", json={"path": str(src)}, headers=ACTOR).status_code == 200
    assert client.post(f"{API}/ingest/stig", json={"path": str(tmp_path / "missing.xml")}, headers=ACTOR).status_code == 400
    assert client.post(f"{API}/ingest/stig", json={}, headers=ACTOR).status_code == 400
    assert len(client.get(f"{API}/ingest/history").json()["deltas"]) == 2


def test_stig_rescan_starts_targeted_scan(client, ingest):
    add_target(client)
    client.post(f"{API}/ingest/stig", files={"file": ("a.xml", b"<x/>", "application/xml")}, headers=ACTOR)
    r = client.post(f"{API}/ingest/stig/delta-1/rescan", headers=ACTOR)
    assert r.status_code == 202
    assert r.json()["trigger"] == "stig_delta" and r.json()["rule_filter"] == [SSH_ROOT]
    assert client.post(f"{API}/ingest/stig/nope/rescan", headers=ACTOR).status_code == 404


def test_bulletin_json_and_file(client, ingest):
    add_target(client)
    scan_and_wait(client)
    b = {"id": "2026-A-0123", "title": "OpenSSH", "severity": "high", "cves": ["CVE-2024-6387"],
         "affected": [{"package": "openssh", "versions_below": "9.8"}], "source": "IAVM"}
    r = client.post(f"{API}/ingest/bulletin", json=b, headers=ACTOR)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["bulletin_id"] == "2026-A-0123" and out["findings"][0]["cat"]
    r = client.post(f"{API}/ingest/bulletin", files={"file": ("b.json", json.dumps(b).encode(), "application/json")},
                    headers=ACTOR)
    assert r.status_code == 200 and r.json()["hosts_affected"] == ["web01"]
    assert client.post(f"{API}/ingest/bulletin", json={"title": "no id"}, headers=ACTOR).status_code == 400
    assert client.post(f"{API}/ingest/bulletin", content=b"{not json", headers={**ACTOR, "Content-Type": "application/json"}
                       ).status_code == 400


def test_reports(client, ctx):
    ctx.reports = FakeReports()
    r = client.get(f"{API}/reports/commander")
    assert r.headers["content-type"].startswith("text/html") and "<h1>" in r.text
    r = client.get(f"{API}/reports/commander", params={"format": "md"})
    assert r.headers["content-type"].startswith("text/markdown") and r.text.startswith("#")
    assert client.get(f"{API}/reports/commander", params={"format": "pdf"}).status_code == 400
    r = client.get(f"{API}/reports/poam.csv")
    assert r.headers["content-type"].startswith("text/csv") and r.text.startswith("id,weakness")
    assert client.get(f"{API}/reports/checklist.cklb", params={"host": "web01"}).json()["target_data"]["host_name"] == "web01"
    assert client.get(f"{API}/reports/fleet").status_code == 200
    assert client.get(f"{API}/reports/friction", params={"format": "md"}).text == "# Friction"
    assert client.get(f"{API}/reports/score").json()["share"] == 1.0
    assert client.get(f"{API}/reports/score", params={"scan_id": "nope"}).status_code == 404
    assert client.post(f"{API}/reports/queue", json={"kind": "poam"}, headers=ACTOR).json()["kind"] == "poam"
    assert client.post(f"{API}/reports/queue", json={"kind": "everything"}, headers=ACTOR).status_code == 400


def test_demo_delegates(client, ctx, monkeypatch):
    from cyberthunder.inventory.targets import Target

    state = {"armed": False}

    def load(c, actor):
        t = c.inventory.add(Target(id="sim-linux", name="sim-linux", asset_type="linux", transport="simulated",
                                   simulated=True))
        c.save_inventory(actor, "demo.load", {"targets": [t.id]})
        return [t]

    def reset(c, actor):
        c.audit.append("demo.reset", actor)
        return True

    def set_flag(c, value, actor):
        state["armed"] = value

    def status(c):
        return {"loaded": bool(c.inventory.all()), "simulate_verify_fail_next": state["armed"]}

    mod = types.SimpleNamespace(load=load, reset=reset, set_simulate_verify_fail=set_flag, status=status)
    monkeypatch.setattr(util, "demo_module", lambda: mod)
    assert client.get(f"{API}/demo").json()["loaded"] is False
    r = client.post(f"{API}/demo/load", headers=ACTOR)
    assert r.json()["targets"][0]["simulated"] is True
    d = client.get(f"{API}/demo").json()
    assert d["available"] is True and d["loaded"] is True and d["targets"][0]["id"] == "sim-linux"
    assert client.put(f"{API}/demo", json={"simulate_verify_fail_next": True}, headers=ACTOR).json()[
        "simulate_verify_fail_next"] is True
    assert client.post(f"{API}/demo/reset", headers=ACTOR).json() == {"ok": True}
    acts = [r["action"] for r in client.get(f"{API}/audit").json()["records"]]
    assert "demo.load" in acts and "demo.reset" in acts
