"""Status, identity, targets (scope audit), scans and findings."""
from __future__ import annotations

from tests.api.conftest import ACTOR, SSH_ROOT, add_target, scan_and_wait

API = "/api/v1"


def test_status_includes_link_and_outbox(client):
    st = client.get(f"{API}/status").json()
    assert st["kill"]["engaged"] is False
    assert st["audit"]["verified"] is True
    assert st["adapters"] == ["linux"]
    assert set(st["link"]) >= {"kbps", "latency_ms", "connected"}
    assert st["outbox"] == {"pending": 0}


def test_status_reads_link_file_and_outbox_dir(client, ctx):
    ctx.store.write_json(ctx.store.link_state, {"kbps": 9.6, "connected": False})
    (ctx.store.outbox_dir / "commander.html").write_text("x", encoding="utf-8")
    st = client.get(f"{API}/status").json()
    assert st["link"]["kbps"] == 9.6 and st["link"]["connected"] is False
    assert st["outbox"]["pending"] == 1


def test_mutations_require_a_named_human(client):
    body = {"id": "x", "asset_type": "linux"}
    assert client.post(f"{API}/targets", json=body).status_code == 400
    assert client.post(f"{API}/targets", json=body, headers={"X-Actor": "  "}).status_code == 400
    for machine in ("agent", "LLM", "system", "policy:someone"):
        r = client.post(f"{API}/kill/engage", json={}, headers={"X-Actor": machine})
        assert r.status_code == 400, machine
        assert "reserved" in r.json()["detail"]
    assert client.get(f"{API}/kill").json()["engaged"] is False


def test_targets_crud_and_scope_audit(client, ctx):
    t = add_target(client, "web01")
    assert t["asset_type"] == "linux" and t["in_scope"] is True
    assert client.post(f"{API}/targets", json={"id": "web01", "asset_type": "linux"}, headers=ACTOR).status_code == 409
    assert client.post(f"{API}/targets", json={"id": "bad", "asset_type": "toaster"}, headers=ACTOR).status_code == 400
    assert client.post(f"{API}/targets", json={"id": "bad", "asset_type": "linux", "password": "x"},
                       headers=ACTOR).status_code == 400
    assert [x["id"] for x in client.get(f"{API}/targets").json()["targets"]] == ["web01"]

    r = client.put(f"{API}/targets/web01", json={"in_scope": False, "notes": "out for maintenance"}, headers=ACTOR)
    assert r.status_code == 200 and r.json()["in_scope"] is False
    rec = client.get(f"{API}/audit", params={"action": "scope.change"}).json()["records"][-1]
    assert rec["actor"] == "ITC Rivera"
    assert rec["details"]["before"] == {"in_scope": True} and rec["details"]["after"] == {"in_scope": False}

    r = client.put(f"{API}/targets/web01", json={"notes": "back"}, headers=ACTOR)
    assert r.status_code == 200
    assert client.get(f"{API}/audit", params={"action": "inventory.update"}).json()["records"]
    assert client.put(f"{API}/targets/web01", json={"id": "other"}, headers=ACTOR).status_code == 400
    assert client.put(f"{API}/targets/nope", json={"notes": "x"}, headers=ACTOR).status_code == 404

    # out of scope: discover is refused
    assert client.post(f"{API}/targets/web01/discover", headers=ACTOR).status_code == 403
    client.put(f"{API}/targets/web01", json={"in_scope": True}, headers=ACTOR)
    facts = client.post(f"{API}/targets/web01/discover", headers=ACTOR).json()
    assert facts["hostname"] == "rocky9-web01" and facts["os_name"] == "Rocky Linux"

    assert client.delete(f"{API}/targets/web01", headers=ACTOR).json() == {"ok": True}
    assert client.delete(f"{API}/targets/web01", headers=ACTOR).status_code == 404
    acts = [r["action"] for r in client.get(f"{API}/audit").json()["records"]]
    assert {"inventory.add", "scope.change", "inventory.update", "inventory.discover", "inventory.remove"} <= set(acts)
    assert ctx.inventory.all() == []


def test_discover_without_adapter_is_501(client, ctx):
    add_target(client, "sw01", asset_type="cisco_ios")
    r = client.post(f"{API}/targets/sw01/discover", headers=ACTOR)
    assert r.status_code == 501 and "not available on this build" in r.json()["detail"]


def test_scan_runs_in_background_and_polls(client):
    add_target(client)
    r = client.post(f"{API}/scans", json={"modules": ["check", "hunt"]}, headers=ACTOR)
    assert r.status_code == 202
    assert r.json()["progress"]["total"] == 1
    run = scan_and_wait(client)
    assert run["progress"] == {"done": 1, "total": 1} and run["findings_count"] == 3
    scans = client.get(f"{API}/scans").json()["scans"]
    assert run["id"] in [s["id"] for s in scans] and len(scans) == 2
    assert client.get(f"{API}/scans/nope").status_code == 404


def test_scan_validation(client):
    assert client.post(f"{API}/scans", json={}, headers=ACTOR).status_code == 400          # no targets yet
    add_target(client)
    assert client.post(f"{API}/scans", json={"modules": ["exploit"]}, headers=ACTOR).status_code == 400
    assert client.post(f"{API}/scans", json={"target_ids": ["ghost"]}, headers=ACTOR).status_code == 404
    assert client.post(f"{API}/scans", json={"trigger": "whenever"}, headers=ACTOR).status_code == 400
    client.put(f"{API}/targets/web01", json={"in_scope": False}, headers=ACTOR)
    assert client.post(f"{API}/scans", json={"target_ids": ["web01"]}, headers=ACTOR).status_code == 403


def test_findings_list_filter_get(client, scanned):
    body = client.get(f"{API}/findings").json()
    assert body["total"] == 3 and body["scan_id"]
    assert body["summary"]["open_by_severity"]["high"] == 1
    first = body["findings"][0]
    assert first["severity"] == "high" and first["cat"] == "CAT I"       # sorted by severity
    ssh = scanned[SSH_ROOT]
    assert ssh["fix"]["fix_ref"] == "test:sshd_disable_root_login" and ssh["proposal"] is None
    assert ssh["explanation"] is None
    hunt = scanned["hunt:linux:cron_persistence"]
    assert hunt["fix"] is None and "T1053.003" in [r["id"] for r in hunt["references"]]

    def total(**p):
        return client.get(f"{API}/findings", params=p).json()["total"]

    assert total(status="open") == 2
    assert total(severity="CAT II") == 1
    assert total(severity="high,low") == 2
    assert total(source="hunt") == 1
    assert total(asset_type="windows") == 0
    assert total(host="web01") == 3
    assert total(q="255045") == 1
    assert total(q="root account") == 1
    page = client.get(f"{API}/findings", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3 and len(page["findings"]) == 1
    assert client.get(f"{API}/findings", params={"severity": "spicy"}).status_code == 400
    assert client.get(f"{API}/findings", params={"limit": 0}).status_code == 400
    assert client.get(f"{API}/findings", params={"scan_id": "nope"}).status_code == 404

    assert client.get(f"{API}/findings/{ssh['id']}").json()["rule_version"] == SSH_ROOT
    assert client.get(f"{API}/findings/nope").status_code == 404


def test_findings_propose_and_explain(client, scanned):
    ssh = scanned[SSH_ROOT]
    r = client.post(f"{API}/findings/{ssh['id']}/propose", headers=ACTOR)
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["state"] == "proposed" and p["fix"]["fix_ref"] == "test:sshd_disable_root_login"
    assert p["finding"]["id"] == ssh["id"] and "proposal" not in p["finding"]
    assert p["target"] == {"id": "web01", "name": "web01", "asset_type": "linux", "simulated": False}
    assert p["cat"] == "CAT II" and p["policy"]["auto_eligible"] is False
    assert client.post(f"{API}/findings/{ssh['id']}/propose", headers=ACTOR).status_code == 409
    assert client.get(f"{API}/findings/{ssh['id']}").json()["proposal"] == {"id": p["id"], "state": "proposed"}

    hunt = scanned["hunt:linux:cron_persistence"]
    assert client.post(f"{API}/findings/{hunt['id']}/propose", headers=ACTOR).status_code == 404

    e = client.post(f"{API}/findings/{ssh['id']}/explain", json={"force": True}, headers=ACTOR).json()
    assert e["finding_id"] == ssh["id"] and SSH_ROOT in e["citations"]
    assert client.get(f"{API}/findings/{ssh['id']}").json()["explanation"]["risk"]
    assert client.post(f"{API}/findings/explain", json={}, headers=ACTOR).json() == {"queued": 2}
    assert client.post(f"{API}/findings/explain", json={"ids": [hunt["id"]]}, headers=ACTOR).json() == {"queued": 1}
    assert client.post(f"{API}/findings/explain", json={"ids": ["nope"]}, headers=ACTOR).status_code == 404


def test_skeleton_services_answer_501(client, ctx):
    from tests.api.conftest import SkeletonEngine, SkeletonExplain, SkeletonScanner

    add_target(client)
    scan_and_wait(client)
    fid = client.get(f"{API}/findings", params={"q": SSH_ROOT}).json()["findings"][0]["id"]
    ctx.scanner, ctx.engine, ctx.explain = SkeletonScanner(ctx), SkeletonEngine(ctx), SkeletonExplain(ctx)
    for path, name in ((f"{API}/scans", "scanner"), (f"{API}/findings/{fid}/propose", "remediation engine"),
                       (f"{API}/findings/{fid}/explain", "explain"), (f"{API}/findings/explain", "explain")):
        r = client.post(path, json={}, headers=ACTOR)
        assert r.status_code == 501, path
        assert r.json()["detail"] == f"{name} not available on this build"
    # listing still works with the skeletons, and status reports the model as not built
    assert client.get(f"{API}/findings").json()["total"] == 3
    assert client.get(f"{API}/status").json()["llm"]["available"] is False
