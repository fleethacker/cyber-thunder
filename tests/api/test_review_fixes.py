"""Outbox counts and shape, verified fixes closing findings, target and policy input types, the demo
verify-fail toggle surviving a refused apply, and an unnamed kill switch engage."""
from __future__ import annotations

import types

from cyberthunder.api import util
from cyberthunder.inventory.targets import ScopeViolation
from tests.api.conftest import ACTOR, add_target, wait_state

API = "/api/v1"


class _Outbox:
    def __init__(self):
        self.pending = [{"id": "20261104T1-ab-commander-latest.html", "kind": "commander", "name": "commander-latest.html",
                         "bytes": 4096, "enqueued_at": "2026-11-04T10:00:00+00:00", "status": "pending"},
                        {"id": "20261104T2-cd-commander-latest.html", "kind": "commander", "name": "commander-latest.html",
                         "bytes": 4096, "enqueued_at": "2026-11-04T10:05:00+00:00", "status": "pending"}]
        self.synced = [{"id": "20261104T0-ef-poam.csv", "kind": "poam", "name": "poam.csv", "bytes": 100,
                        "enqueued_at": "2026-11-04T09:00:00+00:00", "synced_at": "2026-11-04T09:01:00+00:00",
                        "transfer_seconds": 1.5, "status": "synced"}]

    def list(self):
        return {"pending": list(self.pending), "synced": list(self.synced)}


class _Ingest:
    """Shaped like IngestService: `outbox` is a property returning the Outbox object, not a method."""

    def __init__(self):
        self._outbox = _Outbox()

    @property
    def outbox(self):
        return self._outbox

    def link_state(self):
        return {"kbps": 56.0, "latency_ms": 500, "connected": True}


def test_status_counts_outbox_entries_from_the_service(client, ctx):
    ctx.ingest = _Ingest()
    # the files on disk would count twice (payload + .meta.json) if the service were bypassed
    for e in ctx.ingest.outbox.pending:
        (ctx.store.outbox_dir / e["id"]).write_text("x", encoding="utf-8")
        (ctx.store.outbox_dir / (e["id"] + ".meta.json")).write_text("{}", encoding="utf-8")
    assert client.get(f"{API}/status").json()["outbox"]["pending"] == 2
    assert len(client.get(f"{API}/outbox").json()["pending"]) == 2


def test_status_outbox_fallback_counts_entries_not_files(client, ctx):
    (ctx.store.outbox_dir / "a-commander.html").write_text("x", encoding="utf-8")
    (ctx.store.outbox_dir / "a-commander.html.meta.json").write_text("{}", encoding="utf-8")
    assert client.get(f"{API}/status").json()["outbox"]["pending"] == 1


def test_outbox_entries_carry_the_documented_fields(client, ctx):
    ctx.ingest = _Ingest()
    ob = client.get(f"{API}/outbox").json()
    pend, synced = ob["pending"], ob["synced"]
    assert pend[0]["created_at"] == "2026-11-04T10:00:00+00:00" and pend[0]["synced_at"] is None
    assert len({e["id"] for e in pend}) == 2          # unique keys even for a re-queued report name
    assert synced[0]["created_at"] == "2026-11-04T09:00:00+00:00"
    # Old transfer_seconds values were modeled timings, never measured delivery.
    assert synced[0]["seconds"] is None
    assert synced[0]["test_estimate_seconds"] == 1.5


def test_verified_fix_closes_the_finding(client, approved):
    fid = approved["finding_id"]
    before = client.get(f"{API}/findings").json()["summary"]["open_by_severity"]["medium"]
    assert before >= 1
    client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    wait_state(client, approved["id"], {"verified"})
    f = client.get(f"{API}/findings/{fid}").json()
    assert f["status"] == "not_a_finding" and f["proposal"]["state"] == "verified"
    assert f["remediated"]["proposal_id"] == approved["id"] and f["remediated"]["scan_status"] == "open"
    listing = client.get(f"{API}/findings", params={"status": "open"}).json()
    assert fid not in {x["id"] for x in listing["findings"]}
    assert listing["summary"]["open_by_severity"]["medium"] == before - 1
    closed = client.get(f"{API}/findings", params={"status": "not_a_finding"}).json()["findings"]
    assert fid in {x["id"] for x in closed}


def test_a_rescan_after_the_fix_wins(client, ctx, approved):
    client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    wait_state(client, approved["id"], {"verified"})
    p = ctx.gate.get(approved["id"])
    f = util.get_finding(ctx, approved["finding_id"])
    assert util.remediated_by(f, p) is not None
    later = util.replace(f, collected_at="2999-01-01T00:00:00+00:00")
    assert util.remediated_by(later, p) is None


def test_target_field_types_are_enforced(client, ctx):
    add_target(client)
    for bad in ({"in_scope": "no"}, {"sudo": 0}, {"simulated": "yes"}, {"port": "22"}, {"port": True},
                {"tags": "dmz"}, {"tags": [1]}, {"options": []}):
        r = client.put(f"{API}/targets/web01", json=bad, headers=ACTOR)
        assert r.status_code == 400, (bad, r.text)
    assert ctx.inventory.get("web01").in_scope is True
    assert client.put(f"{API}/targets/web01", json={"port": 2222, "tags": ["dmz"]}, headers=ACTOR).status_code == 200


def test_target_id_must_be_a_plain_name(client):
    for bad in ("../x", "../../../x", "a/b", "a\\b", ".hidden", "-x", "x" * 65):
        r = client.post(f"{API}/targets", json={"id": bad, "asset_type": "linux"}, headers=ACTOR)
        assert r.status_code == 400, bad
    assert client.get(f"{API}/targets").json()["targets"] == []
    r = client.post(f"{API}/targets", json={"id": "sim-linux_01.a", "asset_type": "linux", "transport": "fixture"},
                    headers=ACTOR)
    assert r.status_code == 201, r.text


def test_refused_apply_keeps_the_demo_toggle_armed(client, ctx, approved, monkeypatch):
    armed = {"on": True}

    def consume(c):
        hit, armed["on"] = armed["on"], False
        return hit

    def set_flag(c, flag, actor):
        armed["on"] = bool(flag)
        return bool(flag)

    monkeypatch.setattr(util, "demo_module", lambda: types.SimpleNamespace(
        consume_simulate_verify_fail=consume, set_simulate_verify_fail_next=set_flag))

    def out_of_scope(pid, *, actor, simulate_verify_fail=False):
        raise ScopeViolation("web01 is out of scope")

    monkeypatch.setattr(ctx.engine, "execute", out_of_scope)
    r = client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    assert r.status_code == 403, r.text
    assert armed["on"] is True


def test_kill_engage_needs_no_name_but_release_does(client):
    st = client.post(f"{API}/kill/engage", json={"reason": "beaconing"}).json()
    assert st["engaged"] is True and st["by"].startswith("unidentified operator")
    rec = client.get(f"{API}/audit", params={"action": "killswitch.engage"}).json()["records"][-1]
    assert rec["actor"].startswith("unidentified operator")
    assert client.post(f"{API}/kill/engage", json={}, headers={"X-Actor": "agent"}).status_code == 400
    assert client.post(f"{API}/kill/release", json={}).status_code == 400
    assert client.post(f"{API}/kill/release", json={}, headers=ACTOR).json()["engaged"] is False


RULE = {"name": "ssh", "asset_types": ["linux"], "max_disruption": "low", "allow_service_restart": True}


def test_policy_rule_types_and_partial_put(client, ctx):
    r = client.put(f"{API}/policy", json={"enabled": False, "rules": [{**RULE, "asset_types": "linux"}]}, headers=ACTOR)
    assert r.status_code == 400 and "asset_types must be a list" in r.json()["detail"]
    for bad in ({"allow_patch": "yes"}, {"fix_allowlist": "x"}, {"target_allowlist": [1]},
                {"window_start": 5, "window_end": 6}):
        assert client.put(f"{API}/policy", json={"rules": [{**RULE, **bad}]}, headers=ACTOR).status_code == 400, bad
    r = client.put(f"{API}/policy", json={"enabled": False, "rules": [{**RULE, "fix_allowlist": None,
                                                                        "target_allowlist": None}]}, headers=ACTOR)
    assert r.status_code == 200 and r.json()["rules"][0]["fix_allowlist"] == []
    assert r.json()["rules"][0]["target_allowlist"] == []
    on = client.put(f"{API}/policy", json={"enabled": True, "reason": "CO approved", "rules": [RULE]}, headers=ACTOR)
    assert on.json()["enabled"] is True
    # rules only: the policy stays on, and a change to a signed policy still needs a reason
    assert client.put(f"{API}/policy", json={"rules": [RULE]}, headers=ACTOR).status_code == 400
    r = client.put(f"{API}/policy", json={"rules": [{**RULE, "allow_patch": True}], "reason": "add patches"},
                   headers=ACTOR)
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert ctx.policy.enabled is True
