"""The decision queue: approve, deny, cancel, apply, rollback, diff, bulk; kill switch and demo toggle."""
from __future__ import annotations

import types

from tests.api.conftest import ACTOR, SSH_ROOT, wait_state

API = "/api/v1"


def _propose(client, fid):
    r = client.post(f"{API}/findings/{fid}/propose", headers=ACTOR)
    assert r.status_code == 200, r.text
    return r.json()


def test_list_and_filter(client, scanned):
    p = _propose(client, scanned[SSH_ROOT]["id"])
    lst = client.get(f"{API}/proposals").json()["proposals"]
    assert [x["id"] for x in lst] == [p["id"]]
    assert client.get(f"{API}/proposals", params={"state": "approved"}).json()["proposals"] == []
    assert len(client.get(f"{API}/proposals", params={"state": "proposed,approved"}).json()["proposals"]) == 1
    assert len(client.get(f"{API}/proposals", params={"host": "web01"}).json()["proposals"]) == 1
    assert client.get(f"{API}/proposals", params={"asset_type": "windows"}).json()["proposals"] == []
    assert client.get(f"{API}/proposals", params={"state": "maybe"}).status_code == 400
    assert client.get(f"{API}/proposals/nope").status_code == 404


def test_approve_records_actor_and_note(client, approved):
    assert approved["decided_by"] == "ITC Rivera" and approved["decision_note"] == "change window 1400"
    rec = client.get(f"{API}/audit", params={"action": "proposal.approved"}).json()["records"][-1]
    assert rec["actor"] == "ITC Rivera" and rec["subject"] == approved["id"]
    # a second approval is an illegal transition
    assert client.post(f"{API}/proposals/{approved['id']}/approve", headers=ACTOR).status_code == 409


def test_deny_and_cancel(client, scanned):
    p = _propose(client, scanned[SSH_ROOT]["id"])
    r = client.post(f"{API}/proposals/{p['id']}/deny", json={"note": "not during underway period"}, headers=ACTOR)
    assert r.json()["state"] == "denied"
    assert client.post(f"{API}/proposals/{p['id']}/cancel", headers=ACTOR).status_code == 409
    p2 = _propose(client, scanned[SSH_ROOT]["id"])        # a denied proposal is not live: a new one is allowed
    assert client.post(f"{API}/proposals/{p2['id']}/cancel", headers=ACTOR).json()["state"] == "cancelled"
    assert client.post(f"{API}/proposals/{p2['id']}/approve").status_code == 400          # no actor


def test_apply_verifies_in_background(client, approved):
    pid = approved["id"]
    r = client.post(f"{API}/proposals/{pid}/apply", json={}, headers=ACTOR)
    assert r.status_code == 202
    assert r.json() == {"proposal_id": pid, "state": "applying", "simulate_verify_fail": False}
    assert wait_state(client, pid, {"verified"})["state"] == "verified"
    assert client.post(f"{API}/proposals/{pid}/apply", headers=ACTOR).status_code == 409
    d = client.get(f"{API}/proposals/{pid}/diff").json()
    assert d["files"][0]["path"] == "/etc/ssh/sshd_config" and "verify" in d and "apply" in d

    r = client.post(f"{API}/proposals/{pid}/rollback", headers=ACTOR)
    assert r.status_code == 202
    assert wait_state(client, pid, {"rolled_back"})["history"][-1]["actor"] == "ITC Rivera"
    assert client.post(f"{API}/proposals/{pid}/rollback", headers=ACTOR).status_code == 409


def test_apply_requires_approved(client, scanned):
    p = _propose(client, scanned[SSH_ROOT]["id"])
    r = client.post(f"{API}/proposals/{p['id']}/apply", headers=ACTOR)
    assert r.status_code == 409 and "approved" in r.json()["detail"]
    assert client.post(f"{API}/proposals/{p['id']}/rollback", headers=ACTOR).status_code == 409
    assert client.post(f"{API}/proposals/nope/apply", headers=ACTOR).status_code == 404


def test_apply_blocked_by_kill_switch(client, approved):
    pid = approved["id"]
    assert client.post(f"{API}/kill/engage", json={"reason": "drill"}, headers=ACTOR).json()["engaged"] is True
    r = client.post(f"{API}/proposals/{pid}/apply", headers=ACTOR)
    assert r.status_code == 423 and "kill switch" in r.json()["detail"]
    assert client.get(f"{API}/proposals/{pid}").json()["state"] == "approved"
    blocked = client.get(f"{API}/audit", params={"action": "action.blocked"}).json()["records"]
    assert blocked and blocked[-1]["outcome"] == "blocked"
    client.post(f"{API}/kill/release", json={"reason": "drill over"}, headers=ACTOR)
    assert client.post(f"{API}/proposals/{pid}/apply", headers=ACTOR).status_code == 202
    wait_state(client, pid, {"verified"})


def test_forced_verify_failure_rolls_back(client, approved):
    pid = approved["id"]
    r = client.post(f"{API}/proposals/{pid}/apply", json={"simulate_verify_fail": True}, headers=ACTOR)
    assert r.json()["simulate_verify_fail"] is True
    p = wait_state(client, pid, {"rolled_back"})
    assert [h["state"] for h in p["history"]][-3:] == ["applied", "failed", "rolled_back"]


def test_demo_toggle_is_consumed_on_apply(client, approved, monkeypatch):
    from cyberthunder.api import util

    armed = {"n": 1}

    def consume(ctx):
        hit, armed["n"] = armed["n"] > 0, 0
        return hit

    monkeypatch.setattr(util, "demo_module", lambda: types.SimpleNamespace(consume_simulate_verify_fail=consume))
    r = client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    assert r.json()["simulate_verify_fail"] is True and armed["n"] == 0
    wait_state(client, approved["id"], {"rolled_back"})


def test_bulk(client, scanned):
    p = _propose(client, scanned[SSH_ROOT]["id"])
    r = client.post(f"{API}/proposals/bulk", json={"action": "approve", "ids": [p["id"], "ghost"]}, headers=ACTOR)
    res = r.json()["results"]
    assert res[0] == {"id": p["id"], "state": "approved"}
    assert res[1]["id"] == "ghost" and res[1]["status"] == 404 and "ghost" in res[1]["error"]
    again = client.post(f"{API}/proposals/bulk", json={"action": "deny", "ids": [p["id"]]}, headers=ACTOR).json()
    assert again["results"][0]["status"] == 409
    assert client.post(f"{API}/proposals/bulk", json={"action": "apply", "ids": [p["id"]]},
                       headers=ACTOR).status_code == 400
    assert client.post(f"{API}/proposals/bulk", json={"action": "approve", "ids": [p["id"]]},
                       headers={"X-Actor": "agent"}).status_code == 400


def test_engine_skeleton_apply_is_501(client, ctx, approved):
    from tests.api.conftest import SkeletonEngine

    ctx.engine = SkeletonEngine(ctx)
    r = client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    assert r.status_code == 501 and r.json()["detail"] == "remediation engine not available on this build"
    assert client.get(f"{API}/proposals/{approved['id']}/diff").status_code == 501
