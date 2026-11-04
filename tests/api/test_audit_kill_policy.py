"""Audit list/verify/stream, kill switch, standing approval policy."""
from __future__ import annotations

import asyncio
import json
import threading
import time

from cyberthunder.api.routes.audit import audit_events
from tests.api.conftest import ACTOR, SSH_ROOT

API = "/api/v1"


def test_audit_list_filters_and_verify(client, ctx):
    ctx.audit.append("test.one", "ITC Rivera", {"n": 1}, subject="a")
    ctx.audit.append("test.two", "ITC Hale", {"n": 2}, subject="b")
    body = client.get(f"{API}/audit").json()
    assert body["count"] == len(body["records"]) == 2 and body["head"] == ctx.audit.head
    assert [r["action"] for r in client.get(f"{API}/audit", params={"action": "test."}).json()["records"]] == \
        ["test.one", "test.two"]
    assert len(client.get(f"{API}/audit", params={"action": "test"}).json()["records"]) == 0
    assert client.get(f"{API}/audit", params={"actor": "ITC Hale"}).json()["records"][0]["subject"] == "b"
    assert client.get(f"{API}/audit", params={"subject": "a"}).json()["records"][0]["seq"] == 1
    assert [r["seq"] for r in client.get(f"{API}/audit", params={"after_seq": 1}).json()["records"]] == [2]
    assert len(client.get(f"{API}/audit", params={"limit": 1}).json()["records"]) == 1
    v = client.get(f"{API}/audit/verify").json()
    assert v == {"ok": True, "count": 2, "head": ctx.audit.head, "bad_seq": None, "reason": None}


def test_audit_verify_detects_tampering(client, ctx, state_dir):
    ctx.audit.append("test.one", "ITC Rivera", {"n": 1})
    ctx.audit.append("test.two", "ITC Rivera", {"n": 2})
    lines = ctx.audit.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["actor"] = "someone else"
    tampered = [json.dumps(rec, sort_keys=True)] + lines[1:]
    good = ctx.audit.path.read_text(encoding="utf-8")
    ctx.audit.path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
    try:
        v = client.get(f"{API}/audit/verify").json()
        assert v["ok"] is False and v["bad_seq"] == 1
    finally:
        ctx.audit.path.write_text(good, encoding="utf-8")


def test_audit_stream_replays_then_tails(client, ctx):
    ctx.audit.append("test.before", "ITC Rivera")
    ctx.audit.append("test.before2", "ITC Rivera")

    def later():
        time.sleep(0.4)
        ctx.audit.append("test.live", "ITC Rivera")

    threading.Thread(target=later, daemon=True).start()
    with client.stream("GET", f"{API}/audit/stream", params={"after_seq": 1, "max_seconds": 1.5}) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        text = "".join(r.iter_text())
    events = [json.loads(line[len("data: "):]) for line in text.splitlines() if line.startswith("data: ")]
    assert [e["action"] for e in events] == ["test.before2", "test.live"]
    assert "event: audit" in text and "id: 2" in text


def test_audit_stream_generator_keepalive_and_disconnect(ctx):
    ctx.audit.append("test.one", "ITC Rivera")
    calls = {"n": 0}

    async def disconnected():
        calls["n"] += 1
        return calls["n"] > 3

    async def collect():
        return [chunk async for chunk in audit_events(ctx.audit.path, 0, disconnected, poll_s=0.01, keepalive_s=0.0)]

    chunks = asyncio.run(collect())
    assert any(c.startswith("event: audit") or "event: audit" in c for c in chunks)
    assert ": keepalive\n\n" in chunks
    assert calls["n"] == 4                       # stopped as soon as the client went away


def test_kill_engage_release(client):
    assert client.get(f"{API}/kill").json()["engaged"] is False
    st = client.post(f"{API}/kill/engage", json={"reason": "suspicious traffic"}, headers=ACTOR).json()
    assert st == {**st, "engaged": True, "by": "ITC Rivera", "reason": "suspicious traffic", "via": "state_file"}
    assert client.get(f"{API}/status").json()["kill"]["engaged"] is True
    st = client.post(f"{API}/kill/release", headers=ACTOR).json()
    assert st["engaged"] is False
    acts = [r["action"] for r in client.get(f"{API}/audit", params={"action": "killswitch."}).json()["records"]]
    assert acts == ["killswitch.engage", "killswitch.release"]
    assert client.post(f"{API}/kill/engage", json={}).status_code == 400


RULE = {"name": "low-risk ssh hardening", "asset_types": ["linux"], "max_disruption": "low",
        "allow_service_restart": True}


def test_policy_put_rules(client, ctx):
    assert client.get(f"{API}/policy").json()["enabled"] is False
    r = client.put(f"{API}/policy", json={"enabled": True, "rules": [RULE]}, headers=ACTOR)
    assert r.status_code == 400 and "reason" in r.json()["detail"]
    assert client.put(f"{API}/policy", json={"enabled": True, "reason": "x", "rules": []}, headers=ACTOR).status_code == 400
    for bad in ({"name": "a", "max_disruption": "extreme"}, {"name": "a", "bogus": 1}, {"name": "a", "window_start": "25:99",
                "window_end": "01:00"}, {"name": "a", "window_start": "01:00"}, {"name": "a", "asset_types": ["toaster"]},
                {"name": ""}):
        r = client.put(f"{API}/policy", json={"enabled": False, "rules": [bad]}, headers=ACTOR)
        assert r.status_code == 400, bad
    r = client.put(f"{API}/policy", json={"enabled": True, "reason": "CO approved low-risk SSH fixes", "rules": [RULE],
                                          "signed_by": "forged", "version": 99}, headers=ACTOR)
    assert r.status_code == 200, r.text
    pol = r.json()
    assert pol["enabled"] is True and pol["signed_by"] == "ITC Rivera" and pol["signed_at"] and pol["version"] == 2
    assert ctx.policy.signed_by == "ITC Rivera"
    assert client.put(f"{API}/policy", json={"enabled": True, "reason": "x", "rules": [RULE]},
                      headers={"X-Actor": "system"}).status_code == 400
    rec = client.get(f"{API}/audit", params={"action": "policy.update"}).json()["records"][-1]
    assert rec["actor"] == "ITC Rivera" and rec["details"]["enabled"] is True

    off = client.put(f"{API}/policy", json={"enabled": False}, headers=ACTOR).json()
    assert off["enabled"] is False and off["version"] == 3 and off["rules"][0]["name"] == RULE["name"]


def test_policy_evaluate(client, scanned):
    p = client.post(f"{API}/findings/{scanned[SSH_ROOT]['id']}/propose", headers=ACTOR).json()
    d = client.post(f"{API}/policy/evaluate", json={"proposal_id": p["id"]}).json()
    assert d["auto_eligible"] is False and "disabled" in d["reasons"][0]
    client.put(f"{API}/policy", json={"enabled": True, "reason": "CO approved", "rules": [RULE]}, headers=ACTOR)
    d = client.post(f"{API}/policy/evaluate", json={"proposal_id": p["id"]}).json()
    assert d == {"auto_eligible": True, "rule": RULE["name"], "reasons": d["reasons"]}
    assert client.get(f"{API}/proposals/{p['id']}").json()["policy"]["auto_eligible"] is True
    assert client.post(f"{API}/policy/evaluate", json={"proposal_id": "nope"}).status_code == 404
