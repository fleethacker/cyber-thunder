"""API routes on a bare FastAPI app, and the CLI through a parser built here."""
from __future__ import annotations

import argparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cyberthunder.api.routes import discovery as routes
from cyberthunder.discovery.cli import register_cli
from cyberthunder.discovery.service import service_for

H = {"X-Actor": "it1.jones"}


@pytest.fixture
def client(ctx):
    app = FastAPI()
    app.state.ctx = ctx
    app.include_router(routes.router)
    return TestClient(app)


def test_api_flow(client, ctx):
    r = client.get("/discovery")
    assert r.status_code == 200 and r.json()["last_run"] is None and r.json()["scopes"] == []
    assert client.put("/discovery/scopes", json={"scopes": [{"cidr": "192.168.56.0/24"}], "reason": ""},
                      headers=H).status_code == 400
    assert client.put("/discovery/scopes", json={"scopes": [{"cidr": "192.168.56.0/24"}], "reason": "enclave"},
                      headers={"X-Actor": "agent"}).status_code == 400
    r = client.put("/discovery/scopes", json={"scopes": [{"cidr": "192.168.56.0/24"}], "reason": "enclave A"}, headers=H)
    assert r.status_code == 200 and r.json()["scopes"][0]["added_by"] == "it1.jones"
    assert client.put("/discovery/scopes", json={"scopes": [{"cidr": "8.8.8.0/24"}], "reason": "x"},
                      headers=H).status_code == 400

    r = client.post("/discovery/sweep", json={"mode": "simulated"}, headers=H)
    assert r.status_code == 202
    run_id = r.json()["id"]
    svc = service_for(ctx)
    assert svc.join(run_id, timeout=30).status == "finished"
    assert client.post("/discovery/sweep", json={"mode": "bogus"}, headers=H).status_code == 400

    assert client.get("/discovery/runs").json()[0]["id"] == run_id
    run = client.get(f"/discovery/runs/{run_id}").json()
    assert run["new"] == 7 and len(run["assets"]) == 7              # empty inventory: everything is new
    assert client.get("/discovery/runs/nope").status_code == 404
    overview = client.get("/discovery").json()
    assert overview["last_run"]["id"] == run_id and overview["counts"]["new"] == 7

    new = client.get("/discovery/assets", params={"status": "new"}).json()
    assert len(new) == 7
    assert client.get("/discovery/assets", params={"status": "weird"}).status_code == 400
    pi = next(a for a in new if a["address"] == "192.168.56.66")
    assert client.get(f"/discovery/assets/{pi['id']}").json()["vendor"].startswith("Raspberry")
    assert client.get("/discovery/assets/zzz").status_code == 404

    findings = client.get("/discovery/findings").json()
    rogue = [f for f in findings if f["host"] == "discovered:192.168.56.66" and f["rule_id"] == "discovery:unknown_asset"]
    assert rogue and rogue[0]["severity"] == "high" and any(x["id"] == "T1200" for x in rogue[0]["references"])
    assert client.get("/discovery/findings", params={"run_id": "nope"}).status_code == 404

    linux = next(a for a in new if a["hostname"] == "sim-linux-01")
    body = {"in_scope": True, "reason": "enclave host"}
    assert client.post(f"/discovery/assets/{linux['id']}/accept", json=body,
                       headers={"X-Actor": "llm"}).status_code == 400
    assert client.post(f"/discovery/assets/{linux['id']}/accept", json={"in_scope": True, "reason": ""},
                       headers=H).status_code == 400
    assert client.post(f"/discovery/assets/{pi['id']}/accept", json=body, headers=H).status_code == 400  # type unknown
    r = client.post(f"/discovery/assets/{linux['id']}/accept", json=dict(body, username="ctadmin"), headers=H)
    assert r.status_code == 200 and r.json()["id"] == "sim-linux-01" and r.json()["tags"] == ["discovered"]
    # a host from a simulated sweep exists only in the emulator: no live transport, no credentials
    assert r.json()["username"] is None and r.json()["transport"] == "simulated" and r.json()["simulated"] is True
    assert ctx.inventory.get("sim-linux-01").in_scope
    assert client.post("/discovery/assets/zzz/accept", json=body, headers=H).status_code == 404

    r = client.post(f"/discovery/assets/{pi['id']}/ignore", json={"reason": "demo board"}, headers=H)
    assert r.status_code == 200 and r.json()["status"] == "ignored"

    rows = client.get("/discovery/applicable", params={"benchmark": "RHEL_9_STIG"}).json()
    assert [x["target"] for x in rows] == ["sim-linux-01"]
    assert client.get("/discovery/applicable").status_code == 400

    ctx.killswitch.engage("it1.jones", "drill")
    assert client.post("/discovery/sweep", json={"mode": "simulated"}, headers=H).status_code == 423
    assert ctx.audit.verify().ok


def _parser():
    ap = argparse.ArgumentParser(prog="cyberthunder")
    ap.add_argument("--state-dir")
    ap.add_argument("--actor", default="it1.jones")
    sp = ap.add_subparsers(dest="cmd", required=True)
    register_cli(sp)
    return ap


def _run(state_dir, *argv):
    a = _parser().parse_args(["--state-dir", str(state_dir), *argv])
    return a.fn(a)


def test_cli_smoke(ctx, state_dir, capsys):
    assert _run(state_dir, "discover", "scopes", "--add", "192.168.56.0/24") == 2         # reason required
    assert _run(state_dir, "discover", "scopes", "--add", "192.168.56.0/24", "--reason", "enclave A") == 0
    assert "192.168.56.0/24" in capsys.readouterr().out
    assert _run(state_dir, "discover", "scopes", "--add", "8.8.8.0/24", "--reason", "x") == 2
    assert _run(state_dir, "discover", "scopes", "--add", "8.8.8.0/24", "--reason", "authorized test", "--allow-public") == 0
    capsys.readouterr()
    assert _run(state_dir, "discover", "sweep", "--mode", "simulated", "--scope", "192.168.56.0/24", "--wait") == 0
    assert "new=7" in capsys.readouterr().out
    assert _run(state_dir, "discover", "list", "--status", "new") == 0
    listing = capsys.readouterr().out
    assert "192.168.56.66" in listing and "consumer/iot device" in listing
    assert _run(state_dir, "discover", "findings") == 0
    assert "discovery:unknown_asset" in capsys.readouterr().out
    pi_id = next(line.split()[0] for line in listing.splitlines() if "192.168.56.66" in line)
    sw_id = next(line.split()[0] for line in listing.splitlines() if "192.168.56.3 " in line)
    assert _run(state_dir, "--actor", "agent", "discover", "accept", sw_id, "--in-scope", "--reason", "x") == 2
    with pytest.raises(SystemExit):
        _parser().parse_args(["discover", "accept", sw_id, "--reason", "x"])             # scope decision required
    assert _run(state_dir, "discover", "accept", sw_id, "--name", "SW-SPARE-03", "--in-scope", "--reason", "now managed") == 0
    assert '"asset_type": "cisco_ios"' in capsys.readouterr().out
    assert _run(state_dir, "discover", "ignore", pi_id, "--reason", "demo board") == 0
    assert _run(state_dir, "discover", "applicable", "--title", "Cisco IOS XE Switch NDM") == 0
    assert _run(state_dir, "discover", "applicable", "--benchmark", "nonesuch") == 2
    from cyberthunder.audit.chain import verify_file
    assert verify_file(state_dir / "audit.jsonl").ok
    assert ctx.audit.verify().ok


def test_prefixed_machine_actor_refused_at_the_edge(client):
    body = {"scopes": [{"cidr": "192.168.56.0/24"}], "reason": "range plan"}
    assert client.put("/discovery/scopes", json=body, headers={"X-Actor": "agent:planner"}).status_code == 400


def test_accept_refuses_live_transport_and_raw_env_credentials_from_a_simulated_sweep(client, ctx, monkeypatch):
    monkeypatch.setenv("SOME_SECRET_TOKEN", "hunter2")
    run_id = client.post("/discovery/sweep", json={"mode": "simulated"}, headers=H).json()["id"]
    service_for(ctx).join(run_id, timeout=30)
    sw = next(a for a in client.get("/discovery/assets", params={"status": "new"}).json()
              if a["address"] == "192.168.56.3")
    body = {"credential_ref": "SOME_SECRET_TOKEN", "transport": "ssh", "in_scope": True, "reason": "probe"}
    r = client.post(f"/discovery/assets/{sw['id']}/accept", json=body, headers=H)
    assert r.status_code == 400 and "simulated" in r.json()["detail"]
    r = client.post(f"/discovery/assets/{sw['id']}/accept", json=dict(body, transport=None), headers=H)
    assert r.status_code == 200
    t = ctx.inventory.get(r.json()["id"])
    assert t.transport == "simulated" and t.simulated and t.credential_ref is None
