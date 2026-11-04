"""Every route that changes state refuses a request that does not name a person.

The table is built from the app's own routes, so a new mutating route is covered the day it lands."""
from __future__ import annotations

import pytest

from tests.api.conftest import ACTOR

API = "/api/v1"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
# Read-only computations that happen to take a POST body; they change nothing and write no audit line.
NO_ACTOR = {("POST", f"{API}/policy/evaluate")}
# Engaging the kill switch must never wait for a name; it records an unidentified operator instead.
UNNAMED_OK = {("POST", f"{API}/kill/engage")}
REFUSED = [None, "", "   ", "agent", "LLM", "system",
           "agent:planner", "llm:explain", "System:scheduler", "policy:cdr", "POLICY:standing"]


def _mutating_routes(app) -> list[tuple[str, str]]:
    """(METHOD, concrete path) for every state-changing route the app publishes, path params filled in."""
    out = []
    for path, ops in app.openapi()["paths"].items():
        if not path.startswith(API):
            continue
        for m in sorted(k.upper() for k in ops if k.upper() in MUTATING):
            if (m, path) not in NO_ACTOR:
                out.append((m, path.replace("{", "").replace("}", "")))
    return out


def test_route_table_is_not_empty(client):
    routes = _mutating_routes(client.app)
    assert (("PUT", f"{API}/discovery/scopes") in routes and ("POST", f"{API}/discovery/sweep") in routes
            and ("POST", f"{API}/proposals/pid/approve") in routes and ("POST", f"{API}/kill/engage") in routes)


@pytest.mark.parametrize("actor", REFUSED)
def test_every_mutating_route_refuses_unnamed_and_machine_actors(client, ctx, actor):
    before = len(ctx.audit)
    headers = {} if actor is None else {"X-Actor": actor}
    for method, path in _mutating_routes(client.app):
        if (method, path) in UNNAMED_OK and not (actor or "").strip():
            continue
        r = client.request(method, path, json={}, headers=headers)
        assert r.status_code == 400, (method, path, actor, r.status_code, r.text)
        detail = r.json()["detail"].lower()
        assert "x-actor" in detail or "reserved" in detail, (method, path, actor, detail)
    assert len(ctx.audit) == before


def test_anonymous_scope_change_is_refused_and_not_attributed(client, ctx):
    body = {"scopes": [{"cidr": "10.20.0.0/24"}], "reason": "range enclave"}
    assert client.put(f"{API}/discovery/scopes", json=body).status_code == 400
    assert client.put(f"{API}/discovery/scopes", json=body, headers={"X-Actor": "policy:cdr"}).status_code == 400
    assert not client.get(f"{API}/audit", params={"action": "discovery.scopes"}).json()["records"]
    r = client.put(f"{API}/discovery/scopes", json=body, headers=ACTOR)
    assert r.status_code == 200, r.text
    rec = client.get(f"{API}/audit", params={"action": "discovery.scopes"}).json()["records"][-1]
    assert rec["actor"] == ACTOR["X-Actor"]


def test_verify_without_engine_support_is_501(client, ctx, approved, monkeypatch):
    # a node whose engine build has no verify step answers 501, not a transition error
    monkeypatch.setattr(ctx.engine, "verify", None, raising=False)
    r = client.post(f"{API}/proposals/{approved['id']}/verify", headers=ACTOR)
    assert r.status_code == 501, r.text


def test_verify_calls_engine_verify_with_the_actor(client, ctx, approved, monkeypatch):
    calls = []

    def fake_verify(pid, *, actor):
        calls.append((pid, actor))
        return ctx.gate.get(pid)

    monkeypatch.setattr(ctx.engine, "verify", fake_verify, raising=False)
    r = client.post(f"{API}/proposals/{approved['id']}/verify", headers=ACTOR)
    assert r.status_code == 200, r.text
    assert calls == [(approved["id"], ACTOR["X-Actor"])]
    assert r.json()["id"] == approved["id"]
    assert client.post(f"{API}/proposals/{approved['id']}/verify", headers={"X-Actor": "agent:planner"}).status_code == 400
