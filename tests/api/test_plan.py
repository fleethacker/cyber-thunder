"""HTTP contract over the real static planner and isolated state, without background work."""
import pytest

from tests.api.conftest import ACTOR
from tests.engine.test_plan import forbid_side_effects, seed, statuses, stored_state

API = "/api/v1/proposals"


@pytest.fixture(autouse=True)
def no_runtime_jobs(monkeypatch):
    from cyberthunder.runtime import RuntimeTasks
    monkeypatch.setattr(RuntimeTasks, "start", lambda self: None)


@pytest.mark.parametrize("approved", [False, True])
def test_plan_contract_and_no_apply_or_demo_side_effects(ctx, client, monkeypatch, approved):
    _, p, fix = seed(ctx, approved=approved)
    before, seq = stored_state(ctx), len(ctx.audit)
    forbid_side_effects(monkeypatch, ctx)
    response = client.post(f"{API}/{p.id}/plan", headers=ACTOR)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["mode"] == "static" and result["version"] == 1
    assert result["proposal_id"] == p.id and result["fix"] == fix.to_dict()
    assert set(result["target"]) == {"id", "name", "asset_type", "simulated", "in_scope"}
    assert "private-" not in response.text and "192.0.2.37" not in response.text
    assert statuses(result)["approval"] == ("pass" if approved else "blocked")
    assert stored_state(ctx) == before
    records = list(ctx.audit.records())[seq:]
    assert len(records) == 1 and records[0]["action"] == "remediation.plan"
    assert records[0]["actor"] == ACTOR["X-Actor"]


@pytest.mark.parametrize("headers", [{}, {"X-Actor": " "}, {"X-Actor": "agent"}, {"X-Actor": "system2"},
                                      {"X-Actor": "policy:Rivera"}])
def test_plan_requires_named_actor_dependency(ctx, client, monkeypatch, headers):
    _, p, _ = seed(ctx)
    forbid_side_effects(monkeypatch, ctx)
    monkeypatch.setattr(ctx.engine, "plan", lambda *a, **k: pytest.fail("invalid actor reached planner"))
    assert client.post(f"{API}/{p.id}/plan", headers=headers).status_code == 400


@pytest.mark.parametrize("problem,expected", [("kill", 423), ("unknown", 404), ("changed", 409), ("missing", 409)])
def test_plan_maps_refusals(ctx, client, monkeypatch, problem, expected):
    _, p, fix = seed(ctx, approved=True)
    pid = p.id
    if problem == "kill":
        monkeypatch.setenv("CT_KILL", "1")
    elif problem == "unknown":
        pid = "unknown-proposal"
    elif problem == "changed":
        fix.verify = {"changed": True}
    else:
        from cyberthunder.remediation.library import FixLibrary
        ctx.library = FixLibrary()
        (ctx.store.snapshots_dir / p.id / "fix.json").unlink()
    before = stored_state(ctx)
    forbid_side_effects(monkeypatch, ctx)
    response = client.post(f"{API}/{pid}/plan", headers=ACTOR)
    assert response.status_code == expected, response.text
    assert "detail" in response.json()
    assert stored_state(ctx) == before


def test_plan_endpoint_is_post_only(ctx, client, monkeypatch):
    monkeypatch.setattr(ctx.engine, "plan", lambda *a, **k: pytest.fail("GET reached planner"))
    schema = client.get("/api/openapi.json").json()
    assert set(schema["paths"][f"{API}/{{pid}}/plan"]) == {"post"}
    # The optional static-files mount may handle unmatched GETs as 404 rather than 405.
    assert client.get(f"{API}/any/plan", headers=ACTOR).status_code in {404, 405}


@pytest.mark.parametrize("engine", [None, object(), type("NoPlanner", (), {"plan": None})()])
def test_missing_planner_returns_unavailable(ctx, client, engine):
    ctx.engine = engine
    response = client.post(f"{API}/any/plan", headers=ACTOR)
    assert response.status_code == 501
    assert "not available on this build" in response.json()["detail"]
