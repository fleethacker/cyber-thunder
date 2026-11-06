"""Recipe API validation and conflict responses; no actual discovery I/O."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cyberthunder.api.routes.discovery import router
from .test_scope_recipes import recipe

PATH = "/discovery/scopes/recipes"
ACTOR = {"X-Actor": "IT1 Jones"}


@pytest.fixture
def client(ctx):
    app = FastAPI()
    app.state.ctx = ctx
    app.include_router(router)
    return TestClient(app)


def request_body(client, rows=None):
    return {"revision": client.get(PATH).json()["revision"], "recipes": rows if rows is not None else [recipe()]}


def save_body(client, body):
    response = client.post(PATH + "/preview", json=body)
    assert response.status_code == 200, response.text
    return {**body, "preview_fingerprint": response.json()["fingerprint"], "reason": "Reviewed recipe decisions"}


def test_api_roundtrip_revision_conflicts_and_audit(client, ctx):
    body = request_body(client, [recipe(), recipe("ipv6", name="Réseau IPv6", include=["fd00::1-fd00::4"], exclude=["fd00::2"])])
    submit = save_body(client, body)
    assert client.get(PATH).json()["recipes"] == []
    saved = client.put(PATH, json=submit, headers=ACTOR)
    assert saved.status_code == 200, saved.text
    current = client.get(PATH).json()
    assert current["recipes"][0]["include"] == body["recipes"][0]["include"]
    assert current["recipes"][1]["exclude"] == ["fd00::2"]
    assert client.get("/discovery").json()["scopes"] == current["scopes"]
    assert client.put(PATH, json=submit, headers=ACTOR).status_code == 409
    assert client.post(PATH + "/preview", json=body).status_code == 409
    assert client.get(PATH).json() == current
    assert ctx.audit.verify().ok


@pytest.mark.parametrize("headers", [{}, {"X-Actor": "agent"}, {"X-Actor": "system:worker"}])
def test_human_edge_refuses_unauthorized_recipe_saves(client, headers):
    before = client.get(PATH).json()
    submit = save_body(client, request_body(client))
    assert client.put(PATH, json=submit, headers=headers).status_code == 400
    assert client.get(PATH).json() == before


@pytest.mark.parametrize("changes", [{"allow_public": "true"}, {"acknowledge_normalization": 1},
    {"include": [1]}, {"exclude": "10.1.0.1"}, {"id": "../scope"}, {"extra": True},
    {"include": ["10.1.0.1"] * 129}, {"name": "x" * 81}])
def test_api_rejects_coercion_unknown_fields_and_bounds(client, changes):
    body = request_body(client, [recipe(**changes)])
    assert client.post(PATH + "/preview", json=body).status_code == 422
    assert client.get(PATH).json()["scopes"] == []


@pytest.mark.parametrize("include", [["１０.1.0.1"], ["10.1.0.1\u200b"], ["10.1.0.4-10.1.0.1"]])
def test_invalid_expressions_fail_at_api_without_writes(client, include):
    body = request_body(client, [recipe(include=include)])
    assert client.post(PATH + "/preview", json=body).status_code == 400
    assert client.get(PATH).json()["scopes"] == []


def test_binding_and_host_bits_cannot_be_bypassed(client):
    body = request_body(client, [recipe(include=["10.1.0.9/24"])])
    submit = save_body(client, body)
    assert client.put(PATH, json=submit, headers=ACTOR).status_code == 400
    submit["recipes"][0]["acknowledge_normalization"] = True
    assert client.put(PATH, json=submit, headers=ACTOR).status_code == 400
    submit = save_body(client, {k: submit[k] for k in ("recipes", "revision")})
    assert client.put(PATH, json=submit, headers=ACTOR).status_code == 200


def test_kill_and_unknown_scanner_are_refused(client, ctx):
    body = request_body(client, [recipe(scanner_target="missing")])
    assert client.post(PATH + "/preview", json=body).status_code == 404
    submit = save_body(client, request_body(client))
    ctx.killswitch.engage("IT1 Other", "Stop")
    assert client.put(PATH, json=submit, headers=ACTOR).status_code == 423
    assert client.get(PATH).json()["scopes"] == []


def test_compatibility_ranges_save_retains_submitted_expressions(client):
    data = {"include": ["10.1.0.1-10.1.0.9"], "exclude": ["10.1.0.4"], "reason": "Compatibility save"}
    response = client.put("/discovery/scopes/ranges", json=data, headers=ACTOR)
    assert response.status_code == 200, response.text
    recipe = client.get(PATH).json()["recipes"][0]
    assert recipe["include"] == data["include"] and recipe["exclude"] == data["exclude"]
    assert recipe["original_expressions_known"]
