"""Public library routes, upload limits and stale subscription protection."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.ingest.service import IngestService
from tests.api.conftest import ACTOR
from tests.ingest.content_helpers import W11_XCCDF, guard_network

BASE = "/api/v1/ingest"


@pytest.fixture
def api(ctx, monkeypatch):
    guard_network(monkeypatch)
    ctx.ingest = IngestService(ctx)
    with TestClient(create_app(ctx)) as client:
        yield client


def preferences(api):
    row = api.get(BASE + "/library").json()["preferences"]
    return {k: row[k] for k in ("mode", "products", "kinds", "check_on_reconnect", "auto_pull", "revision")}


def test_library_and_revision_conflict(api):
    row = api.get(BASE + "/library")
    assert row.status_code == 200, row.text
    assert row.json()["sync"]["last_successful_check_at"] is None
    body = {**preferences(api), "mode": "selected", "products": ["RHEL_9"], "kinds": ["scap_benchmark"]}
    saved = api.put(BASE + "/library/preferences", json=body, headers=ACTOR)
    assert saved.status_code == 200, saved.text
    assert saved.json()["revision"] == 1
    assert api.put(BASE + "/library/preferences", json=body, headers=ACTOR).status_code == 409
    view = api.get(BASE + "/library").json()
    assert len(view["selection"]["wanted"]) == 1
    assert view["selection"]["wanted"][0]["kind"] == "scap_benchmark"
    updates = api.get(BASE + "/updates").json()
    assert updates["checked_at"] is None
    assert updates["updates"] == view["selection"]["updates"]


def test_preferences_validation_and_actor(api):
    body = preferences(api)
    assert api.put(BASE + "/library/preferences", json=body).status_code == 400
    for update in ({"extra": True}, {"auto_pull": "false"}, {"revision": True}):
        assert api.put(BASE + "/library/preferences", json={**body, **update}, headers=ACTOR).status_code == 400


def test_xml_upload_is_visible_idempotent_and_local(api, ctx):
    files = {"file": ("manual.xml", W11_XCCDF.read_bytes(), "application/xml")}
    first = api.post(BASE + "/content/upload", files=files, headers=ACTOR)
    assert first.status_code == 201, first.text
    assert first.json()["record"]["source"] == "uploaded"
    assert first.json()["delta"]["full_import"]
    second = api.post(BASE + "/content/upload", files=files, headers=ACTOR)
    assert second.status_code == 201 and second.json()["delta"] is None
    view = api.get(BASE + "/library").json()
    assert len(view["held"]["files"]) == 1
    assert view["held"]["files"][0]["ingest"]["upload"]["imported_by"] == ACTOR["X-Actor"]
    assert view["sync"]["last_import_at"] and view["sync"]["last_download_at"] is None
    assert view["sync"]["last_successful_check_at"] is None


def test_upload_requires_actor_and_obeys_stop(api, ctx):
    files = {"file": ("manual.xml", W11_XCCDF.read_bytes())}
    assert api.post(BASE + "/content/upload", files=files).status_code == 400
    ctx.killswitch.engage("ITC Rivera", "test")
    assert api.post(BASE + "/content/upload", files=files, headers=ACTOR).status_code == 423
    assert api.put(BASE + "/library/preferences", json=preferences(api), headers=ACTOR).status_code == 423
    assert api.get(BASE + "/library").json()["held"]["files"] == []


def test_upload_rejects_malformed_multiple_empty_and_oversize(api):
    assert api.post(BASE + "/content/upload", content=b"hello", headers=ACTOR).status_code == 400
    many = [("file", ("one.xml", b"<x/>")), ("file", ("two.xml", b"<x/>"))]
    assert api.post(BASE + "/content/upload", files=many, headers=ACTOR).status_code == 400
    assert api.post(BASE + "/content/upload", files={"file": ("empty.xml", b"")}, headers=ACTOR).status_code == 400
    headers = {**ACTOR, "Content-Length": str(34 * 1024 * 1024)}
    assert api.post(BASE + "/content/upload", content=b"x", headers=headers).status_code == 413
    invalid = api.post(BASE + "/content/upload", files={"file": ("not-a-benchmark.xml", b"<x/>")}, headers=ACTOR)
    assert invalid.status_code == 400, invalid.text
