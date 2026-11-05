"""Content-update routes: check, pull job, held content, manifest and import-dir, against a loopback file
server. Nothing here leaves the machine."""
from __future__ import annotations

import json
import time

import pytest

from tests.api.conftest import ACTOR
from tests.ingest.content_helpers import (FileServer, guard_network, loopback_client, node_client, record, scap_zip,
                                          stig_zip)

API = "/api/v1"
STIG = "U_MS_Windows_11_V2R11_STIG.zip"
SCAP = "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip"


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch):
    guard_network(monkeypatch)


@pytest.fixture
def server(tmp_path):
    srv = FileServer().start()
    src = tmp_path / "src"
    src.mkdir()
    srv.add(STIG, stig_zip(src / STIG).read_bytes(), etag='"a"')
    srv.add(SCAP, scap_zip(src / SCAP).read_bytes(), etag='"b"')
    yield srv
    srv.stop()


@pytest.fixture
def api(ctx, server):
    from fastapi.testclient import TestClient
    from cyberthunder.api.app import create_app
    from cyberthunder.ingest.service import IngestService
    from cyberthunder.inventory.targets import Target
    ctx.ingest = IngestService(ctx)
    ctx.ingest.content.client = node_client(lambda: [record(STIG, server.url(STIG)), record(SCAP, server.url(SCAP))])
    ctx.inventory.add(Target(id="ws01", name="ws01", asset_type="windows", transport="winrm",
                             options={"stig_products": ["MS_Windows_11"]}))
    with TestClient(create_app(ctx)) as tc:
        yield tc
    ctx.ingest.content.wait(30)


def _wait_job(api, job_id, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        j = api.get(f"{API}/ingest/updates/jobs/{job_id}").json()
        if j["state"] not in ("queued", "running"):
            return j
        time.sleep(0.1)
    raise AssertionError("pull job did not finish")


def test_updates_before_any_check(api):
    r = api.get(f"{API}/ingest/updates")
    assert r.status_code == 200
    body = r.json()
    assert body["checked_at"] is None
    assert {r["filename"] for r in body["updates"]} == {STIG, SCAP}
    assert body["index_estimate"]["seconds"] > 0 and body["connected"] is True


def test_check_pull_job_content(api, ctx):
    r = api.post(f"{API}/ingest/updates/check", json={}, headers=ACTOR)
    assert r.status_code == 200, r.text
    assert {u["filename"] for u in r.json()["updates"]} == {STIG, SCAP}
    assert api.get(f"{API}/ingest/updates").json()["new_count"] == 2

    r = api.post(f"{API}/ingest/updates/pull", json={"all_matching": True}, headers=ACTOR)
    assert r.status_code == 202, r.text
    job = _wait_job(api, r.json()["id"])
    assert job["state"] == "done" and job["deltas"] and job["deltas"][0]["counts"]["added"] > 0

    # the delta is listed like a hand import, so the existing rescan route and button apply to it
    delta_id = job["deltas"][0]["id"]
    hist = api.get(f"{API}/ingest/history").json()["deltas"]
    assert hist[0]["id"] == delta_id and hist[0]["filename"] == STIG

    content = api.get(f"{API}/ingest/content").json()
    assert {f["filename"] for f in content["files"]} == {STIG, SCAP}
    assert content["scap"][0]["datastream_path"].endswith(".xml")
    rec = [x for x in ctx.audit.records() if x["action"] == "content.fetch"][-1]
    assert rec["actor"] == ACTOR["X-Actor"]


def test_pull_needs_a_choice_and_unknown_job_is_404(api):
    r = api.post(f"{API}/ingest/updates/pull", json={}, headers=ACTOR)
    assert r.status_code == 400
    assert api.get(f"{API}/ingest/updates/jobs/pull-nope").status_code == 404


def test_disconnected_check_is_409_with_the_manifest_path(api, ctx):
    api.put(f"{API}/ingest/link", json={"connected": False}, headers=ACTOR)
    r = api.post(f"{API}/ingest/updates/check", json={"source": "live"}, headers=ACTOR)
    assert r.status_code == 409 and "manifest" in r.json()["detail"]
    assert api.post(f"{API}/ingest/updates/pull", json={"all_matching": True}, headers=ACTOR).status_code == 409
    snap = api.post(f"{API}/ingest/updates/check", json={"source": "snapshot"}, headers=ACTOR)
    assert snap.status_code == 200 and snap.json()["index_entries"] == 417
    assert api.post(f"{API}/ingest/updates/check", json={"source": "carrier pigeon"}, headers=ACTOR).status_code == 400


def test_manifest_and_import_dir(api, ctx, server, tmp_path):
    api.post(f"{API}/ingest/updates/check", json={}, headers=ACTOR)
    m = api.post(f"{API}/ingest/manifest", headers=ACTOR)
    assert m.status_code == 200, m.text
    man = m.json()
    assert {i["filename"] for i in man["items"]} == {STIG, SCAP} and man["path"].endswith("manifest.json")

    from cyberthunder.ingest.content.service import fetch_manifest
    media = tmp_path / "usb"
    fetch_manifest(man["path"], media, loopback_client())
    r = api.post(f"{API}/ingest/import-dir", json={"path": str(media)}, headers=ACTOR)
    assert r.status_code == 200, r.text
    assert len(r.json()["imported"]) == 2 and r.json()["verified_by"] == "manifest.lock.json"
    assert api.post(f"{API}/ingest/import-dir", json={"path": str(tmp_path / "nope")}, headers=ACTOR).status_code == 400
    assert json.loads((media / "manifest.lock.json").read_text(encoding="utf-8"))["failed"] == []


@pytest.mark.parametrize("method,path", [("POST", "/ingest/updates/check"), ("POST", "/ingest/updates/pull"),
                                         ("POST", "/ingest/manifest"), ("POST", "/ingest/import-dir")])
def test_mutating_content_routes_need_a_named_person(api, method, path):
    r = api.request(method, f"{API}{path}", json={}, headers={"X-Actor": "agent"})
    assert r.status_code == 400
