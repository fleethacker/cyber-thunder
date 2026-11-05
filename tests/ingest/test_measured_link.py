"""CON-04: offline tests of controls, bounded observations and disposable probes."""
import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.ingest.link import Link, LinkState, OBSERVATION_LIMIT, transfer_seconds
from cyberthunder.ingest.content.http import ContentClient, ContentNetworkError
from cyberthunder.ingest.content import fetch
from cyberthunder.ingest import probe

ACTOR = "IT2 Smith"
URL = "https://www.cyber.mil/"


@pytest.fixture(autouse=True)
def no_live_http(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("live HTTP is forbidden in CON-04 validation")
    monkeypatch.setattr("urllib.request.OpenerDirector.open", refuse)


def test_defaults_legacy_numbers_and_offline_migration(ctx):
    link = ctx.ingest.link
    assert link.connected and link.state().reachability == "unknown"
    assert link.state().kbps is None and link.state().latency_ms is None
    assert transfer_seconds(100, link.state()) is None
    assert not link.state().probe_enabled
    ctx.store.write_json(ctx.store.link_state, {"kbps": 9.6, "latency_ms": 600, "connected": True})
    assert link.state().mode == "production" and link.state().kbps is None
    ctx.store.write_json(ctx.store.link_state, {"kbps": 56, "latency_ms": 500, "connected": False})
    assert not link.connected and link.state().offline_override
    state = link.set(actor=ACTOR, connected=True)
    assert state.connected and state.reachability == "unknown" and state.kbps is None
    ctx.settings.link_connected = False
    assert not link.set(actor=ACTOR, offline_override=False).connected


def test_test_mode_is_explicit_audited_and_keeps_operator_offline(ctx):
    link = ctx.ingest.link
    with pytest.raises(ValueError, match="audit log"):
        Link(ctx.store, ctx.settings).set(actor=ACTOR, mode="test")
    with pytest.raises(ValueError, match="test mode"):
        link.set(actor=ACTOR, kbps=56)
    for rate in (float("nan"), float("inf"), 0, -1):
        with pytest.raises(ValueError):
            link.set(actor=ACTOR, mode="test", kbps=rate)
    link.set(actor=ACTOR, offline_override=True)
    state = link.set(actor=ACTOR, mode="test", kbps=8, latency_ms=500, connected=True)
    assert not state.connected and state.offline_override
    assert transfer_seconds(1000, state) == 1.5
    state = link.set(actor=ACTOR, mode="production", offline_override=False)
    assert state.connected and state.kbps is None and state.latency_ms is None
    records = [row for row in ctx.audit.records() if row["action"] == "link.change"]
    assert records[-2]["details"]["controls"]["mode"] == "test"
    assert records[-2]["actor"] == ACTOR
    assert Link(ctx.store, ctx.settings).state().mode == "production"


def test_bounded_timestamped_observations_and_stale_unknown(ctx, monkeypatch):
    link = ctx.ingest.link
    for i in range(OBSERVATION_LIMIT + 2):
        item = link.observe(endpoint=URL + "?secret=discard", method="GET",
                           application_bytes=1000 + i, elapsed_seconds=2, success=True, status=200)
    state = link.state()
    assert len(state.observations) == OBSERVATION_LIMIT
    assert state.last_observation["endpoint"] == URL
    assert state.last_observation["at"] and state.kbps is None
    assert state.observed_kbps == pytest.approx((1000 + OBSERVATION_LIMIT + 1) * 8 / 2000)
    assert state.reachability == "reachable"
    monkeypatch.setattr("cyberthunder.ingest.link._now", lambda: 10**12)
    assert link.state().reachability == "unknown" and link.connected
    assert link.state().observed_kbps is None


def test_failure_and_test_observations_do_not_invent_production_rates(ctx):
    link = ctx.ingest.link
    link.observe(endpoint=URL, method="GET", application_bytes=80, elapsed_seconds=2,
                 success=False, error="TimeoutError")
    assert not link.connected and link.state().observed_kbps is None
    link.set(actor=ACTOR, mode="test")
    link.observe(endpoint=URL, method="GET", application_bytes=9999, elapsed_seconds=1, success=True, status=200)
    link.set(actor=ACTOR, mode="production")
    assert link.state().observed_kbps is None
    assert link.state().last_observation["success"] is False


class Response(io.BytesIO):
    status = 200
    url = URL
    headers = {}
    def geturl(self):
        return self.url


def client_for(ctx, payload=b"abcd", status=200):
    response = Response(payload)
    response.status = status
    client = ContentClient(opener=SimpleNamespace(open=lambda *a, **k: response))
    ctx.ingest.content.client = client
    return ctx.ingest.content.client, response


def test_real_content_client_records_body_and_head_without_claiming_rtt(ctx, monkeypatch):
    from itertools import count
    ticks = count(10.0, 0.01)
    monkeypatch.setattr("cyberthunder.ingest.content.http.time.monotonic", lambda: next(ticks))
    client, _ = client_for(ctx)
    client.request("GET", URL + "?token=redacted", max_bytes=4)
    item = ctx.ingest.link.state().last_observation
    assert item["application_bytes"] == 4 and item["success"]
    assert "token" not in json.dumps(item)
    assert item["observed_kbps"] > 0 and ctx.ingest.link.state().latency_ms is None
    client, _ = client_for(ctx)
    client.request("HEAD", URL, max_bytes=0)
    item = ctx.ingest.link.state().last_observation
    assert item["application_bytes"] == 0 and item["observed_kbps"] is None


def test_request_caps_and_failed_partial_read_are_not_success(ctx):
    client, _ = client_for(ctx, b"abcdef")
    with pytest.raises(ContentNetworkError):
        client.request("GET", URL, max_bytes=3)
    item = ctx.ingest.link.state().last_observation
    assert not item["success"] and item["application_bytes"] == 4 and item["observed_kbps"] is None
    client, response = client_for(ctx)
    def broken(size):
        import http.client
        raise http.client.IncompleteRead(b"ab", 2)
    response.read = broken
    with pytest.raises(Exception):
        client.request("GET", URL)
    item = ctx.ingest.link.state().last_observation
    assert not item["success"] and item["application_bytes"] == 2


def test_offline_and_kill_block_network_controls_and_local_sync(ctx):
    client, response = client_for(ctx)
    ctx.ingest.set_link(actor=ACTOR, offline_override=True)
    with pytest.raises(Exception):
        client.request("GET", URL)
    assert response.tell() == 0
    ctx.killswitch.engage(ACTOR)
    with pytest.raises(KillSwitchEngaged):
        ctx.ingest.set_link(actor=ACTOR, mode="test")
    with pytest.raises(KillSwitchEngaged):
        ctx.ingest.link.probe(actor=ACTOR)
    with pytest.raises(KillSwitchEngaged):
        ctx.ingest.outbox.sync(force=True, actor=ACTOR)


def test_local_outbox_and_snapshot_are_not_network_measurements(ctx):
    ctx.ingest.outbox.enqueue("report", "report.txt", b"sample", actor=ACTOR)
    result = ctx.ingest.outbox.sync(actor=ACTOR)
    assert result["transfer_kind"] == "local_move" and result["test_estimate_seconds"] is None
    entry = ctx.ingest.outbox.list()["synced"][0]
    assert entry["transfer_seconds"] is None and entry["transfer_kind"] == "local_move"
    ctx.ingest.check_updates(ACTOR, source="snapshot")
    assert ctx.ingest.link.state().observations == []


def test_production_pacing_fails_before_any_request(ctx, tmp_path):
    with pytest.raises(ValueError, match="test mode"):
        ctx.ingest.pull(actor=ACTOR, pace=True, background=False)
    with pytest.raises(fetch.ContentError, match="test mode"):
        fetch.download(None, {}, tmp_path, link=LinkState(kbps=56), pace=True)


def test_probe_session_is_explicit_bounded_and_recovers(ctx, monkeypatch):
    link = ctx.ingest.link
    calls = []
    def fake(endpoint, guard):
        guard()
        calls.append(endpoint)
        return {"success": len(calls) > 1, "status": 200 if len(calls) > 1 else None,
                "elapsed_seconds": 0.2}
    monkeypatch.setattr(probe, "bounded_probe", fake)
    assert link.probe(actor=ACTOR, background=True) is None and calls == []
    link.set(actor=ACTOR, probe_enabled=True)
    link.probe(actor=ACTOR, background=True)
    assert not link.connected and link.state().observed_kbps is None
    assert link.probe(actor=ACTOR, background=True) is None
    link.probe(actor=ACTOR)
    assert link.connected
    monkeypatch.setattr("cyberthunder.ingest.link._now", lambda: 10**12)
    assert not link.state().probe_enabled
    assert link.probe(actor=ACTOR, background=True) is None
    assert len(calls) == 2


def test_probe_policy_no_redirects_and_zero_body(monkeypatch):
    with pytest.raises(ValueError):
        probe.bounded_probe("https://example.org/", guard=lambda: None)
    with pytest.raises(ValueError, match="redirect"):
        probe.NoRedirects().redirect_request(None, None, 302, "", {}, "https://example.org/")
    response = Response(b"")
    response.headers = {}
    monkeypatch.setattr(probe.urllib.request, "build_opener",
                        lambda *a: SimpleNamespace(open=lambda *a, **k: response))
    assert probe.request_probe(URL)["success"]
    response = Response(b"x")
    assert not probe.request_probe(URL)["success"]


def test_parent_probe_deadline_and_kill_cancel_child(monkeypatch):
    clock = [0.0]
    class Process:
        returncode = None
        killed = False
        def communicate(self, timeout):
            if self.killed:
                return b"", None
            clock[0] += timeout
            raise subprocess.TimeoutExpired("fixture", timeout)
        def poll(self):
            return 0 if self.killed else None
        def kill(self):
            self.killed = True
    child = Process()
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: child)
    result = probe.bounded_probe(URL, guard=lambda: None)
    assert result["error"] == "deadline" and child.killed
    assert clock[0] <= 5.001
    clock[0] = 0
    child = Process()
    def killed():
        if clock[0] >= 0.2:
            raise KillSwitchEngaged("fixture")
    with pytest.raises(KillSwitchEngaged):
        probe.bounded_probe(URL, guard=killed)
    assert child.killed


def test_link_api_validation_and_kill(ctx, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from cyberthunder.api.routes.ingest import router
    from cyberthunder.api.util import get_ctx
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_ctx] = lambda: ctx
    client = TestClient(app)
    headers = {"X-Actor": ACTOR}
    assert client.get("/ingest/link").json()["reachability"] == "unknown"
    assert client.put("/ingest/link", json={"kbps": 56}, headers=headers).status_code == 400
    result = client.put("/ingest/link", json={"mode": "test", "kbps": 8}, headers=headers)
    assert result.status_code == 200 and result.json()["mode"] == "test"
    assert client.put("/ingest/link", json={"probe_endpoint": "http://127.0.0.1"}, headers=headers).status_code == 400
    ctx.killswitch.engage(ACTOR)
    assert client.put("/ingest/link", json={"offline_override": False}, headers=headers).status_code in (409, 423)


def test_probe_releases_sqlite_lock_and_offline_cancels(ctx, monkeypatch):
    import threading
    link = ctx.ingest.link
    failures = []
    def fake(endpoint, guard):
        def disable():
            try:
                link.set(actor=ACTOR, offline_override=True)
            except Exception as exc:
                failures.append(exc)
        worker = threading.Thread(target=disable)
        worker.start()
        worker.join(timeout=2)
        assert not worker.is_alive(), "probe held the SQLite write lock during network I/O"
        assert not failures
        guard()
        raise AssertionError("offline cancellation did not stop the probe")
    monkeypatch.setattr(probe, "bounded_probe", fake)
    with pytest.raises(ValueError, match="stopped"):
        link.probe(actor=ACTOR)
    assert link.state().offline_override


def test_runtime_does_not_probe_without_explicit_session(ctx, monkeypatch):
    from cyberthunder.runtime import RuntimeTasks
    calls = []
    monkeypatch.setattr(ctx.ingest.link, "probe", lambda **kwargs: calls.append(kwargs))
    runtime = RuntimeTasks(ctx)
    runtime._probe_link()
    assert calls == []
    ctx.ingest.set_link(actor=ACTOR, probe_enabled=True)
    runtime._probe_link()
    assert calls == [{"actor": ctx.settings.scheduler_actor, "background": True}]
    ctx.killswitch.engage(ACTOR)
    runtime._probe_link()
    assert len(calls) == 1
