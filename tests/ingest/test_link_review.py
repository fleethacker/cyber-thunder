"""Mocked regressions from the bounded measured-link review."""
import io
import json
import urllib.request
from types import SimpleNamespace

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.ingest.content.http import ContentClient, _AllowListRedirects
from cyberthunder.ingest.link import Link
from cyberthunder.ingest.outbox import LinkDisconnected

ACTOR = "IT2 Smith"
URL = "https://www.cyber.mil/"


@pytest.fixture(autouse=True)
def no_live_requests(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("review tests must not make network requests")
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse)


@pytest.mark.parametrize("control", ["offline", "kill", "test_disconnect"])
def test_redirect_rechecks_control_before_another_network_request(ctx, control):
    client = ctx.ingest.content.client
    client.before_request()  # original request was permitted
    if control == "offline":
        ctx.ingest.link.set(actor=ACTOR, offline_override=True)
    elif control == "test_disconnect":
        ctx.ingest.link.set(actor=ACTOR, mode="test", connected=False)
    else:
        ctx.killswitch.engage(ACTOR)
    handler = _AllowListRedirects(client)
    with pytest.raises((LinkDisconnected, KillSwitchEngaged)):
        handler.redirect_request(urllib.request.Request(URL), None, 302, "Found", {},
                                 "https://dl.dod.cyber.mil/")


def test_observations_and_probe_reservations_use_selected_document_backend(ctx, monkeypatch):
    from cyberthunder.ingest import probe
    link = ctx.ingest.link
    link.set(actor=ACTOR, mode="test", kbps=8, latency_ms=15)
    monkeypatch.setattr(probe, "bounded_probe", lambda endpoint, guard:
                        {"success": True, "status": 200, "elapsed_seconds": 0.1})
    link.probe(actor=ACTOR)
    assert ctx.store.docs.get("link-observations.json") is not None
    assert ctx.store.docs.get("link-probe-schedule.json") is not None
    restored = Link(ctx.store, ctx.settings, ctx.audit).state()
    assert restored.mode == "test" and restored.kbps == 8 and restored.latency_ms == 15
    assert restored.last_observation["test_mode"] is True
    link.set(actor=ACTOR, mode="production")
    assert link.state().last_observation is None
    assert ctx.audit.verify().ok


def test_status_while_measurement_writer_is_active_is_read_only(ctx, monkeypatch):
    import threading
    link = ctx.ingest.link
    started, release = threading.Event(), threading.Event()
    errors = []

    def writer():
        try:
            link.observe(endpoint=URL, method="GET", application_bytes=4,
                         elapsed_seconds=0.2, success=True, status=200)
            with ctx.store.lock("link"):
                started.set()
                assert release.wait(timeout=2)
        except Exception as exc:
            errors.append(exc)
            started.set()

    worker = threading.Thread(target=writer)
    worker.start()
    assert started.wait(timeout=2)
    def forbidden(*args, **kwargs):
        raise AssertionError("state read cannot write or audit")
    monkeypatch.setattr(ctx.store, "write_json", forbidden)
    monkeypatch.setattr(ctx.audit, "append", forbidden)
    try:
        state = link.state()
        assert state.reachability in {"reachable", "unknown"}
    finally:
        release.set()
        worker.join(timeout=2)
    assert not worker.is_alive() and not errors


def test_http_range_observation_counts_only_new_body_bytes_and_full_request_time(ctx, monkeypatch):
    from cyberthunder.ingest.content import http
    ticks = [20.0]
    class Response(io.BytesIO):
        status = 206
        url = URL + "?token=discarded#private"
        headers = {"Content-Length": "3", "Content-Range": "bytes 7-9/10"}
        def read(self, size=-1):
            ticks[0] += 0.25
            return super().read(size)
    response = Response(b"new")
    def open_response(*args, **kwargs):
        ticks[0] += 0.5  # connection/header time
        return response
    ctx.ingest.content.client = ContentClient(opener=SimpleNamespace(open=open_response))
    monkeypatch.setattr(http.time, "monotonic", lambda: ticks[0])
    status, _, body = ctx.ingest.content.client.request("GET", URL, headers={"Range": "bytes=7-"})
    observation = ctx.ingest.link.state().last_observation
    assert status == 206 and body == b"new"
    assert observation["application_bytes"] == 3 and observation["elapsed_seconds"] == 0.75
    assert observation["observed_kbps"] == 0.032 and observation["success"]
    assert "discarded" not in json.dumps(observation) and "private" not in json.dumps(observation)
