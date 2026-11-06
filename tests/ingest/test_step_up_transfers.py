"""Real loopback HTTPS pulls retain their decision while all live guards still apply."""
from dataclasses import replace
import json
import time
from unittest.mock import Mock

import pytest

from cyberthunder.control.principal import principal_scope
from cyberthunder.ingest.content import fetch as fx, signatures as sig
from cyberthunder.ingest.content import service as content_service
from cyberthunder.security.step_up import StepUpRequired
from tests.ingest.test_content_live_authenticity import https_source, prepare
from tests.ingest.test_content_signatures import verified, signing, key_directory
from tests.security.test_sessions import advance


@pytest.mark.parametrize("kind", ["manual_stig", "scap_benchmark"])
@pytest.mark.parametrize("background", [False, True])
def test_admitted_pull_publishes_after_five_minutes_without_renewing_authentication(verified, https_source, tmp_path, monkeypatch, kind, background):
    ctx, human = verified
    human = replace(human, expires_at=time.time() + 1800)
    prepare(ctx, https_source, tmp_path, monkeypatch, kind)
    original = fx.download
    def delayed(*args, **kwargs):
        advance(monkeypatch, 301)
        return original(*args, **kwargs)
    monkeypatch.setattr(fx, "download", delayed)
    with principal_scope(human):
        job = ctx.ingest.content.pull(human.actor, all_matching=True, background=background)
    ctx.ingest.content.wait(10)
    saved = ctx.ingest.content.get_job(job["id"])
    assert saved["state"] == "done", saved
    assert ctx.ingest.content.store.records()[0]["authenticity"]["status"] == "trusted_https_source"
    assert any(method == "GET" for method, *_ in https_source.requests)
    with principal_scope(human), pytest.raises(StepUpRequired):
        ctx.authorize("admin", actor=human.actor)
    with principal_scope(human), pytest.raises(StepUpRequired):
        sig.decide(ctx, {"status": "unsigned"}, human.actor, "new override decision")
    assert ctx.ingest.content._running is None


@pytest.mark.parametrize("revocation", ["policy", "session", "expiry", "assurance", "intent", "kill"])
def test_pull_revocation_before_network_is_terminal_and_publishes_nothing(verified, https_source, tmp_path, monkeypatch, revocation):
    ctx, human = verified
    human = replace(human, expires_at=time.time() + 1800)
    item = prepare(ctx, https_source, tmp_path, monkeypatch)
    invalid = [False]
    def validity():
        if invalid[0]: raise PermissionError("fixture session revoked")
    original = fx.download
    def revoke(*args, **kwargs):
        advance(monkeypatch, 301)
        if revocation == "policy": ctx.access.path.write_text(ctx.access.path.read_text() + "\n")
        elif revocation == "session": invalid[0] = True
        elif revocation == "expiry": advance(monkeypatch, 1800)
        elif revocation == "assurance": ctx.settings.step_up_max_age_s = 302
        elif revocation == "intent": item["title"] = "different transfer declaration"
        else: ctx.killswitch.engage(reason="fixture safety stop", actor=human.actor)
        return original(*args, **kwargs)
    monkeypatch.setattr(fx, "download", revoke)
    with principal_scope(human, validity=validity):
        job = ctx.ingest.content.pull(human.actor, all_matching=True, background=False)
    assert job["state"] in {"stopped", "failed"}, job
    assert job["finished_at"] and not any(f["state"] == "pending" for f in job["files"])
    assert ctx.ingest.content.store.records() == [] and https_source.requests == []
    assert ctx.ingest.content._running is None


def test_content_worker_start_failure_is_terminal(verified, https_source, tmp_path, monkeypatch):
    ctx, human = verified
    prepare(ctx, https_source, tmp_path, monkeypatch)
    saved = []
    original = ctx.ingest.content.store.save_job
    def save(job):
        saved.append(json.loads(json.dumps(job)))
        return original(job)
    monkeypatch.setattr(ctx.ingest.content.store, "save_job", save)
    monkeypatch.setattr("cyberthunder.ingest.content.service.threading.Thread", Mock(side_effect=RuntimeError("fixture")))
    with principal_scope(human), pytest.raises(Exception, match="content worker could not start"):
        ctx.ingest.content.pull(human.actor, all_matching=True)
    assert saved[-1]["state"] == "failed" and saved[-1]["finished_at"]
    assert all(f["state"] == "failed" for f in saved[-1]["files"])
    assert ctx.ingest.content._running is None and https_source.requests == []


@pytest.mark.parametrize("revocation", ["policy", "session"])
def test_authorization_revoked_after_download_prevents_publication(verified, https_source, tmp_path, monkeypatch, revocation):
    ctx, human = verified
    human = replace(human, expires_at=time.time() + 1800)
    prepare(ctx, https_source, tmp_path, monkeypatch)
    invalid = [False]
    def validity():
        if invalid[0]:
            raise PermissionError("fixture session revoked")
    original = fx.download
    def downloaded(*args, **kwargs):
        result = original(*args, **kwargs)
        advance(monkeypatch, 301)
        if revocation == "policy":
            ctx.access.path.write_text(ctx.access.path.read_text() + "\n")
        else:
            invalid[0] = True
        return result
    monkeypatch.setattr(fx, "download", downloaded)
    with principal_scope(human, validity=validity):
        job = ctx.ingest.content.pull(human.actor, all_matching=True, background=False)
    assert any(method == "GET" for method, *_ in https_source.requests)
    assert job["state"] == "failed" and job["finished_at"]
    assert all(f["state"] == "failed" for f in job["files"])
    assert ctx.ingest.content.store.records() == [] and ctx.ingest.content._running is None


@pytest.mark.parametrize("phase", ["initial", "terminal"])
def test_job_persistence_failure_closes_admission_and_cleans_worker_state(verified, https_source, tmp_path, monkeypatch, phase):
    ctx, human = verified
    prepare(ctx, https_source, tmp_path, monkeypatch)
    service = ctx.ingest.content
    admitted = []
    original_admit = content_service.admit_transfer
    def admit(*args, **kwargs):
        receipt = original_admit(*args, **kwargs)
        admitted.append(receipt)
        return receipt
    monkeypatch.setattr(content_service, "admit_transfer", admit)
    original_save = service.store.save_job
    def save(job):
        if phase == "initial" or job["finished_at"] is not None:
            raise OSError("fixture persistence unavailable")
        return original_save(job)
    monkeypatch.setattr(service.store, "save_job", save)
    with principal_scope(human), pytest.raises(OSError, match="fixture persistence unavailable"):
        service.pull(human.actor, all_matching=True, background=False)
    assert len(admitted) == 1 and admitted[0].closed.is_set()
    assert service._running is None and not list((service.store.root / "incoming").glob("live-*"))
    if phase == "initial":
        assert https_source.requests == [] and service.store.records() == []
    else:
        assert service.store.records()[0]["authenticity"]["status"] == "trusted_https_source"
