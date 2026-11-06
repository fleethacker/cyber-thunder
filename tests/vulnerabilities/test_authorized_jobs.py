"""Node job authorization survives worker boundaries and stops before publication."""
from __future__ import annotations

import threading
from unittest.mock import Mock

import pytest

from cyberthunder.control.principal import current_principal, principal_scope
from cyberthunder.vulnerabilities import service as module
from cyberthunder.vulnerabilities.errors import VulnerabilityUnavailable
from cyberthunder.vulnerabilities.storage import Lease
from tests.security.job_helpers import enable_auth, revoke


def test_update_worker_carries_identity_and_session_validity(svc, fake_download, monkeypatch):
    p = enable_auth(svc.ctx, node=["admin"])
    seen, validity_threads = [], []
    original = module.engine.run

    def download(*args, **kwargs):
        seen.append(current_principal())
        return original(*args, **kwargs)

    monkeypatch.setattr(module.engine, "run", download)
    with principal_scope(p, validity=lambda: validity_threads.append(threading.current_thread().name)):
        job = svc.update(actor=p.actor)
    svc.wait(5)
    assert svc.job(job["id"])["state"] == "completed"
    assert seen == [p, p] and "vulnerability-update" in validity_threads
    finished = [r for r in svc.ctx.audit.records() if r["action"] == "vulnerabilities.update_finished"][-1]
    assert finished["principal"]["sub"] == p.subject
    assert current_principal() is None


@pytest.mark.parametrize("revocation", ["policy", "session", "expiry"])
def test_queued_revocation_is_terminal_without_downloader(svc, fake_download, monkeypatch, revocation):
    p = enable_auth(svc.ctx, node=["admin"])
    ready, release = threading.Event(), threading.Event()
    invalid = [False]
    original = svc._run_update

    def delayed(*args):
        ready.set()
        assert release.wait(3)
        return original(*args)

    def validity():
        if invalid[0]:
            raise PermissionError("fixture session revoked")

    monkeypatch.setattr(svc, "_run_update", delayed)
    with principal_scope(p, validity=validity):
        job = svc.update(actor=p.actor)
    assert ready.wait(3)
    try:
        if revocation == "policy":
            revoke(svc.ctx)
        elif revocation == "session":
            invalid[0] = True
        else:
            monkeypatch.setattr("cyberthunder.control.principal.time.time", lambda: p.expires_at + 1)
    finally:
        release.set()
    svc.wait(5)
    record = svc.job(job["id"])
    assert record["state"] == "stopped" and record["finished_at"]
    assert fake_download == [] and not svc._state().get("selected")
    assert not list(svc.staging.iterdir())
    with Lease(svc.root / "operation.lock"):
        pass


@pytest.mark.parametrize("phase", ["construction", "start"])
def test_thread_failure_does_not_leave_pending_job(svc, monkeypatch, phase):
    p = enable_auth(svc.ctx, node=["admin"])
    if phase == "construction":
        monkeypatch.setattr(module.threading, "Thread", Mock(side_effect=RuntimeError("fixture start failure")))
    else:
        monkeypatch.setattr(module.threading.Thread, "start", Mock(side_effect=RuntimeError("fixture start failure")))
    with principal_scope(p), pytest.raises(VulnerabilityUnavailable):
        svc.update(actor=p.actor)
    assert [j["state"] for j in svc.jobs()] == ["failed"]
    svc.wait(1)
    with Lease(svc.root / "operation.lock"):
        pass


def test_revocation_at_generation_publication_preserves_selected_database(svc, offline_bundle, fake_download, monkeypatch):
    previous = svc.import_bundle(offline_bundle, actor="fixture operator")["generation"]
    p = enable_auth(svc.ctx, node=["admin"])
    original = svc._audit

    def audit(action, *args, **kwargs):
        original(action, *args, **kwargs)
        if action == "publish":
            revoke(svc.ctx)

    monkeypatch.setattr(svc, "_audit", audit)
    with principal_scope(p):
        job = svc.update(actor=p.actor, background=False)
    assert job["state"] == "stopped"
    assert svc._state()["selected"]["generation"] == previous
    assert not list(svc.staging.iterdir())


def test_import_permission_does_not_require_or_confer_admin(svc, offline_bundle):
    p = enable_auth(svc.ctx, node=["import"])
    with principal_scope(p):
        assert svc.import_bundle(offline_bundle, actor=p.actor)["state"] == "ready"
        with pytest.raises(PermissionError):
            svc.update(actor=p.actor)
        with pytest.raises(PermissionError):
            svc.save_settings({"expected_revision": 0}, actor=p.actor)
        with pytest.raises(PermissionError):
            svc.export_lease(actor=p.actor)


def test_export_only_and_scan_read_do_not_require_admin_or_import(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="fixture operator")
    p = enable_auth(svc.ctx, node=["export"])
    with principal_scope(p):
        with svc.export_lease(actor=p.actor) as path:
            assert path.is_file()
        with pytest.raises(PermissionError):
            svc.import_bundle(offline_bundle, actor=p.actor)
    p = enable_auth(svc.ctx)
    with principal_scope(p), svc.scan_context() as snapshot:
        assert snapshot["integrity_verified"]


def test_import_revocation_after_unpack_preserves_permission_error_and_cleans_staging(svc, offline_bundle, monkeypatch):
    p = enable_auth(svc.ctx, node=["import"])
    original = module.import_zip

    def unpack(*args, **kwargs):
        original(*args, **kwargs)
        revoke(svc.ctx)

    monkeypatch.setattr(module, "import_zip", unpack)
    with principal_scope(p), pytest.raises(PermissionError):
        svc.import_bundle(offline_bundle, actor=p.actor)
    assert not svc._state().get("selected") and not list(svc.staging.iterdir())


def test_export_rechecks_before_releasing_bundle(svc, offline_bundle, monkeypatch):
    svc.import_bundle(offline_bundle, actor="fixture operator")
    p = enable_auth(svc.ctx, node=["export"])
    original = svc._audit

    def audit(action, *args, **kwargs):
        original(action, *args, **kwargs)
        if action == "export":
            revoke(svc.ctx)

    monkeypatch.setattr(svc, "_audit", audit)
    with principal_scope(p), pytest.raises(PermissionError):
        svc.export_lease(actor=p.actor)
    assert not list(svc.exports.glob("*.zip")) and not list(svc.exports.glob("*.partial"))
