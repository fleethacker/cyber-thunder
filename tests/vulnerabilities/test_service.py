from __future__ import annotations

import json
import subprocess
import sys
import threading
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.ingest.link import Link
from cyberthunder.vulnerabilities import engine
from cyberthunder.vulnerabilities.errors import VulnerabilityConflict, VulnerabilityError, VulnerabilityUnavailable
from cyberthunder.vulnerabilities.service import MAX_GENERATIONS, VulnerabilityService
from cyberthunder.vulnerabilities.storage import Lease
from .conftest import bundle, payloads


def test_status_and_default_schedule_are_passive(svc, monkeypatch):
    monkeypatch.setattr(engine, "run", lambda *a, **k: pytest.fail("Unexpected execution"))
    first = svc.status()
    assert first["state"] == "missing"
    assert first["generation"] is None and not first["integrity_verified"]
    assert first["settings"] == {"revision": 0, "auto_update": False, "interval_hours": 24, "include_java": True}
    assert svc.status() == first and svc.jobs() == []
    assert svc.due_update() is False and svc.update_scheduled() is None
    assert not svc.state_path.exists()
    assert not list(svc.generations.iterdir())
    json.dumps(first)
    with pytest.raises(VulnerabilityUnavailable):
        with svc.scan_context():
            pytest.fail("Missing data allowed scan")


def test_settings_revision_persistence_and_backend_routing(svc):
    saved = svc.save_settings({"expected_revision": 0, "auto_update": True, "interval_hours": 4}, actor="joshua")
    assert saved["revision"] == 1
    with pytest.raises(VulnerabilityConflict):
        svc.save_settings({"expected_revision": 0, "auto_update": False}, actor="joshua")
    again = VulnerabilityService(svc.ctx)
    assert again.settings() == saved
    if svc.store.backend_name == "sqlite":
        assert not svc.settings_path.exists()
        assert svc.store.docs.get("vulnerabilities/settings.json") == saved
    assert list(svc.ctx.audit.records())[-1]["actor"] == "joshua"


@pytest.mark.parametrize("changes", [{}, {"expected_revision": True}, {"expected_revision": 0, "x": 1},
    {"expected_revision": 0, "auto_update": "true"}, {"expected_revision": 0, "interval_hours": True},
    {"expected_revision": 0, "interval_hours": 0}, {"expected_revision": 0, "interval_hours": 169},
    {"expected_revision": 0, "include_java": None}])
def test_settings_reject_invalid_types(svc, changes):
    with pytest.raises(VulnerabilityError):
        svc.save_settings(changes, actor="joshua")
    assert svc.settings()["revision"] == 0


@pytest.mark.parametrize("actor", ["", "system", "policy:test", "agent:worker", "bad\nactor"])
def test_explicit_writes_need_named_human(svc, offline_bundle, actor):
    with pytest.raises(PermissionError):
        svc.update(actor=actor, background=False)
    with pytest.raises(PermissionError):
        svc.import_bundle(offline_bundle, actor=actor)
    with pytest.raises(PermissionError):
        svc.export_bundle(actor=actor)
    with pytest.raises(PermissionError):
        svc.save_settings({"expected_revision": 0}, actor=actor)


def test_import_export_roundtrip_and_import_never_trusts_origin(svc, offline_bundle):
    status = svc.import_bundle(offline_bundle, actor="joshua")
    assert status["state"] == "ready" and status["integrity_verified"]
    assert status["provenance"] == "offline_import" and status["imported_at"]
    assert status["source"] == "offline_bundle"
    assert any("authenticity" in w for w in status["warnings"])
    assert [d["schema"] for d in status["databases"]] == [2, 1]
    exported = svc.export_bundle(actor="joshua")
    assert exported.parent == svc.exports
    second = svc.import_bundle(exported, actor="joshua")
    assert second["generation"] != status["generation"]
    assert second["databases"] == status["databases"]
    assert second["provenance"] == "offline_import"
    assert VulnerabilityService(svc.ctx).status() == second
    assert "cache_dir" not in json.dumps(status) and str(svc.root) not in json.dumps(status)
    if svc.store.backend_name == "sqlite":
        assert not svc.state_path.exists()
        assert svc.store.docs.get("vulnerabilities/state.json")["selected"]["generation"] == second["generation"]


@pytest.mark.parametrize("age,next_hours,max_age", [(24, 12, 72), (80, 100, 72)])
def test_staleness_and_optional_java_explicit_in_snapshot(svc, tmp_path, age, next_hours, max_age):
    svc.ctx.settings.vulnerability_db_max_age_hours = max_age
    status = svc.import_bundle(bundle(tmp_path / "stale.zip", payloads(java=False, age=age, next_hours=next_hours)),
                               actor="joshua")
    assert status["state"] == "stale"
    assert status["databases"][0]["stale"] and not status["databases"][1]["present"]
    with svc.scan_context() as snapshot:
        assert snapshot["state"] == "stale" and snapshot["cache_dir"].is_dir()
        assert snapshot["generation"] == status["generation"]
        snapshot["databases"][0]["schema"] = 999
    assert svc.status()["databases"][0]["schema"] == 2


def test_tampered_generation_refuses_status_scan_and_export(svc, offline_bundle):
    before = svc.import_bundle(offline_bundle, actor="joshua")
    path = svc.generations / before["generation"] / "db" / "trivy.db"
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] + b"X")
    assert svc.status()["state"] == "invalid"
    assert not svc.status()["integrity_verified"]
    with pytest.raises(VulnerabilityUnavailable):
        with svc.scan_context():
            pytest.fail("Tampered database accepted")
    with pytest.raises(VulnerabilityUnavailable):
        svc.export_bundle(actor="joshua")


def test_unsupported_engine_still_allows_offline_transfer(svc, offline_bundle, monkeypatch):
    monkeypatch.setattr(svc, "_engine", lambda **k: {"available": True, "version": "0.71.0",
                        "supported": False, "error": "Trivy 0.71.1 or newer is required"})
    status = svc.import_bundle(offline_bundle, actor="joshua")
    assert status["state"] == "unavailable" and status["integrity_verified"]
    assert svc.export_bundle(actor="joshua").is_file()
    with pytest.raises(VulnerabilityUnavailable):
        with svc.scan_context():
            pytest.fail("Unsupported engine accepted")
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "failed" and "0.71.1" in job["error"]
    assert svc.status()["generation"] == status["generation"]


def test_update_uses_official_separate_commands_and_persists_job(svc, fake_download):
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "completed", job
    assert job["generation"] and job["finished_at"] and job["error"] is None
    assert len(fake_download) == 2
    for argv in fake_download:
        assert argv[argv.index("--db-repository") + 1] == engine.MAIN_REPOSITORY
        assert argv[argv.index("--java-db-repository") + 1] == engine.JAVA_REPOSITORY
        assert "--skip-version-check" in argv and "--config" in argv
        assert ("--download-db-only" in argv) != ("--download-java-db-only" in argv)
    status = svc.status()
    assert status["provenance"] == "official_download" and status["active_job"] is None
    assert status["last_attempt"] == job["started_at"] and status["last_success"]
    assert svc.jobs() == [job] and VulnerabilityService(svc.ctx).job(job["id"]) == job
    assert not list(svc.staging.iterdir())
    if svc.store.backend_name == "sqlite":
        assert not svc._job_path(job["id"]).exists()
        assert svc.store.docs.get(f"vulnerabilities/jobs/{job['id']}.json") == job


def test_main_only_and_failure_keep_old_generation(svc, fake_download, monkeypatch):
    old = svc.update(actor="joshua", include_java=False, background=False)
    assert old["state"] == "completed"
    assert len(fake_download) == 1 and not svc.status()["databases"][1]["present"]
    def fail(*args, **kwargs):
        raise OSError("SECRET=C:/sensitive/token")
    monkeypatch.setattr(engine, "run", fail)
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "failed" and job["generation"] is None
    status = svc.status()
    assert status["generation"] == old["generation"]
    assert "SECRET" not in json.dumps(status) + json.dumps(svc.jobs())
    assert not list(svc.staging.iterdir())


@pytest.mark.parametrize("control", ["kill", "link", "size", "timeout"])
def test_update_controls_abort_and_preserve_selected(svc, offline_bundle, monkeypatch, control):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    monkeypatch.setattr(engine, "executable", lambda _: "fixture")
    def run(argv, *, home, timeout, guard):
        if control == "kill":
            svc.ctx.killswitch.engage("joshua")
        elif control == "link":
            Link(svc.store, svc.ctx.settings).set(actor="joshua", connected=False)
        elif control == "size":
            (home / "oversize").write_bytes(b"x" * (svc.max_unpacked_bytes + 300000))
        else:
            from cyberthunder.vulnerabilities.errors import UpdateStopped
            raise UpdateStopped("Trivy operation timed out")
        guard()
    monkeypatch.setattr(engine, "run", run)
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == ("failed" if control == "size" else "stopped")
    assert svc.status()["generation"] == old and job["error"]
    assert not list(svc.staging.iterdir())


def test_kill_blocks_writes_but_status_remains_readable(svc, offline_bundle):
    svc.ctx.killswitch.engage("joshua")
    with pytest.raises(KillSwitchEngaged):
        svc.import_bundle(offline_bundle, actor="joshua")
    with pytest.raises(KillSwitchEngaged):
        svc.export_bundle(actor="joshua")
    with pytest.raises(KillSwitchEngaged):
        svc.update(actor="joshua", background=False)
    with pytest.raises(KillSwitchEngaged):
        svc.save_settings({"expected_revision": 0}, actor="joshua")
    assert svc.status()["state"] == "missing"


def test_offline_import_and_export_do_not_require_link(svc, offline_bundle):
    Link(svc.store, svc.ctx.settings).set(actor="joshua", connected=False)
    assert svc.import_bundle(offline_bundle, actor="joshua")["state"] == "ready"
    assert svc.export_bundle(actor="joshua").exists()
    with pytest.raises(VulnerabilityUnavailable):
        svc.update(actor="joshua", background=False)


def test_retention_holds_snapshots_across_service_instances(svc, offline_bundle):
    first = svc.import_bundle(offline_bundle, actor="joshua")
    other = VulnerabilityService(svc.ctx)
    with svc.scan_context() as snapshot:
        for _ in range(MAX_GENERATIONS + 2):
            other.import_bundle(offline_bundle, actor="joshua")
        assert snapshot["cache_dir"].is_dir()
        assert snapshot["generation"] == first["generation"]
        assert len(list(svc.generations.iterdir())) <= MAX_GENERATIONS
    other.import_bundle(offline_bundle, actor="joshua")
    assert not snapshot["cache_dir"].exists()


def test_retention_refuses_when_every_generation_is_pinned(svc, offline_bundle):
    with ExitStack() as stack:
        for _ in range(MAX_GENERATIONS):
            svc.import_bundle(offline_bundle, actor="joshua")
            stack.enter_context(svc.scan_context())
        before = svc.status()["generation"]
        with pytest.raises(VulnerabilityConflict):
            svc.import_bundle(offline_bundle, actor="joshua")
        assert svc.status()["generation"] == before
    svc.import_bundle(offline_bundle, actor="joshua")


def test_job_conflict_and_background_completion(svc, fake_download, offline_bundle, monkeypatch):
    started, release = threading.Event(), threading.Event()
    original = engine.run
    def waiting(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(engine, "run", waiting)
    job = svc.update(actor="joshua", background=True)
    try:
        assert started.wait(3)
        other = VulnerabilityService(svc.ctx)
        assert other.job(job["id"])["state"] == "running"
        assert other.status()["active_job"]["id"] == job["id"]
        with pytest.raises(VulnerabilityConflict):
            other.update(actor="joshua", background=False)
        with pytest.raises(VulnerabilityConflict):
            other.import_bundle(offline_bundle, actor="joshua")
    finally:
        release.set()
        svc.wait(5)
    assert svc.job(job["id"])["state"] == "completed"


def test_recover_interrupted_job_and_staging(svc):
    job_id = uuid.uuid4().hex
    job = {"id": job_id, "kind": "update", "state": "running", "started_at": "2026-01-01T00:00:00+00:00",
           "finished_at": None, "actor": "joshua", "generation": None, "error": None}
    svc.store.write_json(svc._job_path(job_id), job)
    stage = svc.staging / job_id
    stage.mkdir()
    (stage / "partial").write_bytes(b"x")
    recovered = VulnerabilityService(svc.ctx)
    assert recovered.job(job_id)["state"] == "stopped"
    assert not stage.exists() and recovered.status()["last_error"]


def test_failed_pointer_publication_preserves_previous(svc, offline_bundle, monkeypatch):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    original = svc.store.write_json
    def fail(path, value):
        if path == svc.state_path and (value.get("selected") or {}).get("generation") != old:
            raise OSError("simulated pointer write failure")
        return original(path, value)
    monkeypatch.setattr(svc.store, "write_json", fail)
    with pytest.raises(VulnerabilityError):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert svc.status()["generation"] == old


def test_schedule_is_opt_in_throttled_and_uses_scheduler_actor(svc, fake_download):
    assert not svc.due_update()
    svc.save_settings({"expected_revision": 0, "auto_update": True, "include_java": False}, actor="joshua")
    assert svc.due_update()
    svc.ctx.settings.scheduler_actor = "system:scheduler"
    job = svc.update_scheduled()
    assert job and job["actor"] == "system:scheduler"
    svc.wait(5)
    assert not svc.due_update() and svc.update_scheduled() is None
    with svc.store.lock("vulnerabilities"):
        svc._write_state(last_attempt=(datetime.now(timezone.utc) - timedelta(hours=25)).isoformat())
    assert svc.due_update()
    Link(svc.store, svc.ctx.settings).set(actor="joshua", connected=False)
    assert not svc.due_update()


def test_unknown_and_pathlike_job_ids_are_key_errors(svc):
    for value in ("../../state", "x", uuid.uuid4().hex):
        with pytest.raises(KeyError):
            svc.job(value)


def test_export_retention_is_bounded(svc, offline_bundle):
    svc.import_bundle(offline_bundle, actor="joshua")
    for _ in range(4):
        svc.export_bundle(actor="joshua")
    assert len(list(svc.exports.glob("*.zip"))) == 2
    assert not list(svc.exports.glob("*.partial"))


def test_jobs_are_newest_first_and_physically_bounded(svc, fake_download, monkeypatch):
    import cyberthunder.vulnerabilities.service as module
    monkeypatch.setattr(module, "MAX_JOBS", 3)
    results = [svc.update(actor="joshua", include_java=False, background=False) for _ in range(5)]
    assert [j["id"] for j in svc.jobs()] == [j["id"] for j in reversed(results[-3:])]
    assert len(svc.store.list_json(svc.jobs_dir)) == 3
    assert len(list(svc.generations.iterdir())) <= MAX_GENERATIONS


def test_java_failure_does_not_publish_main_only(svc, offline_bundle, fake_download, monkeypatch):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    original = engine.run
    def fail_java(argv, **kwargs):
        if "--download-java-db-only" in argv:
            raise VulnerabilityUnavailable("Java download failed")
        return original(argv, **kwargs)
    monkeypatch.setattr(engine, "run", fail_java)
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "failed" and svc.status()["generation"] == old
    assert not list(svc.staging.iterdir())


def test_kill_immediately_before_publication_keeps_previous(svc, offline_bundle, fake_download, monkeypatch):
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    original = svc._audit
    def engage(action, *args, **kwargs):
        original(action, *args, **kwargs)
        if action == "publish":
            svc.ctx.killswitch.engage("joshua")
    monkeypatch.setattr(svc, "_audit", engage)
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "stopped" and svc.status()["generation"] == old
    events = [r for r in svc.ctx.audit.records() if r["action"] == "vulnerabilities.publish"]
    assert events[-1]["outcome"] == "prepared"


def test_version_probe_observes_same_update_controls(svc, monkeypatch):
    def require(*, refresh=False, guard=None):
        Link(svc.store, svc.ctx.settings).set(actor="joshua", connected=False)
        guard()
    monkeypatch.setattr(svc, "_require_engine", require)
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "stopped" and "disconnected" in job["error"]


def test_interrupted_job_after_pointer_commit_recovers_completed(svc, fake_download):
    job = svc.update(actor="joshua", background=False)
    job.update(state="running", finished_at=None, generation=None)
    svc.store.write_json(svc._job_path(job["id"]), job)
    recovered = VulnerabilityService(svc.ctx)
    job = recovered.job(job["id"])
    assert job["state"] == "completed" and job["generation"] == recovered.status()["generation"]


@pytest.mark.parametrize("probe", ["is_symlink", "is_junction"])
def test_link_payload_is_rejected_before_open(svc, offline_bundle, tmp_path, monkeypatch, probe):
    old = svc.import_bundle(offline_bundle, actor="joshua")
    original = svc.generations / old["generation"] / "db" / "trivy.db"
    outside = tmp_path / "outside.db"
    outside.write_bytes(original.read_bytes())
    # Model the filesystem's link result without requiring Windows link privileges.
    # The ZIP-member symlink tests separately exercise archive mode validation.
    check = getattr(Path, probe, lambda path: False)
    monkeypatch.setattr(Path, probe, lambda path: path == original or check(path), raising=False)
    open_file = Path.open

    def refuse_payload_read(path, *args, **kwargs):
        if path == original:
            pytest.fail("Linked database payload was opened")
        return open_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_payload_read)
    assert svc.status()["state"] == "invalid"
    with pytest.raises(VulnerabilityUnavailable):
        with svc.scan_context():
            pytest.fail("Linked payload accepted")
    with pytest.raises(VulnerabilityUnavailable):
        svc.export_bundle(actor="joshua")
    assert outside.exists()


def test_existing_scheduler_recovers_dead_worker_without_restart(svc, fake_download):
    svc.save_settings({"expected_revision": 0, "auto_update": True}, actor="joshua")
    job_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    svc.store.write_json(svc._job_path(job_id), {
        "id": job_id, "kind": "update", "state": "running", "started_at": started,
        "finished_at": None, "actor": "joshua", "generation": None, "error": None})
    with svc.store.lock("vulnerabilities"):
        svc._write_state(last_attempt=started)
    # Runtime asks due_update before invoking update_scheduled. Recovery must be
    # reachable even while the normal retry interval has not elapsed.
    assert svc.due_update()
    assert svc.update_scheduled() is None
    assert svc.job(job_id)["state"] == "stopped"
    assert not svc.due_update() and fake_download == []


def test_integrity_cache_keeps_one_generation_during_refresh(svc, offline_bundle, tmp_path):
    svc.import_bundle(offline_bundle, actor="joshua")
    with svc._selected() as first:
        _, _, first_databases = svc._inspect_selected(first)
        first_cache = svc._integrity_cache
        svc.import_bundle(bundle(tmp_path / "second.zip", payloads(marker=2)), actor="joshua")
        second_cache = svc._integrity_cache

        class RefreshBetweenReads(tuple):
            def __getitem__(self, index):
                # A second reader can replace the shared cache after the signature
                # comparison but before the first reader copies its database list.
                if index == 0:
                    svc._integrity_cache = second_cache
                return super().__getitem__(index)

        svc._integrity_cache = RefreshBetweenReads(first_cache)
        _, _, actual = svc._inspect_selected(first)
        assert actual == first_databases


def test_scan_lease_released_even_when_state_lock_fails(svc, offline_bundle, monkeypatch):
    svc.import_bundle(offline_bundle, actor="joshua")
    reader = svc._selected()
    reader.__enter__()
    path, = svc.leases.glob("*.lock")

    @contextmanager
    def unavailable(*args):
        raise TimeoutError("state lock busy")
        yield

    monkeypatch.setattr(svc.store, "lock", unavailable)
    with pytest.raises(TimeoutError) as failure:
        reader.__exit__(None, None, None)
    assert "state lock busy" in str(failure.value)
    with Lease(path):
        pass


def test_reader_in_another_process_pins_generation_until_process_exit(svc, offline_bundle):
    first = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    code = "\n".join([
        "import sys", "from types import SimpleNamespace", "from cyberthunder.store import StateStore",
        "from cyberthunder.vulnerabilities.service import VulnerabilityService",
        "store = StateStore(sys.argv[1])", "service = VulnerabilityService(SimpleNamespace(store=store))",
        "with service._selected():", "    print('ready', flush=True)", "    sys.stdin.readline()"])
    process = subprocess.Popen([sys.executable, "-c", code, str(svc.store.root)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert process.stdout.readline().strip() == "ready"
        for _ in range(MAX_GENERATIONS + 1):
            svc.import_bundle(offline_bundle, actor="joshua")
        assert (svc.generations / first).is_dir()
        assert len(list(svc.generations.iterdir())) == MAX_GENERATIONS
    finally:
        process.terminate()
        process.communicate(timeout=5)
    svc.import_bundle(offline_bundle, actor="joshua")
    assert not (svc.generations / first).exists()
    assert not list(svc.leases.glob(f"{first}.*.lock"))


def test_schedule_disable_before_reservation_prevents_download(svc, fake_download, monkeypatch):
    svc.save_settings({"expected_revision": 0, "auto_update": True}, actor="joshua")
    original = svc._start_update

    def disable(**kwargs):
        svc.save_settings({"expected_revision": 1, "auto_update": False}, actor="joshua")
        return original(**kwargs)

    monkeypatch.setattr(svc, "_start_update", disable)
    assert svc.update_scheduled() is None
    assert svc.jobs() == [] and fake_download == []


def test_staging_guard_tolerates_removed_downloader_temporary_file(svc, monkeypatch):
    from cyberthunder.vulnerabilities import storage
    stage = svc.staging / uuid.uuid4().hex
    stage.mkdir()
    temporary = stage / "temporary"
    temporary.write_bytes(b"x")
    original = storage.regular

    def disappeared(path):
        if path == temporary:
            temporary.unlink()
        return original(path)

    monkeypatch.setattr(storage, "regular", disappeared)
    svc._guard("joshua", stage=stage)


def test_staging_guard_counts_cache_and_home_temporary_copies(svc):
    stage = svc.staging / uuid.uuid4().hex
    (stage / "cache").mkdir(parents=True)
    (stage / "home").mkdir()
    raw = b"x" * (svc.max_unpacked_bytes // 2 + 200000)
    (stage / "cache" / "database").write_bytes(raw)
    (stage / "home" / "temporary-copy").write_bytes(raw)
    with pytest.raises(VulnerabilityError, match="size limit"):
        svc._guard("joshua", stage=stage)


def test_staging_budget_does_not_relax_final_payload_limit(svc, offline_bundle):
    svc.ctx.settings.vulnerability_max_unpacked_bytes = 1000
    svc.ctx.settings.vulnerability_max_staging_bytes = 1024 * 1024
    assert svc.max_staging_bytes > svc.max_unpacked_bytes
    with pytest.raises(VulnerabilityError, match="size limit"):
        svc.import_bundle(offline_bundle, actor="joshua")
    assert svc.status()["generation"] is None


def test_low_disk_update_preflight_preserves_selected_without_subprocess(svc, offline_bundle,
                                                                       fake_download, monkeypatch):
    from types import SimpleNamespace
    from cyberthunder.vulnerabilities import storage
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    monkeypatch.setattr(storage.shutil, "disk_usage", lambda _: SimpleNamespace(free=1024))
    job = svc.update(actor="joshua", background=False)
    assert job["state"] == "failed" and "free disk" in job["error"]
    assert fake_download == [] and svc.status()["generation"] == old
    assert not list(svc.staging.iterdir())


def test_low_disk_import_and_export_remove_partial_files(svc, offline_bundle, monkeypatch):
    from types import SimpleNamespace
    from cyberthunder.vulnerabilities import storage
    old = svc.import_bundle(offline_bundle, actor="joshua")["generation"]
    monkeypatch.setattr(storage.shutil, "disk_usage", lambda _: SimpleNamespace(free=1024))
    with pytest.raises(VulnerabilityError, match="free disk"):
        svc.import_bundle(offline_bundle, actor="joshua")
    with pytest.raises(VulnerabilityError, match="free disk"):
        svc.export_bundle(actor="joshua")
    assert svc.status()["generation"] == old
    assert not list(svc.staging.iterdir()) and not list(svc.exports.iterdir())
