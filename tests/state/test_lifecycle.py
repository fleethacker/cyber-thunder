"""Explicit lifecycle receipts; no live targets or automatic fixture cleanup."""
import gc
import os
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.runtime import RuntimeTasks
from cyberthunder.state.sqlite import SqliteBackend


def context(path, backend):
    return AppContext(Settings(state_dir=path, state_backend=backend, auth_mode="dev",
                               llm_backend="template", scan_interval_s=0,
                               content_check_interval_s=0))


def connections(ctx):
    return [c for _, c in getattr(ctx.store.docs, "_conns", {}).values()]


def assert_closed(conns):
    for conn in conns:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


def state_handles(root):
    if not Path("/proc/self/fd").is_dir():
        return None
    count = 0
    for fd in Path("/proc/self/fd").iterdir():
        try:
            count += os.readlink(fd).startswith(str(root))
        except FileNotFoundError:
            pass
    return count


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_repeated_owned_api_and_context_close(tmp_path, monkeypatch, backend):
    import cyberthunder.api.app as api
    enabled = gc.isenabled()
    gc.disable()
    retained = []  # Verify deterministic release even when callers retain the objects.
    try:
        for i in range(12):
            ctx = context(tmp_path / str(i), backend)
            monkeypatch.setattr(api, "AppContext", lambda: ctx)
            app = create_app()
            retained.append(app)
            with TestClient(app):
                ctx.store.write_json(ctx.store.root / "demo.json", {"i": i})
                conns = connections(ctx)
            assert_closed(conns)
            assert app.state.close()
        assert state_handles(tmp_path) in (None, 0)
        for app in retained:
            ctx = app.state.ctx
            ctx.store.write_json(ctx.store.root / "demo.json", {"later": True})
            assert ctx.close() and ctx.close()
            reopened = context(ctx.store.root, backend)
            try:
                assert reopened.store.read_json(reopened.store.root / "demo.json") == {"later": True}
            finally:
                assert reopened.close()
        assert state_handles(tmp_path) in (None, 0)
    finally:
        for app in retained:
            app.state.close()
        if enabled:
            gc.enable()


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_borrowed_context_and_audit_survive(tmp_path, backend):
    ctx = context(tmp_path, backend)
    ctx.audit.append("lifecycle.test", "tester", {})
    audit = ctx.store.audit_log.read_bytes()
    conns = connections(ctx)
    with TestClient(create_app(ctx)):
        pass
    for conn in conns:
        assert conn.execute("SELECT 1").fetchone() == (1,)
    ctx.store.write_json(tmp_path / "demo.json", {"alive": True})
    assert ctx.close()
    assert_closed(conns)
    assert ctx.store.audit_log.read_bytes() == audit


@pytest.mark.parametrize("backend", ["json", "sqlite"])
@pytest.mark.parametrize("registry", ["scan", "discovery", "content", "vulnerabilities", "api", "runtime"])
def test_active_work_timeout_retry_and_late_write(tmp_path, backend, registry):
    from cyberthunder.api import util
    from types import SimpleNamespace
    ctx = context(tmp_path, backend)
    entered, finish = threading.Event(), threading.Event()
    errors = []
    def work():
        try:
            ctx.store.write_json(tmp_path / "demo.json", {"phase": 1})
            entered.set()
            assert finish.wait(5)
            ctx.store.write_json(tmp_path / "demo.json", {"phase": 2})
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=work)
    if registry == "scan": ctx.scanner._threads["test"] = thread
    elif registry == "discovery": ctx.discovery._threads["test"] = thread
    elif registry == "content": ctx.ingest._content = SimpleNamespace(threads=[thread])
    elif registry == "vulnerabilities": ctx.vulnerabilities.threads.append(thread)
    elif registry == "api":
        with util._threads_lock: util._threads.append(thread)
    else:
        tasks = RuntimeTasks(ctx)
        tasks._threads.append(thread)
    thread.start()
    try:
        assert entered.wait(5)
        conns = connections(ctx)
        assert ctx.close(timeout=0.01) is False
        for conn in conns:
            assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        finish.set()
        thread.join(5)
        assert ctx.close()
    assert not errors
    assert_closed(conns)
    assert ctx.store.read_json(tmp_path / "demo.json") == {"phase": 2}
    assert ctx.close()


def test_constructor_failure_closes_sqlite(tmp_path, monkeypatch):
    import cyberthunder.context as module
    opened = []
    original = module.StateStore
    def store(*args, **kwargs):
        result = original(*args, **kwargs)
        opened.extend(c for _, c in result.docs._conns.values())
        return result
    def fail(*args, **kwargs): raise RuntimeError("construction failed")
    monkeypatch.setattr(module, "StateStore", store)
    monkeypatch.setattr(module, "AuditLog", fail)
    with pytest.raises(RuntimeError, match="construction failed"):
        context(tmp_path, "sqlite")
    assert opened
    assert_closed(opened)


def test_backend_schema_failure_closes_connection(tmp_path, monkeypatch):
    opened = []
    def fail(self):
        opened.append(self._conn())
        raise RuntimeError("schema failed")
    monkeypatch.setattr(SqliteBackend, "_init_schema", fail)
    with pytest.raises(RuntimeError, match="schema failed"):
        SqliteBackend(tmp_path)
    assert_closed(opened)


@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize("phase", ["configure", "startup"])
def test_api_failure_ownership(tmp_path, monkeypatch, owned, phase):
    import cyberthunder.api.app as api
    ctx = context(tmp_path, "sqlite")
    conns = connections(ctx)
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    def fail(*args, **kwargs): raise RuntimeError("startup failed")
    if phase == "configure": monkeypatch.setattr(api, "_configure_app", fail)
    else: monkeypatch.setattr(RuntimeTasks, "start", fail)
    try:
        with pytest.raises(RuntimeError, match="startup failed"):
            app = create_app(None if owned else ctx)
            with TestClient(app): pass
        if owned: assert_closed(conns)
        else:
            for conn in conns: assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        assert ctx.close()

@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_api_shutdown_waits_for_spawned_child(tmp_path, monkeypatch, backend):
    import cyberthunder.api.app as api
    from cyberthunder.api.util import run_background
    ctx = context(tmp_path, backend)
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    app = create_app()
    entered, finish = threading.Event(), threading.Event()
    errors = []
    def child():
        entered.set()
        finish.wait(5)
        try: ctx.store.write_json(tmp_path / "demo.json", {"child": True})
        except BaseException as exc: errors.append(exc)
    def parent():
        thread = threading.Thread(target=child)
        ctx.scanner._threads["child"] = thread
        thread.start()
    run_background(parent, "lifecycle-parent")
    try:
        assert entered.wait(5)
        assert app.state.close(timeout=0.01) is False
    finally:
        finish.set()
        assert app.state.close()
    assert not errors
    assert ctx.store.read_json(tmp_path / "demo.json") == {"child": True}
    assert ctx.close()


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_explanation_work_drains_before_close(tmp_path, backend):
    from cyberthunder.explain.worker import ExplainWorker
    from cyberthunder.findings.schema import Finding
    ctx = context(tmp_path, backend)
    entered, finish = threading.Event(), threading.Event()
    def explain(finding):
        entered.set()
        assert finish.wait(5)
        ctx.store.write_json(tmp_path / "demo.json", {"explained": True})
    worker = ExplainWorker(explain)
    ctx.explain._worker = worker
    worker.submit(Finding(host="local-test", source="native", rule_id="lifecycle", title="test", severity="low", status="open"))
    try:
        assert entered.wait(5)
        assert ctx.close(timeout=0.01) is False
    finally:
        finish.set()
        assert ctx.close()
    assert not worker.alive and worker.failed == 0
    assert ctx.store.read_json(tmp_path / "demo.json") == {"explained": True}
    assert ctx.close()


def test_partial_runtime_start_failure_drains(tmp_path, monkeypatch):
    import cyberthunder.api.app as api
    ctx = context(tmp_path, "sqlite")
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    captured = []
    def fail(tasks):
        tasks._start_interval("test-idle", 60, lambda: None)
        captured.extend(tasks._threads)
        raise RuntimeError("partial start")
    monkeypatch.setattr(RuntimeTasks, "start", fail)
    conns = connections(ctx)
    with pytest.raises(RuntimeError, match="partial start"):
        with TestClient(create_app()): pass
    assert all(not thread.is_alive() for thread in captured)
    assert_closed(conns)

@pytest.mark.parametrize("owned", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_serve_ownership_on_return_and_failure(tmp_path, monkeypatch, owned, failure):
    import cyberthunder.api.app as api
    import uvicorn
    ctx = context(tmp_path, "sqlite")
    conns = connections(ctx)
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    def run(*args, **kwargs):
        if failure: raise RuntimeError("server failed")
    monkeypatch.setattr(uvicorn, "run", run)
    try:
        if failure:
            with pytest.raises(RuntimeError, match="server failed"):
                api.serve(ctx=None if owned else ctx)
        else:
            api.serve(ctx=None if owned else ctx)
        if owned: assert_closed(conns)
        else:
            for conn in conns: assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        assert ctx.close()


def test_explanation_callback_child_is_drained(tmp_path):
    """A callback can publish another registered writer while close waits for it."""
    from cyberthunder.api.util import run_background
    from cyberthunder.explain.worker import ExplainWorker
    from cyberthunder.findings.schema import Finding
    ctx = context(tmp_path, "sqlite")
    entered, release, child_entered, child_release = [threading.Event() for _ in range(4)]
    errors = []
    def child():
        try:
            ctx.store.write_json(tmp_path / "demo.json", {"phase": 1})
            child_entered.set()
            assert child_release.wait(10)
            ctx.store.write_json(tmp_path / "demo.json", {"phase": 2})
        except BaseException as exc:
            errors.append(exc)
    def callback(finding):
        entered.set()
        assert release.wait(10)
        run_background(child, "lifecycle-callback-child", early_wait=0)
        assert child_entered.wait(10)
    worker = ExplainWorker(callback)
    ctx.explain._worker = worker
    worker.submit(Finding(host="local", source="native", rule_id="callback", title="test",
                          severity="low", status="open"))
    assert entered.wait(10)
    # Release only when close has reached the real explanation drain.
    original = worker.wait_idle
    def wait_idle(timeout):
        release.set()
        return original(timeout)
    worker.wait_idle = wait_idle
    try:
        assert ctx.close(timeout=0.2) is False
        assert child_entered.is_set()
        for conn in connections(ctx):
            assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        release.set()
        child_release.set()
        assert ctx.close()
    assert not errors
    assert state_handles(tmp_path) in (None, 0)


def test_runtime_constructor_failure_releases_owned_context(tmp_path, monkeypatch):
    import cyberthunder.api.app as api
    import cyberthunder.runtime as runtime
    ctx = context(tmp_path, "sqlite")
    saved = connections(ctx)
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    def fail(ctx):
        raise RuntimeError("runtime construction failed")
    monkeypatch.setattr(runtime, "RuntimeTasks", fail)
    try:
        with pytest.raises(RuntimeError, match="runtime construction failed"):
            with TestClient(create_app()):
                pass
        assert_closed(saved)
        assert state_handles(tmp_path) in (None, 0)
    finally:
        assert ctx.close()


def test_real_runtime_probe_and_reconnect_writer(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from cyberthunder.ingest import probe
    ctx = context(tmp_path, "sqlite")
    ctx.settings.content_check_on_reconnect = True
    link = ctx.ingest.link
    content = ctx.ingest.content
    link.set(actor="Joshua Ott", probe_enabled=True)
    link.observe(endpoint=link.state().probe_endpoint, method="HEAD", application_bytes=0,
                 elapsed_seconds=0.01, success=False, status=None, reachable=False, kind="probe")
    probe_entered, probe_release, fetch_entered, fetch_release = [threading.Event() for _ in range(4)]
    def response(endpoint, *, guard):
        guard()
        probe_entered.set()
        assert probe_release.wait(10)
        guard()
        return {"success": True, "status": 200, "elapsed_seconds": 0.01}
    def fetch():
        fetch_entered.set()
        assert fetch_release.wait(10)
        return SimpleNamespace(entries=[], stats=lambda: {})
    monkeypatch.setattr(probe, "bounded_probe", response)
    monkeypatch.setattr(content, "_fetch_live", fetch)
    tasks = RuntimeTasks(ctx)
    # Exercise the actual producer loop without waiting the production five seconds.
    tasks._start_interval("probe-review", 0.001, tasks._probe_link)
    try:
        assert probe_entered.wait(10)
        assert ctx.close(timeout=0.02) is False
        probe_release.set()
        assert fetch_entered.wait(10)
        assert tasks.stop(1)
        saved = connections(ctx)
        assert ctx.close(timeout=0.02) is False
        for conn in saved:
            assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        probe_release.set()
        fetch_release.set()
        assert ctx.close()
    assert_closed(saved)
    assert state_handles(tmp_path) in (None, 0)
    assert content.last_check()["source"] == "live"
    assert ctx.close()


def test_partial_context_failure_drains_existing_service(tmp_path, monkeypatch):
    import cyberthunder.context as module
    import cyberthunder.explain.service as explain
    from cyberthunder.api.util import run_background
    captured, saved = [], []
    original = module.StateStore
    def store(*args, **kwargs):
        result = original(*args, **kwargs)
        saved.extend(c for _, c in result.docs._conns.values())
        return result
    def fail(ctx):
        captured.append(ctx)
        run_background(lambda: ctx.store.write_json(tmp_path / "partial.json", {"done": True}),
                       "partial-context-writer", early_wait=0)
        raise RuntimeError("partial context")
    monkeypatch.setattr(module, "StateStore", store)
    monkeypatch.setattr(explain, "ExplainService", fail)
    with pytest.raises(RuntimeError, match="partial context"):
        context(tmp_path, "sqlite")
    assert_closed(saved)
    assert state_handles(tmp_path) in (None, 0)
    assert captured[0].store.read_json(tmp_path / "partial.json") == {"done": True}
    assert captured[0].close()


def test_real_download_worker_finishes_before_release(tmp_path, monkeypatch):
    from cyberthunder.ingest.content import fetch
    ctx = context(tmp_path, "sqlite")
    content = ctx.ingest.content
    entries, _ = content.catalog_entries()
    entry = next(e for e in entries if e.format_supported and
                 e.allowed_by(content.client.allowed_hosts, content.client.allow_http))
    entered, release = threading.Event(), threading.Event()
    def download(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        raise fetch.Stopped("controlled transport stop")
    monkeypatch.setattr(fetch, "download", download)
    job = content.pull("Joshua Ott", filenames=[entry.filename], background=True)
    try:
        assert entered.wait(10)
        saved = connections(ctx)
        assert ctx.close(timeout=0.02) is False
        for conn in saved:
            assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        release.set()
        assert ctx.close()
    assert_closed(saved)
    assert state_handles(tmp_path) in (None, 0)
    assert content.get_job(job["id"])["state"] == "stopped"
    assert ctx.close()
