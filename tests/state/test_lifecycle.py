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
