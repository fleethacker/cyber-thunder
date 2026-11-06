"""Impact ownership across caller timeout, state reads, and context shutdown."""
import json
import threading

import pytest

from cyberthunder.api.app import create_app
from cyberthunder.context import AppContext
from cyberthunder.impact import service as module
from tests.state.test_lifecycle import assert_closed, connections, context, state_handles


def owned_context(rig):
    # Use the persisted proposal/inventory, but real context wiring and findings reads.
    rig.ctx.store.close()  # Release setup handles before measuring the new owner's lifetime.
    ctx = AppContext(rig.ctx.settings)
    ctx.library = rig.ctx.library
    ctx.explain.backend = rig.backend
    ctx.store.save_scan_run({"id": "lifecycle", "targets": [rig.target.id],
                             "started_at": rig.packet["generated_at"], "status": "done"})
    ctx.store.save_findings("lifecycle", rig.current)
    assert ctx.store.current_findings()
    return ctx


@pytest.mark.parametrize("phase", ["probe", "generate"])
def test_timed_out_guard_cannot_read_after_successful_shutdown(rig, monkeypatch, phase):
    import cyberthunder.api.app as api
    ctx = owned_context(rig)
    monkeypatch.setattr(api, "AppContext", lambda: ctx)
    app = create_app()
    entered, release = threading.Event(), threading.Event()
    captured = []
    calls = [0]
    real_findings = ctx.store.current_findings
    def findings():
        if threading.current_thread().name == "impact-model":
            calls[0] += 1
            if calls[0] == (1 if phase == "probe" else 2):
                captured.append(threading.current_thread())
                entered.set()
                assert release.wait(10)
        return real_findings()
    monkeypatch.setattr(ctx.store, "current_findings", findings)
    monkeypatch.setattr(module, "PROBE_TIMEOUT_S", 0.2)
    monkeypatch.setattr(module, "MODEL_TIMEOUT_S", 0.5)
    try:
        result = ctx.impact.assess(rig.proposal.id, actor="Joshua")
        assert entered.is_set()
        assert result["model"]["fallback_reason"] == "model_timeout"
        saved = connections(ctx)
        closed = app.state.close(timeout=0.02)
        after_close = state_handles(ctx.store.root)
        connections_after_close = len(connections(ctx))
        if not closed:
            for conn in saved:
                assert conn.execute("SELECT 1").fetchone() == (1,)
        release.set()
        for thread in captured:
            thread.join(5)
            assert not thread.is_alive()
        # Capture the actual late-read evidence before retry cleanup can conceal it.
        print(json.dumps({"phase": phase, "backend": ctx.store.backend_name,
                          "close_returned": closed, "handles_after_close": after_close,
                          "connections_after_close": connections_after_close,
                          "connections_after_guard": len(connections(ctx)),
                          "handles_after_guard": state_handles(ctx.store.root)}))
        assert closed is False
        saved.extend(conn for conn in connections(ctx) if conn not in saved)
        assert app.state.close()
        assert_closed(saved)
        assert not ctx.impact.worker_threads()
        assert state_handles(ctx.store.root) in (None, 0)
    finally:
        release.set()
        for thread in captured:
            thread.join(5)
        assert ctx.close()


def test_impact_child_created_during_drain_is_owned(tmp_path, monkeypatch):
    ctx = context(tmp_path, "sqlite")
    parent_entered, parent_release, child_entered, child_release = [threading.Event() for _ in range(4)]
    errors = []
    def child():
        child_entered.set()
        assert child_release.wait(10)
        ctx.store.write_json(tmp_path / "demo.json", {"child": True})
    def parent():
        parent_entered.set()
        assert parent_release.wait(10)
        result = module._bounded_call(child, 0.05, owner=ctx.impact)
        if result != (None, "model_timeout"):
            errors.append(result)
    assert module._bounded_call(parent, 0.1, owner=ctx.impact) == (None, "model_timeout")
    assert parent_entered.is_set()
    parent_thread, = ctx.impact.worker_threads()
    join = parent_thread.join
    def join_parent(timeout=None):
        parent_release.set()  # Spawn only after close has taken its initial snapshot.
        return join(timeout)
    monkeypatch.setattr(parent_thread, "join", join_parent)
    saved = connections(ctx)
    try:
        assert ctx.close(timeout=0.2) is False
        assert child_entered.is_set()
        assert not parent_thread.is_alive()
        assert len(ctx.impact.worker_threads()) == 1
        for conn in saved:
            assert conn.execute("SELECT 1").fetchone() == (1,)
    finally:
        parent_release.set()
        child_release.set()
        assert ctx.close()
    assert not errors and not ctx.impact.worker_threads()
    assert_closed(saved)
    assert state_handles(tmp_path) in (None, 0)
    assert ctx.store.read_json(tmp_path / "demo.json") == {"child": True}
    assert ctx.close()


def test_multiple_impact_workers_share_close_deadline(tmp_path, monkeypatch):
    ctx = context(tmp_path, "sqlite")
    release = threading.Event()
    entered = [threading.Event() for _ in range(3)]
    joins = []
    def call(event):
        event.set()
        assert release.wait(10)
        ctx.store.read_json(tmp_path / "demo.json")
    try:
        for event in entered:
            assert module._bounded_call(lambda event=event: call(event), 0.1,
                                        owner=ctx.impact) == (None, "model_timeout")
            assert event.is_set()
        threads = ctx.impact.worker_threads()
        assert len(threads) == 3
        for thread in threads:
            original = thread.join
            def join(timeout=None, original=original):
                joins.append(timeout)
                return original(timeout)
            monkeypatch.setattr(thread, "join", join)
        assert ctx.close(timeout=0.1) is False
        assert len(joins) == 3
        assert sum(joins) <= 0.11  # A per-worker allowance would total about 0.3.
        assert len(ctx.impact.worker_threads()) == 3
    finally:
        release.set()
        assert ctx.close()
    assert not ctx.impact.worker_threads()
    assert state_handles(tmp_path) in (None, 0)


def test_borrowed_context_and_other_owner_do_not_close_impact_state(tmp_path):
    first = context(tmp_path / "first", "sqlite")
    other = context(tmp_path / "other", "sqlite")
    entered, release = threading.Event(), threading.Event()
    def work():
        entered.set()
        assert release.wait(10)
        first.store.write_json(first.store.root / "demo.json", {"done": True})
    saved = connections(first)
    try:
        assert module._bounded_call(work, 0.1, owner=first.impact) == (None, "model_timeout")
        assert entered.is_set()
        assert create_app(first).state.close(timeout=0)
        assert other.close(timeout=0)
        assert first.impact.worker_threads()
        for conn in saved:
            assert conn.execute("SELECT 1").fetchone() == (1,)
        assert first.close(timeout=0) is False
    finally:
        release.set()
        assert first.close() and other.close()
    assert_closed(saved)
    assert state_handles(tmp_path) in (None, 0)


def test_failed_start_releases_slot_and_propagates(tmp_path, monkeypatch):
    ctx = context(tmp_path, "sqlite")
    real_thread = module.threading.Thread
    class CannotStart(real_thread):
        def start(self):
            raise RuntimeError("worker start failed")
    try:
        with monkeypatch.context() as patch:
            patch.setattr(module.threading, "Thread", CannotStart)
            # More failures than the semaphore capacity detects leaked permits.
            for _ in range(5):
                with pytest.raises(RuntimeError, match="worker start failed"):
                    module._bounded_call(lambda: None, 1, owner=ctx.impact)
        assert not ctx.impact.worker_threads()
        assert module._bounded_call(lambda: "ok", 1, owner=ctx.impact) == ("ok", None)
        def denied():
            raise PermissionError("revoked")
        with pytest.raises(PermissionError, match="revoked"):
            module._bounded_call(denied, 1, owner=ctx.impact)
    finally:
        assert ctx.close()


def test_impact_self_close_returns_false_and_later_use_reopens(tmp_path):
    ctx = context(tmp_path, "sqlite")
    try:
        for cycle in range(2):
            ctx.store.write_json(tmp_path / "demo.json", {"cycle": cycle})
            assert module._bounded_call(lambda: ctx.close(0), 1, owner=ctx.impact) == (False, None)
            saved = connections(ctx)
            assert ctx.close()
            assert_closed(saved)
            assert not ctx.impact.worker_threads()
    finally:
        assert ctx.close()
