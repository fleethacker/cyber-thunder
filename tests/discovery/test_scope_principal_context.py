"""Discovery's optional application authorization hook and background requester context."""
from contextvars import ContextVar
from threading import Event

import pytest

from cyberthunder.discovery.models import DiscoveryRun
from cyberthunder.discovery.service import DiscoveryService, SCOPE_COMPLETE
from cyberthunder.inventory.targets import Target


def authorize_mode(ctx, monkeypatch, callback):
    monkeypatch.setattr(ctx.settings, "auth_mode", "authenticated", raising=False)
    monkeypatch.setattr(ctx, "authorize", callback, raising=False)


def test_background_sweep_copies_request_context_for_authorization_and_execution(ctx, monkeypatch):
    principal = ContextVar("fixture_current_principal", default=None)
    operation = ContextVar("fixture_operation_scope", default=None)
    entered, release = Event(), Event()
    calls = []

    def authorize(action, *, actor):
        calls.append((action, actor, principal.get(), operation.get()))

    authorize_mode(ctx, monkeypatch, authorize)
    svc = DiscoveryService(ctx)
    svc.set_scopes(["10.1.0.1/32"], "IT1 Requester", "Reviewed range")
    audit_contexts = []
    append = ctx.audit.append

    def audit(action, *args, **kwargs):
        audit_contexts.append((action, principal.get(), operation.get()))
        return append(action, *args, **kwargs)

    monkeypatch.setattr(ctx.audit, "append", audit)

    def collect(run, scopes, actor):
        entered.set()
        assert release.wait(10)
        svc._authorize_discovery(actor)
        return [], None, {}

    monkeypatch.setattr(svc, "_collect", collect)
    token, scope_token = principal.set("verified-requester"), operation.set("reviewed-operation")
    try:
        run = svc.sweep(mode="simulated", actor="IT1 Requester", background=True)
        assert entered.wait(10)
        principal.set("different-requester")
        operation.set("different-operation")
        release.set()
        assert svc.join(run.id, timeout=10).status == "finished"
        assert len(calls) == 2
        assert calls == [("discover", "IT1 Requester", "verified-requester", "reviewed-operation")] * 2
        assert ("discovery.finish", "verified-requester", "reviewed-operation") in audit_contexts
    finally:
        release.set()
        principal.reset(token)
        operation.reset(scope_token)


def test_entry_authorization_refusal_precedes_run_creation(ctx, monkeypatch):
    svc = DiscoveryService(ctx)

    def deny(*args, **kwargs):
        raise PermissionError("principal may not discover")

    authorize_mode(ctx, monkeypatch, deny)
    with pytest.raises(PermissionError, match="may not discover"):
        svc.sweep(mode="simulated", actor="IT1 Requester")
    assert svc.runs() == []
    assert not any(r["action"] == "discovery.start" for r in ctx.audit.records())


def test_revocation_before_next_range_prevents_its_collection(ctx, monkeypatch):
    svc = DiscoveryService(ctx)
    svc.set_scopes(["10.1.0.1/32", "10.2.0.1/32"], "IT1 Requester", "Reviewed ranges")
    seen = []

    def authorize(*args, **kwargs):
        if seen:
            raise PermissionError("principal revoked")

    def collect(scope, run):
        seen.append(scope.cidr)
        return [], SCOPE_COMPLETE

    authorize_mode(ctx, monkeypatch, authorize)
    monkeypatch.setattr(svc, "_nmap", collect)
    with pytest.raises(PermissionError, match="principal revoked"):
        svc.sweep(mode="quick", actor="IT1 Requester", background=False)
    assert seen == ["10.1.0.1/32"]
    assert svc.last_run().status == "failed"


def test_revocation_before_next_inventory_source_prevents_transport(ctx, monkeypatch):
    for name in ("switch-a", "switch-b"):
        ctx.inventory.add_new(Target(name, name, "cisco_ios", in_scope=True))
    svc = DiscoveryService(ctx)
    seen, opened = [], []

    def authorize(*args, **kwargs):
        if seen:
            raise PermissionError("principal revoked")

    class NoNetwork:
        def close(self):
            pass

    authorize_mode(ctx, monkeypatch, authorize)
    monkeypatch.setattr(ctx, "transport_for", lambda t: opened.append(t.id) or NoNetwork())
    monkeypatch.setattr(svc, "_gear", lambda tr, t, run: seen.append(t.id) or [])
    with pytest.raises(PermissionError, match="principal revoked"):
        svc._inventory_sources([], DiscoveryRun(id="fixture", requested_by="IT1 Requester"))
    assert opened == seen == ["switch-a"]


def test_development_skips_hook_but_authenticated_mode_without_hook_fails_closed(ctx, monkeypatch):
    svc = DiscoveryService(ctx)
    monkeypatch.setattr(ctx.settings, "auth_mode", "dev", raising=False)
    monkeypatch.setattr(ctx, "authorize", lambda *args, **kwargs: pytest.fail("development called external authorization"), raising=False)
    svc._authorize_discovery("IT1 Requester")
    monkeypatch.setattr(ctx.settings, "auth_mode", "authenticated")
    monkeypatch.setattr(ctx, "authorize", None)
    with pytest.raises(PermissionError, match="authorization is unavailable"):
        svc._authorize_discovery("IT1 Requester")
