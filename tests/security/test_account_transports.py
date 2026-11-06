"""Integrated account selection and revocation before remote operations."""
import json
import time

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.principal import Principal, principal_scope, operation_scope
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import Transport, CommandResult


class RecordedTransport(Transport):
    kind = "ssh"

    def __init__(self):
        self.calls = []

    def run(self, command, *, timeout=120, sudo=False):
        self.calls.append((command, sudo))
        return CommandResult(command, 0, "done")

    def read_file(self, path):
        self.calls.append(path)
        return b"test"

    def write_file(self, path, data, *, mode=None, sudo=False):
        self.calls.append(path)


@pytest.fixture
def bound_context(state_dir, monkeypatch):
    ctx = AppContext(Settings(state_dir=state_dir, auth_mode="oidc", security_mode="range",
                              llm_backend="template", auto_propose=False, explain_precompute=False))
    target = Target("host", "Host", "linux", "ssh", address="127.0.0.1", username="shared-admin",
                    credential_ref="SHARED", sudo=True, environment="A")
    ctx.inventory.add(target)
    ctx.inventory.save()
    person = Principal("https://identity.example.test", "alice", "Alice", kind="human",
                       roles=("analyst", "approver"), expires_at=time.time() + 300)
    path = state_dir / "auth" / "access.json"
    path.parent.mkdir(mode=0o700)
    policy = {"version": 1, "entries": [{"issuer": person.issuer, "subject": person.subject, "node_actions": [],
        "grants": [
            {"target_ids": ["host"], "actions": ["read", "scan"],
             "credential": {"username": "alice-reader", "credential_ref": "READ_ONLY", "sudo": False, "options": {}}},
            {"target_ids": ["host"], "actions": ["apply"],
             "credential": {"username": "alice-change", "credential_ref": "CHANGE", "sudo": True, "options": {}}},
        ]}]}
    path.write_text(json.dumps(policy))
    path.chmod(0o600)
    opened = []

    def factory(selected, settings, **kwargs):
        transport = RecordedTransport()
        opened.append((selected, transport, kwargs))
        return transport

    monkeypatch.setattr("cyberthunder.context.make_transport", factory)
    return ctx, target, person, path, policy, opened


def test_scan_and_apply_use_distinct_accounts_without_mutating_inventory(bound_context):
    ctx, target, person, _, _, opened = bound_context
    with principal_scope(person):
        with operation_scope("scan"):
            scan = ctx.transport_for(target)
            scan.run("read")
            with pytest.raises(PermissionError, match="privilege"):
                scan.run("elevate", sudo=True)
        with operation_scope("apply"):
            apply = ctx.transport_for(target)
            apply.run("change", sudo=True)
    assert [entry[0].username for entry in opened] == ["alice-reader", "alice-change"]
    assert [entry[0].credential_ref for entry in opened] == ["READ_ONLY", "CHANGE"]
    assert opened[0][1].calls == [("read", False)]
    assert ctx.inventory.get("host").username == "shared-admin"
    assert ctx.inventory.get("host").sudo is True
    rows = [json.loads(line) for line in ctx.audit.path.read_text().splitlines()]
    uses = [row for row in rows if row["action"] == "credential.use"]
    assert [row["details"]["username"] for row in uses] == ["alice-reader", "alice-change"]
    assert all(row["principal"]["sub"] == "alice" for row in uses)
    assert "READ_ONLY" not in json.dumps(uses)


def test_revoked_policy_stops_existing_connection_before_next_command(bound_context):
    ctx, target, person, path, _, opened = bound_context
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
        transport.run("before")
        path.write_text('{"version":1,"entries":[]}')
        with pytest.raises(PermissionError):
            transport.run("after")
    assert opened[0][1].calls == [("before", False)]


def test_connection_cannot_be_reused_by_another_account(bound_context):
    ctx, target, person, _, _, opened = bound_context
    with principal_scope(person), operation_scope("scan"):
        transport = ctx.transport_for(target)
    with principal_scope(Principal(person.issuer, "bob", "Bob", kind="human", roles=person.roles,
                                   expires_at=person.expires_at)), operation_scope("scan"):
        with pytest.raises(PermissionError, match="another authenticated session"):
            transport.read_file("private")
    assert not opened[0][1].calls


def test_missing_binding_never_falls_back_to_shared_target_account(bound_context):
    ctx, target, person, path, policy, opened = bound_context
    del policy["entries"][0]["grants"][0]["credential"]
    path.write_text(json.dumps(policy))
    with principal_scope(person), operation_scope("scan"):
        with pytest.raises(PermissionError):
            ctx.transport_for(target)
    assert not opened
