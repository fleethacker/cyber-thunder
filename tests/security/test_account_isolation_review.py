"""Account ownership must not change between a snapshot and its authorization."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import json
from types import SimpleNamespace

import pytest

from cyberthunder.adapters.base import AssetFacts, Collected
from cyberthunder.api.routes.targets import discover_target
from cyberthunder.control.principal import operation_scope, principal_scope
from cyberthunder.inventory.targets import Inventory, Target
from cyberthunder.report import history
from cyberthunder.scan import ScanRun
from cyberthunder.security import resources
from cyberthunder.transport.base import CommandResult, Transport
from tests.security.test_identity_boundary import headers, identity, verified_app


def environment_reader(ctx):
    policy = json.loads(ctx.access.path.read_text())
    policy["entries"][1]["node_actions"] = ["export"]
    policy["entries"][1]["grants"] = [{"environments": ["beta"], "actions": ["read", "export", "scan"]}]
    ctx.access.path.write_text(json.dumps(policy))
    return identity("second-user", roles=("analyst", "auditor"))


def replace_alpha(ctx, change):
    # A different inventory writer changes ownership without updating this
    # request's already-loaded target object.
    inventory = Inventory.load(ctx.inventory.path)
    if change == "move":
        target = inventory.get("alpha")
        target.environment, target.name = "beta", "New account target"
        target.notes = ""
        inventory.save()
    else:
        inventory.remove("alpha")
        inventory.save()
        inventory.add_new(Target("alpha", "New account target", "linux", transport="simulated",
                                 simulated=True, environment="beta"))


@pytest.mark.parametrize("change", ["move", "reuse"])
def test_target_snapshot_cannot_borrow_replacement_account_rights(verified_app, change):
    ctx, _, _, _, _ = verified_app
    person = environment_reader(ctx)
    snapshot = deepcopy(ctx.inventory.get("alpha"))
    replace_alpha(ctx, change)
    with principal_scope(person):
        assert ctx.may_access("alpha")
        assert not ctx.may_access(snapshot)
        with pytest.raises(PermissionError):
            ctx.authorize("read", target=snapshot)


@pytest.mark.parametrize("change", ["move", "reuse"])
@pytest.mark.parametrize("route", ["record", "report"])
def test_owner_change_between_artifact_check_and_grant_cannot_reveal_old_data(
        verified_app, monkeypatch, change, route):
    ctx, _, _, _, _ = verified_app
    person = environment_reader(ctx)
    scope = resources.capture(ctx, ["alpha"])[0]
    record = {"host": "alpha", "authorization_scope": scope}
    ctx.store.write_json(history._path(ctx, "former-account-report"), {
        "id": "former-account-report", "targets": ["alpha"], "authorization_scopes": [scope],
        "content": "former account private report", "kind": "commander",
    })
    load = resources.persisted_target
    changed = []

    def switched(inventory, target_id, **kwargs):
        target = load(inventory, target_id, **kwargs)
        if target_id == "alpha" and not changed:
            changed.append(True)
            replace_alpha(ctx, change)
        return target

    monkeypatch.setattr(resources, "persisted_target", switched)
    with principal_scope(person), pytest.raises(PermissionError):
        if route == "record":
            resources.check_record(ctx, record)
        else:
            history.get(ctx, "former-account-report")
    assert changed
    with principal_scope(person):
        assert ctx.may_access("alpha")
        assert not resources.visible_record(ctx, record)


@pytest.mark.parametrize("change", ["move", "reuse"])
def test_target_list_cannot_serialize_former_account_snapshot(verified_app, monkeypatch, change):
    ctx, _, tokens, client, _ = verified_app
    person = environment_reader(ctx)
    ctx.inventory.get("alpha").notes = "former account private notes"
    ctx.inventory.save()
    can_read = ctx.may_access
    changed = []

    def switched(target, action="read"):
        if getattr(target, "id", None) == "alpha" and not changed:
            changed.append(True)
            replace_alpha(ctx, change)
        return can_read(target, action)

    monkeypatch.setattr(ctx, "may_access", switched)
    response = client.get("/api/v1/targets", headers=headers(tokens, person))
    assert response.status_code == 200
    assert changed and "former account private notes" not in response.text
    assert [target["id"] for target in response.json()["targets"]] == ["beta"]
    # A fresh request can see the replacement using its own current details.
    response = client.get("/api/v1/targets", headers=headers(tokens, person))
    assert "former account private notes" not in response.text
    assert {target["id"] for target in response.json()["targets"]} == {"alpha", "beta"}
    assert next(t for t in response.json()["targets"] if t["id"] == "alpha")["name"] == "New account target"


@pytest.mark.parametrize("change", ["move", "reuse"])
def test_transport_does_not_retarget_a_stale_snapshot(verified_app, monkeypatch, change):
    ctx, _, _, _, _ = verified_app
    person = environment_reader(ctx)
    snapshot = deepcopy(ctx.inventory.get("alpha"))
    replace_alpha(ctx, change)
    opened = []

    def connect(target, *_args, **_kwargs):
        opened.append(target.id)
        return SimpleNamespace()

    monkeypatch.setattr("cyberthunder.context.make_transport", connect)
    with principal_scope(person), operation_scope("scan"):
        with pytest.raises(PermissionError):
            ctx.transport_for(snapshot)
    assert not opened


class ReadOnlyTransport(Transport):
    def run(self, command, **kwargs):
        return CommandResult(command, 0, "private host facts")

    def read_file(self, path):
        raise AssertionError("not used")

    def write_file(self, path, data, **kwargs):
        raise AssertionError("discovery must not write")


@pytest.mark.parametrize("change", ["unchanged", "policy", "session", "move", "reuse"])
def test_discovery_rechecks_authorization_after_last_io_in_copied_worker(verified_app, monkeypatch, change):
    ctx, _, _, _, _ = verified_app
    person = identity()
    revoked = []

    def validity():
        if revoked:
            raise PermissionError("session revoked")

    def discover(target, transport):
        assert transport.run("hostname").ok
        if change == "policy":
            policy = json.loads(ctx.access.path.read_text())
            policy["entries"][0]["grants"] = []
            ctx.access.path.write_text(json.dumps(policy))
        elif change == "session":
            revoked.append(True)
        elif change in {"move", "reuse"}:
            replace_alpha(ctx, change)
        return AssetFacts(hostname="private host facts")

    monkeypatch.setattr("cyberthunder.context.make_transport", lambda *_args, **_kwargs: ReadOnlyTransport())
    monkeypatch.setattr(ctx, "adapter_for", lambda _target: SimpleNamespace(discover=discover))
    with principal_scope(person, validity=validity), operation_scope("discover"):
        inherited = copy_context()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(inherited.run, discover_target, "alpha", ctx=ctx, actor=person.actor)
        if change == "unchanged":
            assert future.result(timeout=10)["hostname"] == "private host facts"
        else:
            with pytest.raises(PermissionError):
                future.result(timeout=10)
    rows = [json.loads(line) for line in ctx.audit.path.read_text().splitlines()]
    if change != "unchanged":
        assert not any(row["action"] == "inventory.discover" and row["outcome"] == "ok" for row in rows)


@pytest.mark.parametrize("change", ["move", "reuse"])
def test_queued_scan_cannot_switch_target_ownership_before_execution(verified_app, monkeypatch, change):
    ctx, _, _, _, _ = verified_app
    person = identity()
    run = ScanRun("queued-owner", ["alpha"], requested_by=person.actor,
                  authorization_scopes=resources.capture(ctx, ["alpha"]))
    replace_alpha(ctx, change)
    collected = []
    monkeypatch.setattr(ctx.scanner, "_scan_target", lambda *_: collected.append(True))
    with principal_scope(person), pytest.raises(PermissionError):
        ctx.scanner.run(run)
    assert not collected


@pytest.mark.parametrize("change", ["unchanged", "policy", "session", "move", "reuse"])
def test_scan_rechecks_authorization_before_publishing_collected_facts(verified_app, monkeypatch, change):
    ctx, _, _, _, _ = verified_app
    person = identity()
    revoked = []

    def validity():
        if revoked:
            raise PermissionError("session revoked")

    def collect(target, transport, workdir, **kwargs):
        assert transport.run("hostname").ok
        return Collected(target.id, target.asset_type, str(workdir), facts=AssetFacts(hostname="private scan facts"))

    def detect(target, collected):
        if change == "policy":
            policy = json.loads(ctx.access.path.read_text())
            policy["entries"][0]["grants"] = []
            ctx.access.path.write_text(json.dumps(policy))
        elif change == "session":
            revoked.append(True)
        elif change in {"move", "reuse"}:
            replace_alpha(ctx, change)
        return []

    adapter = SimpleNamespace(discover=lambda *_: AssetFacts(), collect=collect, run_detection=detect)
    monkeypatch.setattr(ctx, "adapter_for", lambda _target: adapter)
    monkeypatch.setattr("cyberthunder.context.make_transport", lambda *_args, **_kwargs: ReadOnlyTransport())
    with principal_scope(person, validity=validity):
        inherited = copy_context()
    with ThreadPoolExecutor(max_workers=1) as pool:
        run = pool.submit(inherited.run, ctx.scanner.start, ["alpha"], requested_by=person.actor,
                          background=False).result(timeout=10)
    raw = ctx.store.scan_dir(run.id) / "raw" / "alpha" / "collected.json"
    if change == "unchanged":
        assert run.status == "done" and run.results["alpha"].facts["hostname"] == "private scan facts"
        assert ctx.store.read_json(raw)["facts"]["hostname"] == "private scan facts"
    else:
        assert run.status == "error" and run.results["alpha"].facts is None
        assert ctx.store.read_json(raw) is None
        assert "private scan facts" not in json.dumps(run.to_dict())
