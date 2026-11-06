"""Independent source-history isolation and sanitized failure regressions."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from contextvars import copy_context
from dataclasses import replace
import threading

import pytest

from cyberthunder.control.principal import principal_scope
from .test_vsphere_account_access import configured, identity
from .test_vsphere_runs import BASE, client, collect, documents, limited, source
from cyberthunder.security.resources import target_scope
from .vsphere_support import FIX, PASSWORD, Response, envelope


@pytest.mark.parametrize("view", ["list", "get"])
def test_same_source_read_grant_does_not_share_other_collectors_history(source, client, view):
    f = source
    f.policy([limited(), limited("bob", ref="BOB_VC")])
    f.who = identity("bob")
    response = collect(client)
    assert response.status_code == 200 and response.json()["observation_count"] == 4
    run = response.json()
    f.who = identity("alice")
    if view == "list":
        response = client.get(BASE + "vc/runs")
        assert response.status_code == 200 and response.json() == []
    else:
        response = client.get(BASE + "vc/runs/" + run["id"])
        assert response.status_code == 404
    assert run["id"] not in response.text and "build-box" not in response.text


@pytest.mark.parametrize("view", ["list", "get"])
def test_history_storage_permission_error_does_not_echo_exception_text(source, client, monkeypatch, view):
    f = source
    run = collect(client).json()
    original = f.ctx.store.read_json

    def unavailable(path, *args, **kwargs):
        if str(path).endswith(run["id"] + ".json"):
            raise PermissionError(PASSWORD)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(f.ctx.store, "read_json", unavailable)
    response = client.get(BASE + "vc/runs" + ("/" + run["id"] if view == "get" else ""))
    assert response.status_code in {403, 503}
    assert PASSWORD not in response.text
    assert response.json()["detail"].startswith("vsphere:")


@pytest.mark.parametrize("exception", [ValueError, OSError, RuntimeError])
def test_history_storage_failures_are_sanitized_unavailability(source, client, monkeypatch, exception):
    f = source
    run = collect(client).json()
    original = f.ctx.store.read_json

    def unavailable(path, *args, **kwargs):
        if str(path).endswith(run["id"] + ".json"):
            raise exception(PASSWORD)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(f.ctx.store, "read_json", unavailable)
    for suffix in ("", "/" + run["id"]):
        response = client.get(BASE + "vc/runs" + suffix)
        assert response.status_code == 503
        assert response.json() == {"detail": "vsphere:history_unavailable"}


def test_narrower_remote_collection_does_not_inherit_broader_same_source_history(source, client, monkeypatch):
    f = source
    f.policy([limited(), limited("bob", ref="BOB_VC")])
    f.who = identity("bob")
    broad = collect(client).json()
    assert broad["observation_count"] == 4
    f.who = identity("alice")
    f.server.overrides["RetrievePropertiesEx"] = lambda: Response(envelope("RetrievePropertiesEx"))
    narrow = collect(client).json()
    assert narrow["complete"] and narrow["observation_count"] == 0
    before = len(f.server.calls)
    # A source-history read must neither contact the source nor enumerate another user's records.
    read = f.ctx.store.read_json
    broad_path = next(p for p in f.ctx.store.list_json(f.runs.directory, "*/*.json") if p.stem == broad["id"])

    def own_only(path, *args, **kwargs):
        assert path != broad_path
        return read(path, *args, **kwargs)

    monkeypatch.setattr(f.ctx.store, "read_json", own_only)
    for limit in (1, 100):
        response = client.get(BASE + f"vc/runs?limit={limit}")
        assert [run["id"] for run in response.json()] == [narrow["id"]]
    assert client.get(BASE + "vc/runs/" + broad["id"]).status_code == 404
    assert client.get(BASE + "vc/runs/" + narrow["id"]).json() == narrow
    assert len(f.server.calls) == before


@pytest.mark.parametrize("sharing", ["same-subject-other-issuer", "same-remote-account"])
def test_no_implicit_sharing_by_subject_or_remote_credential(source, client, sharing):
    f = source
    run = collect(client).json()
    if sharing == "same-subject-other-issuer":
        f.who = identity(issuer="https://other-issuer.example.test")
        row = limited()
        row["issuer"] = f.who.issuer
    else:
        f.who = identity("bob")
        row = limited()
        # Deliberately identical credential, roles and source grant; different verified user.
        row["subject"] = "bob"
    f.policy([row])
    assert client.get(BASE + "vc/runs").json() == []
    assert client.get(BASE + "vc/runs/" + run["id"]).status_code == 404


def test_collector_history_survives_session_rotation_with_read_only_grant(source, client):
    f = source
    run = collect(client).json()
    row = limited()
    row["grants"][0].pop("credential")
    row["grants"][0]["actions"] = ["read"]
    f.policy([row])
    f.who = replace(f.who, display_name="Renamed operator", roles=("viewer",), session_id="new-session")
    assert client.get(BASE + "vc/runs/" + run["id"]).json() == run
    assert [r["id"] for r in client.get(BASE + "vc/runs").json()] == [run["id"]]
    assert collect(client).status_code == 403


@pytest.mark.parametrize("record", ["foreign-collector", "legacy-no-collector", "development"])
def test_misplaced_history_cannot_inherit_directory_collector(source, client, record):
    f = source
    f.policy([limited(), limited("bob", ref="BOB_VC")])
    run = collect(client).json()
    stored = documents(f)[0]
    if record == "foreign-collector":
        f.who = identity("bob")
    elif record == "legacy-no-collector":
        stored.pop("collector_scope")
    else:
        stored["collector_scope"] = {"version": 1, "mode": "dev"}
    with principal_scope(f.who):
        directory = f.runs._directory(target_scope(f.target), f.runs._collector())
    f.ctx.store.write_json(directory / (run["id"] + ".json"), stored)
    assert client.get(BASE + "vc/runs").json() == []
    assert client.get(BASE + "vc/runs/" + run["id"]).status_code == 404


@pytest.mark.parametrize("view", ["list", "get"])
def test_collector_change_during_history_read_is_refused(source, monkeypatch, view):
    f = source
    f.policy([limited(), limited("bob", ref="BOB_VC")])
    with principal_scope(f.who), ExitStack() as contexts:
        run = f.runs.collect("vc", f.who.actor)
        read = f.ctx.store.read_json

        def change_reader(path, *args, **kwargs):
            result = read(path, *args, **kwargs)
            if str(path).endswith(run["id"] + ".json"):
                contexts.enter_context(principal_scope(identity("bob")))
            return result

        monkeypatch.setattr(f.ctx.store, "read_json", change_reader)
        with pytest.raises(PermissionError):
            f.runs.runs("vc") if view == "list" else f.runs.get("vc", run["id"])


def test_deleted_and_recreated_source_never_reassigns_collectors_history(source, client):
    f = source
    run = collect(client).json()
    f.ctx.inventory.remove("vc")
    f.ctx.inventory.save()
    for suffix in ("", "/" + run["id"]):
        # The shared resource guard refuses a deleted source before route lookup.
        assert client.get(BASE + "vc/runs" + suffix).status_code == 403
    f.ctx.inventory.add_new(replace(f.target))
    f.ctx.inventory.save()
    assert target_scope(f.ctx.inventory.get("vc")) != run["authorization_scope"]
    assert client.get(BASE + "vc/runs").json() == []
    assert client.get(BASE + "vc/runs/" + run["id"]).status_code == 404


def test_concurrent_different_collectors_preserve_separate_history(source, monkeypatch):
    f = source
    f.policy([limited(), limited("bob", ref="BOB_VC")])
    response = f.server.response

    def repeatable(method):
        if method in {"RetrievePropertiesEx", "ContinueRetrievePropertiesEx"}:
            return Response((FIX / ("page1.xml" if method == "RetrievePropertiesEx" else "page2.xml")).read_bytes())
        return response(method)

    monkeypatch.setattr(f.server, "response", repeatable)
    barrier = threading.Barrier(2)
    f.server.after = lambda method: barrier.wait(timeout=15) if method == "RetrieveServiceContent" else None
    people = [identity(), identity("bob")]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = []
        for who in people:
            with principal_scope(who):
                futures.append(pool.submit(copy_context().run, f.runs.collect, "vc", who.actor))
        results = [future.result(timeout=45) for future in futures]
    assert len({r["id"] for r in results}) == 2 and all(r["complete"] for r in results)
    for who, own, other in ((people[0], results[0], results[1]), (people[1], results[1], results[0])):
        with principal_scope(who):
            assert [r["id"] for r in f.runs.runs("vc")] == [own["id"]]
            assert f.runs.get("vc", own["id"]) == own
            with pytest.raises(KeyError):
                f.runs.get("vc", other["id"])
    paths = f.ctx.store.list_json(f.runs.directory, "*/*.json")
    assert len(paths) == 2 and len({p.parent for p in paths}) == 2
    assert f.ctx.audit.verify().ok


@pytest.mark.parametrize("change", ["reference", "username", "selector", "read-only-mapping", "ambiguous"])
def test_credential_mapping_change_revokes_old_source_history(source, change):
    f = source
    who = replace(f.who, groups=("operators",))
    with principal_scope(who):
        run = f.runs.collect("vc", who.actor)
    row = limited()
    if change in {"reference", "read-only-mapping"}:
        row["grants"][0]["credential"]["credential_ref"] = "BOB_VC"
    elif change == "username":
        row["grants"][0]["credential"]["username"] = "narrower@lab"
    elif change == "selector":
        row = limited(group="operators")
    if change == "read-only-mapping":
        row["grants"][0]["actions"] = ["read"]
    rows = [row]
    if change == "ambiguous":
        rows.append(limited(group="operators", ref="BOB_VC"))
    f.policy(rows)
    with principal_scope(replace(who, roles=("viewer",))):
        assert f.runs.runs("vc") == []
        with pytest.raises(PermissionError):
            f.runs.get("vc", run["id"])


@pytest.mark.parametrize("mapping", ["removed", "unchanged-read-only", "unrelated-policy"])
def test_history_binding_check_needs_neither_discover_grant_nor_credentials(source, monkeypatch, mapping):
    f = source
    with principal_scope(f.who):
        run = f.runs.collect("vc", f.who.actor)
    row = limited()
    row["grants"][0]["actions"] = ["read"]
    if mapping == "removed":
        row["grants"][0].pop("credential")
    rows = [row]
    if mapping == "unrelated-policy":
        rows.append(limited("bob", target="vc-b", environment="B", ref="BOB_VC"))
        rows[-1]["node_actions"] = ["read"]
    f.policy(rows)
    from cyberthunder.discovery.sources import vsphere
    from cyberthunder.discovery.sources.vsphere_access import SourceAccess
    def forbidden(*args, **kwargs):
        pytest.fail("history must not select or resolve credentials or contact vCenter")
    monkeypatch.setattr(f.ctx.access, "credential", forbidden)
    monkeypatch.setattr(SourceAccess, "credentials", forbidden)
    monkeypatch.setattr(vsphere, "InventoryClient", forbidden)
    with principal_scope(replace(f.who, roles=("viewer",))):
        assert f.runs.get("vc", run["id"]) == run
        assert [r["id"] for r in f.runs.runs("vc")] == [run["id"]]


@pytest.mark.parametrize("view", ["list", "get"])
def test_mapping_change_during_history_load_cannot_publish_old_inventory(source, monkeypatch, view):
    f = source
    with principal_scope(f.who):
        run = f.runs.collect("vc", f.who.actor)
    read = f.ctx.store.read_json

    def remap(path, *args, **kwargs):
        result = read(path, *args, **kwargs)
        if str(path).endswith(run["id"] + ".json"):
            f.policy([limited(ref="BOB_VC")])
        return result

    monkeypatch.setattr(f.ctx.store, "read_json", remap)
    with principal_scope(replace(f.who, roles=("viewer",))):
        if view == "list":
            assert f.runs.runs("vc") == []
        else:
            with pytest.raises(PermissionError):
                f.runs.get("vc", run["id"])


def test_unchanged_split_read_discover_selectors_preserve_own_history(source):
    f = source
    discovery, reading = limited(), limited(group="readers")
    discovery["grants"][0]["actions"] = ["discover"]
    reading["grants"][0]["actions"] = ["read"]
    f.policy([discovery, reading])
    who = replace(f.who, groups=("readers",))
    with principal_scope(who):
        run = f.runs.collect("vc", who.actor)
        assert f.runs.get("vc", run["id"]) == run
        assert [r["id"] for r in f.runs.runs("vc")] == [run["id"]]
    # Retiring only the discover mapping must not require discover on history.
    f.policy([reading])
    with principal_scope(replace(who, roles=("viewer",))):
        assert f.runs.get("vc", run["id"]) == run
