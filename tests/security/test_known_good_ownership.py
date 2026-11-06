"""Known-good suppression and management stay with the original inventory generation."""
from contextlib import contextmanager
from copy import deepcopy
import importlib
import sys
from types import ModuleType, SimpleNamespace

import pytest

from cyberthunder.adapters.kubernetes.known_good import KnownGoodException, KubernetesKnownGoodState
from cyberthunder.adapters.kubernetes.kubectl import OBJ_TAG
from cyberthunder.api.routes import cluster
from cyberthunder.api.schemas import KnownGoodBody, KnownGoodFromFindingBody
from cyberthunder.findings.schema import Finding, Severity, Status
from cyberthunder.store import StateStore


def scope_of(target):
    return {"version": 1, "target_id": target.id, "environment": target.environment,
            "authorization_id": target.authorization_id}


def principal(subject="alice", *, roles=("admin", "read", "scan")):
    return SimpleNamespace(issuer="https://issuer.test", subject=subject, actor=f"human:{subject}",
                           verified=True, roles=roles)


@pytest.fixture
def identity(monkeypatch):
    state = SimpleNamespace(principal=principal())
    try:
        module = importlib.import_module("cyberthunder.control.principal")
    except ModuleNotFoundError as exc:
        if exc.name != "cyberthunder.control.principal":
            raise
        module = ModuleType("cyberthunder.control.principal")
        module.authorize = lambda ctx, action, **kw: ctx.authorize(action, **kw)
        monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(module, "current_principal", lambda: state.principal, raising=False)
    return state


@pytest.fixture
def ownership_seam(monkeypatch, identity):
    # Use the parent's real ownership helpers when present. This branch also supports
    # testing before those shared files land, with the same narrow public contract.
    try:
        return importlib.import_module("cyberthunder.security.resources")
    except ModuleNotFoundError as exc:
        if exc.name != "cyberthunder.security.resources":
            raise
    module = ModuleType("cyberthunder.security.resources")
    module.target_scope = scope_of

    def authorize_artifact(ctx, scopes, action="read"):
        if ctx.settings.auth_mode == "dev":
            return
        if isinstance(scopes, dict):
            scopes = [scopes]
        if not isinstance(scopes, list) or not scopes:
            raise PermissionError("artifact ownership is unavailable")
        for scope in scopes:
            try:
                current = ctx.inventory.get(scope["target_id"])
                if scope != scope_of(current):
                    raise ValueError
            except (KeyError, TypeError, ValueError):
                raise PermissionError("artifact belongs to an unavailable or changed target") from None
            ctx.authorize(action, target=current)

    def visible_artifact(ctx, scopes, action="read"):
        try:
            authorize_artifact(ctx, scopes, action)
            return True
        except PermissionError:
            return False

    def object_scopes(obj):
        scope = getattr(obj, "authorization_scope", None)
        return scope if isinstance(scope, dict) and scope.get("target_id") == obj.host else None

    module.authorize_artifact = authorize_artifact
    module.visible_artifact = visible_artifact
    module.object_scopes = object_scopes
    module.check_record = lambda ctx, obj, action="read": authorize_artifact(ctx, object_scopes(obj), action)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module


class Inventory:
    path = None

    def __init__(self):
        self.targets = {
            "cluster-a": SimpleNamespace(id="cluster-a", asset_type="kubernetes", environment="env-a",
                                         authorization_id="a" * 32, in_scope=True),
            "cluster-b": SimpleNamespace(id="cluster-b", asset_type="kubernetes", environment="env-b",
                                         authorization_id="b" * 32, in_scope=True),
        }

    def get(self, target_id):
        return deepcopy(self.targets[target_id])


class Context:
    def __init__(self, store, identity):
        self.store, self.identity = store, identity
        self.settings = SimpleNamespace(auth_mode="oidc")
        self.inventory = Inventory()
        self.grants = {("alice", "cluster-a", "env-a", action) for action in ("admin", "read", "scan")}
        self.grants |= {("bob", "cluster-b", "env-b", action) for action in ("admin", "read", "scan")}
        self.calls, self.events = [], []
        self.audit = SimpleNamespace(append=lambda *args, **kw: self.events.append((args, kw)))

    def authorize(self, action, *, actor=None, target=None):
        if self.settings.auth_mode == "dev":
            return None
        who = self.identity.principal
        self.calls.append((action, actor, getattr(target, "id", target)))
        if (who is None or not who.verified or action not in who.roles
                or (actor is not None and actor != who.actor)):
            raise PermissionError("identity or role denied")
        try:
            current = self.inventory.get(target if isinstance(target, str) else target.id)
        except (KeyError, AttributeError):
            raise PermissionError("target denied") from None
        if (who.subject, current.id, current.environment, action) not in self.grants:
            raise PermissionError("target denied")
        if action == "scan" and not current.in_scope:
            raise PermissionError("target is out of scope")
        return who


@pytest.fixture
def ctx(state_dir, identity, ownership_seam):
    store = StateStore(state_dir)
    yield Context(store, identity)
    store.close()


@pytest.fixture
def state(ctx):
    return KubernetesKnownGoodState(ctx.store, ctx=ctx)


def finding(target_id="cluster-a"):
    return Finding(host=target_id, source="hunt", asset_type="kubernetes", rule_id="rule-one",
                   title="Unexpected pod", severity=Severity.HIGH, status=Status.OPEN,
                   tags=[f"{OBJ_TAG}kube-system/pod/collector-abc123"])


def add(state, **kw):
    return state.add(**{"actor": "human:alice", "reason": "approved collector", "target_id": "cluster-a",
                        "rule_id": "rule-one", **kw})


def raw_rows(state):
    return state.store.read_json(state.path, {}).get("exceptions", [])


def write_rows(state, rows):
    state.store.write_json(state.path, {"schema_version": "1.0", "exceptions": rows})


def test_add_captures_original_scope_and_does_not_retain_a_mutable_inventory_alias(ctx, state):
    item = add(state)
    original = scope_of(ctx.inventory.get("cluster-a"))
    assert item.target_scope == original
    assert raw_rows(state)[0]["target_scope"] == original
    item.target_scope["environment"] = "caller-edit"
    ctx.inventory.targets["cluster-a"].environment = "moved"
    assert raw_rows(state)[0]["target_scope"] == original
    assert all(target is not None for _, _, target in ctx.calls)


def test_list_filters_each_current_account_before_returning_reasons(ctx, state, identity):
    first = add(state)
    identity.principal = principal("bob")
    second = add(state, actor="human:bob", target_id="cluster-b", reason="other account's exception")
    assert [x.id for x in state.list()] == [second.id]
    identity.principal = principal()
    assert [x.id for x in state.list()] == [first.id]
    ctx.grants.remove(("alice", "cluster-a", "env-a", "read"))
    assert state.list() == []


@pytest.mark.parametrize("problem", ["role", "target_grant", "actor", "missing_actor", "other_target"])
def test_add_requires_both_target_admin_and_exact_actor(ctx, state, identity, problem):
    kw = {}
    if problem == "role":
        identity.principal = principal(roles=("read", "scan"))
    elif problem == "target_grant":
        ctx.grants.remove(("alice", "cluster-a", "env-a", "admin"))
    elif problem == "actor":
        kw["actor"] = "human:bob"
    elif problem == "missing_actor":
        kw["actor"] = None
    else:
        kw["target_id"] = "cluster-b"
    with pytest.raises(PermissionError):
        add(state, **kw)
    assert raw_rows(state) == []


@pytest.mark.parametrize("actor", [None, "", "human:bob"])
def test_delete_rejects_omitted_or_forged_actor_without_writing(ctx, state, actor):
    item = add(state)
    before = raw_rows(state)
    with pytest.raises(PermissionError):
        state.delete(item.id, actor=actor)
    assert raw_rows(state) == before


@pytest.mark.parametrize("problem", ["role", "target_grant", "other_account"])
def test_delete_is_not_allowed_by_read_or_admin_role_alone(ctx, state, identity, problem):
    item = add(state)
    before = raw_rows(state)
    if problem == "role":
        identity.principal = principal(roles=("read", "scan"))
    elif problem == "target_grant":
        ctx.grants.remove(("alice", "cluster-a", "env-a", "admin"))
    else:
        identity.principal = principal("bob")
    with pytest.raises(PermissionError):
        state.delete(item.id, actor=identity.principal.actor)
    assert raw_rows(state) == before


@pytest.mark.parametrize("change", ["deleted", "recreated", "environment"])
def test_old_scope_cannot_be_listed_deleted_or_used_to_suppress(ctx, state, change):
    item = add(state)
    before = raw_rows(state)
    if change == "deleted":
        del ctx.inventory.targets["cluster-a"]
    elif change == "recreated":
        ctx.inventory.targets["cluster-a"].authorization_id = "c" * 32
    else:
        ctx.inventory.targets["cluster-a"].environment = "env-b"
        ctx.grants |= {("alice", "cluster-a", "env-b", a) for a in ("admin", "read", "scan")}
    f = finding()
    assert state.list() == []
    assert state.match(f) is None
    assert state.apply([f]) == []
    assert f.status == Status.OPEN and "known-good:" not in str(f.tags)
    with pytest.raises(PermissionError):
        state.delete(item.id, actor="human:alice")
    assert raw_rows(state) == before


@pytest.mark.parametrize("scope_change", [None, {}, {"version": True}, {"extra": "field"},
                                         {"target_id": "cluster-b"}, {"environment": ""},
                                         {"authorization_id": "old-generation"}])
def test_legacy_or_confused_ownership_never_suppresses_or_gets_retrofitted(ctx, state, scope_change):
    row = KnownGoodException(id="legacy", target_id="cluster-a", rule_id="rule-one").to_dict()
    if scope_change is None:
        row.pop("target_scope")
    elif scope_change == {}:
        row["target_scope"] = {}
    else:
        row["target_scope"] = {**scope_of(ctx.inventory.get("cluster-a")), **scope_change}
    write_rows(state, [row])
    assert state.list() == []
    assert state.match(finding()) is None
    assert state.apply([finding()]) == []
    with pytest.raises(PermissionError):
        state.delete("legacy", actor="human:alice")
    assert raw_rows(state) == [row]


def test_counter_update_preserves_unrelated_legacy_rows_exactly(ctx, state):
    legacy = {"id": "legacy", "target_id": "cluster-a", "rule_id": "rule-one", "custom_metadata": "retain"}
    write_rows(state, [legacy])
    item = add(state)
    assert state.apply([finding(), finding()]) == [item.id, item.id]
    rows = raw_rows(state)
    assert rows[0] == legacy and "target_scope" not in rows[0]
    assert rows[1]["target_scope"] == item.target_scope
    assert rows[1]["match_count"] == 2 and rows[1]["last_matched_at"]


def test_fresh_unstamped_findings_use_current_scope_and_scan_permission(ctx, state, identity):
    item = add(state)
    identity.principal = principal(roles=("scan",))
    ctx.grants = {("alice", "cluster-a", "env-a", "scan")}
    f = finding()
    assert getattr(f, "authorization_scope", None) is None
    assert state.list() == []
    assert state.apply([f]) == [item.id]
    assert f.status == Status.NOT_APPLICABLE


def test_read_permission_does_not_permit_suppression_and_revocation_is_immediate(ctx, state):
    item = add(state)
    assert state.match(finding()).id == item.id
    ctx.grants.remove(("alice", "cluster-a", "env-a", "scan"))
    assert [x.id for x in state.list()] == [item.id]
    f = finding()
    assert state.apply([f]) == [] and f.status == Status.OPEN


def test_scope_is_rechecked_for_each_finding_not_cached_per_state_instance(ctx, state, monkeypatch):
    item = add(state)
    original = state._visible
    checks = 0

    def moving(item, action):
        nonlocal checks
        checks += 1
        if checks == 2:
            ctx.inventory.targets["cluster-a"].authorization_id = "d" * 32
        return original(item, action)

    monkeypatch.setattr(state, "_visible", moving)
    first, second = finding(), finding()
    assert state.apply([first, second]) == [item.id]
    assert first.status == Status.NOT_APPLICABLE and second.status == Status.OPEN
    assert raw_rows(state)[0]["target_scope"] == item.target_scope


def test_out_of_scope_inventory_still_allows_explicit_read_admin_but_not_suppression(ctx, state):
    ctx.inventory.targets["cluster-a"].in_scope = False
    item = add(state)
    assert [x.id for x in state.list()] == [item.id]
    assert state.apply([finding()]) == []
    assert state.delete(item.id, actor="human:alice") is True


@pytest.mark.parametrize("operation", ["list", "add", "delete", "match", "apply"])
@pytest.mark.parametrize("context_kind", ["missing", "dev"])
def test_verified_identity_cannot_fall_back_to_contextless_or_dev_behavior(ctx, identity, monkeypatch,
                                                                         operation, context_kind):
    ctx.settings.auth_mode = "dev"
    unsafe = KubernetesKnownGoodState(ctx.store, ctx=ctx if context_kind == "dev" else None)

    def forbidden(*args, **kwargs):
        raise AssertionError("contextless verified call reached storage")

    monkeypatch.setattr(ctx.store, "read_json", forbidden)
    calls = {"list": unsafe.list, "add": lambda: add(unsafe), "delete": lambda: unsafe.delete("unknown"),
             "match": lambda: unsafe.match(finding()), "apply": lambda: unsafe.apply([finding()])}
    with pytest.raises(PermissionError, match="application context"):
        calls[operation]()


@pytest.mark.parametrize("change", ["missing_stamp", "recreated", "environment", "wrong_host"])
def test_add_from_finding_requires_original_record_ownership(ctx, state, change):
    f = finding()
    f.authorization_scope = scope_of(ctx.inventory.get(f.host))
    if change == "missing_stamp":
        f.authorization_scope = None
    elif change == "recreated":
        ctx.inventory.targets[f.host].authorization_id = "e" * 32
    elif change == "environment":
        ctx.inventory.targets[f.host].environment = "env-b"
        ctx.grants.add(("alice", f.host, "env-b", "admin"))
    else:
        f.authorization_scope["target_id"] = "cluster-b"
    with pytest.raises(PermissionError):
        state.add_from_finding(f, actor="human:alice", reason="reviewed")
    assert raw_rows(state) == []


def test_authorized_record_creates_exception_with_the_original_scope(ctx, state):
    f = finding()
    f.authorization_scope = scope_of(ctx.inventory.get(f.host))
    item = state.add_from_finding(f, actor="human:alice", reason="reviewed", scope="rule")
    assert item.target_scope == f.authorization_scope
    assert item.finding_id == f.id and item.rule_id == f.rule_id


def test_target_change_before_save_is_denied_without_rebinding(ctx, state, monkeypatch):
    original = ctx.store.lock

    @contextmanager
    def changed(name):
        with original(name):
            ctx.inventory.targets["cluster-a"].authorization_id = "f" * 32
            yield

    monkeypatch.setattr(ctx.store, "lock", changed)
    with pytest.raises(PermissionError):
        add(state)
    assert raw_rows(state) == []


def test_duplicate_exception_identity_cannot_delete_another_rows_ownership(ctx, state):
    item = add(state)
    first = raw_rows(state)[0]
    other = {**first, "target_id": "cluster-b", "target_scope": scope_of(ctx.inventory.get("cluster-b"))}
    write_rows(state, [first, other])
    with pytest.raises(PermissionError, match="ambiguous"):
        state.delete(item.id, actor="human:alice")
    assert raw_rows(state) == [first, other]


@pytest.mark.parametrize("disabled", [True, False])
def test_disabled_or_expired_exception_does_not_suppress(ctx, state, disabled):
    row = add(state).to_dict()
    row.update(enabled=not disabled, expires_at=None if disabled else "2000-01-01T00:00:00Z")
    write_rows(state, [row])
    assert len(state.list()) == 1 and state.list(include_disabled=False) == []
    assert state.apply([finding()]) == []


def test_legacy_development_can_still_suppress_and_delete_unowned_exceptions(ctx, identity):
    identity.principal = None
    legacy = KubernetesKnownGoodState(ctx.store)
    item = add(legacy, actor="local operator")
    assert item.target_scope is None
    assert legacy.apply([finding()]) == [item.id]
    assert legacy.delete(item.id) is True


def test_development_with_current_context_captures_new_scope(ctx, identity):
    identity.principal = None
    ctx.settings.auth_mode = "dev"
    item = add(KubernetesKnownGoodState(ctx.store, ctx=ctx), actor="local operator")
    assert item.target_scope == scope_of(ctx.inventory.get("cluster-a"))


def test_cluster_routes_pass_context_and_actor_and_audit_only_authorized_mutations(ctx, state, identity):
    body = KnownGoodBody(target_id="cluster-a", rule_id="rule-one", reason="reviewed")
    item = cluster.add_known_good(body, ctx=ctx, actor="human:alice")
    assert item["target_scope"] == scope_of(ctx.inventory.get("cluster-a"))
    assert cluster.known_good(ctx=ctx)["exceptions"][0]["id"] == item["id"]
    identity.principal = principal("bob")
    assert cluster.known_good(ctx=ctx) == {"exceptions": []}
    with pytest.raises(PermissionError):
        cluster.delete_known_good(item["id"], ctx=ctx, actor="human:bob")
    with pytest.raises(PermissionError):
        cluster.add_known_good(body, ctx=ctx, actor="human:bob")
    assert len(ctx.events) == 1
    identity.principal = principal()
    with pytest.raises(PermissionError):
        cluster.delete_known_good(item["id"], ctx=ctx, actor="human:bob")
    cluster.delete_known_good(item["id"], ctx=ctx, actor="human:alice")
    assert raw_rows(state) == [] and len(ctx.events) == 2


def test_cluster_from_finding_route_cannot_rebind_stale_records(ctx, state, monkeypatch):
    f = finding()
    f.authorization_scope = scope_of(ctx.inventory.get(f.host))
    monkeypatch.setattr(cluster, "get_finding", lambda *_: f)
    ctx.inventory.targets[f.host].authorization_id = "9" * 32
    with pytest.raises(PermissionError):
        cluster.add_known_good_from_finding(f.id, KnownGoodFromFindingBody(reason="reviewed"),
                                             ctx=ctx, actor="human:alice")
    assert not ctx.events and not raw_rows(state)
