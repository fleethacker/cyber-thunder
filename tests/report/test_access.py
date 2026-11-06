"""Report ownership contract tests with inert authorization, on both stores.

The resource-stamp implementation is owned by the parent change. This fixture
models its declared interface so this sidecar can be tested at its base commit.
It does not replace integration tests of the real policy or target lifecycle.
"""
from copy import deepcopy
import sys
from types import ModuleType, SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from cyberthunder.api.routes.reports import router
from cyberthunder.report import access, history, onepager, score
from cyberthunder.report.service import ReportService
from tests.report.conftest import SCAN


def stamp(target, environment=None, generation="original"):
    return dict(version=1, target_id=target, environment=environment or target, authorization_id=generation)


@pytest.fixture
def policy(node, monkeypatch):
    owners = {target: stamp(target) for target in ("A", "B", "rhel-01", "sw-01")}
    allowed = set(owners)
    actions = {"export", "audit"}
    calls = []

    def authorize(action, *, target=None, actor=None):
        calls.append((action, target))
        if action not in actions or (target is not None and target not in allowed):
            raise PermissionError("export not granted")

    def authorize_artifact(ctx, scopes, action="read"):
        if ctx.settings.auth_mode == "dev":
            return
        scopes = [scopes] if isinstance(scopes, dict) else scopes
        if not isinstance(scopes, list) or not scopes:
            raise PermissionError("unknown artifact owner")
        for scope in scopes:
            if not isinstance(scope, dict) or scope != owners.get(scope.get("target_id")):
                raise PermissionError("changed or missing owner")
            authorize(action, target=scope["target_id"])

    def capture(ctx, target_ids):
        return [deepcopy(owners[target]) for target in sorted(set(target_ids))]

    def visible(ctx, scopes, action="read"):
        try:
            authorize_artifact(ctx, scopes, action)
            return True
        except PermissionError:
            return False

    module = ModuleType("cyberthunder.security.resources")
    module.authorize_artifact, module.capture, module.visible_artifact = authorize_artifact, capture, visible
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(node, "authorize", authorize)
    return SimpleNamespace(owners=owners, allowed=allowed, actions=actions, calls=calls, ctx=node)


def saved(node, targets, text="secret", **kwargs):
    return history.save(node, "commander", text, "html", targets=targets,
                        authorization_scopes=[stamp(t) for t in targets], **kwargs)


@pytest.mark.parametrize("change", ["no_export", "deleted", "moved", "reused"])
def test_saved_report_owner_checked_before_search_totals_get_download(node, policy, change):
    a = saved(node, ["A"], "A visible")
    b = saved(node, ["B"], "B-ONLY-CONTENT")
    mixed = saved(node, ["A", "B"], "mixed B-ONLY-CONTENT")
    node.settings.auth_mode = "oidc"
    if change == "no_export":
        policy.allowed.remove("B")
    elif change == "deleted":
        del policy.owners["B"]
    elif change == "moved":
        policy.owners["B"] = stamp("B", environment="A")
    else:
        policy.owners["B"] = stamp("B", generation="new-target")
    assert history.search(node)["total"] == 1
    assert history.search(node)["reports"][0]["id"] == a["id"]
    assert history.search(node, q="B-ONLY-CONTENT")["total"] == 0
    assert history.search(node, target="B")["reports"] == []
    assert history.search(node, offset=1, limit=1)["reports"] == []
    app = FastAPI()
    app.state.ctx = node
    app.include_router(router)
    with TestClient(app) as client:
        for doc in (b, mixed):
            assert client.get(f'/reports/history/{doc["id"]}').status_code == 403
            assert client.get(f'/reports/history/{doc["id"]}/download').status_code == 403
        assert client.get(f'/reports/history/{a["id"]}/download').text == "A visible"


@pytest.mark.parametrize("scopes", [None, [], {}, [stamp("B")], [{"target_id": "A"}], "A"])
def test_ambiguous_or_mismatched_ownership_is_denied(node, policy, scopes):
    doc = saved(node, ["A"])
    doc["authorization_scopes"] = scopes
    node.store.write_json(history._path(node, doc["id"]), doc)
    node.settings.auth_mode = "oidc"
    assert history.search(node)["total"] == 0
    with pytest.raises(PermissionError):
        history.get(node, doc["id"])


def test_legacy_import_never_invents_current_ownership(node, policy):
    node.store.write_json(node.store.root / "reports/A.json", {"target": {"id": "A"}, "secret": "legacy"})
    node.ingest.outbox.enqueue("report.poam", "legacy.csv", "B-secret", {})
    node.settings.auth_mode = "oidc"
    assert history.search(node)["total"] == 0
    imported = [node.store.read_json(p) for p in node.store.list_json(node.store.root / "reports/history")]
    assert len(imported) == 2
    assert all(row["authorization_scopes"] == [] for row in imported)
    assert any(row["targets"] == [] for row in imported)
    node.settings.auth_mode = "dev"
    assert history.search(node)["total"] == 2


def bind_inputs(node, monkeypatch):
    """Supply the parent's new model fields without rewriting its schema here."""
    load_run, load_findings, list_proposals = node.store.load_scan_run, node.store.load_findings, node.gate.list

    def runs(sid):
        run = load_run(sid)
        if run:
            run["authorization_scopes"] = [stamp(t) for t in run.get("targets", [])]
        return run

    def findings(*args, **kwargs):
        result = load_findings(*args, **kwargs)
        for finding in result:
            finding.authorization_scope = stamp(finding.host)
        return result

    def proposals(*args, **kwargs):
        result = list_proposals(*args, **kwargs)
        for proposal in result:
            proposal.authorization_scope = stamp(proposal.host)
        return result

    monkeypatch.setattr(node.store, "load_scan_run", runs)
    monkeypatch.setattr(node.store, "load_findings", findings)
    monkeypatch.setattr(node.gate, "list", proposals)


@pytest.mark.parametrize("kind,source", [(kind, source)
    for kind in ("commander", "poam", "checklist", "score") for source in ("run", "finding", "proposal")
    if (kind, source) != ("score", "proposal")])
def test_each_historical_contributor_requires_export_before_render(node, policy, monkeypatch, kind, source, key_dir):
    bind_inputs(node, monkeypatch)
    node.settings.auth_mode = "oidc"
    if source == "run":
        policy.allowed.remove("sw-01")
    elif source == "finding":
        load = node.store.load_findings

        def changed(*args, **kwargs):
            findings = load(*args, **kwargs)
            findings[0].authorization_scope = stamp(findings[0].host, generation="old-owner")
            return findings

        monkeypatch.setattr(node.store, "load_findings", changed)
    else:
        items = node.gate.list()
        items[0].authorization_scope = None
        monkeypatch.setattr(node.gate, "list", lambda: items)
    monkeypatch.setenv("CT_ANSWER_KEY_DIR", str(key_dir))
    with pytest.raises(PermissionError):
        ReportService(node).render_kind(kind, SCAN, "rhel-01")
    assert not node.store.list_json(node.store.root / "reports/history")


def test_capture_includes_contributors_beyond_anchor_and_queue_preserves_it(node, policy, monkeypatch):
    bind_inputs(node, monkeypatch)
    load = node.store.load_scan_run

    def anchor(sid):
        run = load(sid)
        run["targets"] = ["rhel-01"]
        run["authorization_scopes"] = [stamp("rhel-01")]
        return run

    monkeypatch.setattr(node.store, "load_scan_run", anchor)
    queued = []
    monkeypatch.setattr(node.ingest.outbox, "enqueue", lambda kind, name, content, meta, actor: queued.append(meta))
    node.settings.auth_mode = "oidc"
    ReportService(node).queue("poam", SCAN, actor="reviewer")
    expected = [stamp("rhel-01"), stamp("sw-01")]
    assert queued[0]["authorization_scopes"] == expected
    doc = history.get(node, history.search(node)["reports"][0]["id"])
    assert doc["authorization_scopes"] == expected
    assert doc["targets"] == ["rhel-01", "sw-01"]
    policy.allowed.remove("sw-01")
    with pytest.raises(PermissionError):
        ReportService(node).queue("poam", SCAN)
    assert len(queued) == 1


def test_authority_change_during_render_prevents_save_and_queue(node, policy, monkeypatch):
    bind_inputs(node, monkeypatch)
    from cyberthunder.report import poam
    render = poam.poam_csv

    def revoked(*args):
        text = render(*args)
        policy.allowed.remove("sw-01")
        return text

    monkeypatch.setattr(poam, "poam_csv", revoked)
    monkeypatch.setattr(node.ingest.outbox, "enqueue", lambda *a, **kw: pytest.fail("unauthorized queue"))
    node.settings.auth_mode = "oidc"
    with pytest.raises(PermissionError):
        ReportService(node).queue("poam", SCAN)
    assert not node.store.list_json(node.store.root / "reports/history")


def test_discovery_denial_is_never_swallowed(node, policy, monkeypatch):
    node.settings.auth_mode = "oidc"
    finding = node.findings["root"]  # Deliberately unstamped historical data.
    monkeypatch.setattr(node.discovery, "findings", lambda: [finding])
    monkeypatch.setattr(node.discovery, "runs", lambda: [SimpleNamespace(status="finished")])
    with pytest.raises(PermissionError):
        onepager.discovery_open(node)
    with pytest.raises(PermissionError):
        score._discovery_findings(node)


@pytest.mark.parametrize("kind", ["fleet", "friction", "coverage"])
def test_node_export_does_not_imply_global_audit(node, policy, kind):
    node.settings.auth_mode = "oidc"
    policy.actions.remove("audit")
    with pytest.raises(PermissionError):
        ReportService(node).render_kind(kind)
    assert ("audit", None) in policy.calls


def test_empty_new_snapshot_is_not_authorized_by_node_export(node, policy):
    node.settings.auth_mode = "oidc"
    with pytest.raises(PermissionError):
        history.save(node, "commander", "unclassified", "html", targets=[])
    assert not node.store.list_json(node.store.root / "reports/history")


@pytest.mark.parametrize("complete", [False, True])
def test_dev_render_preserves_known_ownership_without_promoting_partial_ownership(node, policy, complete):
    with access.collecting(node):
        access.artifact(node, [stamp("A")], targets=["A"])
        access.artifact(node, [stamp("B")] if complete else None, targets=["B"])
        doc = history.save(node, "commander", "A and B", "html", targets=["A", "B"])
    assert doc["authorization_scopes"] == ([stamp("A"), stamp("B")] if complete else [])
    node.settings.auth_mode = "oidc"
    assert history.search(node)["total"] == int(complete)


def test_legacy_answer_key_cannot_export_unscanned_target_facts(node, policy, monkeypatch, key_dir):
    bind_inputs(node, monkeypatch)
    node.settings.auth_mode = "oidc"
    with pytest.raises(PermissionError, match="unknown artifact owner"):
        ReportService(node).score(SCAN, str(key_dir))


def test_denied_content_is_not_searched(node, policy, monkeypatch):
    saved(node, ["B"], "B-SECRET")
    node.settings.auth_mode = "oidc"
    policy.allowed.remove("B")
    original = history.json.dumps

    def dumps(value, *args, **kwargs):
        if isinstance(value, dict) and value.get("content") == "B-SECRET":
            pytest.fail("unauthorized report content reached search matching")
        return original(value, *args, **kwargs)

    monkeypatch.setattr(history.json, "dumps", dumps)
    assert history.search(node, q="secret")["total"] == 0
