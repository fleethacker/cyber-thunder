"""Complete authorized query views, with real JSON/SQLite history and fixture-only accounts."""
from copy import deepcopy
import json

import pytest

from cyberthunder.api import util
from cyberthunder.findings.reassessment import ReassessmentView
from tests.api.test_findings_query import ids, query
from tests.findings.test_reassessment import OLD, LATER, NEWEST, observation, save_run, seed
from tests.security.test_identity_boundary import verified_app, headers, identity

URL = "/api/v1/findings"


def counts(page):
    return {o["value"]: o["count"] for o in page["facets"]["reassessment"]}


@pytest.fixture
def catalog(ctx):
    seed(ctx)
    rows = [observation(id=f"gap-{i:03}", rule_id=f"rule-{i:03}", benchmark="RHEL 9 STIG", benchmark_release="V2R1",
                        collection_provenance={"observed_at": "2026-11-05T09:00:00Z"}) for i in range(203)]
    rows += [observation(id="no-gap", rule_id="other-rule"),
             observation(id="unknown-time", collection_provenance={"observed_at": None}),
             observation(id="unknown-producer", source="scanner-import")]
    ctx.store.save_findings("base", rows)
    save_run(ctx, rule_filter=[f.rule_id for f in rows[:203]])
    return ctx.store.load_findings()


def test_full_view_combined_filters_facets_pages_and_no_query_side_effects(client, ctx, catalog, monkeypatch):
    before = [f.to_dict() for f in catalog]
    audit = len(ctx.audit)
    decorated = []
    original = util.finding_plus

    def decorate(context, finding, *args, **kwargs):
        decorated.append(finding.id)
        return original(context, finding, *args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("A read-only query attempted generation or persistence")

    monkeypatch.setattr(util, "finding_plus", decorate)
    for owner, name in ((ctx.explain, "explain"), (ctx.explain, "precompute"), (ctx.engine, "propose"),
                        (ctx.store, "save_findings"), (ctx.store, "save_scan_run"), (ctx.audit, "append")):
        monkeypatch.setattr(owner, name, forbidden)
    params = dict(reassessment="not_reassessed", status="open", category="stig", host="alpha", source="native",
                  benchmark="RHEL 9 STIG", benchmark_release="V2R1", review="unreviewed", q="SSH",
                  sort_by="observed_at", sort_dir="desc")
    page = query(client, **params, limit=200)
    tail = query(client, **params, limit=200, offset=200)
    assert ids(page) == [f"gap-{i:03}" for i in range(200)]
    assert ids(tail) == ["gap-200", "gap-201", "gap-202"]
    assert page["total"] == tail["total"] == 203
    assert page["unfiltered_total"] == page["summary"]["total"] == 206
    assert counts(page) == counts(tail) == {"not_reassessed": 203, "no_known_gap": 1, "unknown": 2}
    assert len(decorated) == 203, "Only returned rows need explanation/fix/proposal decoration"
    none = query(client, **{**params, "q": "absent text"}, offset=10000)
    assert none["findings"] == [] and none["total"] == 0 and none["facets"] == page["facets"]
    union = query(client, reassessment='"NO_KNOWN_GAP",unknown', confidence="high,medium,low,unknown")
    assert set(ids(union)) == {"no-gap", "unknown-time", "unknown-producer"}
    for row in tail["findings"]:
        detail = client.get(f"{URL}/{row['id']}").json()
        assert row["reassessment"] == detail["reassessment"]
    assert [f.to_dict() for f in ctx.store.load_findings()] == before
    assert len(ctx.audit) == audit


@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_observation_instants_ties_and_missing_times_differ_from_collection(client, ctx, direction):
    seed(ctx)
    observed = {"early": "2026-11-05T08:00:00Z", "tie-b": "2026-11-05T04:00:00-05:00",
                "tie-a": "2026-11-05T09:00:00Z", "late": "2026-11-05T10:00:00+00:00",
                "missing-b": "invalid", "missing-a": None, "missing-c": "2026-11-05T12:00:00"}
    rows = [observation(id=fid, rule_id=fid, collected_at=f"2026-11-05T{18-i:02}:00:00Z",
                        collection_provenance={"observed_at": at}) for i, (fid, at) in enumerate(observed.items())]
    ctx.store.save_findings("base", rows)
    expected = (["early", "tie-a", "tie-b", "late"] if direction == "asc" else ["late", "tie-a", "tie-b", "early"])
    expected += ["missing-a", "missing-b", "missing-c"]
    pages = [query(client, sort_by="observed_at", sort_dir=direction, limit=2, offset=i) for i in range(0, 7, 2)]
    assert [fid for page in pages for fid in ids(page)] == expected
    assert all(page["total"] == 7 for page in pages)
    assert ids(query(client, sort_by="collected_at", sort_dir=direction)) != expected
    assert counts(pages[0]) == {"no_known_gap": 4, "unknown": 3}
    ctx.store.save_findings("base", list(reversed(rows)))
    assert ids(query(client, sort_by="observed_at", sort_dir=direction)) == expected


def test_historical_filter_uses_selected_cutoff_and_exact_helper(client, ctx):
    f = seed(ctx)
    save_run(ctx, findings=[f])
    save_run(ctx, "ambiguous-a", at=NEWEST)
    save_run(ctx, "ambiguous-b", at=NEWEST)
    assert counts(query(client, scan_id="base", reassessment="no_known_gap")) == {"no_known_gap": 1}
    historical = query(client, scan_id="later", reassessment="not_reassessed", sort_by="observed_at")
    assert ids(historical) == [f.id] and counts(historical) == {"not_reassessed": 1}
    assert historical["findings"][0]["reassessment"] == ReassessmentView(ctx, scan_id="later").assess(f.to_dict())
    assert query(client, reassessment="not_reassessed")["total"] == 0
    assert counts(query(client, reassessment="unknown")) == {"unknown": 1}


@pytest.mark.parametrize("params", [
    {"reassessment": "fresh"}, {"reassessment": "not_reassessed,clean"}, {"reassessment": "unknown,"},
    {"reassessment": '"unclosed'}, {"reassessment": "__proto__"}, {"sort_by": "observation"},
    {"sort_by": "observed_at", "sort_dir": "newest"},
])
def test_invalid_query_contract_on_empty_view(client, params):
    response = client.get(URL, params=params)
    assert response.status_code == 400 and isinstance(response.json()["detail"], str)


def test_accounts_receive_unequal_full_views_and_cannot_query_mixed_history(verified_app):
    ctx, _, tokens, client, _ = verified_app
    rows = [observation(id="alpha-gap"), observation(id="alpha-unknown", source="scanner-import"),
            observation(id="beta-gap", host="beta")]
    save_run(ctx, "base", at=OLD, targets=["alpha", "beta"], findings=rows, coverage_incomplete=False)
    save_run(ctx, "alpha-attempt")
    save_run(ctx, "beta-attempt", targets=["beta"])
    save_run(ctx, "private-mixed", at=NEWEST, targets=["alpha", "beta"], findings=rows)
    for subject, expected, unfiltered in (("first-user", ["alpha-gap"], 2), ("second-user", ["beta-gap"], 1)):
        h = headers(tokens, identity(subject))
        result = client.get(URL, headers=h, params={"reassessment": "not_reassessed", "sort_by": "observed_at", "limit": 1})
        assert result.status_code == 200, result.text
        page = result.json()
        assert ids(page) == expected and page["total"] == 1 and page["unfiltered_total"] == unfiltered
        assert counts(page) == ({"not_reassessed": 1, "unknown": 1} if unfiltered == 2 else {"not_reassessed": 1})
        assert ("beta" if subject == "first-user" else "alpha") not in result.text
        assert "private-mixed" not in result.text
        denied = client.get(URL, headers=h, params={"scan_id": "private-mixed", "reassessment": "unknown", "offset": 999})
        assert denied.status_code == 403


@pytest.mark.parametrize("stage", ["storage", "history", "page"])
def test_revocation_of_off_page_finding_cannot_leave_counts_or_facets(verified_app, monkeypatch, stage):
    ctx, _, tokens, client, _ = verified_app
    rows = [observation(id="a"), observation(id="b", source="scanner-import")]
    save_run(ctx, "base", at=OLD, findings=rows)
    save_run(ctx)
    policy = json.loads(ctx.access.path.read_text())
    revoked = False

    def revoke():
        nonlocal revoked
        revoked = True
        policy["entries"][0]["grants"] = []
        ctx.access.path.write_text(json.dumps(policy))

    if stage in {"storage", "history"}:
        load = ctx.store.load_findings

        def guarded_load(sid=None):
            result = load(sid)
            if (stage == "storage" and sid is None) or (stage == "history" and sid == "later"):
                revoke()
            return result

        monkeypatch.setattr(ctx.store, "load_findings", guarded_load)
    else:
        decorate = util.finding_plus

        def guarded_decoration(*args, **kwargs):
            result = decorate(*args, **kwargs)
            revoke()
            return result

        monkeypatch.setattr(util, "finding_plus", guarded_decoration)
    response = client.get(URL, headers=headers(tokens), params={"reassessment": "not_reassessed", "limit": 1})
    assert revoked
    if stage == "storage":
        assert response.status_code == 200
        assert response.json()["unfiltered_total"] == 0 and counts(response.json()) == {}
    else:
        assert response.status_code == 403, response.text


@pytest.mark.parametrize("reassessment", ["not_reassessed", "no_known_gap"])
@pytest.mark.parametrize("stage", ["history", "page"])
def test_revoked_mixed_history_rebuilds_filters_counts_and_page(verified_app, monkeypatch, reassessment, stage):
    ctx, _, tokens, client, _ = verified_app
    rows = [observation(id="gap-a", rule_id="gap"), observation(id="gap-b", rule_id="gap"),
            observation(id="unchanged", rule_id="different", rule_version=None)]
    save_run(ctx, "base", at=OLD, findings=rows, targets=["alpha", "beta"], coverage_incomplete=False)
    policy = json.loads(ctx.access.path.read_text())
    original_policy = deepcopy(policy)
    policy["entries"][0]["grants"][0]["target_ids"] = ["alpha", "beta"]
    ctx.access.path.write_text(json.dumps(policy))
    save_run(ctx, "mixed", targets=["alpha", "beta"], rule_filter=["gap"])
    revoked = False

    def revoke():
        nonlocal revoked
        revoked = True
        ctx.access.path.write_text(json.dumps(original_policy))

    if stage == "history":
        load = ctx.store.load_findings

        def guarded_load(sid=None):
            result = load(sid)
            if sid == "mixed":
                revoke()
            return result

        monkeypatch.setattr(ctx.store, "load_findings", guarded_load)
    else:
        decorate = util.finding_plus

        def guarded_decoration(*args, **kwargs):
            result = decorate(*args, **kwargs)
            revoke()
            return result

        monkeypatch.setattr(util, "finding_plus", guarded_decoration)
    response = client.get(URL, headers=headers(tokens), params={"reassessment": reassessment, "sort_by": "observed_at", "limit": 1})
    assert response.status_code == 200, response.text
    assert revoked and "mixed" not in response.text
    page = response.json()
    assert counts(page) == {"no_known_gap": 3}
    assert page["unfiltered_total"] == 3
    assert page["total"] == (0 if reassessment == "not_reassessed" else 3)
    assert ids(page) == ([] if reassessment == "not_reassessed" else ["gap-a"])


def test_named_empty_page_rechecks_whole_run_after_query_reads(verified_app, monkeypatch):
    ctx, _, tokens, client, _ = verified_app
    policy = json.loads(ctx.access.path.read_text())
    policy["entries"][0]["grants"][0]["target_ids"] = ["alpha", "beta"]
    ctx.access.path.write_text(json.dumps(policy))
    save_run(ctx, "base", at=OLD, findings=[observation()], targets=["alpha", "beta"])
    original = ReassessmentView.assess_many

    def assess_and_revoke(self, findings):
        result = original(self, findings)
        policy["entries"][0]["grants"][0]["target_ids"] = ["alpha"]
        ctx.access.path.write_text(json.dumps(policy))
        return result

    monkeypatch.setattr(ReassessmentView, "assess_many", assess_and_revoke)
    response = client.get(URL, headers=headers(tokens), params={"scan_id": "base", "offset": 1000, "reassessment": "unknown"})
    assert response.status_code == 403, response.text


def test_revoked_off_page_target_cannot_leak_through_unfiltered_facets(verified_app, monkeypatch):
    ctx, _, tokens, client, _ = verified_app
    policy = json.loads(ctx.access.path.read_text())
    policy["entries"][0]["grants"][0]["target_ids"] = ["alpha", "beta"]
    ctx.access.path.write_text(json.dumps(policy))
    save_run(ctx, "base", at=OLD, targets=["alpha", "beta"],
             findings=[observation(id="visible"), observation(id="off-page", host="beta")],
             coverage_incomplete=False, scheduling=None)
    original = util.finding_plus

    def decorate_and_revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        policy["entries"][0]["grants"][0]["target_ids"] = ["alpha"]
        ctx.access.path.write_text(json.dumps(policy))
        return result

    monkeypatch.setattr(util, "finding_plus", decorate_and_revoke)
    response = client.get(URL, headers=headers(tokens), params={"host": "alpha", "sort_by": "observed_at", "limit": 1})
    assert response.status_code == 200, response.text
    assert "beta" not in response.text and "off-page" not in response.text
    page = response.json()
    assert ids(page) == ["visible"]
    assert page["unfiltered_total"] == page["total"] == page["summary"]["total"] == 1
    assert counts(page) == {"no_known_gap": 1}
