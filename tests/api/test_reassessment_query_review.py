"""Independent query boundaries with real authorization and both document backends."""
from copy import deepcopy
import json

import pytest

from cyberthunder.api import util
from cyberthunder.findings.reassessment import ReassessmentView
from cyberthunder.inventory.targets import Target
from cyberthunder.security import resources
from tests.findings.test_reassessment import OLD, observation, save_run
from tests.security.test_identity_boundary import verified_app, headers

URL = "/api/v1/findings"


def grant_both(ctx):
    policy = json.loads(ctx.access.path.read_text())
    policy["entries"][0]["grants"][0]["target_ids"] = ["alpha", "beta"]
    ctx.access.path.write_text(json.dumps(policy))
    return policy


@pytest.mark.parametrize("change", ["grant", "generation"])
@pytest.mark.parametrize("query", [
    {"host": "alpha", "offset": 0},
    {"source": "native", "offset": 0},
    {"offset": 1},
    {"q": "no such observation", "offset": 999},
])
def test_revoked_contributor_rebuilds_every_facet_and_page(verified_app, monkeypatch, change, query):
    ctx, _, tokens, client, _ = verified_app
    policy = grant_both(ctx)
    rows = [observation(id="a-private", host="beta", source="scanner-import", benchmark="PRIVATE benchmark"),
            observation(id="b-public"), observation(id="c-public")]
    save_run(ctx, "base", at=OLD, targets=["alpha", "beta"], findings=rows,
             coverage_incomplete=False, scheduling=None)
    # The complete baseline replaces the fixture's scan-both observations.
    assert {f.id for f in ctx.store.load_findings()} == {f.id for f in rows}
    original = ReassessmentView.assess_many
    calls = 0

    def revoke_after_final_history_read(self, findings):
        nonlocal calls
        result = original(self, findings)
        calls += 1
        if calls == 2:
            if change == "grant":
                policy["entries"][0]["grants"][0]["target_ids"] = ["alpha"]
                ctx.access.path.write_text(json.dumps(policy))
            else:
                ctx.inventory.remove("beta")
                ctx.inventory.add(Target("beta", "Replacement", "linux", transport="simulated",
                                         simulated=True, environment="beta"))
                ctx.inventory.save()
        return result

    monkeypatch.setattr(ReassessmentView, "assess_many", revoke_after_final_history_read)
    params = {"sort_by": "observed_at", "limit": 1, **query}
    response = client.get(URL, headers=headers(tokens), params=params)
    assert response.status_code == 200, response.text
    assert calls >= 2
    page = response.json()
    assert page["unfiltered_total"] == page["summary"]["total"] == 2
    assert "PRIVATE" not in response.text and "a-private" not in response.text and "beta" not in response.text
    expected = [] if "q" in query else ["c-public" if query["offset"] else "b-public"]
    assert [f["id"] for f in page["findings"]] == expected
    assert page["total"] == (0 if "q" in query else 2)
    monkeypatch.setattr(ReassessmentView, "assess_many", original)
    stable = client.get(URL, headers=headers(tokens), params=params).json()
    for field in ("facets", "summary", "total", "unfiltered_total", "scan_id"):
        assert page[field] == stable[field], field
    assert all(o["count"] == 2 for options in page["facets"].values() for o in options)


def test_history_revoked_during_final_page_authority_check_is_not_exposed(verified_app, monkeypatch):
    ctx, _, tokens, client, _ = verified_app
    policy = grant_both(ctx)
    save_run(ctx, "base", at=OLD, targets=["alpha", "beta"], findings=[observation(id="public")],
             coverage_incomplete=False, scheduling=None)
    save_run(ctx, "PRIVATE-mixed-history", targets=["alpha", "beta"])
    assert [f.id for f in ctx.store.load_findings()] == ["public"]
    check = resources.check_record
    assess = ReassessmentView.assess_many
    history_reads = 0
    revoked = False

    def count_history(self, findings):
        nonlocal history_reads
        history_reads += 1
        return assess(self, findings)

    def check_and_revoke(context, obj, *args, **kwargs):
        nonlocal revoked
        check(context, obj, *args, **kwargs)
        if history_reads >= 1 and isinstance(obj, dict) and obj.get("id") == "public":
            revoked = True
            policy["entries"][0]["grants"][0]["target_ids"] = ["alpha"]
            ctx.access.path.write_text(json.dumps(policy))

    monkeypatch.setattr(resources, "check_record", check_and_revoke)
    monkeypatch.setattr(ReassessmentView, "assess_many", count_history)
    response = client.get(URL, headers=headers(tokens), params={"reassessment": "not_reassessed"})
    assert revoked and response.status_code == 200, response.text
    assert "PRIVATE" not in response.text
    assert response.json()["total"] == 0
    assert response.json()["facets"]["reassessment"] == [
        {"value": "no_known_gap", "label": "No known gap", "count": 1}]


def test_repeated_grant_changes_have_a_bounded_sanitized_response(verified_app, monkeypatch):
    ctx, _, tokens, client, _ = verified_app
    both = grant_both(ctx)
    alpha = deepcopy(both)
    alpha["entries"][0]["grants"][0]["target_ids"] = ["alpha"]
    save_run(ctx, "base", at=OLD, targets=["alpha", "beta"], findings=[observation(id="public")],
             coverage_incomplete=False, scheduling=None)
    save_run(ctx, "PRIVATE-mixed-history", targets=["alpha", "beta"])
    assert [f.id for f in ctx.store.load_findings()] == ["public"]
    assess = ReassessmentView.assess_many
    calls = 0

    def changing_grants(self, findings):
        nonlocal calls
        calls += 1
        assert calls <= 12, "query never bounded repeated real grant changes"
        ctx.access.path.write_text(json.dumps(both if calls % 2 else alpha))
        return assess(self, findings)

    monkeypatch.setattr(ReassessmentView, "assess_many", changing_grants)
    response = client.get(URL, headers=headers(tokens), params={"reassessment": "not_reassessed"})
    assert response.status_code == 409, response.text
    assert calls <= 8
    assert set(response.json()) == {"detail"}
    assert "PRIVATE" not in response.text and "beta" not in response.text


@pytest.mark.parametrize("scan_id", [None, "base"])
def test_final_page_check_rejects_changed_observation_generation(verified_app, monkeypatch, scan_id):
    ctx, _, tokens, client, _ = verified_app
    save_run(ctx, "base", at=OLD, findings=[observation(id="old-generation")],
             coverage_incomplete=False, scheduling=None)
    decorate = util.finding_plus

    def replace_target(*args, **kwargs):
        result = decorate(*args, **kwargs)
        ctx.inventory.remove("alpha")
        ctx.inventory.add(Target("alpha", "Replacement", "linux", transport="simulated",
                                 simulated=True, environment="alpha"))
        ctx.inventory.save()
        return result

    monkeypatch.setattr(util, "finding_plus", replace_target)
    response = client.get(URL, headers=headers(tokens), params={"scan_id": scan_id} if scan_id else {})
    assert response.status_code == 403
    assert "old-generation" not in response.text
