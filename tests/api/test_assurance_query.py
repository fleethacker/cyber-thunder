"""Confidence/review filtering precedes pagination and preserves raw scanner status."""
from datetime import datetime, timedelta, timezone

from cyberthunder.findings.review import ReviewService
from tests.api.test_findings_query import finding, save, query, ids


def test_assurance_filters_facets_sort_and_immutable_observation(client, ctx, monkeypatch):
    from cyberthunder.findings import confidence
    grades = {"first": "low", "second": "high", "third": "unknown"}
    monkeypatch.setattr(confidence, "assess_for_context", lambda ctx, f, **kw:
                        {"grade": grades[f.id], "reason": "Fixture assessment", "reasons": [],
                         "version": "test", "assessed_at": None, "observed_at": f.collected_at, "evidence": {}})
    rows = [finding(i, evidence="Setting observed") for i in grades]
    save(ctx, rows)
    service = ReviewService(ctx)
    f = ctx.store.get_finding("first")
    review = service.summary(f)
    service.save(f, actor="ITC Rivera", disposition="false_positive", reason="Reviewed fixture baseline",
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                 expected_revision=review["revision"], evidence_fingerprint=review["evidence_fingerprint"])
    result = query(client, confidence="high,low", review="unreviewed", limit=1, sort_by="confidence", sort_dir="desc")
    assert ids(result) == ["second"] and result["total"] == 1
    assert result["unfiltered_total"] == 3
    assert sum(r["count"] for r in result["facets"]["review"]) == 3
    assert ids(query(client, sort_by="confidence", sort_dir="asc")) == ["first", "second", "third"]
    assert ids(query(client, sort_by="confidence", sort_dir="desc")) == ["second", "first", "third"]
    reviewed = query(client, review="false_positive")["findings"][0]
    assert reviewed["review"]["suppressed"] and reviewed["scanner_status"] == reviewed["status"] == "open"
    assert ctx.store.get_finding("first").status.value == "open"
    response = client.post("/api/v1/findings/first/propose", headers={"X-Actor": "ITC Rivera"})
    assert response.status_code == 409


def test_assurance_filter_validation(client):
    for params in ({"confidence": "99%"}, {"review": "risk_forever"}):
        assert client.get("/api/v1/findings", params=params).status_code == 400
    for status in ("risk_accepted", "risk_expired", "risk_reopened", "risk_revoked"):
        assert client.get("/api/v1/findings", params={"review": status}).status_code == 200


def test_suppressed_apply_is_rejected_before_background_work(client, ctx, approved):
    finding = ctx.store.get_finding(approved["finding_id"])
    service = ReviewService(ctx)
    review = service.summary(finding)
    service.save(finding, actor="ITC Rivera", disposition="false_positive", reason="Temporary fixture review",
                 expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                 expected_revision=review["revision"], evidence_fingerprint=review["evidence_fingerprint"])
    response = client.post(f"/api/v1/proposals/{approved['id']}/apply", headers={"X-Actor": "ITC Rivera"})
    assert response.status_code == 409
    assert ctx.gate.get(approved["id"]).state.value == "approved"
