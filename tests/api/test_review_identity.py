"""Router attribution boundary; login verification itself is covered separately."""
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from cyberthunder.api.routes.finding_reviews import router
from cyberthunder.control.principal import principal_scope
from cyberthunder.findings.review import ReviewService
from tests.findings.test_review_identity import reviewer
from tests.findings.test_reviews import context, observation, persist


@pytest.fixture
def identity_api(state_dir):
    ctx = context(state_dir)
    finding = observation()
    persist(ctx, finding)
    principal = reviewer()
    app = FastAPI()
    app.state.ctx = ctx
    app.include_router(router)

    @app.middleware("http")
    async def verified_identity(request, call_next):
        with principal_scope(principal):
            return await call_next(request)

    with TestClient(app) as client:
        yield client, ctx, finding, principal
    ctx.store.close()


def body(ctx, finding):
    view = ReviewService(ctx).summary(finding)
    return dict(disposition="false_positive", reason="Configuration reviewed",
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                expected_revision=view["revision"], evidence_fingerprint=view["evidence_fingerprint"])


def test_authenticated_actor_ignores_spoofed_header(identity_api):
    client, ctx, finding, principal = identity_api
    path = f"/findings/{finding.id}/review"
    response = client.put(path, json=body(ctx, finding), headers={"X-Actor": "Forged Name"})
    assert response.status_code == 200, response.text
    assert response.json()["current"]["reviewed_by"] == principal.actor
    assert response.json()["current"]["reviewed_principal"] == principal.evidence()
    assert client.get(path).json() == response.json()


@pytest.mark.parametrize("field", ["identity_verified", "reviewed_principal", "principal", "reviewed_by", "actor"])
def test_body_cannot_supply_provenance(identity_api, field):
    client, ctx, finding, principal = identity_api
    payload = body(ctx, finding)
    payload[field] = principal.evidence() if "principal" in field else True
    response = client.put(f"/findings/{finding.id}/review", json=payload)
    assert response.status_code == 400, response.text
    assert ReviewService(ctx).history(finding)["revision"] == 0
    assert not list(ctx.audit.records())
