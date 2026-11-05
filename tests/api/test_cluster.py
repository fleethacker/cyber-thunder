"""A requested cluster baseline persists risk profiles and the operator's identity."""
from tests.api.conftest import ACTOR


def test_baseline_records_operator_and_persists_risk(client, ctx, monkeypatch):
    monkeypatch.setattr(ctx.cluster, "survey", lambda: {
        "namespaces": [{"name": "demo"}],
        "workloads": [{"namespace": "demo", "kind": "Deployment", "name": "web",
                       "images": ["example.test/web:1"]}],
        "errors": [],
    })
    monkeypatch.setattr(ctx.cluster, "_scan_image", lambda image, run_dir: ({
        "image": image,
        "vulnerabilities": [{"severity": "HIGH", "cvss": 8.0, "fixed_version": "2"}],
    }, None))

    response = client.post("/api/v1/cluster/baseline", json={"use_openai": False}, headers=ACTOR)
    assert response.status_code == 200, response.text
    baseline = response.json()
    assert baseline["errors"] == []
    profile = baseline["namespaces"][0]
    assert profile["namespace"] == "demo"
    assert profile["summary"]["high"] == 1
    assert profile["fixable_vulnerabilities"] == 1
    assert profile["description_source"] == "template"
    saved = client.get("/api/v1/cluster/risk").json()
    assert saved["id"] == baseline["id"]
    assert saved["namespaces"] == baseline["namespaces"]
    audit = [r for r in ctx.audit.records() if r["action"] == "cluster.baseline"]
    assert len(audit) == 1
    assert audit[0]["actor"] == ACTOR["X-Actor"]
    assert audit[0]["subject"] == baseline["id"]
