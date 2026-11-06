"""Target reports and history obey actual account policy with other environments present."""
import json

from tests.security.test_identity_boundary import verified_app, identity, headers


def test_target_export_and_history_exclude_other_accounts_and_reused_targets(verified_app):
    ctx, _, tokens, client, _ = verified_app
    policy = json.loads(ctx.access.path.read_text())
    for entry in policy["entries"]:
        entry["node_actions"] += ["export", "read"]
    ctx.access.path.write_text(json.dumps(policy))
    first = headers(tokens, identity(roles=("auditor",)))
    second = headers(tokens, identity("second-user", roles=("auditor",)))
    result = client.post("/api/v1/reports", headers=first, json={"target": "alpha"})
    assert result.status_code == 200, result.text
    saved = result.json()
    assert saved["targets"] == ["alpha"]
    assert "beta" not in json.dumps(saved)
    assert client.get("/api/v1/reports/alpha", headers=first).status_code == 200
    assert client.get("/api/v1/reports/alpha", headers=second).status_code == 403
    history = client.get("/api/v1/reports/history", headers=first)
    assert history.status_code == 200, history.text
    assert history.json()["total"] >= 1
    assert "beta" not in json.dumps(history.json())
    assert client.get("/api/v1/reports/history", headers=second).json()["total"] == 0
    original = ctx.inventory.get("alpha")
    original.environment = "moved"
    ctx.inventory.add(original)
    ctx.inventory.save()
    assert client.get("/api/v1/reports/alpha", headers=first).status_code == 403
    assert client.get("/api/v1/reports/history", headers=first).json()["total"] == 0
