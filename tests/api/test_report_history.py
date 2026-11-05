"""Target report revisions remain searchable when the latest report is replaced."""
from cyberthunder.report import history
from tests.api.conftest import ACTOR, add_target


def test_target_report_revisions_and_preexisting_report_are_retained(client, ctx):
    add_target(client)
    legacy = {"target": ctx.inventory.get("web01").to_dict(), "generated_at": "2026-10-01T00:00:00+00:00",
              "generated_by": "Prior operator", "findings": 10, "open": 8}
    ctx.store.write_json(ctx.store.root / "reports/web01.json", legacy)
    first = client.post("/api/v1/reports", json={"target": "web01"}, headers=ACTOR).json()
    second = client.post("/api/v1/reports", json={"target": "web01"}, headers=ACTOR).json()
    assert first["report_id"] != second["report_id"]
    assert client.get("/api/v1/reports/web01").json() == second
    results = client.get("/api/v1/reports/history", params={"kind": "target", "target": "web01"}).json()
    assert results["total"] == 3
    assert history.search(ctx, q="Prior operator")["total"] == 1
    ctx.inventory.remove("web01")
    ctx.inventory.save()
    assert client.get(f'/api/v1/reports/history/{first["report_id"]}').status_code == 200
    assert client.get("/api/v1/reports/history", params={"kind": "target"}).json()["total"] == 3
