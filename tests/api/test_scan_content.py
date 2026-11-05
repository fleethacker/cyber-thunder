from tests.api.conftest import add_target


def test_preflight_route_is_local_read_only_without_actor(client, ctx, monkeypatch):
    add_target(client, "web01")
    def forbidden(*args, **kwargs):
        raise AssertionError("GET must be local and read-only")
    monkeypatch.setattr(ctx.audit, "append", forbidden)
    monkeypatch.setattr(ctx, "transport_for", forbidden)
    monkeypatch.setattr(ctx.scanner, "start", forbidden)
    monkeypatch.setattr(ctx.store, "write_json", forbidden)
    response = client.get("/api/v1/scans/preflight", params=[("target_ids", "web01"), ("modules", "check")])
    assert response.status_code == 200
    doc = response.json()
    assert doc["local_only"] and not doc["automatic_downloads"]
    assert doc["targets"][0]["target_id"] == "web01"
    assert doc["modules"] == ["check"]


def test_preflight_validates_scope_unknown_target_and_modules(client):
    add_target(client, "outside", in_scope=False)
    assert client.get("/api/v1/scans/preflight?target_ids=outside").status_code == 403
    assert client.get("/api/v1/scans/preflight?target_ids=missing").status_code == 404
    assert client.get("/api/v1/scans/preflight?modules=bad").status_code == 400
