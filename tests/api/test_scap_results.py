"""Passive API upload, verified grants and current/report views on JSON and SQLite."""
import argparse
import asyncio
import base64
import json
import threading
from unittest.mock import Mock

import httpx
import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.ingest import scap_results as scap
from cyberthunder.ingest import scap_cli
from cyberthunder.report.service import ReportService
from tests.ingest.test_scap_results import ACTOR, auth, manifest, setup_targets, xml
from tests.security.job_helpers import revoke

URL = "/api/v1/ingest/scap-results"
HEADERS = {"X-Actor": ACTOR}


def envelope(data=None, declaration=None):
    return {"xml_base64": base64.b64encode(xml() if data is None else data).decode(),
            "manifest": manifest() if declaration is None else declaration}


@pytest.fixture
def configured(ctx, monkeypatch):
    setup_targets(ctx)
    ctx.reports = ReportService(ctx)
    for obj, names in ((ctx, ["transport_for", "adapter_for"]), (ctx.scanner, ["start", "run"]),
                       (ctx.engine, ["propose", "execute", "rollback"]), (ctx.explain, ["precompute"])):
        for name in names:
            monkeypatch.setattr(obj, name, Mock(side_effect=AssertionError("passive import only")))
    return ctx


@pytest.fixture
def scap_client(configured):
    client = TestClient(create_app(configured))
    yield client
    client.close()


def test_upload_persists_current_scan_and_report(scap_client, configured):
    response = scap_client.post(URL, json=envelope(), headers=HEADERS)
    assert response.status_code == 200, response.text
    receipt = response.json()
    assert receipt["imported_count"] == 6 and not receipt["compliance_claim"]
    findings = scap_client.get("/api/v1/findings").json()["findings"]
    assert len(findings) == 7
    assert {f["collection_provenance"]["raw_result"] for f in findings
            if "raw_result" in f["collection_provenance"]} == set(receipt["result_counts"])
    run = scap_client.get("/api/v1/scans/" + receipt["scan_id"])
    assert run.status_code == 200 and run.json()["coverage_incomplete"]
    report = scap_client.get("/api/v1/reports/commander?format=json")
    assert report.status_code == 200, report.text
    assert "unverified" in report.text.lower()
    assert "not_reviewed" in report.text and "scanner_error" in report.text
    repeat = scap_client.post(URL, json=envelope(), headers=HEADERS)
    assert repeat.json() == {**receipt, "repeated": True}
    assert len(configured.store.list_scan_runs()) == 1


@pytest.mark.parametrize("body", [{"path": "/private-secret"}, {"xml_base64": "a", "manifest": {}},
    {"xml_base64": "@!", "manifest": {}}, {"xml_base64": "", "manifest": {}, "actor": ACTOR}])
def test_malformed_envelope_and_server_paths_rejected(scap_client, configured, body):
    response = scap_client.post(URL, json=body, headers=HEADERS)
    assert response.status_code == 400 and "private-secret" not in response.text
    assert not configured.store.list_scan_runs()


@pytest.mark.parametrize("headers,status", [({}, 400), ({"X-Actor": "operator"}, 403),
    ({"X-Actor": "agent"}, 400), ({**HEADERS, "Content-Length": "-1"}, 400),
    ({**HEADERS, "Content-Length": str(scap.MAX_UPLOAD_BYTES + 1)}, 413)])
def test_actor_and_length_guards(scap_client, headers, status):
    assert scap_client.post(URL, json=envelope(), headers=headers).status_code == status


def test_streaming_size_guard_and_content_type(scap_client, monkeypatch):
    from cyberthunder.api.routes import scap_results as route
    monkeypatch.setattr(route, "MAX_UPLOAD_BYTES", 64)
    response = scap_client.post(URL, content=iter([b"{" * 40, b"}" * 40]),
                               headers={**HEADERS, "Content-Type": "application/json"})
    assert response.status_code == 413
    assert scap_client.post(URL, content=b"x", headers=HEADERS).status_code == 415


def test_storage_and_kill_preserve_visibility(scap_client, configured, monkeypatch):
    monkeypatch.setattr(configured.store, "save_scan_run", Mock(side_effect=OSError("private-secret")))
    response = scap_client.post(URL, json=envelope(), headers=HEADERS)
    assert response.status_code == 503 and "private-secret" not in response.text
    assert scap_client.get("/api/v1/findings").json()["findings"] == []
    (configured.store.root / "KILL").write_text("stop")
    assert scap_client.post(URL, json=envelope(), headers=HEADERS).status_code == 423


def verified_client(ctx, monkeypatch, **claims_changes):
    p = auth(ctx)
    claims = {"iss": p.issuer, "sub": p.subject, "name": p.display_name, "ct_kind": "human",
              "ct_roles": list(p.roles), "exp": p.expires_at, "auth_time": p.auth_time, "acr": p.acr,
              **claims_changes}
    from cyberthunder.api import auth as api_auth
    monkeypatch.setattr(api_auth, "make_validator", lambda *args: Mock(validate=lambda token: claims))
    return TestClient(create_app(ctx)), p


def test_verified_route_uses_current_grants_and_ignores_raw_actor(configured, monkeypatch):
    client, p = verified_client(configured, monkeypatch)
    headers = {"Authorization": "Bearer fixture", "X-Actor": "Spoofed actor"}
    with client:
        # Unrelated target has no read/import grant; this endpoint requires only its explicit destination.
        assert client.post(URL, json=envelope(), headers=HEADERS).status_code == 401
        response = client.post(URL, json=envelope(), headers=headers)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        sid = response.json()["scan_id"]
        assert configured.store.load_scan_run(sid)["requested_by"] == p.actor
        assert len(client.get("/api/v1/findings", headers=headers).json()["findings"]) == 7
        report = client.get("/api/v1/reports/commander?format=json", headers=headers)
        assert report.status_code == 200, report.text
        revoke(configured)
        assert client.post(URL, json=envelope(), headers=headers).status_code == 403
        assert client.get("/api/v1/findings", headers=headers).json()["findings"] == []
        assert client.get("/api/v1/reports/commander?format=json", headers=headers).status_code == 403


@pytest.mark.parametrize("changes", [{"ct_roles": ["viewer"]}, {"exp": 1}])
def test_verified_role_and_expiry_denied(configured, monkeypatch, changes):
    client, _ = verified_client(configured, monkeypatch, **changes)
    response = client.post(URL, json=envelope(), headers={"Authorization": "Bearer fixture"})
    assert response.status_code == 403 and not configured.store.list_scan_runs()
    client.close()


def test_reused_target_cannot_read_historical_findings_or_report(configured, monkeypatch):
    client, _ = verified_client(configured, monkeypatch)
    headers = {"Authorization": "Bearer fixture"}
    receipt = client.post(URL, json=envelope(), headers=headers).json()
    from cyberthunder.inventory.targets import Target
    configured.inventory.remove("container-a")
    configured.inventory.add(Target("container-a", "Replacement", "containers", transport="fixture"))
    configured.inventory.save()
    assert client.get("/api/v1/findings", headers=headers).json()["findings"] == []
    assert client.get("/api/v1/scans/" + receipt["scan_id"], headers=headers).status_code == 403
    assert client.get("/api/v1/reports/commander?format=json", headers=headers).status_code == 403
    assert client.post(URL, json=envelope(), headers=headers).status_code == 403
    client.close()


def test_parsing_does_not_block_current_views(configured, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    parse = scap.parse_results
    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(10)
        return parse(*args, **kwargs)
    monkeypatch.setattr(scap, "parse_results", blocked)
    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(configured)),
                                     base_url="http://testserver") as client:
            pending = asyncio.create_task(client.post(URL, json=envelope(), headers=HEADERS))
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                response = await asyncio.wait_for(client.get("/api/v1/findings"), timeout=5)
                assert response.status_code == 200 and not pending.done()
            finally:
                release.set()
                response = await pending
            assert response.status_code == 200
    asyncio.run(exercise())


def test_standalone_cli_and_registration_seam(configured, tmp_path, capsys):
    path, declaration = tmp_path / "sample.xml", tmp_path / "manifest.json"
    path.write_bytes(xml())
    declaration.write_text(json.dumps(manifest()))
    arguments = ["--state-dir", str(configured.store.root), "--actor", ACTOR, str(path), "--manifest", str(declaration)]
    assert scap_cli.main(arguments) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["imported_count"] == 6
    assert scap_cli.main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["repeated"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir")
    parser.add_argument("--actor")
    scap_cli.register_cli(parser.add_subparsers())
    parsed = parser.parse_args(["--state-dir", str(configured.store.root), "--actor", ACTOR,
                                "scap-results-import", str(path), "--manifest", str(declaration)])
    assert parsed.fn(parsed) == 0
    capsys.readouterr()


def test_cli_verified_mode_refuses_actor_bypass(configured, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CT_AUTH_MODE", "oidc")
    assert scap_cli.main(["--state-dir", str(configured.store.root), "--actor", ACTOR,
                          str(tmp_path / "not-read.xml"), "--manifest", "not-read.json"]) == 2
    assert "authenticated SCAP upload API" in capsys.readouterr().err
    assert not configured.store.list_scan_runs()


def test_verified_workload_route_uses_account_grants(configured, monkeypatch):
    client, p = verified_client(configured, monkeypatch, ct_kind="workload")
    response = client.post(URL, json=envelope(), headers={"Authorization": "Bearer fixture"})
    assert response.status_code == 200, response.text
    actor = configured.store.load_scan_run(response.json()["scan_id"])["requested_by"]
    assert actor.startswith("workload:") and actor != p.actor
    revoke(configured)
    assert client.post(URL, json=envelope(), headers={"Authorization": "Bearer fixture"}).status_code == 403
    client.close()
