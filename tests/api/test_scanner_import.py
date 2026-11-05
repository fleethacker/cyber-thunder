"""Real import service and existing findings/report routes, using fixture input only."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from cyberthunder.api.app import create_app
from cyberthunder.cli import main
from cyberthunder.findings.schema import Finding
from cyberthunder.ingest import scanner_results as imports
from cyberthunder.ingest.service import IngestService
from cyberthunder.inventory.targets import Target
from cyberthunder.report.service import ReportService
from cyberthunder.scan import ScanRun

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "parsers" / "sample.nessus"
MAPPING = {"ws-014.enclave.example": "workstation", "10.20.1.30": "server"}
ACTOR = {"X-Actor": "IT2 Rivera"}
URL = "/api/v1/ingest/scanner"


@pytest.fixture
def scanner_client(ctx, monkeypatch):
    ctx.ingest = IngestService(ctx)
    ctx.reports = ReportService(ctx)
    for tid, kind in (("workstation", "windows"), ("server", "linux"), ("other", "linux")):
        ctx.inventory.add(Target(tid, tid, kind, transport="fixture", in_scope=False))
    ctx.inventory.save()
    for name in ("transport_for", "adapter_for"):
        monkeypatch.setattr(ctx, name, Mock(side_effect=AssertionError("collection is forbidden")))
    for name in ("start", "run"):
        monkeypatch.setattr(ctx.scanner, name, Mock(side_effect=AssertionError("scanning is forbidden")))
    for name in ("propose", "execute", "rollback"):
        monkeypatch.setattr(ctx.engine, name, Mock(side_effect=AssertionError("remediation is forbidden")))
    monkeypatch.setattr(ctx.explain, "precompute", Mock(side_effect=AssertionError("explanation is forbidden")))
    # No lifespan is needed for these routes; never start periodic background collection in a test.
    client = TestClient(create_app(ctx))
    yield client
    client.close()
    assert ctx.gate.list() == []
    assert all(not t.in_scope for t in ctx.inventory.all())


def upload(client, data=None, mapping=None, headers=None, **extra):
    return client.post(URL, headers=ACTOR if headers is None else headers,
                       files={"file": ("../../private-secret.nessus", SAMPLE.read_bytes() if data is None else data,
                                       "application/xml")},
                       data={"host_map": json.dumps(MAPPING if mapping is None else mapping), **extra})


def seed_full(ctx):
    finding = Finding(host="other", source="hunt", rule_id="prior-observation", title="Existing risk",
                      severity="high", status="open")
    ctx.store.save_findings("baseline", [finding])
    ctx.store.save_scan_run(ScanRun(id="baseline", targets=["other"], status="done",
                                   started_at="2020-01-01T00:00:00+00:00").to_dict())
    return finding


@pytest.mark.parametrize("entry", ["api", "cli"])
def test_fixture_import_visible_in_existing_findings_and_reports(scanner_client, ctx, tmp_path, capsys,
                                                                 monkeypatch, entry):
    if entry == "api":
        response = upload(scanner_client)
        assert response.status_code == 200, response.text
        result = response.json()
    else:
        from cyberthunder.ingest import cli
        monkeypatch.setattr(cli, "_service", lambda args: ctx.ingest)
        mapping = tmp_path / "mapping.json"
        mapping.write_text(json.dumps(MAPPING), encoding="utf-8")
        assert main(["--state-dir", str(ctx.store.root), "--actor", "IT2 Rivera", "ingest", "scanner", str(SAMPLE),
                     "--host-map", str(mapping)]) == 0
        result = json.loads(capsys.readouterr().out)
    sid = result["scan_id"]
    assert result["imported_count"] == 5
    response = scanner_client.get("/api/v1/findings")
    assert response.status_code == 200 and response.json()["total"] == 5
    findings = response.json()["findings"]
    assert {f["host"] for f in findings} == set(MAPPING.values())
    smb = next(f for f in findings if f["rule_id"] == "nessus:97833")
    assert smb["id"] == Finding.make_id("workstation", "acas", "nessus:97833")
    assert {r["id"] for r in smb["references"] if r["system"] == "cve"} == {"CVE-2017-0143", "CVE-2017-0144"}
    for suffix in ("", "?scan_id=" + sid):
        report = scanner_client.get("/api/v1/reports/poam.csv" + suffix)
        assert report.status_code == 200
        assert "CVE-2023-48795" in report.text and "server" in report.text
    commander = scanner_client.get("/api/v1/reports/commander?format=md&scan_id=" + sid)
    assert commander.status_code == 200 and "workstation" in commander.text
    run = scanner_client.get("/api/v1/scans/" + sid)
    assert run.status_code == 200 and run.json()["status"] == "done"
    assert not (ctx.store.ingest_dir / "uploads").exists()


def test_existing_full_picture_is_preserved_and_named_import_is_readable(scanner_client, ctx):
    prior = seed_full(ctx)
    response = upload(scanner_client)
    assert response.status_code == 200
    sid = response.json()["scan_id"]
    current = ctx.store.current_findings()
    assert len(current) == 6 and prior.id in {f.id for f in current}
    named = scanner_client.get("/api/v1/findings", params={"scan_id": sid}).json()
    assert named["total"] == 5
    report = scanner_client.get("/api/v1/reports/poam.csv", params={"scan_id": sid})
    assert report.status_code == 200 and "CVE-2017-0144" in report.text
    assert ctx.store.load_findings("baseline")[0].id == prior.id


def test_repeat_upload_is_idempotent_with_different_filename(scanner_client, ctx):
    first = upload(scanner_client).json()
    second = scanner_client.post(URL, headers=ACTOR,
                                 files={"file": ("renamed.nessus", SAMPLE.read_bytes())},
                                 data={"host_map": json.dumps(dict(reversed(list(MAPPING.items()))))})
    assert second.status_code == 200
    assert second.json() == dict(first, repeated=True)
    assert len(ctx.store.list_scan_runs()) == 1
    assert scanner_client.get("/api/v1/findings").json()["total"] == 5
    audit = json.dumps(list(ctx.audit.records()))
    assert "private-secret" not in audit and "renamed.nessus" not in audit


@pytest.mark.parametrize("headers,code", [({}, 400), ({"X-Actor": "agent:job"}, 400),
                                         ({"X-Actor": "policy:automatic"}, 400), ({"X-Actor": "operator"}, 403)])
def test_actor_required_before_import(scanner_client, ctx, headers, code):
    assert upload(scanner_client, headers=headers).status_code == code
    assert ctx.store.list_scan_runs() == []


def test_engaged_kill_refuses_upload_before_writes(scanner_client, ctx):
    ctx.killswitch.engage("IT2 Rivera")
    assert upload(scanner_client).status_code == 423
    assert ctx.store.list_scan_runs() == []
    assert not (ctx.store.ingest_dir / "uploads").exists()


@pytest.mark.parametrize("payload", [b"", b"<broken>private-secret", b"<NessusClientData_v2><Report/></NessusClientData_v2>",
    b'<!DOCTYPE NessusClientData_v2 SYSTEM "file:///private-secret"><NessusClientData_v2/>'])
def test_malformed_empty_and_unsafe_xml_preserve_existing(scanner_client, ctx, payload):
    prior = seed_full(ctx)
    response = upload(scanner_client, payload)
    assert response.status_code == 400 and "private-secret" not in response.text
    assert [f.id for f in ctx.store.current_findings()] == [prior.id]
    assert len(ctx.store.list_scan_runs()) == 1


@pytest.mark.parametrize("mapping", [{}, {"wrong": "server"}, dict(MAPPING, **{"10.20.1.30": "unknown"})])
def test_unknown_or_incomplete_mapping_writes_nothing(scanner_client, ctx, mapping):
    assert upload(scanner_client, mapping=mapping).status_code == 400
    assert ctx.store.list_scan_runs() == []


def test_server_paths_are_not_accepted(scanner_client, ctx, tmp_path):
    source = tmp_path / "private-secret.nessus"
    source.write_bytes(SAMPLE.read_bytes())
    response = scanner_client.post(URL, headers=ACTOR, json={"path": str(source), "host_map": MAPPING})
    assert response.status_code == 400 and "private-secret" not in response.text
    assert ctx.store.list_scan_runs() == []


def test_oversize_content_length_and_stream_are_bounded(scanner_client, ctx, monkeypatch):
    monkeypatch.setattr(imports, "MAX_UPLOAD_BYTES", 256)
    assert upload(scanner_client).status_code == 413
    # No content length: exercise incremental ASGI stream accounting, not just the header check.
    response = scanner_client.post(URL, headers={**ACTOR, "Content-Type": "multipart/form-data; boundary=abc"},
                                   content=iter([b"x" * 200, b"y" * 200]))
    assert response.status_code == 413
    assert ctx.store.list_scan_runs() == []


def test_xml_limit_applies_inside_allowed_multipart_envelope(scanner_client, ctx, monkeypatch):
    monkeypatch.setattr(imports, "MAX_XML_BYTES", 100)
    assert upload(scanner_client).status_code == 400
    assert ctx.store.list_scan_runs() == []


@pytest.mark.parametrize("length", ["-1", "invalid", "9" * 30])
def test_invalid_content_length_is_safe(scanner_client, ctx, length):
    response = scanner_client.post(URL, headers={**ACTOR, "Content-Length": length}, content=b"private-secret")
    assert response.status_code == 400 and "private-secret" not in response.text
    assert ctx.store.list_scan_runs() == []


@pytest.mark.parametrize("extra", [{"path": "private-secret"}, {"include_info": "maybe"}])
def test_unknown_form_fields_and_invalid_options_rejected(scanner_client, ctx, extra):
    assert upload(scanner_client, **extra).status_code == 400
    assert ctx.store.list_scan_runs() == []


def test_duplicate_mapping_form_field_rejected(scanner_client, ctx):
    response = scanner_client.post(URL, headers=ACTOR, files=[
        ("file", ("input.nessus", SAMPLE.read_bytes())),
        ("host_map", (None, json.dumps(MAPPING))),
        ("host_map", (None, json.dumps(MAPPING))),
    ])
    assert response.status_code == 400
    assert ctx.store.list_scan_runs() == []


def test_include_info_is_explicit(scanner_client):
    response = upload(scanner_client, include_info="true")
    assert response.status_code == 200 and response.json()["imported_count"] == 6
    findings = scanner_client.get("/api/v1/findings").json()["findings"]
    info = next(f for f in findings if f["rule_id"] == "nessus:19506")
    assert info["status"] == "not_reviewed"


def test_storage_failure_does_not_publish_or_leak_paths(scanner_client, ctx, monkeypatch):
    prior = seed_full(ctx)
    monkeypatch.setattr(ctx.store, "save_findings", Mock(side_effect=OSError("private-secret")))
    response = upload(scanner_client)
    assert response.status_code == 503 and "private-secret" not in response.text
    assert [f.id for f in ctx.store.current_findings()] == [prior.id]
