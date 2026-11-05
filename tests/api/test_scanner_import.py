"""Real import service and existing findings/report routes, using fixture input only."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest
import httpx
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
                      severity="high", status="open", scan_id="baseline")
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


def test_default_findings_and_reports_overlay_import_and_preserve_explicit_history(scanner_client, ctx):
    prior = seed_full(ctx)
    baseline_run = ctx.store.load_scan_run("baseline")
    baseline_findings = [f.to_dict() for f in ctx.store.load_findings("baseline")]
    response = upload(scanner_client)
    assert response.status_code == 200
    sid = response.json()["scan_id"]
    imported = ctx.store.load_findings(sid)
    imported_ids = {f.id for f in imported}
    current_ids = imported_ids | {prior.id}
    for params, expected_ids, anchor, view in (
        ({}, current_ids, "baseline", "current"),
        ({"scan_id": "baseline"}, {prior.id}, "baseline", "scan"),
        ({"scan_id": sid}, imported_ids, sid, "scan"),
    ):
        found = scanner_client.get("/api/v1/findings", params=params)
        assert found.status_code == 200
        body = found.json()
        assert body["scan_id"] == anchor and body["view"] == view
        assert body["total"] == body["summary"]["total"] == len(expected_ids)
        assert {f["id"] for f in body["findings"]} == expected_ids
        for f in body["findings"]:
            assert f["scan_id"] == ("baseline" if f["id"] == prior.id else sid)
        report = scanner_client.get("/api/v1/reports/poam.csv", params=params)
        assert report.status_code == 200
        rows = list(csv.DictReader(io.StringIO(report.text)))
        assert {row["Finding ID"] for row in rows} == expected_ids
        assert {row["Host"] for row in rows} == {f["host"] for f in body["findings"]}
        assert ("CVE-2017-0144" in report.text) == bool(imported_ids & expected_ids)
        for fmt in ("md", "html"):
            commander = scanner_client.get("/api/v1/reports/commander", params=dict(params, format=fmt))
            assert commander.status_code == 200
            assert f"{len(expected_ids)} open finding(s)" in commander.text
            assert ("Existing risk" in commander.text) == (prior.id in expected_ids)
            assert ("workstation" in commander.text) == bool(imported_ids & expected_ids)
            assert ("--scan-id" in commander.text) == bool(params)
    filtered = scanner_client.get("/api/v1/findings", params={"source": "acas", "limit": 2}).json()
    assert filtered["view"] == "current" and filtered["total"] == 5 and len(filtered["findings"]) == 2
    assert filtered["summary"]["total"] == 6
    assert set(filtered["summary"]["hosts"]) == {"other", "server", "workstation"}
    assert ctx.store.load_scan_run("baseline") == baseline_run
    assert [f.to_dict() for f in ctx.store.load_findings("baseline")] == baseline_findings


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


def nested_upload(depth, *, kind="multipart/mixed"):
    body = [b'--outer\r\nContent-Disposition: form-data; name="file"; filename="input.nessus"\r\n',
            f'Content-Type: {kind}; boundary=inner0\r\n\r\n'.encode()]
    for level in range(depth):
        body.append(f'--inner{level}\r\nContent-Type: {kind}; boundary=inner{level + 1}\r\n\r\n'.encode())
    body.append(b"private-secret\r\n")
    body.extend(f'--inner{level}--\r\n'.encode() for level in reversed(range(depth + 1)))
    body.extend([b'--outer\r\nContent-Disposition: form-data; name="host_map"\r\n\r\n',
                 json.dumps(MAPPING).encode(), b'\r\n--outer--\r\n'])
    return b"".join(body)


@pytest.mark.parametrize("depth,kind", [(1, "multipart/mixed"), (1200, "multipart/mixed"),
                                       (1200, "message/rfc822")])
def test_nested_mime_is_refused_without_writes(scanner_client, ctx, depth, kind):
    seed_full(ctx)
    before = {p.relative_to(ctx.store.root): p.read_bytes() for p in ctx.store.root.rglob("*") if p.is_file()}
    body = nested_upload(depth, kind=kind)
    assert len(body) < imports.MAX_UPLOAD_BYTES
    response = scanner_client.post(URL, headers={**ACTOR, "Content-Type": "multipart/form-data; boundary=outer"},
                                   content=body)
    assert response.status_code == 400 and "private-secret" not in response.text
    assert {p.relative_to(ctx.store.root): p.read_bytes()
            for p in ctx.store.root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_compliance_upload_preserves_current_picture(scanner_client, ctx, reverse):
    prior = seed_full(ctx)
    before = {p.relative_to(ctx.store.root): p.read_bytes() for p in ctx.store.root.rglob("*") if p.is_file()}
    results = ["PASSED", "FAILED"]
    if reverse:
        results.reverse()
    items = "".join(f'''<ReportItem port="0" protocol="tcp" pluginID="21156"
                        severity="{0 if status == 'PASSED' else 3}">
      <cm:compliance-check-id>different-check-{i}</cm:compliance-check-id>
      <cm:compliance-reference>STIG-ID|WN11-AC-000035</cm:compliance-reference>
      <cm:compliance-result>{status}</cm:compliance-result>
      </ReportItem>''' for i, status in enumerate(results))
    data = (f'<NessusClientData_v2 xmlns:cm="urn:compliance"><Report><ReportHost name="one">'
            f'{items}</ReportHost></Report></NessusClientData_v2>').encode()
    response = upload(scanner_client, data, {"one": "workstation"}, include_info="true")
    assert response.status_code == 400 and "conflicting compliance" in response.json()["detail"]
    assert scanner_client.get("/api/v1/findings").json()["findings"][0]["id"] == prior.id
    assert {p.relative_to(ctx.store.root): p.read_bytes()
            for p in ctx.store.root.rglob("*") if p.is_file()} == before


def flat_upload(data, extra_headers=b""):
    return (b'--flat\r\nContent-Disposition: form-data; name="file"; filename="input.nessus"\r\n'
            b'Content-Type: application/xml\r\n' + extra_headers + b'\r\n' + data
            + b'\r\n--flat\r\nContent-Disposition: form-data; name="host_map"\r\n\r\n'
            + json.dumps(MAPPING).encode() + b'\r\n--flat--\r\n')


@pytest.mark.parametrize("case", ["missing_close", "preamble", "epilogue", "header_size", "header_count",
                                 "duplicate_header"])
def test_malformed_flat_form_is_bounded_and_does_not_write(scanner_client, ctx, case):
    headers = b""
    if case == "header_size":
        headers = b"X-Large: " + b"x" * imports.MAX_PART_HEADER_BYTES + b"\r\n"
    elif case == "header_count":
        headers = b"".join(f"X-{i}: value\r\n".encode() for i in range(imports.MAX_PART_HEADERS))
    elif case == "duplicate_header":
        headers = b"Content-Type: multipart/mixed\r\n"
    body = flat_upload(SAMPLE.read_bytes(), headers)
    if case == "missing_close":
        body = body.removesuffix(b"--flat--\r\n")
    elif case == "preamble":
        body = b"private-secret\r\n" + body
    elif case == "epilogue":
        body += b"private-secret"
    before = {p.relative_to(ctx.store.root): p.read_bytes() for p in ctx.store.root.rglob("*") if p.is_file()}
    response = scanner_client.post(URL, headers={**ACTOR, "Content-Type": "multipart/form-data; boundary=flat"},
                                   content=body)
    assert response.status_code == 400 and "private-secret" not in response.text
    assert {p.relative_to(ctx.store.root): p.read_bytes()
            for p in ctx.store.root.rglob("*") if p.is_file()} == before


def test_flat_form_preserves_boundary_prefix_in_xml():
    data = SAMPLE.read_bytes().replace(b"Encryption level not enforced.", b"Evidence\r\n--flat-not-a-delimiter\r\n")
    parsed, mapping, include_info = imports.parse_upload(flat_upload(data), 'multipart/form-data; boundary="flat"')
    assert parsed == data and mapping == MAPPING and not include_info


def test_upload_parsing_does_not_block_other_requests(scanner_client, ctx, monkeypatch):
    prior = seed_full(ctx)
    entered, release = threading.Event(), threading.Event()
    parse = imports.parse_upload
    loop_thread = threading.get_ident()

    def paused_parse(*args):
        entered.set()
        assert threading.get_ident() != loop_thread, "upload parser ran on the event loop"
        assert release.wait(10), "test did not release the parser"
        return parse(*args)

    monkeypatch.setattr(imports, "parse_upload", paused_parse)

    async def exercise():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=scanner_client.app),
                                     base_url="http://testserver") as client:
            pending = asyncio.create_task(client.post(URL, headers=ACTOR,
                files={"file": ("input.nessus", SAMPLE.read_bytes())}, data={"host_map": json.dumps(MAPPING)}))
            try:
                assert await asyncio.to_thread(entered.wait, 5), "upload parser did not start"
                response = await asyncio.wait_for(client.get("/api/v1/findings"), timeout=5)
                assert response.status_code == 200
                assert {f["id"] for f in response.json()["findings"]} == {prior.id}
                assert not pending.done(), "upload completed before the parser was released"
            finally:
                release.set()
                imported = await pending
            assert imported.status_code == 200 and imported.json()["imported_count"] == 5

    asyncio.run(exercise())


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
