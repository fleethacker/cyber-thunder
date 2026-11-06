"""Retention uses disposable state only, including native permission calibration."""
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import zipfile

import pytest

from cyberthunder.control.approvals import Proposal
from cyberthunder.findings.schema import Finding, findings_doc
from cyberthunder.scan import ScanRun
from cyberthunder.state import retention as r
from cyberthunder.store import StateStore


CUTOFF = "2026-02-01T00:00:00Z"


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def history(state_dir, tmp_path):
    store = StateStore(state_dir)
    for sid, day, host in (("old", "01", "a"), ("live", "02", "b"), ("new", "03", "a")):
        run = ScanRun(id=sid, targets=[host], status="done",
                      started_at=f"2026-01-{day}T00:00:00+00:00",
                      finished_at=f"2026-01-{day}T01:00:00+00:00")
        raw = store.scan_dir(sid) / "raw" / "result.bin"
        raw.write_bytes(b"exact\x00evidence\xff\r\n" + sid.encode())
        rows = [] if sid == "new" else [Finding(
            host=host, source="hunt", rule_id=f"rule-{sid}", title="fixture observation",
            severity="high", status="open", scan_id=sid, raw_ref=f"scans/{sid}/raw/result.bin")]
        # Direct backend writes avoid unrelated services and preserve deliberate byte fixtures.
        store.docs.put(f"scans/{sid}/run.json", run.to_dict())
        store.docs.put(f"scans/{sid}/findings.json", findings_doc(rows))
    private = tmp_path / "custody"
    private.mkdir(mode=0o700)
    yield store, private
    store.close()


def make_plan(store, **kwargs):
    return r.plan(store.root, store.backend_name, cutoff_utc=CUTOFF, **kwargs)


def put_run(store, sid, **changes):
    run = store.load_scan_run(sid)
    store.docs.put(f"scans/{sid}/run.json", {**run, **changes})


def test_exact_archive_roundtrip_and_source_preservation(history):
    store, private = history
    sentinel = {
        "audit.jsonl": b"audit-chain\n", "audit.jsonl.head": b"checkpoint",
        "targets.yaml": b"inventory", "policy.json": b"policy",
        "credentials/key.pem": b"private-key", "sessions/session.json": b"session",
        "tokens/token.json": b"token",
    }
    for key, data in sentinel.items():
        path = store.root / key
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
    current = [f.to_dict() for f in store.current_findings()]
    selected = make_plan(store)
    assert selected["eligible"] == ["old"]
    assert "current-observation" in selected["pinned"]["live"]
    output = private / "evidence.zip"
    receipt = r.archive(store.root, selected, output)
    checked = r.inspect_archive(output, receipt["archive_sha256"])
    assert checked["verified"] and receipt["deletion_enabled"] is False
    assert len(checked["manifest"]["plan"]["source_manifest"]) == 3
    with zipfile.ZipFile(output) as archive:
        for entry in selected["source_manifest"]:
            path = entry["path"]
            if store.backend_name == "sqlite" and path.endswith(("run.json", "findings.json")):
                with sqlite3.connect(store.root / "state.db") as conn:
                    original = conn.execute("SELECT body FROM documents WHERE path=?", (path,)).fetchone()[0].encode()
                assert entry["origin"] == "sqlite-body-utf8"
            else:
                original = (store.root / path).read_bytes()
            assert archive.read(path) == original
            assert digest(original) == entry["sha256"]
        assert all(name == "manifest.json" or name.startswith("scans/old/") for name in archive.namelist())
    assert [f.to_dict() for f in store.current_findings()] == current
    assert all((store.root / key).read_bytes() == data for key, data in sentinel.items())
    assert store.load_scan_run("old") is not None
    assert make_plan(store) == selected


def test_explicit_cutoff_age_and_boundary(history):
    store, _ = history
    age = r.plan(store.root, store.backend_name, age_days=30, now_utc="2026-03-03T00:00:00Z")
    assert age == make_plan(store)
    boundary = r.plan(store.root, store.backend_name, cutoff_utc="2026-01-01T01:00:00Z")
    assert boundary["eligible"] == []
    assert boundary["pinned"]["old"] == ["cutoff"]


@pytest.mark.parametrize("args", [dict(), {"age_days": 0}, {"age_days": -1}, {"age_days": True},
    {"cutoff_utc": CUTOFF, "age_days": 1}, {"cutoff_utc": "2026-01-01"},
    {"cutoff_utc": "2026-01-01T00:00:00+01:00"}, {"cutoff_utc": "9999-01-01T00:00:00Z"}])
def test_invalid_cutoffs(history, args):
    store, _ = history
    with pytest.raises(r.RetentionError):
        r.plan(store.root, store.backend_name, **args)


@pytest.mark.parametrize("trigger", ["verify", "bulletin", "cluster_vulnerabilities"])
def test_partial_and_incomplete_runs_preserve_current_observations(history, trigger):
    store, _ = history
    put_run(store, "new", trigger=trigger)
    selected = make_plan(store)
    assert "old" not in selected["eligible"]
    assert "current-observation" in selected["pinned"]["old"]
    put_run(store, "new", trigger="manual", coverage_incomplete=True)
    assert "current-observation" in make_plan(store)["pinned"]["old"]


def test_proposal_and_rollback_pins_preserve_bytes(history):
    store, private = history
    finding = store.load_findings("old")[0]
    proposal = Proposal(finding_id=finding.id, host="a", title="test", fix_ref="fixture",
                        fix_preview="", rollback_plan="restore fixture", risk="test")
    store.proposals.write_text(json.dumps([proposal.to_dict()]), encoding="utf-8")
    before = store.proposals.read_bytes()
    selected = make_plan(store)
    assert "proposal-reference" in selected["pinned"]["old"]
    with pytest.raises(r.RetentionError, match="no eligible"):
        r.archive(store.root, selected, private / "empty.zip")
    rollback = store.snapshots_dir / proposal.id
    rollback.mkdir()
    saved = rollback / "before.bin"
    saved.write_bytes(b"rollback-original")
    selected = make_plan(store)
    assert all("unknown-reference-or-rollback" in v for v in selected["pinned"].values())
    assert saved.read_bytes() == b"rollback-original" and store.proposals.read_bytes() == before


@pytest.mark.parametrize("path", ["snapshots/p1/before.bin", "outbox/export.bin", "synced/report.bin",
                                   "plugin-reference.json", "explanations/unknown.json"])
def test_unknown_references_pin_all(history, path):
    store, _ = history
    if r.is_document(path):
        store.docs.put(path, {"unknown_reference": "old"})
    else:
        p = store.root / path
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(b"opaque reference")
    assert make_plan(store)["eligible"] == []


@pytest.mark.parametrize("status", ["running", "pending", "unrecognized", None])
def test_active_or_unsupported_scan_refused(history, status):
    store, _ = history
    put_run(store, "new", status=status)
    with pytest.raises(r.RetentionError):
        make_plan(store)


def test_active_job_and_proposal_refused(history):
    store, _ = history
    store.docs.put("content/jobs/active.json", {"state": "running"})
    with pytest.raises(r.RetentionError, match="active"):
        make_plan(store)


@pytest.mark.parametrize("change", ["missing", "bytes", "run", "new-proposal", "new-snapshot", "new-outbox"])
def test_stale_plan_refused_before_output(history, change):
    store, private = history
    selected = make_plan(store)
    if change == "missing":
        (store.root / "scans/old/raw/result.bin").unlink()
    elif change == "bytes":
        (store.root / "scans/old/raw/result.bin").write_bytes(b"changed")
    elif change == "run":
        put_run(store, "old", requested_by="changed")
    elif change == "new-proposal":
        store.proposals.write_text("[]", encoding="utf-8")
    else:
        area = "snapshots" if change == "new-snapshot" else "outbox"
        (store.root / area / "new.bin").write_bytes(b"new reference")
    output = private / "must-not-exist.zip"
    with pytest.raises(r.RetentionError):
        r.archive(store.root, selected, output)
    assert not output.exists()


@pytest.mark.parametrize("area", ["snapshots", "outbox", "proposal", "document"])
def test_cross_process_mutation_during_archive_refuses_receipt(history, monkeypatch, area):
    store, private = history
    selected = make_plan(store)
    original = r.inspect_archive
    called = False

    def concurrent_write(*args, **kwargs):
        nonlocal called
        result = original(*args, **kwargs)
        if not called:
            called = True
            # A real separate process writes after output verification, before source recheck.
            code = """import pathlib, sys
root = pathlib.Path(sys.argv[1])
area = sys.argv[2]
if area == 'document':
    from cyberthunder.state import open_backend
    backend = open_backend(sys.argv[3], root)
    doc = backend.get('scans/old/run.json')
    doc['requested_by'] = 'concurrent fixture'
    backend.put('scans/old/run.json', doc)
    backend.close()
else:
    path = root / ('proposals.json' if area == 'proposal' else area + '/concurrent.bin')
    path.write_bytes(b'[]')
"""
            subprocess.run([sys.executable, "-c", code, str(store.root), area, store.backend_name], check=True)
        return result

    monkeypatch.setattr(r, "inspect_archive", concurrent_write)
    output = private / "unaccepted.zip"
    with pytest.raises(r.RetentionError, match="source changed"):
        r.archive(store.root, selected, output)
    assert output.exists()  # Preserved for review, never represented as an accepted archive.
    assert store.load_scan_run("old") is not None


@pytest.mark.parametrize("field,value", [("scan_id", "foreign"), ("raw_ref", "../../outside"),
                                         ("raw_ref", "scans/new/raw/result.bin"),
                                         ("raw_ref", "sha256:" + "a" * 64)])
def test_foreign_and_unresolvable_references_refused(history, field, value):
    store, _ = history
    path = "scans/old/findings.json"
    doc = store.docs.get(path)
    doc["findings"][0][field] = value
    store.docs.put(path, doc)
    with pytest.raises(r.RetentionError):
        make_plan(store)


@pytest.mark.parametrize("limit", [{"files": 2}, {"file_bytes": 10}, {"total_bytes": 100}])
def test_source_limits(history, limit):
    store, _ = history
    with pytest.raises(r.RetentionError, match="limit"):
        make_plan(store, limits=r.Limits(**limit))


def test_archive_limit_and_plan_tampering(history):
    store, private = history
    selected = make_plan(store, limits=r.Limits(archive_bytes=10))
    with pytest.raises(r.RetentionError, match="limit"):
        r.archive(store.root, selected, private / "too-large.zip")
    selected = make_plan(store)
    selected["eligible"].append("live")
    with pytest.raises(r.RetentionError, match="plan or source changed"):
        r.archive(store.root, selected, private / "forged.zip")


def test_output_collision_and_state_destination_refused(history):
    store, private = history
    selected = make_plan(store)
    collision = private / "exists.zip"
    collision.write_bytes(b"do not replace")
    for path in (collision, store.root / "archive.zip", private / "missing" / "archive.zip"):
        with pytest.raises(r.RetentionError):
            r.archive(store.root, selected, path)
    assert collision.read_bytes() == b"do not replace"


def test_native_private_file_and_destination_negative_calibration(history):
    store, private = history
    selected = make_plan(store)
    path = private / "private.zip"
    receipt = r.archive(store.root, selected, path)
    assert r.inspect_archive(path, receipt["archive_sha256"])["verified"]
    if os.name == "nt":
        from tests.windows_acl import set_dacl, protected_aces
        set_dacl(path, protected_aces() + "(A;;FR;;;WD)")
    else:
        path.chmod(0o644)
    with pytest.raises(r.RetentionError):
        r.inspect_archive(path, receipt["archive_sha256"])
    if os.name == "nt":
        set_dacl(private, protected_aces(directory=True) + "(A;OICI;FR;;;WD)")
    else:
        private.chmod(0o755)
    rejected = private / "rejected.zip"
    with pytest.raises(r.RetentionError):
        r.archive(store.root, selected, rejected)
    assert not rejected.exists() or rejected.stat().st_size == 0


def test_source_hardlink_refused(history):
    store, private = history
    os.link(store.root / "scans/old/raw/result.bin", private / "linked.bin")
    with pytest.raises(r.RetentionError, match="linked"):
        make_plan(store)


def test_source_and_output_redirects_refused(history):
    store, private = history
    selected = make_plan(store)
    redirect = private / "redirect"
    if os.name == "nt":
        # Junctions require no developer-mode symlink privilege.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(redirect), str(store.root / "scans/old/raw")],
                       check=True, capture_output=True)
    else:
        redirect.symlink_to(store.root / "scans/old/raw", target_is_directory=True)
    with pytest.raises(r.RetentionError):
        r.archive(store.root, selected, redirect / "bad.zip")
    scan_redirect = store.root / "scans/old/raw/redirect"
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(scan_redirect), str(private)],
                       check=True, capture_output=True)
    else:
        scan_redirect.symlink_to(private, target_is_directory=True)
    with pytest.raises(r.RetentionError):
        make_plan(store)


def test_corruption_hash_and_member_checks(history):
    store, private = history
    selected = make_plan(store)
    path = private / "evidence.zip"
    receipt = r.archive(store.root, selected, path)
    with pytest.raises(r.RetentionError, match="digest"):
        r.inspect_archive(path, "0" * 64)
    original = path.read_bytes()
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(buffer, "w") as target:
        for entry in source.infolist():
            data = source.read(entry.filename)
            if entry.filename.endswith("result.bin"):
                data = b"x" * len(data)
            target.writestr(entry, data)
    path.write_bytes(buffer.getvalue())
    with pytest.raises(r.RetentionError, match="member integrity"):
        r.inspect_archive(path, digest(path.read_bytes()))
    with pytest.raises(r.RetentionError, match="digest"):
        r.inspect_archive(path, receipt["archive_sha256"])


@pytest.mark.parametrize("member", ["../escape", "audit.jsonl", "scans/old/raw/../../escape"])
def test_archive_inspection_rejects_extra_or_traversing_members(history, member):
    store, private = history
    path = private / "evidence.zip"
    r.archive(store.root, make_plan(store), path)
    with zipfile.ZipFile(path, "a") as archive:
        entry = zipfile.ZipInfo(member)
        entry.external_attr = (stat.S_IFREG | 0o600) << 16
        archive.writestr(entry, b"bad")
    with pytest.raises(r.RetentionError):
        r.inspect_archive(path, digest(path.read_bytes()))


def test_cli_plan_archive_inspect_and_verified_refusal(history, monkeypatch, capsys):
    from cyberthunder.cli import main
    store, private = history
    monkeypatch.setenv("CT_AUTH_MODE", "dev")
    monkeypatch.setenv("CT_SECURITY_MODE", "dev")
    base = ["--state-dir", str(store.root), "state", "retention"]
    assert main([*base, "plan", "--cutoff-utc", CUTOFF]) == 0
    selected = json.loads(capsys.readouterr().out)
    saved = private / "plan.json"
    saved.write_text(json.dumps(selected), encoding="utf-8")
    if os.name != "nt":
        saved.chmod(0o600)
    output = private / "evidence.zip"
    assert main([*base, "archive", "--plan-file", str(saved), "--output", str(output)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert main([*base, "inspect", str(output), "--sha256", receipt["archive_sha256"]]) == 0
    capsys.readouterr()
    monkeypatch.setenv("CT_AUTH_MODE", "oidc")
    assert main([*base, "plan", "--cutoff-utc", CUTOFF]) == 2
    assert "authenticated API session" in capsys.readouterr().err
    assert main([*base, "archive", "--plan-file", str(saved), "--output", str(private / "no.zip")]) == 2
    assert not (private / "no.zip").exists()


def test_backend_schema_mismatch(history):
    store, _ = history
    if store.backend_name == "sqlite":
        with sqlite3.connect(store.root / "state.db") as conn:
            conn.execute("UPDATE meta SET value='999' WHERE key='schema'")
    else:
        (store.root / "state.db").write_bytes(b"foreign backend")
    with pytest.raises(r.RetentionError):
        make_plan(store)


@pytest.mark.parametrize("path", ["scans/old/raw/credentials.json", "scans/old/raw/key.pem",
                                   "scans/old/raw/token.json", "scans/old/raw/shadow"])
def test_misplaced_protected_material_never_exported(history, path):
    store, private = history
    (store.root / path).write_bytes(b"protected fixture")
    with pytest.raises(r.RetentionError, match="protected material"):
        make_plan(store)
    assert not list(private.iterdir())


@pytest.mark.parametrize("value,refused", [({"previous_scan_id": "foreign"}, True),
                                         ({"previous_scan_id": "old"}, False),
                                         ({"future_reference": "opaque"}, False)])
def test_nested_foreign_and_unknown_references(history, value, refused):
    store, _ = history
    put_run(store, "new", summary=value)
    if refused:
        with pytest.raises(r.RetentionError, match="scan reference"):
            make_plan(store)
    else:
        assert "old" not in make_plan(store)["eligible"]


def test_missing_document_and_unknown_fields_fail_closed(history):
    store, _ = history
    put_run(store, "old", future_field=True)
    with pytest.raises(r.RetentionError, match="unsupported scan record"):
        make_plan(store)
    run = store.load_scan_run("old")
    run.pop("future_field")
    store.docs.put("scans/old/run.json", run)
    store.docs.delete("scans/old/findings.json")
    with pytest.raises(r.RetentionError, match="missing run or findings"):
        make_plan(store)


def test_planning_detects_mutation_between_captures(history, monkeypatch):
    store, _ = history
    original = r._snapshot
    count = 0

    def change_after_capture(*args):
        nonlocal count
        snapshot = original(*args)
        count += 1
        if count == 1:
            (store.snapshots_dir / "new.bin").write_bytes(b"new rollback reference")
        return snapshot

    monkeypatch.setattr(r, "_snapshot", change_after_capture)
    with pytest.raises(r.RetentionError, match="source changed during planning"):
        make_plan(store)


def test_native_unsafe_source_permission_negative_calibration(history):
    store, _ = history
    path = store.root / ("state.db" if store.backend_name == "sqlite" else "scans/old/run.json")
    if os.name == "nt":
        from tests.windows_acl import set_dacl, protected_aces
        set_dacl(path, protected_aces() + "(A;;FW;;;WD)")
    else:
        path.chmod(0o666)
    with pytest.raises(r.RetentionError):
        make_plan(store)


def test_raw_absolute_reference_and_missing_root(history):
    store, private = history
    doc = store.docs.get("scans/old/findings.json")
    doc["findings"][0]["raw_ref"] = str(store.root / "scans/old/raw/result.bin")
    store.docs.put("scans/old/findings.json", doc)
    assert make_plan(store)["eligible"] == ["old"]
    missing = private / "missing-state"
    with pytest.raises(r.RetentionError):
        r.plan(missing, store.backend_name, cutoff_utc=CUTOFF)
    assert not missing.exists()


def test_sqlite_foreign_row_or_json_case_collision(history):
    store, _ = history
    if store.backend_name == "sqlite":
        with sqlite3.connect(store.root / "state.db") as conn:
            conn.execute("INSERT INTO documents VALUES (?, ?, ?)", ("../foreign.json", "{}", 0))
    else:
        (store.root / "scans/old/unsupported.bin").write_bytes(b"unsupported")
    with pytest.raises(r.RetentionError):
        make_plan(store)


def test_empty_state_never_produces_an_archive(tmp_path):
    root = tmp_path / "empty-state"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    selected = r.plan(root, "json", cutoff_utc=CUTOFF)
    assert selected["eligible"] == [] and selected["source_manifest"] == []
    with pytest.raises(r.RetentionError, match="no eligible"):
        r.archive(root, selected, private / "none.zip")


def test_archive_bounded_directory_parsing(history):
    import struct
    store, private = history
    path = private / "evidence.zip"
    r.archive(store.root, make_plan(store), path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<HH", data, len(data) - 14, 65535, 65535)
    path.write_bytes(data)
    with pytest.raises(r.RetentionError, match="archive directory"):
        r.inspect_archive(path, digest(data))


@pytest.mark.parametrize("variation", ["valid", "foreign", "missing", "workdir", "unknown"])
def test_collector_manifest_references(history, variation):
    from cyberthunder.adapters.base import Collected
    store, private = history
    directory = store.root / "scans/old/raw/a"
    directory.mkdir()
    collected = Collected(target_id="a", asset_type="linux", workdir=str(directory),
                          artifacts={"result": str(store.root / "scans/old/raw/result.bin")}).to_dict()
    if variation == "foreign":
        collected["artifacts"]["result"] = str(private / "foreign")
    elif variation == "missing":
        collected["artifacts"]["result"] = str(directory / "missing")
    elif variation == "workdir":
        collected["workdir"] = str(private)
    elif variation == "unknown":
        collected["future_field"] = "unsupported"
    (directory / "collected.json").write_text(json.dumps(collected), encoding="utf-8")
    if variation == "valid":
        selected = make_plan(store)
        assert selected["eligible"] == ["old"]
        receipt = r.archive(store.root, selected, private / "collected.zip")
        assert receipt["members"] == 4
    else:
        with pytest.raises(r.RetentionError):
            make_plan(store)


@pytest.mark.parametrize("coverage,result", [(True, {}), (False, {"a": {"target_id": "a", "status": "partial"}})])
def test_completed_but_incomplete_scan_stays_pinned(history, coverage, result):
    store, _ = history
    put_run(store, "old", coverage_incomplete=coverage, results=result)
    assert "incomplete-coverage-or-results" in make_plan(store)["pinned"]["old"]


def test_unknown_target_result_fails_closed(history):
    store, _ = history
    put_run(store, "old", results={"a": {"target_id": "a", "status": "unsupported"}})
    with pytest.raises(r.RetentionError, match="target result"):
        make_plan(store)


def test_exact_noncanonical_document_text(history):
    store, private = history
    key = "scans/old/run.json"
    doc = store.load_scan_run("old")
    doc["requested_by"] = "fixture \u00e9"
    text = json.dumps(doc, indent=5, ensure_ascii=False).replace("\n", "\r\n") + "\r\n \t"
    if store.backend_name == "sqlite":
        with sqlite3.connect(store.root / "state.db") as conn:
            conn.execute("UPDATE documents SET body=? WHERE path=?", (text, key))
    else:
        (store.root / key).write_bytes(text.encode("utf-8"))
    output = private / "exact.zip"
    r.archive(store.root, make_plan(store), output)
    with zipfile.ZipFile(output) as archive:
        assert archive.read(key) == text.encode("utf-8")
