"""The document backends behind StateStore: routing, both implementations, locking, migration, the CLI."""
import json
import logging
import os
import threading

import pytest

from cyberthunder.cli import main
from cyberthunder.findings.schema import Finding, load_findings
from cyberthunder.state import StateError, is_document, match_pattern, open_backend
from cyberthunder.state.json_files import JsonFilesBackend
from cyberthunder.state.migrate import info, migrate
from cyberthunder.state.sqlite import SqliteBackend
from cyberthunder.store import StateStore

DOCUMENTS = ["scans/scan-1/run.json", "scans/scan-1/findings.json", "explanations/f.json", "link.json", "demo.json",
             "ingest/deltas/d.json", "ingest/bulletins/b.json", "discovery/assets.json", "discovery/runs/r.json",
             "content/index.json", "content/last_check.json", "content/source.json", "content/catalog.json",
             "content/jobs/pull-1.json"]
FILES = ["audit.jsonl", "audit.jsonl.head", "proposals.json", "policy.json", "targets.yaml", "killswitch.json", "KILL",
         "scans/scan-1/raw/h1/collected.json", "scans/scan-1/raw/h1/results.xml", "scans/run.json",
         "snapshots/p1/fix.json", "outbox/x.meta.json", "synced/x.meta.json", "content/manifest.json",
         "content/quarantine/a.why.json", "content/files/U_RHEL_9_V2R10_STIG.zip", "ingest/catalog/x.xml",
         "ingest/uploads/u/x.json", "simulated/sim-linux-01.json", "discovery/runs/r.lock", "state.db"]


def _finding(rule, status="open"):
    return Finding(host="h1", source="native", rule_id=rule, title=rule, severity="medium", status=status)


def test_routing_follows_the_layout():
    assert all(is_document(p) for p in DOCUMENTS)
    assert not any(is_document(p) for p in FILES)


def test_pattern_match_stays_inside_one_directory():
    assert match_pattern("a/run.json", "*/run.json") and not match_pattern("a/b/run.json", "*/run.json")
    assert match_pattern("x.meta.json", "*.meta.json") and not match_pattern("x.json", "*.meta.json")
    assert match_pattern("anything/at/all.json", None)


@pytest.mark.parametrize("name", ["json", "sqlite"])
def test_backend_put_get_list_delete(tmp_path, name):
    be = open_backend(name, tmp_path)
    be.put("scans/a/run.json", {"id": "a"})
    be.put("scans/a/findings.json", {"findings": []})
    be.put("scans/b/run.json", {"id": "b"}, mtime=1_700_000_000.0)
    be.put("explanations/x.json", [1, 2, 3])                 # a list is a document too
    assert be.get("scans/a/run.json") == {"id": "a"} and be.get("missing.json") is None
    assert [p for p, _ in be.list("scans", "*/run.json")] == ["scans/a/run.json", "scans/b/run.json"]
    assert [p for p, _ in be.list("scans/")] == ["scans/a/findings.json", "scans/a/run.json", "scans/b/run.json"]
    assert dict(be.list("scans/b"))["scans/b/run.json"] == pytest.approx(1_700_000_000.0, abs=1)
    assert be.count() == 4 and be.size_bytes() > 0 and be.location()
    assert be.delete("scans/b/run.json") and not be.delete("scans/b/run.json")
    assert be.get("explanations/x.json") == [1, 2, 3] and be.count() == 3
    be.close()


def test_json_backend_writes_the_files_the_tool_always_wrote(tmp_path):
    be = JsonFilesBackend(tmp_path)
    be.put("scans/a/run.json", {"id": "a", "n": 1, "text": "café"})
    p = tmp_path / "scans" / "a" / "run.json"
    assert p.read_text(encoding="utf-8") == json.dumps({"id": "a", "n": 1, "text": "café"}, indent=2, ensure_ascii=False)
    assert not p.with_suffix(".json.tmp").exists()
    assert [p for p, _ in be.list()] == ["scans/a/run.json"]


def test_sqlite_backend_is_one_wal_database(tmp_path):
    be = SqliteBackend(tmp_path)
    assert be.created and SqliteBackend.exists(tmp_path)
    assert be._conn().execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert be.meta()["schema"] == "1"
    be.put("link.json", {"kbps": 1})
    be.close()
    again = SqliteBackend(tmp_path)
    assert not again.created and again.get("link.json") == {"kbps": 1}
    again.close()


def test_sqlite_lock_is_a_transaction(tmp_path):
    be = SqliteBackend(tmp_path)
    with pytest.raises(RuntimeError):
        with be.lock("t"):
            be.put("link.json", {"x": 1})
            be.put("demo.json", {"x": 2})
            assert be.get("link.json") == {"x": 1}            # visible inside the transaction
            raise RuntimeError("boom")
    assert be.get("link.json") is None and be.get("demo.json") is None   # rolled back together
    with be.lock("t"):
        be.put("link.json", {"x": 3})
        with be.lock("t"):                                    # re-entrant within the thread
            be.put("demo.json", {"y": 1})
    assert be.get("link.json") == {"x": 3} and be.get("demo.json") == {"y": 1}
    be.close()


@pytest.mark.parametrize("name", ["json", "sqlite"])
def test_lock_serializes_read_modify_write(tmp_path, name):
    be = open_backend(name, tmp_path)
    be.put("link.json", {"n": 0})

    def worker():
        for _ in range(25):
            with be.lock("counter"):
                d = be.get("link.json")
                d["n"] += 1
                be.put("link.json", d)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert be.get("link.json")["n"] == 100
    be.close()


def test_store_routes_documents_and_files(state_dir):
    """Runs on both backends through the fixture: documents follow the backend, files stay files."""
    st = StateStore(state_dir)
    assert st.backend_name == os.environ["CT_STATE_BACKEND"] == st.info()["backend"]
    st.write_json(st.link_state, {"kbps": 9.6})
    raw = st.scan_dir("scan-1") / "raw" / "h1" / "collected.json"
    st.write_json(raw, {"facts": {}})
    st.save_scan_run({"id": "scan-1", "started_at": "2026-11-05T10:00:00+00:00"})
    st.save_findings("scan-1", [_finding("r1")])
    assert raw.exists()                                                          # a file under every backend
    assert (st.scans_dir / "scan-1" / "run.json").exists() == (st.backend_name == "json")
    assert st.read_json(st.link_state) == {"kbps": 9.6} and st.list_scan_runs()[0]["id"] == "scan-1"
    assert [f.rule_id for f in st.load_findings("scan-1")] == ["r1"]
    if st.backend_name == "json":                                                # byte-compatible findings file
        assert [f.rule_id for f in load_findings(st.scans_dir / "scan-1" / "findings.json")] == ["r1"]
    outside = state_dir.parent / "manifest.json"
    st.write_json(outside, {"items": []})                                        # outside the state dir: a file
    assert json.loads(outside.read_text(encoding="utf-8")) == {"items": []} and st.read_json(outside) == {"items": []}
    assert st.read_json(st.root / "nope.json", {"d": 1}) == {"d": 1}
    assert st.logical_path(st.scans_dir / "scan-1" / "run.json") == "scans/scan-1/run.json"
    assert st.logical_path(outside) is None and st.logical_path(st.root) == ""
    (st.outbox_dir / "a.meta.json").write_text("{}", encoding="utf-8")
    assert [p.name for p in st.list_json(st.outbox_dir, "*.meta.json")] == ["a.meta.json"]
    assert [p.name for p in st.list_json(st.scans_dir / "scan-1" / "raw" / "h1")] == ["collected.json"]
    assert [p.name for p in st.list_json(st.scans_dir, "*/run.json")] == ["run.json"]
    assert st.list_json(st.root / "discovery" / "runs") == []
    assert st.delete_json(st.link_state) and st.read_json(st.link_state) is None
    with st.lock("unit"):
        st.save_explanation("f1", {"risk": "r"})
    assert st.load_explanation("f1")["risk"] == "r"
    st.close()


def test_unknown_backend_is_refused(tmp_path, monkeypatch):
    with pytest.raises(StateError):
        StateStore(tmp_path, backend="postgres")
    monkeypatch.setenv("CT_STATE_BACKEND", "oracle")
    with pytest.raises(StateError):
        StateStore(tmp_path)


def test_settings_carry_the_backend(monkeypatch):
    from cyberthunder.config import Settings
    monkeypatch.delenv("CT_STATE_BACKEND", raising=False)
    assert Settings.from_env().state_backend == "json"
    monkeypatch.setenv("CT_STATE_BACKEND", "SQLite")
    assert Settings.from_env().state_backend == "sqlite"


def test_unmigrated_directory_is_reported(tmp_path, caplog):
    root = tmp_path / "state"
    root.mkdir()
    _populate(root, "json")
    with caplog.at_level(logging.WARNING, logger="cyberthunder.store"):
        StateStore(root, backend="sqlite").close()
    assert any("not in state.db" in r.message for r in caplog.records)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="cyberthunder.store"):
        StateStore(root, backend="json").close()
    assert any("CT_STATE_BACKEND=json ignores" in r.message for r in caplog.records)


def _populate(root, backend) -> dict[str, object]:
    """Nine documents of every kind plus two files that must never move. Returns the documents by logical path."""
    st = StateStore(root, backend=backend)
    for i in range(3):
        st.save_scan_run({"id": f"scan-{i}", "started_at": f"2026-11-05T1{i}:00:00+00:00", "status": "done"})
        st.save_findings(f"scan-{i}", [_finding(f"rule-{i}"), _finding("shared", status="not_a_finding")])
    st.save_explanation("f1", {"risk": "r", "citations": ["RHEL-09-255045"]})
    st.write_json(st.link_state, {"kbps": 56.0, "connected": False})
    st.write_json(st.ingest_dir / "bulletins" / "b.json", {"id": "b", "text": "café — ok"})
    st.write_json(st.scan_dir("scan-0") / "raw" / "h1" / "collected.json", {"facts": {"os_name": "Rocky"}})
    (root / "proposals.json").write_text("[]", encoding="utf-8")
    docs = {p: st.read_json(root / p) for p in ["scans/scan-0/run.json", "scans/scan-0/findings.json",
                                                "scans/scan-1/run.json", "scans/scan-1/findings.json",
                                                "scans/scan-2/run.json", "scans/scan-2/findings.json",
                                                "explanations/f1.json", "link.json", "ingest/bulletins/b.json"]}
    st.close()
    return docs


def test_migrate_round_trip_keeps_every_document(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    docs = _populate(root, "json")
    rep = migrate(root, "sqlite")
    assert rep.ok and rep.source == "json" and rep.copied == 9 and rep.present_after == 9 and rep.compared == 9
    assert rep.audit_ok and rep.pruned == 0
    sq = StateStore(root, backend="sqlite")
    assert {p: sq.read_json(root / p) for p in docs} == docs and sq.docs.count() == 9
    assert (root / "proposals.json").exists() and (root / "scans/scan-0/raw/h1/collected.json").exists()
    assert (root / "scans/scan-0/run.json").exists()                    # the source is left in place
    rep2 = migrate(root, "sqlite")                                       # running it again changes nothing
    assert rep2.ok and rep2.copied == 0 and rep2.unchanged == 9
    sq.save_explanation("f2", {"risk": "new"})                           # the target now holds more
    sq.close()
    with pytest.raises(StateError, match="already holds"):
        migrate(root, "sqlite")
    rep3 = migrate(root, "sqlite", force=True)
    assert rep3.ok and rep3.unchanged == 9 and rep3.copied == 0
    rep4 = migrate(root, "json", force=True, prune=True, sample=0)      # back, comparing every document
    assert rep4.ok and rep4.source == "sqlite" and rep4.compared == 10 and rep4.pruned == 10 and rep4.copied == 1
    js = StateStore(root, backend="json")
    assert {p: js.read_json(root / p) for p in docs} == docs and js.load_explanation("f2")["risk"] == "new"
    js.close()
    assert SqliteBackend(root).count() == 0


def test_migrate_carries_timestamps_and_refuses_nonsense(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    _populate(root, "json")
    old = 1_600_000_000.0
    os.utime(root / "scans/scan-0/run.json", (old, old))
    migrate(root, "sqlite")
    assert dict(SqliteBackend(root).list("scans/scan-0"))["scans/scan-0/run.json"] == pytest.approx(old, abs=1)
    with pytest.raises(StateError):
        migrate(root, "json", "json")
    with pytest.raises(StateError):
        migrate(tmp_path / "nope", "sqlite")
    with pytest.raises(StateError):
        migrate(root, "postgres")


def test_info_reports_both_backends_without_creating_a_database(tmp_path):
    root = tmp_path / "state"
    root.mkdir()
    _populate(root, "json")
    d = info(root, "json")
    assert d["backend"] == "json" and d["documents"] == 9 and d["bytes"] > 0 and "other" not in d
    assert d["audit"]["verified"] is True and d["audit"]["records"] == 0
    d = info(root, "sqlite")
    assert d["documents"] == 0 and "not created" in d["location"] and d["other"]["documents"] == 9
    assert not (root / "state.db").exists()
    migrate(root, "sqlite", prune=True)
    d = info(root, "sqlite")
    assert d["documents"] == 9 and d["meta"]["schema"] == "1" and "other" not in d


def test_cli_info_and_migrate(tmp_path, capsys, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    _populate(root, "json")
    monkeypatch.delenv("CT_STATE_BACKEND", raising=False)
    assert main(["--state-dir", str(root), "state", "info"]) == 0
    out = capsys.readouterr().out
    assert "backend    json" in out and "documents  9" in out
    assert main(["--state-dir", str(root), "state", "migrate", "--to", "sqlite", "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["ok"] and rep["copied"] == 9 and rep["target"] == "sqlite"
    assert main(["--state-dir", str(root), "state", "info", "--backend", "sqlite"]) == 0
    assert "documents  9" in capsys.readouterr().out
    assert main(["--state-dir", str(root), "state", "info"]) == 0
    assert "held by the sqlite backend" in capsys.readouterr().out      # the configured one is still json
    StateStore(root, backend="sqlite").save_explanation("f9", {"risk": "x"})
    assert main(["--state-dir", str(root), "state", "migrate", "--to", "sqlite"]) == 2
    assert "refused" in capsys.readouterr().err
    assert main(["--state-dir", str(root), "state", "migrate", "--to", "sqlite", "--force"]) == 0
    assert "result             OK" in capsys.readouterr().out
