from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cyberthunder.ingest.outbox import LinkDisconnected
from cyberthunder.ingest.service import IngestError
from cyberthunder.inventory.targets import Target
from tests.ingest.content_helpers import make_ctx, node_client, record, scap_zip, stig_zip

STIG = "U_MS_Windows_11_V2R11_STIG.zip"
SCAP = "U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip"
ROOT = Path(__file__).resolve().parents[2]


def add_windows_host(ctx, tid="ws01"):
    ctx.inventory.add(Target(id=tid, name=tid, asset_type="windows", transport="winrm"))
    ctx.inventory.save()
    d = ctx.store.scan_dir("scan-20261104T120000-aaaaaa") / "raw" / tid
    d.mkdir(parents=True, exist_ok=True)
    (d / "collected.json").write_text(json.dumps({
        "target_id": tid, "asset_type": "windows", "workdir": str(d),
        "facts": {"hostname": tid, "os_name": "Microsoft Windows 11 Enterprise", "os_version": "10.0.22631",
                  "extra": {"domain": "WORKGROUP"}}}), encoding="utf-8")


@pytest.fixture
def served(tmp_path, file_server):
    """The two Windows 11 files on the loopback server and an index that lists them."""
    src = tmp_path / "src"
    src.mkdir()
    stig = stig_zip(src / STIG)
    scap = scap_zip(src / SCAP)
    file_server.add(STIG, stig.read_bytes(), etag='"stig-1"')
    file_server.add(SCAP, scap.read_bytes(), etag='"scap-1"')
    recs = [record(STIG, file_server.url(STIG)), record(SCAP, file_server.url(SCAP),
                                                         types="STIGs;SCAP 1.3;Security Content Application Protocols (SCAP)"),
            record("U_RHEL_8_V2R9_STIG.zip", file_server.url("U_RHEL_8_V2R9_STIG.zip"), types="STIGs;Sunset")]
    return {"stig": stig, "scap": scap, "records": recs, "server": file_server}


@pytest.fixture
def node(ctx, served):
    add_windows_host(ctx)
    ctx.ingest.content.client = node_client(lambda: served["records"])
    return ctx


def _strip(records):
    drop = {"fetched_at", "fetched_by", "source", "ingest", "url", "etag", "upload_date"}
    return sorted(({k: v for k, v in r.items() if k not in drop} for r in records), key=lambda r: r["filename"])


def test_check_updates_live(node, served):
    rep = node.ingest.check_updates("it2.smith")
    assert rep["index_entries"] == 3 and rep["source"] == "live"
    assert sorted(u["filename"] for u in rep["updates"]) == sorted([SCAP, STIG])
    sizes = {u["filename"]: u["expected_bytes"] for u in rep["updates"]}
    assert sizes[STIG] == served["stig"].stat().st_size
    assert rep["estimate_seconds_at_link"] > 0 and rep["index_estimate_seconds"] > 0
    assert node.ingest.last_update_check()["checked_at"] == rep["checked_at"]
    last = node.store.read_json(node.store.root / "content" / "last_check.json")
    assert last["wanted_count"] == 2 and last["new_count"] == 2 and "gzip" in last and last["index_bytes"] > 0
    rec = [r for r in node.audit.records() if r["action"] == "content.check"][-1]
    assert rec["actor"] == "it2.smith" and set(rec["details"]) <= {"url", "bytes", "seconds", "source", "entries",
                                                                     "updates"}


def test_disconnected_link_refuses_and_names_the_manifest(node):
    node.ingest.set_link(actor="it2.smith", connected=False)
    with pytest.raises(LinkDisconnected) as ei:
        node.ingest.check_updates("it2.smith")
    msg = str(ei.value)
    assert "manifest" in msg and str(node.store.root / "content" / "manifest.json") in msg
    with pytest.raises(LinkDisconnected):
        node.ingest.pull("it2.smith", all_matching=True)
    blocked = [r for r in node.audit.records() if r["action"] in ("content.check", "content.fetch")]
    assert [r["outcome"] for r in blocked] == ["blocked", "blocked"]
    # the snapshot check still works offline
    rep = node.ingest.check_updates("it2.smith", source="snapshot")
    assert rep["index_entries"] == 417
    assert {u["filename"] for u in rep["updates"]} == {STIG, SCAP}


def test_pull_job_end_to_end_matches_a_hand_import(node, served, tmp_path):
    node.ingest.check_updates("it2.smith")
    job = node.ingest.pull("it2.smith", all_matching=True)
    assert job["state"] == "queued" and len(job["files"]) == 2
    node.ingest.content.wait(30)
    job = node.ingest.pull_job(job["id"])
    assert job["state"] == "done", job
    files = {f["filename"]: f for f in job["files"]}
    assert files[STIG]["bytes"] == files[STIG]["total"] == served["stig"].stat().st_size
    delta = files[STIG]["delta"]
    assert delta and job["deltas"] == [delta] and delta["full_import"]
    ds = Path(files[SCAP]["datastream_path"])
    assert ds.is_file() and ds.parent.name == "MS_Windows_11" and ds.read_bytes().startswith(b"<?xml")

    # the same file imported by hand on a fresh node produces the same delta
    other = make_ctx(tmp_path / "hand")
    hand = other.ingest.ingest_stig(served["stig"], actor="it2.smith")
    pulled = node.ingest.get_delta(delta["id"])
    for k in ("benchmark_id", "old_release", "new_release", "counts", "rescan_rule_ids", "full_import"):
        assert pulled[k] == hand[k], k
    assert [d["id"] for d in node.ingest.history()["deltas"]] == [delta["id"]]

    held = node.ingest.held_content()
    assert {r["filename"]: r["source"] for r in held["files"]} == {STIG: "pulled", SCAP: "pulled"}
    rec = {r["filename"]: r for r in held["files"]}[STIG]
    assert rec["ingest"]["delta_id"] == delta["id"] and rec["sha256"] and rec["etag"] == '"stig-1"'
    acts = [r for r in node.audit.records() if r["action"] == "content.fetch"]
    assert len(acts) == 2 and all(set(r["details"]) == {"url", "bytes", "seconds", "sha256"} for r in acts)
    # now current: a second check finds nothing new
    assert node.ingest.check_updates("it2.smith")["updates"] == []


def test_pull_by_name_and_unknown_name(node):
    node.ingest.check_updates("it2.smith")
    job = node.ingest.pull("it2.smith", filenames=[STIG], background=False)
    assert job["state"] == "done" and [f["filename"] for f in job["files"]] == [STIG]
    with pytest.raises(IngestError, match="not in the STIG index"):
        node.ingest.pull("it2.smith", filenames=["U_Nope_V1R1_STIG.zip"])


def test_pull_refused_while_the_kill_switch_is_engaged(node):
    node.ingest.check_updates("it2.smith")
    node.killswitch.engage("it2.smith", "drill")
    with pytest.raises(IngestError, match="kill switch"):
        node.ingest.pull("it2.smith", all_matching=True)


def test_bad_download_is_quarantined_in_a_job(node, served):
    served["server"].files[STIG]["data"] = b"not a zip at all" * 100
    node.ingest.check_updates("it2.smith")
    job = node.ingest.pull("it2.smith", all_matching=True, background=False)
    states = {f["filename"]: f["state"] for f in job["files"]}
    assert states == {STIG: "quarantined", SCAP: "done"} and job["state"] == "partial"
    assert list((node.store.root / "content" / "quarantine").glob("*.why.json"))
    assert any(r["action"] == "content.quarantine" for r in node.audit.records())


def test_manifest_round_trip_equals_a_pull(node, served, tmp_path):
    # node A, link down: write a manifest from the last index it saw
    node.ingest.check_updates("it2.smith")
    node.ingest.set_link(actor="it2.smith", connected=False)
    m = node.ingest.write_manifest("it2.smith", tmp_path / "manifest.json")
    assert {i["filename"] for i in m["items"]} == {STIG, SCAP}
    assert all(i["expected_bytes"] and i["expected_etag"] for i in m["items"])
    assert any(r["action"] == "content.manifest" for r in node.audit.records())

    # connected machine: no node state at all
    from cyberthunder.ingest.content.service import fetch_manifest
    from tests.ingest.content_helpers import loopback_client
    media = tmp_path / "usb"
    lock = fetch_manifest(tmp_path / "manifest.json", media, loopback_client())
    assert lock["failed"] == [] and len(lock["files"]) == 2
    assert json.loads((media / "manifest.lock.json").read_text(encoding="utf-8"))["files"][0]["sha256"]

    # back on the node
    res = node.ingest.import_dir(media, "it2.smith")
    assert res["refused"] == [] and res["verified_by"] == "manifest.lock.json" and len(res["imported"]) == 2
    assert len(res["deltas"]) == 1
    imported = node.ingest.held_content()["files"]
    assert {r["source"] for r in imported} == {"imported"}

    # a pull on a fresh node holds the same content index
    other = make_ctx(tmp_path / "pulled")
    add_windows_host(other)
    other.ingest.content.client = node_client(lambda: served["records"])
    other.ingest.check_updates("it2.smith")
    other.ingest.pull("it2.smith", all_matching=True, background=False)
    assert _strip(other.ingest.held_content()["files"]) == _strip(imported)
    assert node.ingest.check_updates("it2.smith", source="snapshot")["updates"] == []


def test_import_dir_refuses_a_file_that_does_not_match_the_lock(node, served, tmp_path):
    node.ingest.check_updates("it2.smith")
    m = node.ingest.write_manifest("it2.smith", tmp_path / "manifest.json")
    from cyberthunder.ingest.content.service import fetch_manifest
    from tests.ingest.content_helpers import loopback_client
    media = tmp_path / "usb"
    fetch_manifest(Path(m["path"]), media, loopback_client())
    stig = media / STIG
    stig.write_bytes(stig.read_bytes() + b"tampered")
    res = node.ingest.import_dir(media, "it2.smith")
    assert [r["filename"] for r in res["refused"]] == [STIG] and "SHA-256" in res["refused"][0]["reason"]
    assert [r["filename"] for r in res["imported"]] == [SCAP]


def test_import_dir_without_a_lock_uses_the_integrity_checks(ctx, tmp_path):
    media = tmp_path / "usb"
    media.mkdir()
    stig_zip(media / STIG)
    (media / "U_Broken_V1R1_STIG.zip").write_bytes(b"garbage")
    (media / "notes.txt").write_text("hello", encoding="utf-8")
    res = ctx.ingest.import_dir(media, "it2.smith")
    assert [r["filename"] for r in res["imported"]] == [STIG] and res["verified_by"] == "integrity checks"
    assert [r["filename"] for r in res["refused"]] == ["U_Broken_V1R1_STIG.zip"]
    assert len(res["deltas"]) == 1


def test_reconnect_runs_a_check_after_the_outbox_flush(node):
    node.ingest.set_link(actor="it2.smith", connected=False)
    node.ingest.outbox.enqueue("report", "r1.json", b"{}")
    node.ingest.set_link(actor="it2.smith", connected=True)
    flush = node.ingest.link.last_flush
    assert flush["sent"] == 1 and flush["content"]["content_check"] == "started"
    node.ingest.content.wait(30)
    assert node.ingest.last_update_check() is not None
    acts = [r["action"] for r in node.audit.records()]
    assert acts.index("outbox.sync") < acts.index("content.check")


def test_reconnect_check_can_be_turned_off(node):
    node.settings.content_check_on_reconnect = False
    node.ingest.set_link(actor="it2.smith", connected=False)
    node.ingest.set_link(actor="it2.smith", connected=True)
    assert node.ingest.link.last_flush["content"] == {"content_check": "off"}


def test_reconnect_auto_pull(node):
    node.settings.content_auto_pull = True
    node.ingest.set_link(actor="it2.smith", connected=False)
    node.ingest.set_link(actor="it2.smith", connected=True)
    node.ingest.content.wait(30)
    held = {r["filename"] for r in node.ingest.held_content()["files"]}
    assert held == {STIG, SCAP}


@pytest.mark.parametrize("args", [["check"], ["updates"], ["pull"], ["content"], ["manifest"],
                                  ["fetch-manifest"], ["import-dir"]])
def test_every_new_cli_command_parses_with_help(args, state_dir):
    import argparse
    from cyberthunder.ingest.cli import register_cli
    ap = argparse.ArgumentParser(prog="cyberthunder")
    ap.add_argument("--state-dir", default=str(state_dir))
    ap.add_argument("--actor", default="it2.smith")
    register_cli(ap.add_subparsers(dest="cmd"))
    with pytest.raises(SystemExit) as ei:
        ap.parse_args(["ingest", *args, "--help"])
    assert ei.value.code == 0
    ns = ap.parse_args(["ingest", *args, "x", "--out", "y", "--file", "A.zip", "--file", "B.zip", "--all"])
    assert ns.sub == args[0] and ns.names == ["A.zip", "B.zip"] and ns.all_matching


def test_cli_round_trip_offline(ctx, state_dir, tmp_path, capsys):
    from cyberthunder.ingest.cli import register_cli
    import argparse
    add_windows_host(ctx)
    ap = argparse.ArgumentParser(prog="cyberthunder")
    ap.add_argument("--state-dir", default=str(state_dir))
    ap.add_argument("--actor", default="it2.smith")
    register_cli(ap.add_subparsers(dest="cmd"))

    def run(*argv):
        a = ap.parse_args(list(argv))
        return a.fn(a)

    assert run("ingest", "check", "--snapshot") == 0
    out = capsys.readouterr().out
    assert STIG in out and "417 index entries" in out
    assert run("ingest", "updates") == 0 and STIG in capsys.readouterr().out
    ctx.ingest.set_link(actor="it2.smith", connected=False)
    assert run("ingest", "check") == 2
    assert "manifest" in capsys.readouterr().err
    assert run("ingest", "manifest", "--out", str(tmp_path / "m.json")) == 0
    assert json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))["items"]
    assert run("ingest", "pull") == 2 and "--all" in capsys.readouterr().err
    assert run("ingest", "import-dir") == 2
    media = tmp_path / "usb"
    media.mkdir()
    stig_zip(media / STIG)
    assert run("ingest", "import-dir", str(media)) == 0
    assert run("ingest", "content") == 0 and STIG in capsys.readouterr().out


def test_cli_entry_point_help():
    r = subprocess.run([sys.executable, "-m", "cyberthunder", "ingest", "--help"], capture_output=True, text=True,
                       cwd=str(ROOT), timeout=60)
    assert r.returncode == 0 and "fetch-manifest" in r.stdout and "import-dir" in r.stdout


def test_live_check_refused_while_the_kill_switch_is_engaged(node):
    node.killswitch.engage("it2.smith", "drill")
    with pytest.raises(IngestError, match="kill switch"):
        node.ingest.check_updates("it2.smith")
