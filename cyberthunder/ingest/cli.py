"""CLI for the constrained-link side.

  cyberthunder ingest stig <new_file> [--old <file>] [--rescan]
  cyberthunder ingest bulletin <file>
  cyberthunder ingest rescan <delta_id>
  cyberthunder ingest history
  cyberthunder ingest check [--snapshot]                 fetch the DISA index, show what this node needs
  cyberthunder ingest updates                            the last check
  cyberthunder ingest pull [--all | --file NAME ...] [--pace] [--wait]
  cyberthunder ingest content                            DISA files held on this node
  cyberthunder ingest manifest --out PATH                link down: what a connected machine should fetch
  cyberthunder ingest fetch-manifest PATH --out DIR      on the connected machine
  cyberthunder ingest import-dir DIR                     bring the fetched folder in (removable media)
  cyberthunder link show
  cyberthunder link set [--kbps N] [--latency-ms N] [--connected true|false]
  cyberthunder outbox list
  cyberthunder outbox sync [--force]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _service(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    from cyberthunder.ingest.service import IngestService
    ctx = AppContext(Settings.from_env(state_dir=a.state_dir))
    return ctx.ingest if isinstance(ctx.ingest, IngestService) else IngestService(ctx)


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 2


def cmd_ingest(a: argparse.Namespace) -> int:
    from cyberthunder.ingest.bulletin import BulletinError
    from cyberthunder.ingest.delta import BenchmarkError
    from cyberthunder.ingest.service import IngestError
    svc = _service(a)
    try:
        if a.sub == "stig":
            rep = svc.ingest_stig(Path(a.file), old=a.old, actor=a.actor)
            s, t = rep["sizes"], rep["transfer"]
            print(f"{rep['benchmark_id']}: {rep['old_release'] or '(none)'} -> {rep['new_release']}  "
                  f"added {rep['counts']['added']}, changed {rep['counts']['changed']}, removed {rep['counts']['removed']}")
            timing = (f"TEST estimate {t['delta_seconds']} s at {t['link']['kbps']} kbps"
                      if t["link"].get("mode") == "test" else "transfer time unknown; no network observation")
            print(f"full {s['full_bytes']} B vs delta {s['compressed_bytes']} B "
                  f"{s['method']}; {s['ratio']}x smaller; {timing}")
            print(f"delta id: {rep['id']}")
            if a.rescan and rep["rescan_rule_ids"]:
                run = svc.rescan_for_delta(rep["id"], a.actor)
                print(f"rescan started: {run.id}")
        elif a.sub == "bulletin":
            res = svc.ingest_bulletin(Path(a.file).read_bytes(), actor=a.actor)
            _print({k: (len(v) if k == "findings" else v) for k, v in res.items()})
        elif a.sub == "rescan":
            if not a.file:
                return _fail("delta id required")
            run = svc.rescan_for_delta(a.file, a.actor)
            print(f"rescan started: {run.id}")
        elif a.sub == "history":
            _print(svc.history())
    except (BenchmarkError, BulletinError, IngestError, KeyError, OSError) as e:
        return _fail(str(e))
    return 0


def cmd_scanner_import(a: argparse.Namespace) -> int:
    from cyberthunder.control.killswitch import KillSwitchEngaged
    from cyberthunder.ingest.scanner_results import (
        MAX_MAPPING_BYTES, MAX_XML_BYTES, ScannerImportError, import_actor, parse_mapping, read_local_file,
    )
    try:
        actor = import_actor(a.actor)
        if not a.host_map:
            return _fail("ingest scanner needs --host-map with a JSON mapping file")
        mapping = parse_mapping(read_local_file(a.host_map, MAX_MAPPING_BYTES))
        data = read_local_file(a.file, MAX_XML_BYTES)
        _print(_service(a).import_scanner(data, mapping, actor=actor, include_info=a.include_info))
    except (ScannerImportError, PermissionError, KillSwitchEngaged) as e:
        return _fail(str(e))
    except OSError:
        return _fail("scanner import storage is unavailable")
    return 0


# -- content updates -----------------------------------------------------------------------------
def _fmt_bytes(n) -> str:
    if not n:
        return "-"
    n = float(n)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _table(rows: list[list], header: list[str]) -> None:
    if not rows:
        print("  (none)")
        return
    cells = [header] + [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(header))]
    for i, r in enumerate(cells):
        print("  " + "  ".join(c.ljust(widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            print("  " + "  ".join("-" * w for w in widths))


def _print_check(rep: dict) -> None:
    gz = " (gzip)" if rep.get("gzip") else ""
    print(f"checked {rep.get('checked_at')} from {rep.get('source')}: {rep.get('index_entries')} index entries, "
          f"{_fmt_bytes(rep.get('index_wire_bytes'))} on the wire{gz}")
    est = rep.get("estimate_seconds_at_link")
    tail = f", about {est} s at {rep['link']['kbps']} kbps" if est else ""
    print(f"wanted {len(rep.get('wanted') or [])}, current {len(rep.get('current') or [])}, "
          f"updates {len(rep.get('updates') or [])}{tail}")
    print("updates:")
    _table([[u["filename"], u.get("product_key"), u.get("kind"), u.get("version_label"), u.get("upload_date"),
             _fmt_bytes(u.get("expected_bytes")), ",".join(u.get("targets") or [])] for u in rep.get("updates") or []],
           ["file", "product", "kind", "version", "date", "size", "targets"])
    hosts = [s for s in rep.get("skipped") or [] if s.get("target_id")]
    if hosts:
        print("hosts with no content selected:")
        _table([[s["target_id"], s["reason"]] for s in hosts], ["target", "reason"])


def _job_result(f: dict) -> str:
    d = f.get("delta")
    if d:
        c = d.get("counts") or {}
        return f"delta {d['id']} +{c.get('added', 0)} ~{c.get('changed', 0)} -{c.get('removed', 0)}"
    return f.get("datastream_path") or f.get("error") or ""


def _print_job(job: dict) -> None:
    print(f"pull {job['id']}: {job['state']}")
    _table([[f["filename"], f["state"], f"{_fmt_bytes(f.get('bytes'))} / {_fmt_bytes(f.get('total'))}", _job_result(f)]
            for f in job.get("files") or []], ["file", "state", "bytes", "result"])


def _fetch_manifest_cmd(a: argparse.Namespace) -> int:
    from cyberthunder.ingest.content.service import fetch_manifest
    from cyberthunder.ingest.link import LinkState
    from cyberthunder.ingest.service import IngestError
    if not a.out:
        return _fail("fetch-manifest needs --out DIR")
    try:
        lock = fetch_manifest(Path(a.file), Path(a.out), link=LinkState(), pace=a.pace)
    except (IngestError, OSError) as e:
        return _fail(str(e))
    _table([[f["filename"], _fmt_bytes(f["bytes"]), f["sha256"][:16]] for f in lock["files"]],
           ["file", "size", "sha256"])
    for f in lock["failed"]:
        print(f"  failed: {f.get('filename')}: {f['reason']}")
    print(f"lock file: {lock['path']}")
    return 0 if not lock["failed"] else 1


def cmd_content(a: argparse.Namespace) -> int:
    from cyberthunder.ingest.outbox import LinkDisconnected
    from cyberthunder.ingest.service import IngestError
    if a.sub == "fetch-manifest":
        return _fetch_manifest_cmd(a)
    svc = _service(a)
    try:
        if a.sub == "check":
            _print_check(svc.check_updates(a.actor, source="snapshot" if a.snapshot else "live"))
        elif a.sub == "updates":
            rep = svc.last_update_check()
            if not rep:
                print("no update check yet; run: cyberthunder ingest check")
                return 0
            _print_check(rep)
        elif a.sub == "pull":
            if not a.all_matching and not a.names:
                return _fail("pull needs --all or one or more --file NAME")
            job = svc.pull(a.actor, filenames=a.names or None, all_matching=a.all_matching, pace=a.pace,
                           background=not a.wait)
            _print_job(job)
            if not a.wait:
                print(f"running in the background; follow it with GET /api/v1/ingest/updates/jobs/{job['id']}")
            elif job["state"] != "done":
                return 1
        elif a.sub == "content":
            c = svc.held_content()
            rows = []
            for r in c["files"]:
                ing = r.get("ingest") or {}
                rows.append([r["filename"], r.get("product_key"), r.get("kind"), r.get("version_label"),
                             r.get("upload_date"), r.get("source"), ing.get("datastream_path") or ing.get("delta_id") or ""])
            _table(rows, ["file", "product", "kind", "version", "date", "source", "ingest"])
            for q in c["quarantine"]:
                print(f"  quarantined: {q.get('filename')}: {q.get('reason')}")
        elif a.sub == "manifest":
            m = svc.write_manifest(a.actor, Path(a.out) if a.out else None)
            _table([[i["filename"], i.get("product_key"), i.get("version_label")] for i in m["items"]],
                   ["file", "product", "version"])
            print(f"manifest: {m['path']} ({len(m['items'])} items)")
            print(f"on a connected machine: cyberthunder ingest fetch-manifest {m['path']} --out <DIR>")
        elif a.sub == "import-dir":
            res = svc.import_dir(Path(a.file), a.actor)
            rows = []
            for r in res["imported"]:
                ing = r.get("ingest") or {}
                rows.append([r["filename"], r.get("kind"), r.get("version_label"),
                             ing.get("delta_id") or ing.get("datastream_path") or ""])
            _table(rows, ["file", "kind", "version", "ingest"])
            for r in res["refused"]:
                print(f"  refused: {r['filename']}: {r['reason']}")
            for m in res["missing"]:
                print(f"  missing from the folder: {m}")
            print(f"verified by {res['verified_by']}")
            if res["refused"]:
                return 1
    except LinkDisconnected as e:
        return _fail(str(e))
    except (IngestError, KeyError, OSError, ValueError) as e:
        return _fail(str(e))
    return 0


CONTENT_SUBS = ("check", "updates", "pull", "content", "manifest", "fetch-manifest", "import-dir")
NEEDS_FILE = ("stig", "bulletin", "rescan", "fetch-manifest", "import-dir", "scanner")


def _dispatch_ingest(a: argparse.Namespace) -> int:
    if a.sub in NEEDS_FILE and not a.file:
        return _fail(f"ingest {a.sub} needs a {'folder' if a.sub == 'import-dir' else 'file'}")
    if a.sub in CONTENT_SUBS:
        return cmd_content(a)
    if a.sub == "scanner":
        return cmd_scanner_import(a)
    return cmd_ingest(a)


def cmd_link(a: argparse.Namespace) -> int:
    svc = _service(a)
    if a.sub == "show":
        _print(svc.link_state().to_dict())
        return 0
    try:
        st = svc.set_link(actor=a.actor, mode=a.mode, kbps=a.kbps, latency_ms=a.latency_ms,
                          connected=a.connected, offline_override=a.offline, probe_enabled=a.probe_enabled)
    except ValueError as e:
        return _fail(str(e))
    _print(st.to_dict())
    if svc.link.last_flush is not None:
        _print({"outbox_flush": svc.link.last_flush})
    return 0


def cmd_outbox(a: argparse.Namespace) -> int:
    from cyberthunder.ingest.outbox import LinkDisconnected
    svc = _service(a)
    if a.sub == "list":
        items = svc.outbox.list()
        for k in ("pending", "synced"):
            print(f"{k}: {len(items[k])}")
            for e in items[k]:
                print(f"  {e['id']}  {e['kind']}  {e['bytes']} B")
        return 0
    try:
        _print(svc.outbox.sync(force=a.force, actor=a.actor))
    except LinkDisconnected as e:
        return _fail(str(e))
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("ingest", help="STIG release deltas and IAVM/CVE bulletins from the link")
    p.add_argument("sub", choices=["stig", "bulletin", "rescan", "history", "scanner", *CONTENT_SUBS])
    p.add_argument("file", nargs="?", help="new STIG (.xml or DISA .zip), bulletin JSON, delta id for rescan, "
                                           "manifest for fetch-manifest, or folder for import-dir")
    p.add_argument("--old", help="previous release to diff against (default: the catalog copy)")
    p.add_argument("--host-map", help="scanner: JSON mapping of each ReportHost name to an existing target id")
    p.add_argument("--include-info", action="store_true", help="scanner: include severity-zero results")
    p.add_argument("--rescan", action="store_true", help="start a targeted rescan of added/changed rules")
    p.add_argument("--snapshot", action="store_true", help="check: use the bundled index snapshot, no network")
    p.add_argument("--all", dest="all_matching", action="store_true", help="pull: every update from the last check")
    p.add_argument("--file", dest="names", action="append", metavar="NAME", help="pull: one DISA file name (repeat)")
    p.add_argument("--pace", action="store_true", help="pull: hold the transfer to the emulated link rate")
    p.add_argument("--wait", action="store_true", help="pull: run in the foreground and wait for the result")
    p.add_argument("--out", help="manifest: file to write; fetch-manifest: folder to download into")
    p.set_defaults(fn=_dispatch_ingest)

    p = subparsers.add_parser("link", help="observed link state and explicit test controls")
    p.add_argument("sub", choices=["show", "set"])
    p.add_argument("--kbps", type=float)
    p.add_argument("--latency-ms", dest="latency_ms", type=int)
    p.add_argument("--mode", choices=["production", "test"])
    p.add_argument("--offline", choices=["true", "false"], help="intentional operator offline override")
    p.add_argument("--probe-enabled", choices=["true", "false"], help="enable probes for 15 minutes")
    p.add_argument("--connected", choices=["true", "false"])
    p.set_defaults(fn=cmd_link)

    p = subparsers.add_parser("outbox", help="local staging queue; network delivery is not implemented")
    p.add_argument("sub", choices=["list", "sync"])
    p.add_argument("--force", action="store_true", help="stage locally for manual courier even while offline")
    p.set_defaults(fn=cmd_outbox)
