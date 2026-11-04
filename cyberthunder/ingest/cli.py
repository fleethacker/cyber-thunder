"""CLI for the constrained-link side.

  cyberthunder ingest stig <new_file> [--old <file>] [--rescan]
  cyberthunder ingest bulletin <file>
  cyberthunder ingest rescan <delta_id>
  cyberthunder ingest history
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
            print(f"full {s['full_bytes']} B ({t['full_seconds']} s) vs delta {s['compressed_bytes']} B "
                  f"{s['method']} ({t['delta_seconds']} s) at {t['link']['kbps']} kbps; {s['ratio']}x smaller")
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


def cmd_link(a: argparse.Namespace) -> int:
    svc = _service(a)
    if a.sub == "show":
        _print(svc.link_state().to_dict())
        return 0
    try:
        st = svc.set_link(actor=a.actor, kbps=a.kbps, latency_ms=a.latency_ms, connected=a.connected)
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
    p.add_argument("sub", choices=["stig", "bulletin", "rescan", "history"])
    p.add_argument("file", nargs="?", help="new STIG (.xml or DISA .zip), bulletin JSON, or delta id for rescan")
    p.add_argument("--old", help="previous release to diff against (default: the catalog copy)")
    p.add_argument("--rescan", action="store_true", help="start a targeted rescan of added/changed rules")
    p.set_defaults(fn=lambda a: cmd_ingest(a) if a.sub == "history" or a.file else _fail(f"ingest {a.sub} needs a file"))

    p = subparsers.add_parser("link", help="emulated constrained link state")
    p.add_argument("sub", choices=["show", "set"])
    p.add_argument("--kbps", type=float)
    p.add_argument("--latency-ms", dest="latency_ms", type=int)
    p.add_argument("--connected", choices=["true", "false"])
    p.set_defaults(fn=cmd_link)

    p = subparsers.add_parser("outbox", help="queue for shore, sent on reconnect")
    p.add_argument("sub", choices=["list", "sync"])
    p.add_argument("--force", action="store_true", help="send even when the link is marked down")
    p.set_defaults(fn=cmd_outbox)
