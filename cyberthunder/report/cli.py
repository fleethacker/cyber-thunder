"""`cyberthunder report <kind>` commands. Registered by cyberthunder.cli through register_cli."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cyberthunder.report.render import ReportError


def _service(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    ctx = AppContext(Settings.from_env(state_dir=a.state_dir))
    if ctx.reports is None:
        raise ReportError("report service unavailable on this node")
    return ctx.reports


def _emit(text: str, out: str | None) -> None:
    if out:
        p = Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"wrote {p} ({len(text.encode('utf-8'))} bytes)", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def cmd_report(a: argparse.Namespace) -> int:
    try:
        svc = _service(a)
        kind = a.kind
        if a.queue:
            print(json.dumps(svc.queue(kind, a.scan_id), indent=2))
            return 0
        if kind == "commander":
            text = svc.commander(a.scan_id, a.format or "html")
        elif kind == "poam":
            text = svc.poam_csv(a.scan_id)
        elif kind == "checklist":
            text = json.dumps(svc.checklist_cklb(a.scan_id, a.host), indent=2)
        elif kind == "fleet":
            text = svc.fleet(a.format or "html")
        elif kind == "friction":
            text = svc.friction(a.format or "html")
        else:
            res = svc.score(a.scan_id, a.key_dir)
            text = json.dumps(res, indent=2)
            print(f"seeded {res['seeded']}, found {res['found']} ({res['share']:.0%})", file=sys.stderr)
        _emit(text, a.out)
    except ReportError as e:
        print(f"report: {e}", file=sys.stderr)
        return 2
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("report", help="commander one-pager, POA&M, checklist, path to fleet, friction log, score")
    p.add_argument("kind", choices=("commander", "poam", "checklist", "fleet", "friction", "score"))
    p.add_argument("--scan-id", default=None, help="scan run id (default: latest)")
    p.add_argument("--host", default=None, help="checklist: host to build the checklist for")
    p.add_argument("--format", choices=("html", "md"), default=None, help="commander, fleet, friction (default html)")
    p.add_argument("--out", default=None, help="write to this file instead of stdout")
    p.add_argument("--key-dir", default=None, help="score: answer key directory (default range/answer_key)")
    p.add_argument("--queue", action="store_true", help="render and queue in the sync outbox instead of printing")
    p.set_defaults(fn=cmd_report)
