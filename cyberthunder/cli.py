"""Cyber Thunder command line.

Core commands live here. Feature modules add their own by exposing `register_cli(subparsers)` in the
modules listed in CLI_MODULES; a module that is not built yet is simply absent.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path

from cyberthunder import PRODUCT, __version__
from cyberthunder.audit.chain import AuditLog, verify_file
from cyberthunder.config import Settings
from cyberthunder.control.approvals import IllegalTransition
from cyberthunder.control.identity import require_human
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.findings.schema import Finding, dump_findings, summarize
from cyberthunder.parsers.cklb import parse_cklb
from cyberthunder.parsers.xccdf import parse_xccdf

CLI_MODULES = (
    "cyberthunder.inventory.cli",
    "cyberthunder.scan_cli",
    "cyberthunder.remediation.cli",
    "cyberthunder.explain.cli",
    "cyberthunder.ingest.cli",
    "cyberthunder.scap.cli",
    "cyberthunder.report.cli",
    "cyberthunder.api.cli",
    "cyberthunder.demo",
    "cyberthunder.discovery.cli",
)


def _ctx(a: argparse.Namespace):
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=a.state_dir))


def cmd_parse(a: argparse.Namespace) -> int:
    findings: list[Finding] = []
    for f in a.files:
        p = Path(f)
        if p.suffix.lower() == ".nessus":
            from cyberthunder.parsers.nessus import parse_nessus
            got = parse_nessus(p, host=a.host)
            print(f"[acas ] {p.name}: {len(got)} findings", file=sys.stderr)
        elif p.suffix.lower() in {".cklb", ".json"}:
            got = parse_cklb(p, host=a.host)
            print(f"[cklb ] {p.name}: {len(got)} rules", file=sys.stderr)
        else:
            res = parse_xccdf(p, host=a.host, source=a.source)
            got = res.findings
            print(f"[xccdf] {p.name}: {len(res.rules)} rules in catalog, {len(got)} results, "
                  f"targets={res.targets or '-'} profile={res.profile or '-'}", file=sys.stderr)
        findings.extend(got)
    s = summarize(findings)
    print(json.dumps(s, indent=2))
    if not findings:
        print("no findings parsed from the given files", file=sys.stderr)
        return 2
    if a.out:
        dump_findings(findings, a.out, meta={"inputs": a.files})
        print(f"wrote {a.out}", file=sys.stderr)
    if findings and not a.no_audit:
        ctx = _ctx(a)
        ctx.audit.append("scan.ingest", a.actor, {"inputs": a.files, "summary": s})
    return 0


def cmd_audit(a: argparse.Namespace) -> int:
    path = a.path or str(Path(a.state_dir) / "audit.jsonl")
    if a.sub == "verify":
        r = verify_file(path)
        print(r)
        return 0 if r.ok else 2
    recs = list(AuditLog(path).records())
    for r in recs[-a.n:]:
        print(f"{r['seq']:>5}  {r['ts']}  {r['actor']:<14} {r['action']:<24} {r['outcome']:<8} "
              f"{(r.get('subject') or ''):<14} {json.dumps(r['details'])[:90]}")
    return 0


def cmd_kill(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    try:
        if a.sub == "engage":
            ctx.killswitch.engage(a.actor, a.reason)
        elif a.sub == "release":
            ctx.killswitch.release(a.actor, a.reason)
    except PermissionError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    st = ctx.killswitch.status()
    print(json.dumps(st, indent=2))
    return 2 if a.sub == "release" and st["engaged"] else 0


def cmd_proposals(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    gate = ctx.gate
    try:
        if a.sub == "list":
            for p in gate.list():
                print(f"{p.id}  {p.state.value:<11} {p.host:<24} {p.title[:60]}")
        elif a.sub == "show":
            print(json.dumps(gate.get(a.id).to_dict(), indent=2))
        elif a.sub == "approve":
            print(gate.approve(a.id, require_human(a.actor), a.note).state.value)
        elif a.sub == "deny":
            print(gate.deny(a.id, require_human(a.actor), a.note).state.value)
    except (IllegalTransition, PermissionError, KillSwitchEngaged, KeyError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    print(json.dumps(_ctx(a).status(), indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cyberthunder", description=f"{PRODUCT} {__version__}")
    ap.add_argument("--state-dir", default=os.environ.get("CT_STATE_DIR", "state"),
                    help="audit log, kill switch, proposals, scans, snapshots")
    ap.add_argument("--actor", default=os.environ.get("CT_ACTOR") or os.environ.get("USERNAME") or os.environ.get("USER") or "operator",
                    help="who is acting (never 'agent' for approvals)")
    ap.add_argument("--version", action="version", version=f"{PRODUCT} {__version__}")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("status", help="node status: kill switch, audit chain, model, adapters")
    p.set_defaults(fn=cmd_status)

    p = sp.add_parser("parse", help="normalize scanner output files into findings JSON")
    p.add_argument("files", nargs="+")
    p.add_argument("--host", help="override target host name")
    p.add_argument("--source", default="openscap", help="label for XCCDF inputs (openscap|scc|disa)")
    p.add_argument("--out", help="write findings JSON here")
    p.add_argument("--no-audit", action="store_true")
    p.set_defaults(fn=cmd_parse)

    p = sp.add_parser("audit", help="verify or tail the audit chain")
    p.add_argument("sub", choices=["verify", "tail"])
    p.add_argument("path", nargs="?")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_audit)

    p = sp.add_parser("kill", help="kill switch")
    p.add_argument("sub", choices=["status", "engage", "release"])
    p.add_argument("--reason", default="")
    p.set_defaults(fn=cmd_kill)

    p = sp.add_parser("proposals", help="list / approve / deny proposals")
    p.add_argument("sub", choices=["list", "show", "approve", "deny"])
    p.add_argument("id", nargs="?")
    p.add_argument("--note")
    p.set_defaults(fn=cmd_proposals)

    for mod in CLI_MODULES:
        try:
            m = importlib.import_module(mod)
        except ModuleNotFoundError as e:
            if e.name and (e.name == mod or mod.startswith(e.name)):
                continue
            raise
        reg = getattr(m, "register_cli", None)
        if reg:
            reg(sp)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
