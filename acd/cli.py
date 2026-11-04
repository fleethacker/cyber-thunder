"""acd command line.

  python -m acd parse results.xml checklist.cklb [--host H] [--out findings.json]
  python -m acd audit verify state/audit.jsonl
  python -m acd audit tail   state/audit.jsonl [-n 20]
  python -m acd kill status|engage|release [--actor ID] [--reason TEXT]
  python -m acd proposals list|show|approve|deny [ID] --actor ID [--note TEXT]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from acd.audit.chain import AuditLog, verify_file
from acd.control.approvals import ApprovalGate, IllegalTransition, ProposalState
from acd.control.killswitch import KillSwitch, KillSwitchEngaged
from acd.findings.schema import Finding, dump_findings, summarize
from acd.parsers.cklb import parse_cklb
from acd.parsers.xccdf import parse_xccdf

DEFAULT_STATE = Path(os.environ.get("ACD_STATE_DIR", "state"))


def _ctx(state_dir: Path) -> tuple[AuditLog, KillSwitch, ApprovalGate]:
    audit = AuditLog(state_dir / "audit.jsonl")
    ks = KillSwitch(state_dir, audit)
    gate = ApprovalGate(state_dir / "proposals.json", audit, ks)
    return audit, ks, gate


def cmd_parse(a: argparse.Namespace) -> int:
    findings: list[Finding] = []
    for f in a.files:
        p = Path(f)
        if p.suffix.lower() in {".cklb", ".json"}:
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
    if a.out:
        dump_findings(findings, a.out, meta={"inputs": a.files})
        print(f"wrote {a.out}", file=sys.stderr)
    if a.state_dir and findings:
        audit, _, _ = _ctx(Path(a.state_dir))
        audit.append("scan.ingest", a.actor, {"inputs": a.files, "summary": s})
    return 0


def cmd_audit(a: argparse.Namespace) -> int:
    if a.sub == "verify":
        r = verify_file(a.path)
        print(r)
        return 0 if r.ok else 2
    recs = list(AuditLog(a.path).records())
    for r in recs[-a.n:]:
        print(f"{r['seq']:>5}  {r['ts']}  {r['actor']:<12} {r['action']:<22} {r['outcome']:<8} "
              f"{(r.get('subject') or ''):<14} {json.dumps(r['details'])[:80]}")
    return 0


def cmd_kill(a: argparse.Namespace) -> int:
    audit, ks, _ = _ctx(Path(a.state_dir))
    if a.sub == "engage":
        ks.engage(a.actor, a.reason)
    elif a.sub == "release":
        ks.release(a.actor, a.reason)
    print(json.dumps(ks.status(), indent=2))
    return 0


def cmd_proposals(a: argparse.Namespace) -> int:
    audit, ks, gate = _ctx(Path(a.state_dir))
    try:
        if a.sub == "list":
            for p in gate.list():
                print(f"{p.id}  {p.state.value:<11} {p.host:<24} {p.title[:60]}")
        elif a.sub == "show":
            print(json.dumps(gate.get(a.id).to_dict(), indent=2))
        elif a.sub == "approve":
            print(gate.approve(a.id, a.actor, a.note).state.value)
        elif a.sub == "deny":
            print(gate.deny(a.id, a.actor, a.note).state.value)
    except (IllegalTransition, PermissionError, KillSwitchEngaged, KeyError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="acd", description="Autonomous Cyber Defender")
    ap.add_argument("--state-dir", default=str(DEFAULT_STATE), help="audit log + kill switch + proposals dir")
    ap.add_argument("--actor", default=os.environ.get("ACD_ACTOR") or os.environ.get("USERNAME") or "operator")
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("parse", help="normalize scanner output into findings JSON")
    p.add_argument("files", nargs="+")
    p.add_argument("--host", help="override target host name")
    p.add_argument("--source", default="openscap", help="label for XCCDF inputs (openscap|scc|disa)")
    p.add_argument("--out", help="write findings JSON here")
    p.set_defaults(fn=cmd_parse)

    p = sp.add_parser("audit")
    p.add_argument("sub", choices=["verify", "tail"])
    p.add_argument("path")
    p.add_argument("-n", type=int, default=20)
    p.set_defaults(fn=cmd_audit)

    p = sp.add_parser("kill")
    p.add_argument("sub", choices=["status", "engage", "release"])
    p.add_argument("--reason", default="")
    p.set_defaults(fn=cmd_kill)

    p = sp.add_parser("proposals")
    p.add_argument("sub", choices=["list", "show", "approve", "deny"])
    p.add_argument("id", nargs="?")
    p.add_argument("--note")
    p.set_defaults(fn=cmd_proposals)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
