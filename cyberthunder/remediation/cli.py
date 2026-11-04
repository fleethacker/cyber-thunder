"""Remediation commands: propose, apply, rollback, diff.

`apply` runs only an APPROVED proposal (approve it first with `cyberthunder proposals approve <id>`),
and prints the step timeline from the audit log so the operator sees exactly what happened.
"""
from __future__ import annotations

import argparse
import json
import sys

from cyberthunder.control.approvals import IllegalTransition
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.inventory.targets import ScopeViolation
from cyberthunder.remediation.engine import EngineError

REFUSALS = (IllegalTransition, KillSwitchEngaged, ScopeViolation, EngineError, PermissionError, KeyError)


def _ctx(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=a.state_dir))


def _timeline(ctx, pid: str, after_seq: int) -> None:
    for r in ctx.audit.records():
        if r["seq"] <= after_seq or (r.get("subject") != pid and pid not in json.dumps(r.get("details", {}))):
            continue
        note = r["details"].get("note") or r["details"].get("evidence") or r["details"].get("reason") or ""
        print(f"  {r['seq']:>5}  {r['ts']}  {r['actor']:<12} {r['action']:<26} {r['outcome']:<8} {str(note)[:90]}")


def cmd_propose(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    f = ctx.store.get_finding(a.finding_id)
    if f is None:
        print(f"no finding {a.finding_id} in any scan", file=sys.stderr)
        return 2
    p = ctx.engine.propose(f, actor=a.actor)
    if p is None:
        print(f"no vetted fix in the library for {f.rule_id}; remediate by hand from the STIG fix text", file=sys.stderr)
        return 1
    print(f"{p.id}  {p.state.value}  {p.fix_ref}  {p.host}")
    print(f"risk: {p.risk}")
    print("will run:\n" + p.fix_preview)
    print("rollback:\n" + p.rollback_plan)
    return 0


def cmd_apply(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    start = len(ctx.audit)
    try:
        p = ctx.engine.execute(a.proposal_id, actor=a.actor, simulate_verify_fail=a.simulate_verify_fail)
    except REFUSALS as e:
        print(f"refused: {e}", file=sys.stderr)
        _timeline(ctx, a.proposal_id, start)
        return 2
    _timeline(ctx, p.id, start)
    print(f"{p.id}: {p.state.value}")
    return 0 if p.state.value == "verified" else 1


def cmd_rollback(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    start = len(ctx.audit)
    try:
        p = ctx.engine.rollback(a.proposal_id, actor=a.actor)
    except REFUSALS as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    _timeline(ctx, p.id, start)
    print(f"{p.id}: {p.state.value}")
    return 0


def cmd_diff(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    try:
        d = ctx.engine.diff(a.proposal_id)
    except KeyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(d, indent=2, default=str))
        return 0
    p = d["proposal"]
    print(f"{p['id']}  {p['state']}  {p['fix_ref']}  {p['host']}")
    for step in ("apply", "verify", "rollback"):
        r = d.get(step)
        if r:
            print(f"{step}: ok={r.get('ok')}  {str(r.get('evidence') or r.get('output') or '')[:100]}")
    for f in d["files"]:
        print(f"\n--- {f['path']}")
        print(f["diff"] or "(no change)")
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("propose", help="propose the vetted library fix for a finding")
    p.add_argument("finding_id")
    p.set_defaults(fn=cmd_propose)

    p = subparsers.add_parser("apply", help="apply an APPROVED proposal: before-state, apply, verify, auto-rollback")
    p.add_argument("proposal_id")
    p.add_argument("--simulate-verify-fail", action="store_true",
                   help="demonstration only: force verification to fail so the automatic rollback runs (audited)")
    p.set_defaults(fn=cmd_apply)

    p = subparsers.add_parser("rollback", help="roll back an applied or verified change")
    p.add_argument("proposal_id")
    p.set_defaults(fn=cmd_rollback)

    p = subparsers.add_parser("diff", help="before/after evidence for a proposal")
    p.add_argument("proposal_id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_diff)
