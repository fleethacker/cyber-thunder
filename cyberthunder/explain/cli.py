"""CLI for the explain layer.

  cyberthunder explain <finding_id> [--force] [--scan-id ID]   print the explanation for one finding
  cyberthunder explain-status                                  backend, model, reachability, queue
  cyberthunder explain-precompute [--scan-id ID] [--wait]      explain every finding not yet explained

Without --wait, explain-precompute only lists what it would do: the CLI process exits immediately and
would take the background worker with it. The API server precomputes in the background on its own.
"""
from __future__ import annotations

import argparse
import json
import sys


def _ctx(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=getattr(a, "state_dir", None)))


def _print_explanation(exp) -> None:
    print(f"RISK    {exp.risk}")
    print(f"IMPACT  {exp.impact}")
    print(f"PLAN    {exp.plan}")
    print(f"CITES   {', '.join(exp.citations) or '-'}")
    src = exp.backend + (f" / {exp.model}" if exp.model else "")
    flags = []
    if exp.fallback:
        flags.append("template fallback")
    if not exp.validated:
        flags.append("model output rejected")
    if exp.dropped_citations:
        flags.append(f"dropped {len(exp.dropped_citations)} citation(s)")
    print(f"SOURCE  {src}" + (f"  ({'; '.join(flags)})" if flags else ""))


def cmd_explain(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    finding = ctx.store.get_finding(a.finding_id, a.scan_id)
    if finding is None:
        print(f"finding {a.finding_id} not found", file=sys.stderr)
        return 2
    exp = ctx.explain.explain(finding, force=a.force)
    if a.json:
        print(json.dumps(exp.to_dict(), indent=2))
    else:
        print(f"{finding.id}  {finding.host}  {finding.severity.cat}  {finding.title}")
        _print_explanation(exp)
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    print(json.dumps(_ctx(a).explain.status(), indent=2, default=str))
    return 0


def cmd_precompute(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    findings = ctx.store.load_findings(a.scan_id)
    svc = ctx.explain
    if not a.wait:
        todo = svc.plan_precompute(findings)
        print(f"{len(todo)} of {len(findings)} findings need an explanation; run with --wait to generate them now")
        return 0
    n = svc.precompute(findings, background=True)
    print(f"queued {n} of {len(findings)} findings", file=sys.stderr)
    idle = svc.wait(timeout=a.timeout)
    svc.shutdown()
    print(json.dumps({"queued": n, "finished": idle, "status": svc.status()}, indent=2, default=str))
    return 0 if idle else 1


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("explain", help="explain one finding in commander-level language, with citations")
    p.add_argument("finding_id")
    p.add_argument("--force", action="store_true", help="regenerate even if cached")
    p.add_argument("--scan-id", default=None)
    p.add_argument("--json", action="store_true", help="print the stored record")
    p.set_defaults(fn=cmd_explain)

    p = subparsers.add_parser("explain-status", help="local model backend status")
    p.set_defaults(fn=cmd_status)

    p = subparsers.add_parser("explain-precompute", help="explain findings that do not have an explanation yet")
    p.add_argument("--scan-id", default=None)
    p.add_argument("--wait", action="store_true", help="generate now and wait for the queue to drain")
    p.add_argument("--timeout", type=float, default=None, help="seconds to wait with --wait (default: no limit)")
    p.set_defaults(fn=cmd_precompute)
