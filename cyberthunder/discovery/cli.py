"""`cyberthunder discover ...`: scopes, sweeps, candidates, accept/ignore, findings and applicability."""
from __future__ import annotations

import argparse
import json
import sys

from cyberthunder.config import Settings
from cyberthunder.control.killswitch import KillSwitchEngaged

STATUSES = ("new", "known", "ignored", "missing")


def _svc(a: argparse.Namespace):
    from cyberthunder.context import AppContext
    from .service import service_for
    return service_for(AppContext(Settings.from_env(state_dir=a.state_dir)))


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_scopes(a: argparse.Namespace) -> int:
    from .models import DiscoveryScope
    svc = _svc(a)
    if a.add:
        current = svc.scopes()
        for cidr in a.add:
            current.append(DiscoveryScope(cidr=cidr, allow_public=a.allow_public, reason=a.reason or ""))
        svc.set_scopes(current, a.actor, a.reason)
    for s in svc.scopes():
        print(f"{s.cidr:<20} {'public ' if s.allow_public else ''}by {s.added_by or '-'}: {s.reason}"
              + (f" (scanner {s.scanner_target})" if s.scanner_target else ""))
    return 0


def cmd_sweep(a: argparse.Namespace) -> int:
    svc = _svc(a)
    run = svc.sweep(scopes=a.scope or None, mode=a.mode, actor=a.actor, background=not a.wait)
    if a.wait:
        print(f"run {run.id} {run.status}: " + " ".join(f"{k}={v}" for k, v in run.counts().items()))
        for e in run.errors:
            print(f"  error: {e}", file=sys.stderr)
    else:
        # a CLI process exits when this returns, so a background run is joined here with a bounded wait
        run = svc.join(run.id, timeout=170)
        print(f"run {run.id} {run.status}: " + " ".join(f"{k}={v}" for k, v in run.counts().items()))
    return 0 if run.status == "finished" else 1


def cmd_list(a: argparse.Namespace) -> int:
    for x in _svc(a).list_assets(a.status):
        badges = ",".join(sorted({c["kind"] for c in x.changes})) or "-"
        print(f"{x.id}  {x.status:<8} {(x.address or '-'):<16} {(x.mac or '-'):<18} {x.asset_type_guess:<10} "
              f"{x.confidence:.2f}  {(x.hostname or '-')[:24]:<24} {badges}  {x.notes}")
    return 0


def cmd_accept(a: argparse.Namespace) -> int:
    t = _svc(a).accept(a.id, a.actor, name=a.name, asset_type=a.type, transport=a.transport, username=a.username,
                       credential_ref=a.credential_ref, in_scope=a.in_scope, reason=a.reason)
    _print(t.to_dict())
    return 0


def cmd_ignore(a: argparse.Namespace) -> int:
    x = _svc(a).ignore(a.id, a.actor, a.reason)
    print(f"{x.id} ignored")
    return 0


def cmd_findings(a: argparse.Namespace) -> int:
    for f in _svc(a).findings(a.run_id):
        print(f"{f.severity.value:<7} {f.rule_id:<28} {f.host:<28} {', '.join(f.citations[1:])}  {f.title}")
    return 0


def cmd_applicable(a: argparse.Namespace) -> int:
    for h in _svc(a).applicable(benchmark_id=a.benchmark, title=a.title, product=a.product):
        print(f"{h['target']:<24} {h['basis']:<9} {h['reason']}")
    return 0


def _guarded(fn):
    def run(a: argparse.Namespace) -> int:
        try:
            return fn(a)
        except (ValueError, KeyError, PermissionError, KillSwitchEngaged) as e:
            print(f"refused: {e}", file=sys.stderr)
            return 2
    return run


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("discover", help="find assets on the enclave and propose them for the inventory")
    sp = p.add_subparsers(dest="discover_cmd", required=True)

    q = sp.add_parser("scopes", help="show discovery scopes; --add CIDR --reason TEXT to add one")
    q.add_argument("--add", action="append", metavar="CIDR")
    q.add_argument("--reason", help="why this range may be swept (required with --add)")
    q.add_argument("--allow-public", action="store_true", help="permit non-private address space (needs --reason)")
    q.set_defaults(fn=_guarded(cmd_scopes))

    q = sp.add_parser("sweep", help="run a discovery sweep over the saved scopes")
    q.add_argument("--mode", choices=["quick", "full", "passive", "simulated"], default="quick")
    q.add_argument("--scope", action="append", metavar="CIDR", help="sweep only this part of a saved scope")
    q.add_argument("--wait", action="store_true", help="run in the foreground")
    q.set_defaults(fn=_guarded(cmd_sweep))

    q = sp.add_parser("list", help="discovered assets")
    q.add_argument("--status", choices=STATUSES)
    q.set_defaults(fn=_guarded(cmd_list))

    q = sp.add_parser("accept", help="accept a discovered asset into the inventory")
    q.add_argument("id")
    q.add_argument("--name")
    q.add_argument("--type", choices=["linux", "windows", "cisco_ios", "kubernetes", "containers"])
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--in-scope", dest="in_scope", action="store_true")
    g.add_argument("--out-of-scope", dest="in_scope", action="store_false")
    q.add_argument("--reason", required=True)
    q.add_argument("--transport")
    q.add_argument("--username")
    q.add_argument("--credential-ref")
    q.set_defaults(fn=_guarded(cmd_accept))

    q = sp.add_parser("ignore", help="mark a discovered asset as accounted for and not to be inventoried")
    q.add_argument("id")
    q.add_argument("--reason", required=True)
    q.set_defaults(fn=_guarded(cmd_ignore))

    q = sp.add_parser("findings", help="findings from the latest (or a given) discovery run")
    q.add_argument("--run-id")
    q.set_defaults(fn=_guarded(cmd_findings))

    q = sp.add_parser("applicable", help="which inventory targets a STIG or bulletin applies to")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--benchmark")
    g.add_argument("--title")
    g.add_argument("--product")
    q.set_defaults(fn=_guarded(cmd_applicable))
