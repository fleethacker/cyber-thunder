"""`cyberthunder scap ...`: inspect, plan and run DISA SCAP benchmarks.

  scap info <datastream> [--profile ID]            profiles, rule counts, supported and unsupported rules
  scap plan <datastream> [--profile ID]            the collection plan the Windows script would receive
  scap eval --target ID [--datastream PATH] [--profile ID] [--out FILE]
                                                   collect over the target's transport, evaluate, print
                                                   per-rule results and write a findings JSON
  scap subset <datastream> --rule ID ... --out FILE
                                                   write a datastream holding only the given rules

`scap eval` is read-only on the host and audited. It runs the collection script only; findings are not
proposed or stored as a scan (run `cyberthunder scan` with options.scap_datastream set for that).
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .datastream import load, rules_for
from .oval.windows_probes import SUPPORTED


def _ctx(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=a.state_dir))


def _load(path: str):
    try:
        return load(path)
    except (OSError, ValueError, SyntaxError) as e:
        print(f"cannot read {path}: {e}", file=sys.stderr)
        return None


def info(ds, profile: str | None = None) -> dict:
    b = ds.benchmark
    rules = rules_for(ds, profile)
    unsupported: collections.Counter = collections.Counter()
    unsupported_rules = []
    supported = 0
    for r in rules:
        s = ds.support(r, SUPPORTED)
        if s.supported:
            supported += 1
        else:
            unsupported_rules.append({"stig_id": r.version, "rule_id": r.id, "reason": s.reason,
                                      "test_types": sorted(p + "_test" for p in s.unsupported)})
            for p in s.unsupported:
                unsupported[p + "_test"] += 1
    return {"path": ds.path, "kind": ds.kind, "benchmark": b.id, "title": b.title, "release": b.release,
            "counts": ds.counts(), "profile": profile,
            "profiles": [{"id": p.id, "title": p.title, "rules": len(b.selected_rules(p.id))} for p in b.profiles.values()],
            "selected_rules": len(rules), "supported_rules": supported, "unsupported_rules": unsupported_rules,
            "unsupported_test_types": dict(unsupported)}


def cmd_info(a: argparse.Namespace) -> int:
    ds = _load(a.datastream)
    if ds is None:
        return 2
    try:
        d = info(ds, a.profile)
    except KeyError as e:
        print(str(e).strip("'\""), file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(d, indent=1))
        return 0
    print(f"{d['title']}  {d['release'] or ''}\n  {d['path']} ({d['kind']})")
    c = d["counts"]
    print(f"  rules {c['rules']}, OVAL definitions {c.get('definitions', 0)}, tests {c.get('tests', 0)}, "
          f"objects {c.get('objects', 0)}, states {c.get('states', 0)}, variables {c.get('variables', 0)}")
    print("\nprofiles:")
    for p in d["profiles"]:
        print(f"  {p['id']:<52} {p['rules']:>4} rules  {p['title']}")
    print(f"\n{'profile ' + a.profile if a.profile else 'default selection'}: {d['selected_rules']} rules, "
          f"{d['supported_rules']} evaluated by our OVAL engine, {len(d['unsupported_rules'])} not checked")
    for t, n in sorted(d["unsupported_test_types"].items()):
        print(f"  unsupported {t}: {n} rule(s)")
    for u in d["unsupported_rules"]:
        print(f"    {u['stig_id'] or u['rule_id']}: {u['reason']}")
    return 0


def cmd_plan(a: argparse.Namespace) -> int:
    from .windows_plan import build_plan, supported_rules
    ds = _load(a.datastream)
    if ds is None:
        return 2
    try:
        rules = supported_rules(ds, rules_for(ds, a.profile, a.rule or None))
    except KeyError as e:
        print(str(e).strip("'\""), file=sys.stderr)
        return 2
    if a.rule and not rules:
        print("no rule in the benchmark matches " + ", ".join(a.rule), file=sys.stderr)
        return 2
    plan = build_plan(ds, rules)
    print(json.dumps({"rules": len(rules), "summary": plan.summary(), "plan": plan.to_params(),
                      "unplanned": plan.unplanned}, indent=1))
    return 0


def cmd_eval(a: argparse.Namespace) -> int:
    from cyberthunder.findings.schema import dump_findings, summarize
    from cyberthunder.inventory.targets import ScopeViolation
    from cyberthunder.adapters.windows.adapter import run_json
    from .benchmark import evaluate, to_findings
    from .windows_plan import collect_benchmark, script_for, supported_rules

    ctx = _ctx(a)
    try:
        target = ctx.inventory.assert_in_scope(a.target)
    except (ScopeViolation, KeyError) as e:
        print(f"refused: {str(e).strip(chr(39))}", file=sys.stderr)
        ctx.audit.append("action.blocked", a.actor, {"action": "scap.eval", "target": a.target, "reason": str(e)},
                         subject=a.target, outcome="blocked")
        return 2
    if target.asset_type != "windows":
        print(f"{target.id} is a {target.asset_type} target: Linux hosts run the benchmark with OpenSCAP "
              f"(options.benchmark_path) during `cyberthunder scan`", file=sys.stderr)
        return 2
    opts = target.options or {}
    path = a.datastream or opts.get("scap_datastream")
    if not path:
        print("no datastream: pass --datastream or set options.scap_datastream on the target", file=sys.stderr)
        return 2
    ds = _load(path)
    if ds is None:
        return 2
    profile = a.profile or opts.get("scap_profile")
    try:
        rules = rules_for(ds, profile, a.rule or None)
    except KeyError as e:
        print(str(e).strip("'\""), file=sys.stderr)
        return 2
    transport = ctx.transport_for(target)
    try:
        data, rounds = collect_benchmark(ds, supported_rules(ds, rules),
                                         lambda params: run_json(transport, script_for(params), timeout=900))
    except Exception as e:  # noqa: BLE001  transport failures of any kind end the command
        print(f"collection failed: {e}", file=sys.stderr)
        ctx.audit.append("scap.eval", a.actor, {"target": target.id, "datastream": Path(path).name,
                                                "error": str(e)[:300]}, subject=target.id, outcome="error")
        return 1
    finally:
        try:
            transport.close()
        except Exception:  # noqa: BLE001
            pass
    results = evaluate(ds, rules, data)
    findings = to_findings(target, ds, results)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = Path(a.out) if a.out else Path(ctx.settings.state_dir) / "scap" / f"{target.id}-{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    dump_findings(findings, out, meta={"datastream": str(path), "benchmark": ds.benchmark.id,
                                       "release": ds.benchmark.release, "profile": profile, "rounds": rounds})
    counts = collections.Counter(r.result for r in results)
    ctx.audit.append("scap.eval", a.actor, {"target": target.id, "datastream": Path(path).name,
                                            "benchmark": ds.benchmark.id, "profile": profile,
                                            "rules": len(results), "results": dict(counts), "output": str(out)},
                     subject=target.id)
    print(f"{'STIG ID':<16} {'result':<14} {'sev':<7} title")
    for r in results:
        print(f"{r.rule.version or r.rule.short_id:<16} {r.result:<14} {r.rule.severity.value:<7} {r.rule.title[:70]}")
    s = summarize(findings)
    print(f"\n{len(results)} rules: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print(f"open: {s['by_status'].get('open', 0)}  findings written to {out}")
    return 0


def cmd_subset(a: argparse.Namespace) -> int:
    from .subset import subset
    try:
        counts = subset(a.datastream, a.rule, a.out)
    except (KeyError, OSError, ValueError, SyntaxError) as e:
        print(f"refused: {str(e).strip(chr(39))}", file=sys.stderr)
        return 2
    print(json.dumps({"out": a.out, "counts": counts}, indent=1))
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("scap", help="inspect, plan and run DISA SCAP benchmarks (OVAL)")
    sp = p.add_subparsers(dest="scap_cmd", required=True)

    q = sp.add_parser("info", help="profiles, rule counts, supported versus unsupported rules")
    q.add_argument("datastream")
    q.add_argument("--profile")
    q.add_argument("--json", action="store_true")
    q.set_defaults(fn=cmd_info)

    q = sp.add_parser("plan", help="print the collection plan for the Windows collection script")
    q.add_argument("datastream")
    q.add_argument("--profile")
    q.add_argument("--rule", action="append", help="only this rule (STIG id, SV id or V id); repeatable")
    q.set_defaults(fn=cmd_plan)

    q = sp.add_parser("eval", help="collect from a Windows target, evaluate the benchmark, write findings JSON")
    q.add_argument("--target", required=True)
    q.add_argument("--datastream", help="defaults to the target's options.scap_datastream")
    q.add_argument("--profile", help="defaults to options.scap_profile, else the benchmark's default selection")
    q.add_argument("--rule", action="append", help="only this rule; repeatable")
    q.add_argument("--out", help="findings JSON path (default <state>/scap/<target>-<time>.json)")
    q.set_defaults(fn=cmd_eval)

    q = sp.add_parser("subset", help="write a datastream holding only the given rules")
    q.add_argument("datastream")
    q.add_argument("--rule", action="append", required=True)
    q.add_argument("--out", required=True)
    q.set_defaults(fn=cmd_subset)
