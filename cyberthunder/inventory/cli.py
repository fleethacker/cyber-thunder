"""Command line for the asset inventory (`cyberthunder targets ...`).

The inventory is also the scope guardrail, so every change made here is written to the audit log:
who changed what, and for scope changes the before and after values plus the reason.
"""
from __future__ import annotations

import argparse
import json
import sys

from cyberthunder.inventory.targets import ASSET_TYPES, TRANSPORTS, ScopeViolation, Target


def _ctx(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=a.state_dir))


def _parse_options(pairs: list[str] | None) -> dict:
    """Turn repeated key=value flags into a dict. Values that are valid JSON (numbers, true/false) are converted."""
    out: dict = {}
    for item in pairs or []:
        if "=" not in item:
            raise ValueError(f"--option expects key=value, got {item!r}")
        key, _, val = item.partition("=")
        key = key.strip()
        if not key:
            raise ValueError(f"--option has an empty key: {item!r}")
        try:
            out[key] = json.loads(val)
        except ValueError:
            out[key] = val
    return out


def _table(rows: list[list[str]], header: list[str]) -> str:
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    lines = ["  ".join(str(c).ljust(w) for c, w in zip(header, widths)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for r in rows:
        lines.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())
    return "\n".join(lines)


def cmd_list(a: argparse.Namespace) -> int:
    targets = _ctx(a).inventory.all()
    if not targets:
        print("no targets in the inventory")
        return 0
    rows = [[t.id, t.name, t.asset_type, t.transport, f"{t.address or '-'}{':' + str(t.port) if t.port else ''}",
             "in" if t.in_scope else "OUT", "sim" if t.simulated else "", ",".join(t.tags)] for t in targets]
    print(_table(rows, ["ID", "NAME", "TYPE", "TRANSPORT", "ADDRESS", "SCOPE", "SIM", "TAGS"]))
    return 0


def cmd_add(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    if any(t.id == a.id for t in ctx.inventory.all()):
        print(f"refused: target {a.id!r} already exists (use 'targets update')", file=sys.stderr)
        return 2
    # a new target starts out of scope; bringing it in at add time is a scope change and needs a reason
    in_scope = bool(a.in_scope) and not a.out_of_scope
    if in_scope and not (a.reason or "").strip():
        print("refused: --reason is required to add a target in scope", file=sys.stderr)
        return 2
    try:
        t = Target(id=a.id, name=a.name or a.id, asset_type=a.type, transport=a.transport, address=a.address,
                   port=a.port, username=a.username, credential_ref=a.credential_ref, tags=list(a.tag or []),
                   in_scope=in_scope, options=_parse_options(a.option))
    except ValueError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    ctx.inventory.add(t)
    ctx.save_inventory(a.actor, "inventory.add", {"target": t.id, "asset_type": t.asset_type,
                                                  "transport": t.transport, "in_scope": t.in_scope})
    if t.in_scope:
        ctx.save_inventory(a.actor, "scope.change", {"target": t.id, "before": None, "after": True, "reason": a.reason})
    print(f"added {t.id} ({t.label})")
    return 0


def cmd_update(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    changes: dict = {}
    for flag, fld in (("name", "name"), ("type", "asset_type"), ("transport", "transport"), ("address", "address"),
                      ("port", "port"), ("username", "username"), ("credential_ref", "credential_ref")):
        v = getattr(a, flag)
        if v is not None:
            changes[fld] = v
    try:
        current = ctx.inventory.get(a.id)
        if a.tag:
            changes["tags"] = list(a.tag)
        if a.option:
            changes["options"] = {**current.options, **_parse_options(a.option)}
        if "transport" in changes and changes["transport"] != "simulated" and current.simulated:
            changes["simulated"] = False      # a real transport means this is no longer an emulator
        old = {k: getattr(current, k) for k in changes}
        # repointing an in-scope id at another host or transport changes what the scope check bounds
        moved = sorted(k for k in ("address", "port", "transport") if k in changes and changes[k] != old[k])
        if current.in_scope and moved and not (a.reason or "").strip():
            print(f"refused: --reason is required to change {', '.join(moved)} of an in-scope target",
                  file=sys.stderr)
            return 2
        # build a throwaway copy first so a bad value cannot leave the live target half-changed
        Target.from_dict({**current.to_dict(), **changes})
        ctx.inventory.update(a.id, **changes)
    except (KeyError, ValueError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if not changes:
        print("nothing to change")
        return 0
    ctx.save_inventory(a.actor, "inventory.update", {"target": a.id, "before": old, "after": changes})
    if current.in_scope and moved:
        ctx.save_inventory(a.actor, "scope.change", {"target": a.id, "before": {k: old[k] for k in moved},
                                                     "after": {k: changes[k] for k in moved}, "reason": a.reason})
    print(f"updated {a.id}: {', '.join(sorted(changes))}")
    return 0


def cmd_remove(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    try:
        t = ctx.inventory.get(a.id)
    except KeyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    ctx.inventory.remove(a.id)
    ctx.save_inventory(a.actor, "inventory.remove", {"target": t.id, "name": t.name, "asset_type": t.asset_type})
    print(f"removed {a.id}")
    return 0


def cmd_scope(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    if not (a.reason or "").strip():
        print("refused: --reason is required for a scope change", file=sys.stderr)
        return 2
    try:
        t = ctx.inventory.get(a.id)
    except KeyError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    new = a.state == "in"
    old = t.in_scope
    ctx.inventory.update(a.id, in_scope=new)
    ctx.save_inventory(a.actor, "scope.change", {"target": a.id, "before": old, "after": new, "reason": a.reason})
    print(f"{a.id}: scope {'in' if old else 'out'} -> {'in' if new else 'out'}")
    return 0


def cmd_discover(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    try:
        t = ctx.inventory.assert_in_scope(a.id)
        adapter = ctx.adapter_for(t)
        with ctx.transport_for(t) as transport:
            facts = adapter.discover(t, transport)
    except (KeyError, ScopeViolation) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001  - connection problems are reported to the operator, not raised at them
        ctx.audit.append("inventory.discover", a.actor, {"target": a.id, "error": str(e)}, outcome="error", subject=a.id)
        print(f"discover failed: {e}", file=sys.stderr)
        return 1
    ctx.audit.append("inventory.discover", a.actor, {"target": a.id}, subject=a.id)
    print(json.dumps(facts.to_dict(), indent=2))
    return 0


def _host_to_target(h, existing: set[str]) -> Target | None:
    """Accept a Target, or a dict/object from the Nessus host parser, and make a Target (None means skip)."""
    if isinstance(h, Target):
        return None if h.id in existing else h
    get = h.get if isinstance(h, dict) else (lambda k, d=None: getattr(h, k, d))
    address = get("address") or get("ip") or get("host_ip") or get("name")
    name = get("name") or get("hostname") or address
    if not address and not name:
        return None
    tid = str(get("id") or name or address).lower().replace(" ", "-")
    if tid in existing:
        return None
    os_text = str(get("os") or get("operating_system") or "").lower()
    kind = "windows" if "windows" in os_text else "cisco_ios" if "cisco" in os_text else "linux"
    return Target(id=tid, name=str(name), asset_type=kind, transport="winrm" if kind == "windows" else "ssh",
                  address=str(address) if address else None, tags=["imported:nessus"], in_scope=False,
                  notes="Imported from a Nessus export; out of scope until an operator brings it in.")


def cmd_import_nessus(a: argparse.Namespace) -> int:
    try:
        from cyberthunder.parsers.nessus import parse_nessus_hosts
    except ImportError:
        print("the Nessus parser (cyberthunder.parsers.nessus) is not available in this build", file=sys.stderr)
        return 1
    ctx = _ctx(a)
    try:
        hosts = list(parse_nessus_hosts(a.file))
    except (OSError, ValueError) as e:
        print(f"cannot read {a.file}: {e}", file=sys.stderr)
        return 2
    existing = {t.id for t in ctx.inventory.all()}
    added: list[str] = []
    for h in hosts:
        t = _host_to_target(h, existing | set(added))
        if t:
            ctx.inventory.add(t)
            added.append(t.id)
    if added:
        ctx.save_inventory(a.actor, "inventory.import", {"source": a.file, "format": "nessus", "added": added})
    print(f"imported {len(added)} of {len(hosts)} hosts (new hosts start out of scope)")
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("targets", help="manage the asset inventory (the scope of what may be touched)")
    sub = p.add_subparsers(dest="targets_cmd", required=True)

    s = sub.add_parser("list", help="show all targets")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("add", help="add a target")
    s.add_argument("--id", required=True)
    s.add_argument("--name")
    s.add_argument("--type", required=True, choices=ASSET_TYPES)
    s.add_argument("--transport", default="ssh", choices=TRANSPORTS)
    s.add_argument("--address")
    s.add_argument("--port", type=int)
    s.add_argument("--username")
    s.add_argument("--credential-ref", help="name of the CT_CRED_<ref> variable or a key file; never the secret")
    s.add_argument("--tag", action="append")
    s.add_argument("--option", action="append", metavar="KEY=VALUE")
    s.add_argument("--out-of-scope", action="store_true", help="add it out of scope (the default)")
    s.add_argument("--in-scope", action="store_true", help="add it in scope (audited as a scope change)")
    s.add_argument("--reason", help="required with --in-scope")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("update", help="change fields of a target (scope changes use 'targets scope')")
    s.add_argument("id")
    s.add_argument("--name")
    s.add_argument("--type", choices=ASSET_TYPES)
    s.add_argument("--transport", choices=TRANSPORTS)
    s.add_argument("--address")
    s.add_argument("--port", type=int)
    s.add_argument("--username")
    s.add_argument("--credential-ref")
    s.add_argument("--tag", action="append", help="replaces the tag list; repeat for several")
    s.add_argument("--option", action="append", metavar="KEY=VALUE", help="merged into the options")
    s.add_argument("--reason", help="required to change address, port or transport of an in-scope target")
    s.set_defaults(fn=cmd_update)

    s = sub.add_parser("remove", help="remove a target")
    s.add_argument("id")
    s.set_defaults(fn=cmd_remove)

    s = sub.add_parser("scope", help="bring a target in or out of scope (audited, reason required)")
    s.add_argument("id")
    s.add_argument("state", choices=["in", "out"])
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_scope)

    s = sub.add_parser("discover", help="connect to an in-scope target and print what it is")
    s.add_argument("id")
    s.set_defaults(fn=cmd_discover)

    s = sub.add_parser("import-nessus", help="add hosts from a Nessus/ACAS export (new hosts start out of scope)")
    s.add_argument("file")
    s.set_defaults(fn=cmd_import_nessus)
