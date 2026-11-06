"""`cyberthunder state info` and `cyberthunder state migrate`."""
from __future__ import annotations

import argparse
import json
import sys

from cyberthunder.state import BACKENDS, StateError, backend_from_env
from cyberthunder.state.migrate import SAMPLE_DEFAULT, info, migrate


def cmd_info(a: argparse.Namespace) -> int:
    try:
        d = info(a.state_dir, a.backend or backend_from_env())
    except StateError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(d, indent=2))
        return 0
    print(f"backend    {d['backend']}")
    print(f"location   {d['location']}")
    print(f"documents  {d['documents']}")
    print(f"size       {d['bytes']} bytes")
    print(f"audit      {d['audit']['detail']}")
    other = d.get("other")
    if other:
        print(f"note       {other['note']}")
    return 0


def cmd_migrate(a: argparse.Namespace) -> int:
    try:
        rep = migrate(a.state_dir, a.to, a.source, force=a.force, prune=a.prune, sample=a.sample)
    except StateError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        print("\n".join(rep.lines()))
    if rep.ok:
        print(f"documents are in the {rep.target} backend; set CT_STATE_BACKEND={rep.target} for every process "
              f"that uses {rep.root}", file=sys.stderr)
        return 0
    return 2


def cmd_retention(a: argparse.Namespace) -> int:
    from cyberthunder.state.retention import archive, inspect_archive, plan, read_plan
    try:
        if a.retention_cmd == "plan":
            result = plan(a.state_dir, a.backend or backend_from_env(),
                          cutoff_utc=a.cutoff_utc, age_days=a.age_days)
        elif a.retention_cmd == "archive":
            result = archive(a.state_dir, read_plan(a.plan_file), a.output)
        else:
            result = inspect_archive(a.archive_file, a.sha256)
    except StateError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("state", help="document store: inspect it, move it between json files and sqlite")
    sub = p.add_subparsers(dest="state_cmd", required=True)

    s = sub.add_parser("info", help="backend, location, document count and size")
    s.add_argument("--backend", choices=BACKENDS, help="inspect this backend instead of the configured one")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_info)

    s = sub.add_parser("migrate", help="copy every document to another backend and verify the copy")
    s.add_argument("--to", required=True, choices=BACKENDS)
    s.add_argument("--from", dest="source", choices=BACKENDS, help="default: the other backend")
    s.add_argument("--force", action="store_true", help="overwrite documents the target already holds")
    s.add_argument("--prune", action="store_true", help="remove the source documents once the copy verified")
    s.add_argument("--sample", type=int, default=SAMPLE_DEFAULT,
                   help=f"documents compared one by one after the copy (default {SAMPLE_DEFAULT}, 0 = all)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_migrate)

    s = sub.add_parser("retention", help="plan and verify private scan archives; never delete state")
    actions = s.add_subparsers(dest="retention_cmd", required=True)
    action = actions.add_parser("plan", help="print a dry-run source manifest as JSON")
    action.add_argument("--backend", choices=BACKENDS)
    cutoff = action.add_mutually_exclusive_group(required=True)
    cutoff.add_argument("--cutoff-utc", help="exclusive completion cutoff with Z or +00:00 timezone")
    cutoff.add_argument("--age-days", type=int, help="positive age in whole days, measured in UTC")
    action.set_defaults(fn=cmd_retention)
    action = actions.add_parser("archive", help="export a reviewed, unchanged plan to a new private archive")
    action.add_argument("--plan-file", required=True, help="absolute path to a private saved plan")
    action.add_argument("--output", required=True, help="new absolute path outside the state tree")
    action.set_defaults(fn=cmd_retention)
    action = actions.add_parser("inspect", help="verify archive bytes against a separately retained SHA-256")
    action.add_argument("archive_file")
    action.add_argument("--sha256", required=True)
    action.set_defaults(fn=cmd_retention)
