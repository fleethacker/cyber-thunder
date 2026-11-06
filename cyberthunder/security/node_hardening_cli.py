"""Local metadata assessment; deliberately independent of application initialization."""
from __future__ import annotations

import json

from .node_hardening import assess


def cmd_node_hardening(args):
    report = assess(args.state_dir)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        tree = report["state_tree"]
        print(f"State permission observation: {tree['status']}; complete={tree['complete']}; entries={tree['entries_observed']}")
        print("Runtime file guards protect selected files, not the whole state directory.")
        for row in tree["observations"]:
            if row["status"] != "protected":
                print(f"entry {row['entry']} ({row['category']}, {row['kind']}): {row['status']} - {row['code']}")
        print("Pending: " + ", ".join(report["pending"]))
        print("Read-only metadata assessment; no hardening or compliance approval performed.")
    return 0 if report["state_tree"]["status"] == "protected" else 2


def register_cli(subparsers):
    parser = subparsers.add_parser("node-hardening", help="read-only state permission assessment; no repairs")
    parser.add_argument("--json", action="store_true", help="structured metadata-only assessment")
    parser.set_defaults(fn=cmd_node_hardening)
