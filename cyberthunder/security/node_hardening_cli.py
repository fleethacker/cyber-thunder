"""Local metadata assessment; deliberately independent of application initialization."""
from __future__ import annotations

import json
from pathlib import Path

from .node_hardening import assess


def cmd_node_hardening(args):
    state_root = args.state_dir
    try:
        path = Path(state_root)
        if state_root and not path.is_absolute() and not path.drive and not path.root and ".." not in path.parts:
            # Expand the CLI's ordinary relative default without following links
            # or erasing parent components. The core API still requires absolute paths.
            state_root = path.absolute()
    except (OSError, ValueError, TypeError):
        pass  # The assessment returns a sanitized unknown result for this input.
    report = assess(state_root)
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
