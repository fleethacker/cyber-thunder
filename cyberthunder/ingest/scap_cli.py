"""Standalone passive import CLI; also exposes the common register_cli seam."""
from __future__ import annotations

import argparse
import json
import sys

from cyberthunder.ingest.scap_results import (
    MAX_MANIFEST_BYTES, MAX_XML_BYTES, import_results, parse_manifest, read_local_file,
)


def run(args):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    from cyberthunder.control.killswitch import KillSwitchEngaged
    ctx = None
    try:
        ctx = AppContext(Settings.from_env(state_dir=args.state_dir))
        # The offline CLI cannot establish a verified session. The API uses the same core
        # under the authenticated application principal; a raw --actor is never a substitute.
        if ctx.settings.auth_mode != "dev":
            raise PermissionError("use the authenticated SCAP upload API in verified mode")
        result = import_results(ctx, read_local_file(args.xml, MAX_XML_BYTES),
            parse_manifest(read_local_file(args.manifest, MAX_MANIFEST_BYTES)), actor=args.actor)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, PermissionError, KillSwitchEngaged) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        if ctx is not None:
            ctx.store.close()


def _arguments(parser):
    parser.add_argument("xml", help="local NAME-xccdf.xml file")
    parser.add_argument("--manifest", required=True, help="local explicit mapping/provenance JSON")
    parser.set_defaults(fn=run)


def register_cli(subparsers):
    _arguments(subparsers.add_parser("scap-results-import", help="import existing container OS XCCDF results"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", default=None)
    parser.add_argument("--actor", required=True)
    _arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
