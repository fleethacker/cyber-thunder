"""Explicit auth/api namespace; sensitive values never come from argv or environment."""
import getpass
import json
import sys
import warnings

from .api import perform
from .auth import ClientAuth
from .config import ClientProfile
from .errors import ClientError, decode


def _display_device(uri, code):
    # A device code is not stdout data. Require an interactive terminal even if
    # stdout is redirected for the final structured result.
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ClientError("interactive_terminal_required")
    print("Open " + uri + " and enter code " + code + ". Authorize only this request.", file=sys.stderr)


def _note(args):
    if args.stdin:
        return decode(sys.stdin.buffer.read(8193), 8192)
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ClientError("decision_input_requires_terminal_or_stdin")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        note = getpass.getpass("Decision note (hidden, blank to omit): ")
        data = {"note": note} if note else {}
        if args.operation == "approve":
            assessment = getpass.getpass("Assessment acknowledgement or explicit bypass reason (hidden, blank to omit): ")
            if assessment:
                data["assessment_note"] = assessment
    return data


def cmd_client(args):
    try:
        if args.cmd == "auth" and args.operation == "login" and (not sys.stdin.isatty() or not sys.stderr.isatty()):
            raise ClientError("interactive_terminal_required")
        profile = ClientProfile.load(args.profile)
        auth = ClientAuth(profile)
        if args.cmd == "auth":
            if args.operation == "login":
                result, outcome = auth.login(_display_device), 0
            elif args.operation == "status":
                result, outcome = auth.status()
            else:
                result, outcome = auth.logout()
        else:
            note = _note(args) if args.group == "decisions" and args.operation in {"approve", "deny", "cancel", "review-impact"} else None
            result, outcome = perform(auth, args, note)
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        return outcome
    except KeyboardInterrupt:
        print(json.dumps({"error": "interrupted", "source": "client"}))
        return 130
    except ClientError as error:
        print(json.dumps(error.public(), ensure_ascii=True))
        return error.outcome
    except Exception:
        # Library errors, native descriptors and provider text may contain secrets.
        print(json.dumps({"error": "client_operation_failed", "source": "client"}))
        return 2


def argument_error(_message):
    raise ClientError("invalid_client_arguments")


def register_cli(subparsers):
    auth = subparsers.add_parser("auth", help="human device login, online status and local/provider logout")
    auth.error = argument_error
    auth.add_argument("--profile", required=True, help="absolute protected non-secret client profile")
    auth.add_argument("operation", choices=("login", "status", "logout"))
    auth.set_defaults(fn=cmd_client)
    api = subparsers.add_parser("api", help="verified remote operations; never local application state")
    api.error = argument_error
    api.add_argument("--profile", required=True, help="absolute protected non-secret client profile")
    groups = api.add_subparsers(dest="group", required=True)
    for group, operations in {"targets": ("list",), "findings": ("list", "show"),
        "scans": ("list", "show", "start"), "decisions": ("list", "show", "plan", "assess", "approve", "deny", "cancel", "review-impact", "apply", "verify", "rollback")}.items():
        group_parser = groups.add_parser(group)
        group_parser.error = argument_error
        commands = group_parser.add_subparsers(dest="operation", required=True)
        for operation in operations:
            parser = commands.add_parser(operation)
            parser.error = argument_error
            parser.set_defaults(fn=cmd_client)
            if operation not in {"list", "start"}:
                parser.add_argument("id")
            if group == "findings" and operation == "list":
                for name in ("host", "scan-id", "status", "severity"):
                    parser.add_argument("--" + name)
                parser.add_argument("--limit", type=int, default=200)
                parser.add_argument("--offset", type=int, default=0)
            if group == "scans" and operation == "start":
                parser.add_argument("--target", action="append", required=True)
                parser.add_argument("--module", action="append", choices=("check", "hunt", "cve"))
            if group == "decisions" and operation in {"approve", "deny", "cancel", "review-impact"}:
                parser.add_argument("--stdin", action="store_true", help="read a bounded note object from stdin")
            if group == "decisions" and operation in {"approve", "review-impact"}:
                parser.add_argument("--assessment-id", required=operation == "review-impact")
            if group == "decisions" and operation == "assess":
                mode = parser.add_mutually_exclusive_group(required=True)
                mode.add_argument("--live", action="store_true")
                mode.add_argument("--static", action="store_false", dest="live")
