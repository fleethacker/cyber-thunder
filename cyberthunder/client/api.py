"""Small explicit API surface; authorization and decisions belong to the server."""
import re

from .errors import ClientError, redact, text
from .http import require_api


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise ClientError("invalid_identifier")
    return value


def command(args, note=None):
    """Return only a fixed route and a bounded subset of its real request schema."""
    group, operation = args.group, args.operation
    route, method, query, body = None, "GET", {}, None
    if group == "targets" and operation == "list":
        route = "/targets"
    elif group == "findings":
        if operation == "list":
            route = "/findings"
            query = {k: getattr(args, k) for k in ("host", "scan_id", "status", "severity", "limit", "offset") if getattr(args, k, None) is not None}
            if not 1 <= args.limit <= 500 or not 0 <= args.offset <= 1000000:
                raise ClientError("invalid_pagination")
            for key in ("host", "scan_id", "status", "severity"):
                if key in query and not text(query[key], 128):
                    raise ClientError("invalid_filter")
        elif operation == "show":
            route = "/findings/" + identifier(args.id)
    elif group == "scans":
        if operation in {"list", "show"}:
            route = "/scans" + ("/" + identifier(args.id) if operation == "show" else "")
        elif operation == "start":
            if not 1 <= len(args.target) <= 128 or len(set(args.target)) != len(args.target):
                raise ClientError("explicit_unique_targets_required")
            if any(not isinstance(t, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", t) for t in args.target):
                raise ClientError("invalid_target_id")
            targets = list(args.target)
            modules = args.module or ["check"]
            if len(modules) > 16 or len(set(modules)) != len(modules) or set(modules) - {"check", "hunt", "cve"}:
                raise ClientError("invalid_modules")
            route, method = "/scans", "POST"
            body = {"target_ids": targets, "modules": modules, "trigger": "manual"}
    elif group == "decisions":
        route = "/proposals"
        if operation != "list":
            route += "/" + identifier(args.id)
            if operation != "show":
                method = "POST"
                route += "/" + {"assess": "impact"}.get(operation, operation)
                if operation in {"approve", "deny", "cancel", "review-impact"}:
                    if not isinstance(note, dict) or note.keys() - {"note", "assessment_note"}:
                        raise ClientError("decision_input_invalid")
                    if any(not text(v, 2000) for v in note.values()):
                        raise ClientError("decision_input_invalid")
                    if operation != "approve" and "assessment_note" in note:
                        raise ClientError("decision_input_invalid")
                    body = dict(note)
                    assessment = getattr(args, "assessment_id", None)
                    if assessment is not None:
                        if len(assessment) != 36 or not re.fullmatch(r"[A-Za-z0-9_-]+", assessment):
                            raise ClientError("invalid_assessment_id")
                        body["assessment_id"] = assessment
                    if operation == "review-impact" and (not assessment or not note.get("note")):
                        raise ClientError("assessment_and_note_required")
                elif operation == "assess":
                    body = {"live": args.live}
                elif operation not in {"plan", "apply", "verify", "rollback"}:
                    raise ClientError("operation_not_supported")
    if route is None:
        raise ClientError("operation_not_supported")
    return method, route, query, body


def perform(auth, args, note=None):
    method, route, query, body = command(args, note)
    with auth.access() as access:
        response = auth.http.request("api", method=method, route=route, query=query, payload=body, credential=access)
        result = require_api(response, credentials=(access,))
        # Do not export a bearer credential even if a response reflects it.
        result = redact(result, access)
    pending = response.status == 202 or (args.group == "decisions" and args.operation == "approve" and result.get("state") == "proposed")
    operation_id = result.get("proposal_id") or result.get("id")
    return {"status": "accepted_pending" if pending else "completed", "http_status": response.status,
            "operation_id": operation_id, "result": result}, 4 if pending else 0
