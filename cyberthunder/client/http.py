"""Fixed-origin HTTPS requests; no ambient proxy, cookies, redirect or secret argv."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlencode

from .errors import ClientError, decode

TIMEOUT = 10
_ROUTE = re.compile(r"/(?:whoami|targets|findings(?:/[A-Za-z0-9_-]{1,128})?|scans(?:/[A-Za-z0-9_-]{1,128})?|proposals(?:/[A-Za-z0-9_-]{1,128}(?:/(?:plan|impact|approve|deny|cancel|review-impact|apply|verify|rollback))?)?)\Z")


@dataclass(repr=False)
class Response:
    status: int
    body: dict = field(repr=False)


class Transport:
    def __init__(self, profile):
        self.profile = profile

    def request(self, kind, *, method="POST", route=None, query=None, payload=None, credential=None, timeout=TIMEOUT):
        if kind == "api":
            if not isinstance(route, str) or not _ROUTE.fullmatch(route) or method not in {"GET", "POST"}:
                raise ClientError("route_not_supported")
            url = self.profile["api_base_url"] + route
            if query:
                url += "?" + urlencode(query, doseq=True)
            body = json.dumps(payload, separators=(",", ":"), allow_nan=False) if payload is not None else None
            content_type, maximum = "application/json", 4 * 1024 * 1024
        elif kind in {"device_authorization_endpoint", "token_endpoint", "revocation_endpoint"} and method == "POST":
            url = self.profile[kind]
            if url is None or credential is not None or route is not None or query:
                raise ClientError("endpoint_unavailable")
            body, content_type, maximum = urlencode(payload or {}), "application/x-www-form-urlencoded", 65536
        else:
            raise ClientError("route_not_supported")
        if body is not None and len(body.encode()) > 65536:
            raise ClientError("request_too_large")
        request = json.dumps({"url": url, "method": method, "body": body, "credential": credential,
                              "content_type": content_type, "maximum": maximum, "ca": self.profile.ca_pem}).encode()
        # Windows DLL discovery needs SystemRoot; no auth/proxy/SSL override variables.
        environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
        try:
            result = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("_http_worker.py"))],
                input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment,
                timeout=min(TIMEOUT, max(0.01, timeout)), check=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            envelope = decode(result.stdout, 6 * 1024 * 1024)
            if envelope.keys() != {"status", "body"} or type(envelope["status"]) is not int or not 100 <= envelope["status"] <= 599:
                raise ValueError()
            raw = base64.b64decode(envelope["body"], validate=True)
            return Response(envelope["status"], decode(raw, maximum) if raw else {})
        except subprocess.TimeoutExpired:
            raise ClientError("request_timeout", outcome=4, source=kind) from None
        except subprocess.CalledProcessError as error:
            code = "request_timeout" if error.returncode == 3 else "https_request_failed"
            raise ClientError(code, outcome=4, source=kind) from None
        except ClientError:
            raise
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            raise ClientError("https_request_failed", outcome=4, source=kind) from None


def require_api(response):
    if 200 <= response.status < 300:
        return response.body
    code = {400: "invalid_request", 401: "authentication_required", 403: "forbidden", 404: "not_found",
            409: "operation_conflict", 423: "kill_switch_engaged", 429: "rate_limited"}.get(response.status, "api_request_failed")
    challenge = None
    if response.status == 401 and response.body.get("error") == "insufficient_user_authentication":
        from cyberthunder.security.step_up import StepUpPolicy, REASONS
        value = response.body.get("step_up")
        try:
            if (not isinstance(value, dict) or value.keys() != {"reason", "max_age", "acr_values"}
                    or value["reason"] not in REASONS or not isinstance(value["acr_values"], list)):
                raise ValueError()
            policy = StepUpPolicy(value["max_age"], tuple(value["acr_values"]))
            challenge = {"reason": value["reason"], "max_age": policy.max_age, "acr_values": list(policy.acr_values)}
            code = "insufficient_user_authentication"
        except (TypeError, ValueError, KeyError):
            raise ClientError("api_response_invalid") from None
    raise ClientError(code, outcome=3, source="api", status=response.status, challenge=challenge)
