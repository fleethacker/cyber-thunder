"""Fixed-source HEAD probe in a disposable process, including a DNS deadline."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ENDPOINTS = ("https://www.cyber.mil/", "https://dl.dod.cyber.mil/")
DEADLINE_SECONDS = 5.0
MAX_BODY_BYTES = 0


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("probe redirects are refused")


def request_probe(endpoint: str) -> dict:
    if endpoint not in ENDPOINTS:
        raise ValueError("probe endpoint is not a fixed official source")
    # No proxy discovery, cookies, credentials or redirect destinations.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    request = urllib.request.Request(endpoint, method="HEAD", headers={"User-Agent": "cyber-thunder-link-probe"})
    start = time.monotonic()
    try:
        with opener.open(request, timeout=DEADLINE_SECONDS) as response:
            if response.geturl() != endpoint:
                raise ValueError("unexpected probe endpoint")
            status = response.status
            # HEAD has no body. Even a broken injectable response is capped.
            if response.read(MAX_BODY_BYTES + 1):
                raise ValueError("probe returned a response body")
            return {"success": 200 <= status < 300, "status": status,
                    "elapsed_seconds": time.monotonic() - start}
    except urllib.error.HTTPError as exc:
        exc.close()
        return {"success": False, "status": exc.code, "error": "http_status",
                "elapsed_seconds": time.monotonic() - start}
    except Exception as exc:
        return {"success": False, "status": None, "error": type(exc).__name__,
                "elapsed_seconds": time.monotonic() - start}


def bounded_probe(endpoint: str, *, guard) -> dict:
    if endpoint not in ENDPOINTS:
        raise ValueError("probe endpoint is not a fixed official source")
    guard()
    started = time.monotonic()
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
    flags = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), endpoint],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, **flags)
    try:
        while True:
            guard()
            remaining = DEADLINE_SECONDS - (time.monotonic() - started)
            if remaining <= 0:
                return {"success": False, "status": None, "error": "deadline",
                        "elapsed_seconds": time.monotonic() - started}
            try:
                output, _ = process.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        guard()
        try:
            if process.returncode or len(output) > 4096:
                raise ValueError("invalid probe worker output")
            result = json.loads(output)
            if not isinstance(result, dict) or type(result.get("success")) is not bool:
                raise ValueError("invalid probe worker result")
        except (ValueError, TypeError):
            result = {"success": False, "status": None, "error": "invalid_worker_result"}
        result["elapsed_seconds"] = time.monotonic() - started
        return result
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=1)


if __name__ == "__main__":
    print(json.dumps(request_probe(sys.argv[1])))
