"""Bounded HTTPS JWKS reader, run in a disposable isolated interpreter.

The caller terminates this process at its deadline, including stuck DNS, TLS,
headers or a peer trickling bytes. No credential, redirect or proxy handlers.
"""

import http.client
import ssl
import sys
from urllib.parse import urlsplit

MAX_BODY_BYTES = 262144


def fetch(url: str) -> bytes:
    target = urlsplit(url)
    if (target.scheme != "https" or not target.hostname or target.username
            or target.password or target.fragment):
        raise ValueError("Invalid endpoint")
    connection = http.client.HTTPSConnection(
        target.hostname, target.port or 443, timeout=2,
        context=ssl.create_default_context(),
    )
    try:
        path = target.path or "/"
        if target.query:
            path += "?" + target.query
        connection.request("GET", path, headers={
            "Accept": "application/jwk-set+json, application/json",
            "Accept-Encoding": "identity", "Connection": "close",
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("Invalid response")
        content_types = response.headers.get_all("Content-Type", [])
        if (len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower()
                not in {"application/json", "application/jwk-set+json"}):
            raise ValueError("Invalid content type")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise ValueError("Encoded response")
        lengths = response.headers.get_all("Content-Length", [])
        transfers = response.headers.get_all("Transfer-Encoding", [])
        if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers):
            raise ValueError("Ambiguous framing")
        if transfers and transfers[0].lower() != "chunked":
            raise ValueError("Invalid framing")
        if lengths and (not lengths[0].isascii() or not lengths[0].isdecimal()
                        or int(lengths[0]) > MAX_BODY_BYTES):
            raise ValueError("Oversized response")
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES or (lengths and len(body) != int(lengths[0])):
            raise ValueError("Invalid body size")
        return body
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        endpoint = sys.stdin.buffer.read(4097).decode("ascii")
        if len(endpoint) > 4096:
            raise ValueError("Invalid endpoint")
        sys.stdout.buffer.write(fetch(endpoint))
    except Exception:
        # Neither server responses nor library exception text cross the boundary.
        sys.exit(1)
