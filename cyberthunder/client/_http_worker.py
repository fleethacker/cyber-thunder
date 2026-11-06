"""Standalone isolated HTTPS worker. Only fixed errors cross its process boundary."""
import base64
import http.client
import json
import ssl
import sys
from urllib.parse import urlsplit


def headers(fp):
    lines, size = [], 0
    for _ in range(65):
        line = fp.readline(32769)
        size += len(line)
        if size > 32768:
            raise ValueError()
        lines.append(line)
        if line in (b"\r\n", b"\n", b""):
            return lines
    raise ValueError()


def main():
    raw = sys.stdin.buffer.read(524289)
    if len(raw) > 524288:
        raise ValueError()
    request = json.loads(raw)
    target = urlsplit(request["url"])
    if (target.scheme != "https" or not target.hostname or target.username or target.password
            or target.fragment or request["method"] not in {"GET", "POST"}):
        raise ValueError()
    context = ssl.create_default_context()
    if request["ca"] is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=request["ca"])
    http.client._read_headers = headers
    connection = http.client.HTTPSConnection(target.hostname, target.port or 443, context=context, timeout=3)
    try:
        values = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"}
        if request["credential"] is not None:
            values["Authorization"] = "Bearer " + request["credential"]
        body = request["body"]
        if body is not None:
            body = body.encode("utf-8")
            values["Content-Type"] = request["content_type"]
        connection.request(request["method"], target.path + ("?" + target.query if target.query else ""), body, values)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError()
        lengths = response.headers.get_all("Content-Length", [])
        transfers = response.headers.get_all("Transfer-Encoding", [])
        encodings = response.headers.get_all("Content-Encoding", [])
        maximum = request["maximum"]
        if (len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers)
                or (transfers and transfers != ["chunked"])
                or (encodings and encodings != ["identity"])):
            raise ValueError()
        if lengths and (not lengths[0].isascii() or not lengths[0].isdecimal() or int(lengths[0]) > maximum):
            raise ValueError()
        body = response.read(maximum + 1)
        if len(body) > maximum or (lengths and len(body) != int(lengths[0])):
            raise ValueError()
        types = response.headers.get_all("Content-Type", [])
        if body and (len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError()
        sys.stdout.write(json.dumps({"status": response.status, "body": base64.b64encode(body).decode("ascii")}))
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(2)
