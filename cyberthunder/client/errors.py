"""Fixed, credential-free client diagnostics."""
from __future__ import annotations

import json


class ClientError(Exception):
    def __init__(self, code: str, *, outcome=2, source="client", status=None, challenge=None):
        super().__init__(code)
        self.code, self.outcome, self.source = code, outcome, source
        self.status, self.challenge = status, challenge

    def public(self):
        result = {"error": self.code, "source": self.source}
        if self.status is not None:
            result["http_status"] = self.status
        if self.challenge is not None:
            result["step_up"] = self.challenge
        return result


def text(value, maximum=512):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and not any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value))


def decode(raw: bytes, maximum=65536):
    if len(raw) > maximum:
        raise ClientError("response_invalid")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    def constant(_):
        raise ValueError()
    try:
        depth = 0
        quoted = escape = False
        for char in raw:
            if quoted:
                if escape:
                    escape = False
                elif char == 92:
                    escape = True
                elif char == 34:
                    quoted = False
            elif char == 34:
                quoted = True
            elif char in (91, 123):
                depth += 1
                if depth > 12:
                    raise ValueError()
            elif char in (93, 125):
                depth -= 1
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError("response_invalid") from None
