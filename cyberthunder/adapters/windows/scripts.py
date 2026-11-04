"""PowerShell script packaging for the Windows adapter.

Every script the adapter runs lives as a file under ps/ (or as a FixEntry payload) and starts with a marker
line, '# cyberthunder-script: <name>' or '# cyberthunder-fix: <fix_ref>'. Scripts travel as

    powershell -NoProfile -NonInteractive -EncodedCommand <base64 of UTF-16LE text>

so the exact same command works over WinRM, on the local machine and against the simulated host.

Data (never code) is handed to a script by inserting one line directly after the marker:

    $CtParams = '<base64 of UTF-8 JSON>'

Base64 cannot break out of a single-quoted PowerShell string, and the script only ever reads the decoded
JSON as values (names of tasks, services, registry values). Nothing from a finding description, an
operator note or a model output is placed into a script.
"""
from __future__ import annotations

import base64
import json
import re
from functools import lru_cache
from pathlib import Path

PS_DIR = Path(__file__).resolve().parent / "ps"
PS_PREFIX = "powershell -NoProfile -NonInteractive -EncodedCommand "
MARKER_RE = re.compile(r"^#\s*cyberthunder-(script|fix):\s*(\S+)\s*$")
DATA_RE = re.compile(r"^\$(CtParams|CtSpec|CtState)\s*=\s*'([A-Za-z0-9+/=]*)'\s*$", re.M)
ENCODED_RE = re.compile(r"(?i)^\s*powershell(?:\.exe)?\b.*?\s-EncodedCommand\s+([A-Za-z0-9+/=]+)\s*$", re.S)
FILE_RE = re.compile(r"(?i)^\s*powershell(?:\.exe)?\b.*?\s-File\s+\"?([^\"]+?)\"?\s*$", re.S)

# A Windows command line is limited to 32767 characters. Above this size the adapter stages the script
# as a file on the host instead of passing it inline.
MAX_INLINE = 24000

SAFE_VALUE_RE = re.compile(r"^[^\x00-\x1f'\"`]{1,400}$")


@lru_cache(maxsize=None)
def load(name: str) -> str:
    """Text of ps/<name>.ps1. The first line must be the script marker."""
    text = (PS_DIR / f"{name}.ps1").read_text(encoding="utf-8")
    first = text.splitlines()[0] if text else ""
    m = MARKER_RE.match(first)
    if not m or m.group(2) != name:
        raise ValueError(f"ps/{name}.ps1 does not start with '# cyberthunder-script: {name}'")
    return text


def b64json(data) -> str:
    return base64.b64encode(json.dumps(data, sort_keys=True).encode("utf-8")).decode("ascii")


def with_data(script: str, var: str, data) -> str:
    """Insert `$<var> = '<base64 json>'` after the marker line. var is CtParams, CtSpec or CtState."""
    if var not in ("CtParams", "CtSpec", "CtState"):
        raise ValueError(f"unknown data variable {var}")
    lines = script.splitlines()
    if not lines or not MARKER_RE.match(lines[0]):
        raise ValueError("script has no cyberthunder marker line")
    return "\n".join([lines[0], f"${var} = '{b64json(data)}'", *lines[1:]]) + "\n"


def encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def command_for(script: str) -> str:
    return PS_PREFIX + encode(script)


def decode_command(command: str) -> str | None:
    """Script text from a 'powershell ... -EncodedCommand <b64>' command line, else None."""
    m = ENCODED_RE.match(command)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


def marker(script: str) -> tuple[str, str] | None:
    """('script'|'fix', name) from the first line of a script."""
    first = script.lstrip("﻿").splitlines()[0] if script else ""
    m = MARKER_RE.match(first)
    return (m.group(1), m.group(2)) if m else None


def data_of(script: str) -> dict:
    """Decoded data lines of a script: {'CtParams': {...}, ...}."""
    out = {}
    for m in DATA_RE.finditer(script):
        try:
            out[m.group(1)] = json.loads(base64.b64decode(m.group(2)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            out[m.group(1)] = None
    return out


def parse_json_output(text: str):
    """JSON document printed by a script. Tolerates a BOM and stray lines before the document."""
    t = (text or "").lstrip("﻿").strip()
    if not t:
        raise ValueError("script produced no output")
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        start = min((i for i in (t.find("{"), t.find("[")) if i >= 0), default=-1)
        if start < 0:
            raise
        return json.loads(t[start:])


def safe_values(params: dict) -> dict:
    """Reject parameter values that do not look like plain names or paths. Defence in depth: params are
    data to the script, but nothing odd should ever reach a host."""
    for k, v in params.items():
        vals = v if isinstance(v, list) else [v]
        for x in vals:
            if isinstance(x, (int, float, bool)) or x is None:
                continue
            if not isinstance(x, str) or not SAFE_VALUE_RE.match(x):
                raise ValueError(f"parameter {k!r} has an unsafe value")
    return params
