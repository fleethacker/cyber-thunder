"""Search captured application boundaries without printing the secret or its encoding."""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import unquote_to_bytes


class CanaryLeak(AssertionError):
    """Only boundary labels and encoding names are safe in failure diagnostics."""


class CanaryProbe:
    def __init__(self, secret: str):
        self._needles = (secret.encode(), secret.encode("utf-16le"))
        self._samples: list[tuple[str, bytes]] = []

    def __repr__(self):
        return "CanaryProbe(<protected fixture>)"

    def add(self, label: str, value) -> None:
        if isinstance(value, bytes):
            raw = value
        elif isinstance(value, str):
            raw = value.encode("utf-8")
        else:
            raw = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
        self._samples.append((label, raw))

    def tree(self, root: Path) -> None:
        """No state exclusions: inspect bytes, filenames, and logical SQLite rows."""
        for index, path in enumerate(sorted(root.rglob("*"))):
            label = f"state file {index}"
            self.add(label + " path", str(path.relative_to(root)))
            if not path.is_file():
                continue
            raw = path.read_bytes()
            self.add(label, raw)
            if raw.startswith(b"SQLite format 3\x00"):
                # Logical rows also catch values split across SQLite overflow pages.
                with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
                    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                    for table_index, (name,) in enumerate(tables):
                        quoted = '"' + name.replace('"', '""') + '"'
                        for row_index, row in enumerate(db.execute("SELECT * FROM " + quoted)):
                            for column_index, value in enumerate(row):
                                self.add(f"{label} table {table_index} row {row_index} column {column_index}", value)

    def _encoding(self, raw: bytes, depth: int = 0) -> str | None:
        for needle, name in zip(self._needles, ("plaintext", "UTF-16LE")):
            if needle in raw:
                return name
        if depth == 2:
            return None
        if b"%" in raw:
            decoded = unquote_to_bytes(raw)
            if decoded != raw:
                found = self._encoding(decoded, depth + 1)
                if found:
                    return "percent/" + found
        # Decode envelopes, not just base64(secret): offsets/padding change when
        # a secret is embedded inside JSON, an authorization header, or a script.
        for match in re.finditer(rb"[A-Za-z0-9+/_-]{16,}={0,2}", raw):
            token = match.group()
            try:
                decoded = base64.b64decode(token + b"=" * (-len(token) % 4), altchars=b"-_", validate=True)
            except (binascii.Error, ValueError):
                continue
            found = self._encoding(decoded, depth + 1)
            if found:
                return "base64/" + found
        return None

    def assert_clean(self) -> None:
        leaks = []
        for label, raw in self._samples:
            encoding = self._encoding(raw)
            if encoding:
                leaks.append(f"{label} ({encoding})")
        if leaks:
            raise CanaryLeak("credential canary reached: " + "; ".join(leaks))
