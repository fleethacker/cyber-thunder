"""Replay and record transports.

FixtureTransport replays recorded command outputs and files from a directory, so adapters can be tested
and demonstrated without a live host. RecordingTransport wraps a real transport and writes that directory,
so a session against the real range becomes a fixture for later.

Directory layout:
  commands.json   [{"match": "<exact command>" | "regex": "<pattern>", "stdout": "..."|{"file": "name"},
                    "stderr": "", "exit": 0}, ...]
  files/<path>    content returned by read_file("/path")   (leading slash and drive letters stripped)
  missing.log     commands that had no entry (written by FixtureTransport to help authoring)
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .base import CommandResult, Transport, TransportError


def _rel(path: str) -> str:
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = p[2:]
    return p.lstrip("/")


class FixtureTransport(Transport):
    kind = "fixture"

    def __init__(self, root: str | Path, strict: bool = False):
        self.root = Path(root)
        self.strict = strict
        self.files = self.root / "files"
        spec = self.root / "commands.json"
        self.entries: list[dict] = json.loads(spec.read_text(encoding="utf-8")) if spec.exists() else []
        self.calls: list[str] = []

    def _lookup(self, command: str) -> dict | None:
        for e in self.entries:
            if e.get("match") == command:
                return e
        for e in self.entries:
            rx = e.get("regex")
            if rx and re.search(rx, command, re.S):
                return e
        return None

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        self.calls.append(command)
        e = self._lookup(command)
        if e is None:
            with (self.root / "missing.log").open("a", encoding="utf-8") as fh:
                fh.write(command + "\n")
            if self.strict:
                raise TransportError(f"fixture has no entry for command: {command!r}")
            return CommandResult(command, 127, "", f"fixture: no entry for command {command!r}")
        out = e.get("stdout", "")
        if isinstance(out, dict) and "file" in out:
            out = (self.root / out["file"]).read_text(encoding="utf-8", errors="replace")
        return CommandResult(command, int(e.get("exit", 0)), out, e.get("stderr", ""), 0.0, time.time())

    def read_file(self, path: str) -> bytes:
        p = self.files / _rel(path)
        if not p.exists():
            raise TransportError(f"fixture has no file {path!r}")
        return p.read_bytes()

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        p = self.files / _rel(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


class RecordingTransport(Transport):
    """Proxy to a real transport that records every command and file into a fixture directory."""
    kind = "recording"

    def __init__(self, inner: Transport, root: str | Path):
        self.inner = inner
        self.root = Path(root)
        (self.root / "files").mkdir(parents=True, exist_ok=True)
        self.spec = self.root / "commands.json"
        self.entries: list[dict] = json.loads(self.spec.read_text(encoding="utf-8")) if self.spec.exists() else []

    def _save(self) -> None:
        self.spec.write_text(json.dumps(self.entries, indent=2, ensure_ascii=False), encoding="utf-8")

    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        r = self.inner.run(command, timeout=timeout, sudo=sudo)
        n = len(self.entries)
        out_file = f"out_{n:03d}.txt"
        (self.root / out_file).write_text(r.stdout, encoding="utf-8")
        self.entries.append({"match": command, "stdout": {"file": out_file}, "stderr": r.stderr, "exit": r.exit_code})
        self._save()
        return r

    def read_file(self, path: str) -> bytes:
        data = self.inner.read_file(path)
        p = self.root / "files" / _rel(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return data

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        self.inner.write_file(path, data, mode=mode, sudo=sudo)

    def close(self) -> None:
        self.inner.close()
