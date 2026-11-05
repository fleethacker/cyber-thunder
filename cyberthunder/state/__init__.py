"""State backends: where StateStore keeps its documents.

A *document* is a JSON value the application reads and writes only through StateStore: scan runs and
findings, explanations, the link state, ingest deltas and bulletins, discovery state, the content index and
pull jobs. A *file* is anything another program, a person or a transport reads from disk as a file: the audit
chain and its head checkpoint, proposals.json, policy.json and targets.yaml (their owners take a file path and
hold their own cross-process lock), the kill switch state and sentinel, scanner working directories under
scans/<id>/raw, snapshots, the outbox and synced queues, downloaded content and extracted datastreams, the
content manifest, uploads and simulated host state. Documents go to the configured backend; files stay on
disk whatever the backend is.

Backends (CT_STATE_BACKEND):
  json    one file per document under the state directory, written by temp file and rename: the layout the
          tool has always had, so a state directory can still be copied, diffed and synced as files.
  sqlite  one database file, state.db in the state directory, in WAL mode with a busy timeout, and a
          documents table keyed by the logical path. One writer at a time and readers never wait, so two API
          workers and the CLI can share the directory on a local volume. Not for network file systems.

A logical path is the POSIX-style path of a document relative to the state directory, for example
"scans/<id>/run.json". docs/STATE.md describes the layout, the migration commands and the backup implications.
"""
from __future__ import annotations

import fnmatch
import os
from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

BACKENDS = ("json", "sqlite")
DEFAULT_BACKEND = "json"

# Routing is a positive list: a JSON path that is not named here is a file, which is what every path was
# before the backends existed. A new document area is added here on purpose.
DOCUMENT_FILES = frozenset({
    "link.json", "demo.json",
    "cluster/known_good.json",
    "content/index.json", "content/last_check.json", "content/source.json", "content/catalog.json",
    "content/preferences.json", "content/sync.json",
    "vulnerabilities/state.json", "vulnerabilities/settings.json",
})
DOCUMENT_AREAS = ("explanations/", "finding_reviews/", "ingest/deltas/", "ingest/bulletins/", "discovery/", "content/jobs/",
                  "vulnerabilities/jobs/")
SCAN_DOCUMENTS = frozenset({"run.json", "findings.json"})


class StateError(RuntimeError):
    """A backend could not be opened or a migration was refused."""


def is_document(path: str) -> bool:
    """True when the logical path names a document (a row under sqlite); False for every file."""
    if not path.endswith(".json"):
        return False
    if path in DOCUMENT_FILES:
        return True
    if path.startswith("scans/"):
        parts = path.split("/")
        return len(parts) == 3 and parts[2] in SCAN_DOCUMENTS
    return path.startswith(DOCUMENT_AREAS)


def normalize_prefix(prefix: str) -> str:
    """'scans', '/scans/' and 'scans/' all mean the scans area; '' is the whole store."""
    p = prefix.replace("\\", "/").strip("/")
    return p + "/" if p else ""


def match_pattern(rel: str, pattern: str | None) -> bool:
    """Glob match where '*' never crosses a '/' (the semantics of Path.glob for a plain pattern)."""
    if pattern is None:
        return True
    rp, pp = rel.split("/"), pattern.replace("\\", "/").strip("/").split("/")
    return len(rp) == len(pp) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(rp, pp))


def backend_from_env() -> str:
    """The configured backend name, validated. Mirrors Settings.state_backend for code that has no Settings."""
    return validate_backend(os.environ.get("CT_STATE_BACKEND") or DEFAULT_BACKEND)


def validate_backend(name: str | None) -> str:
    n = (name or DEFAULT_BACKEND).strip().lower()
    if n not in BACKENDS:
        raise StateError(f"unknown state backend {name!r}; CT_STATE_BACKEND must be one of {', '.join(BACKENDS)}")
    return n


class Backend(ABC):
    """The storage contract behind StateStore. Paths are logical paths; documents are JSON values."""

    name: str = ""

    @abstractmethod
    def get(self, path: str) -> Any | None:
        """The document, or None when there is none."""

    @abstractmethod
    def put(self, path: str, doc: Any, *, mtime: float | None = None) -> None:
        """Write the document atomically. `mtime` carries a timestamp across a migration."""

    @abstractmethod
    def delete(self, path: str) -> bool:
        """Remove the document; True when something was removed."""

    @abstractmethod
    def list(self, prefix: str = "", pattern: str | None = None) -> list[tuple[str, float]]:
        """(logical path, modified time) of every document under the prefix, sorted by path. `pattern` is a
        glob relative to the prefix, as Path.glob reads it."""

    @abstractmethod
    def lock(self, name: str) -> AbstractContextManager:
        """Exclusive lock shared by every process using this state directory. Under sqlite it is the
        database write transaction, so writes made inside it land together or not at all."""

    @abstractmethod
    def location(self) -> str:
        """Where the documents are, for `state info`."""

    @abstractmethod
    def size_bytes(self) -> int:
        """Bytes the documents occupy on disk."""

    def documents(self) -> list[tuple[str, float]]:
        return [(p, m) for p, m in self.list() if is_document(p)]

    def count(self) -> int:
        return len(self.documents())

    def close(self) -> None:
        return None


def open_backend(name: str, root: str | Path) -> Backend:
    """A backend for the state directory. Modules are imported here so the json backend never loads sqlite."""
    name = validate_backend(name)
    if name == "json":
        from cyberthunder.state.json_files import JsonFilesBackend
        return JsonFilesBackend(root)
    from cyberthunder.state.sqlite import SqliteBackend
    return SqliteBackend(root)


__all__ = ["BACKENDS", "DEFAULT_BACKEND", "Backend", "StateError", "backend_from_env", "is_document",
           "match_pattern", "normalize_prefix", "open_backend", "validate_backend"]
