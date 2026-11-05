"""The sqlite backend: every document is a row in <state_dir>/state.db.

  documents(path TEXT PRIMARY KEY, body TEXT NOT NULL, updated_at REAL NOT NULL)
  meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)      schema version, creation time

The database runs in WAL mode: readers never wait for the writer, and the one writer at a time is what keeps
two API workers and the CLI from losing each other's updates. Every connection has a busy timeout, so a
writer that meets another writer waits instead of failing. A write is one statement in autocommit mode, or
part of the transaction `lock()` opens with BEGIN IMMEDIATE. synchronous=NORMAL: a process crash loses
nothing, a power cut can lose the last few transactions, which matches the json layout (no fsync there).

WAL needs the -wal and -shm files on the same local file system as state.db and shared memory that every
process sees; put the state directory on a local volume, never on NFS or SMB (docs/STATE.md).

Connections are per thread (uvicorn runs routes in a thread pool and scans in their own threads) and never
shared across a fork. Nothing here is imported by the json backend, so the sqlite module loads only when it
is in use.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cyberthunder.findings.schema import utcnow
from cyberthunder.state import Backend, StateError, match_pattern, normalize_prefix

SCHEMA_VERSION = "1"
_BUSY = ("locked", "busy")


def _encode(doc: Any) -> str:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), default=str)


class SqliteBackend(Backend):
    name = "sqlite"
    FILENAME = "state.db"

    def __init__(self, root: str | Path, *, busy_timeout: float = 10.0, lock_timeout: float = 30.0):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / self.FILENAME
        self.busy_timeout = busy_timeout
        self.lock_timeout = lock_timeout
        self._tls = threading.local()
        self._conns: dict[int, tuple[threading.Thread, sqlite3.Connection]] = {}
        self._guard = threading.Lock()
        self.created = not self.path.exists()
        try:
            self._init_schema()
        except sqlite3.DatabaseError as e:
            raise StateError(f"cannot open {self.path}: {e}") from e

    @classmethod
    def exists(cls, root: str | Path) -> bool:
        return (Path(root) / cls.FILENAME).is_file()

    # -- connections ----------------------------------------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._tls, "conn", None)
        if c is not None and getattr(self._tls, "pid", None) == os.getpid():
            return c
        c = sqlite3.connect(str(self.path), timeout=self.busy_timeout, isolation_level=None,
                            check_same_thread=False)
        c.execute(f"PRAGMA busy_timeout={int(self.busy_timeout * 1000)}")
        c.execute("PRAGMA synchronous=NORMAL")
        self._tls.conn, self._tls.pid, self._tls.depth = c, os.getpid(), 0
        me = threading.current_thread()
        with self._guard:
            # connections of threads that have ended are closed here, so a long-lived process does not keep
            # one open file handle per scan thread it ever ran
            for ident in [i for i, (t, _) in self._conns.items() if not t.is_alive()]:
                _, old = self._conns.pop(ident)
                try:
                    old.close()
                except sqlite3.Error:
                    pass
            self._conns[me.ident or 0] = (me, c)
        return c

    def _init_schema(self) -> None:
        c = self._conn()
        self._retry(c, "PRAGMA journal_mode=WAL")
        self._retry(c, "CREATE TABLE IF NOT EXISTS documents ("
                       "path TEXT PRIMARY KEY, body TEXT NOT NULL, updated_at REAL NOT NULL)")
        self._retry(c, "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self._retry(c, "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema', ?)", (SCHEMA_VERSION,))
        self._retry(c, "INSERT OR IGNORE INTO meta(key, value) VALUES ('created_at', ?)", (utcnow(),))

    def _retry(self, c: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """The busy timeout covers almost every wait; the retry covers the moment a WAL checkpoint or a
        schema change makes a statement fail with 'database is locked' after the timeout anyway."""
        for attempt in range(4):
            try:
                return c.execute(sql, params)
            except sqlite3.OperationalError as e:
                if attempt == 3 or not any(word in str(e) for word in _BUSY) or getattr(self._tls, "depth", 0):
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise AssertionError("unreachable")

    # -- documents ------------------------------------------------------------------------------------
    def get(self, path: str) -> Any | None:
        row = self._retry(self._conn(), "SELECT body FROM documents WHERE path = ?", (path,)).fetchone()
        return None if row is None else json.loads(row[0])

    def put(self, path: str, doc: Any, *, mtime: float | None = None) -> None:
        self._retry(self._conn(),
                    "INSERT INTO documents(path, body, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(path) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at",
                    (path, _encode(doc), float(mtime) if mtime is not None else time.time()))

    def delete(self, path: str) -> bool:
        cur = self._retry(self._conn(), "DELETE FROM documents WHERE path = ?", (path,))
        return cur.rowcount > 0

    def list(self, prefix: str = "", pattern: str | None = None) -> list[tuple[str, float]]:
        prefix = normalize_prefix(prefix)
        rows = self._retry(self._conn(), "SELECT path, updated_at FROM documents WHERE substr(path, 1, ?) = ? "
                                         "ORDER BY path", (len(prefix), prefix)).fetchall()
        return [(p, float(m)) for p, m in rows if match_pattern(p[len(prefix):], pattern)]

    def count(self) -> int:
        return int(self._retry(self._conn(), "SELECT count(*) FROM documents").fetchone()[0])

    # -- locking --------------------------------------------------------------------------------------
    @contextmanager
    def lock(self, name: str) -> Iterator[None]:
        """BEGIN IMMEDIATE on this thread's connection: the database write lock, shared with every other
        process that uses the file. Reads and writes made inside use the same connection, so they see each
        other and commit together when the block ends; an exception rolls them all back. Re-entrant within
        a thread. SQLite has one write lock, so every name is the same lock."""
        c = self._conn()
        if self._tls.depth:
            self._tls.depth += 1
            try:
                yield
            finally:
                self._tls.depth -= 1
            return
        deadline = time.monotonic() + self.lock_timeout
        while True:
            try:
                c.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as e:
                if not any(word in str(e) for word in _BUSY):
                    raise
                if time.monotonic() > deadline:
                    raise TimeoutError(f"state lock busy ({name}): {self.path}") from e
                time.sleep(0.02)
        self._tls.depth = 1
        try:
            yield
        except BaseException:
            c.execute("ROLLBACK")
            raise
        else:
            c.execute("COMMIT")
        finally:
            self._tls.depth = 0

    # -- info -----------------------------------------------------------------------------------------
    def location(self) -> str:
        return str(self.path)

    def size_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                total += Path(str(self.path) + suffix).stat().st_size
            except OSError:
                continue
        return total

    def meta(self) -> dict[str, str]:
        return dict(self._retry(self._conn(), "SELECT key, value FROM meta").fetchall())

    def close(self) -> None:
        with self._guard:
            conns = [c for _, c in self._conns.values()]
            self._conns.clear()
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:
                pass
        self._tls = threading.local()
