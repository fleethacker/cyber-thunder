"""Background precompute worker: one daemon thread, one queue, deduplicated by finding id.

Explanations are generated ahead of time so the approver never waits on the model while reviewing.
The worker only ever calls the explain function it is given; it performs no other action.
"""
from __future__ import annotations

import logging
import queue
import threading
from contextvars import Context, copy_context
from typing import Callable

from cyberthunder.findings.schema import Finding

log = logging.getLogger(__name__)


class ExplainWorker:
    def __init__(self, fn: Callable[[Finding], object], *, name: str = "explain-precompute"):
        self._fn = fn
        self._name = name
        self._q: "queue.Queue[tuple[Finding, Context] | None]" = queue.Queue()
        self._ids: set[str] = set()            # queued or in progress
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.done = 0
        self.failed = 0

    # -- queueing ----------------------------------------------------------------------
    def submit(self, finding: Finding) -> bool:
        """Queue one finding; False if it is already queued or being worked."""
        with self._lock:
            if finding.id in self._ids:
                return False
            self._ids.add(finding.id)
        self._ensure_thread()
        self._q.put((finding, copy_context()))
        return True

    def pending(self) -> int:
        with self._lock:
            return len(self._ids)

    def is_queued(self, finding_id: str) -> bool:
        with self._lock:
            return finding_id in self._ids

    # -- lifecycle ---------------------------------------------------------------------
    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                self._q.task_done()
                break
            finding, context = item
            try:
                context.run(self._fn, finding)
                self.done += 1
            except Exception as e:  # noqa: BLE001  one bad finding must not stop the queue
                self.failed += 1
                log.warning("precompute failed for %s: %s", finding.id, e)
            finally:
                with self._idle:
                    self._ids.discard(finding.id)
                    self._idle.notify_all()
                self._q.task_done()

    def wait_idle(self, timeout: float | None = None) -> bool:
        """Block until nothing is queued or in progress. True if idle, False on timeout."""
        with self._idle:
            return self._idle.wait_for(lambda: not self._ids, timeout=timeout)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._q.put(None)
        t = self._thread
        if t is not None:
            t.join(timeout)
        if not self.alive:
            # discard anything not yet started, so a later submit starts clean
            with self._idle:
                self._q = queue.Queue()
                self._ids.clear()
                self._idle.notify_all()

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
