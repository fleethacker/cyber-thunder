"""Runtime helpers for the packaged service.

The Kubernetes deployment registers its own cluster out of scope using its mounted service account kubeconfig.
The CLI stays explicit by default. Optional background tasks check content updates and periodically
scan already in-scope inventory targets.
"""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Callable

from cyberthunder.control.identity import MAX_ACTOR_LEN, normalize_actor
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.inventory.targets import Target

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)


def bootstrap_cluster_target(ctx: "AppContext") -> None:
    """Register the configured host cluster once; retain operator edits and scope across restarts."""
    settings = ctx.settings
    if not settings.bootstrap_cluster_target:
        return
    target_id = settings.bootstrap_cluster_target_id
    try:
        ctx.inventory.get(target_id)
        return
    except KeyError:
        pass
    actor = normalize_actor(settings.scheduler_actor)
    if not actor or len(actor) > MAX_ACTOR_LEN or any(ord(c) < 32 or ord(c) == 127 for c in actor):
        ctx.audit.append("inventory.bootstrap", "?", {"target": target_id, "reason": "invalid scheduler actor"},
                         outcome="rejected")
        raise PermissionError("bootstrap requires a named scheduler actor")
    try:
        ctx.killswitch.guard("inventory.bootstrap", actor)
    except KillSwitchEngaged:
        # Keep the API available so an operator can inspect state and release the switch.
        return
    kubeconfig = str(settings.bootstrap_cluster_kubeconfig)
    target = Target(
        id=target_id,
        name=settings.bootstrap_cluster_name,
        asset_type="kubernetes",
        transport="kubeconfig",
        sudo=False,
        tags=["bootstrap", "discovery-source", "cluster"],
        in_scope=False,
        options={"kubeconfig": kubeconfig, "context": "in-cluster", "kubectl": "kubectl"},
        notes="Registered by the packaged service from its own in-cluster Kubernetes context; "
              "an operator must review and authorize scope before scanning.",
    )
    try:
        ctx.killswitch.guard("inventory.bootstrap", actor)
    except KillSwitchEngaged:
        return
    ctx.inventory.add(target)
    ctx.save_inventory(actor, "inventory.bootstrap", {"target": target.id, "source": "kubernetes",
                                                     "in_scope": False, "authorization_required": True})


class RuntimeTasks:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        bootstrap_cluster_target(self.ctx)
        self._start_interval("content-updates", self.ctx.settings.content_check_interval_s, self._check_content)
        self._start_interval("scan", self.ctx.settings.scan_interval_s, self._scan_inventory)

    def stop(self) -> None:
        self._stop.set()
        for th in self._threads:
            th.join(timeout=5)

    def _start_interval(self, name: str, interval_s: int, fn: Callable[[], None]) -> None:
        if interval_s <= 0:
            return
        th = threading.Thread(target=self._loop, args=(name, interval_s, fn), name=f"cyberthunder-{name}", daemon=True)
        self._threads.append(th)
        th.start()

    def _loop(self, name: str, interval_s: int, fn: Callable[[], None]) -> None:
        while not self._stop.wait(interval_s):
            try:
                fn()
            except Exception:  # noqa: BLE001 - background tasks must never stop the API process
                log.exception("runtime task %s failed", name)

    def _check_content(self) -> None:
        ingest = getattr(self.ctx, "ingest", None)
        if ingest is None or not callable(getattr(ingest, "check_updates", None)):
            return
        ingest.check_updates(self.ctx.settings.scheduler_actor, source="live")

    def _scan_inventory(self) -> None:
        targets = [t.id for t in self.ctx.inventory.all() if t.in_scope]
        if not targets:
            return
        if any(self.ctx.scanner.is_running(r.id) for r in self.ctx.scanner.list()):
            return
        self.ctx.scanner.start(targets, trigger="scheduled", requested_by=self.ctx.settings.scheduler_actor,
                               background=True)
