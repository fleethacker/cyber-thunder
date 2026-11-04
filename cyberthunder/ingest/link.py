"""Emulated constrained link.

This does not shape traffic (on the range that is tc/netem's job). It records what the link looks like
right now so transfer times can be estimated and shown, and so the outbox knows whether it may send.
State lives in <state_dir>/link.json; every change is audited as "link.change". When the link goes from
disconnected to connected, the registered reconnect hook (the outbox flush) runs.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Callable

from cyberthunder.findings.schema import utcnow

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.audit.chain import AuditLog
    from cyberthunder.config import Settings
    from cyberthunder.store import StateStore

log = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on", "up", "connected"}
_FALSE = {"0", "false", "no", "off", "down", "disconnected"}


@dataclass
class LinkState:
    kbps: float = 56.0
    latency_ms: int = 500
    connected: bool = True
    updated_at: str | None = None
    updated_by: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "LinkState":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


def parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    raise ValueError(f"not a boolean: {v!r}")


def transfer_seconds(nbytes: int, state: LinkState) -> float:
    """Serialisation time at the link rate plus one latency. kbps is kilobits (1000 bits) per second."""
    if state.kbps <= 0:
        raise ValueError("link kbps must be positive")
    return round(nbytes * 8 / (state.kbps * 1000) + state.latency_ms / 1000, 3)


class Link:
    def __init__(self, store: "StateStore", settings: "Settings | None" = None, audit: "AuditLog | None" = None,
                 on_reconnect: Callable[[str], Any] | None = None):
        self.store = store
        self.settings = settings
        self.audit = audit
        self.on_reconnect = on_reconnect     # called with the actor after a false -> true transition
        self.last_flush: Any = None

    def _defaults(self) -> LinkState:
        s = self.settings
        if s is None:
            return LinkState()
        return LinkState(kbps=float(s.link_kbps), latency_ms=int(s.link_latency_ms), connected=bool(s.link_connected))

    def state(self) -> LinkState:
        d = self.store.read_json(self.store.link_state)
        return LinkState.from_dict(d) if d else self._defaults()

    @property
    def connected(self) -> bool:
        return self.state().connected

    def transfer_seconds(self, nbytes: int) -> float:
        return transfer_seconds(nbytes, self.state())

    def set(self, *, actor: str, kbps: float | None = None, latency_ms: int | None = None,
            connected: bool | str | None = None) -> LinkState:
        before = self.state()
        after = LinkState.from_dict(before.to_dict())
        if kbps is not None:
            if float(kbps) <= 0:
                raise ValueError("kbps must be positive")
            after.kbps = float(kbps)
        if latency_ms is not None:
            if int(latency_ms) < 0:
                raise ValueError("latency_ms must not be negative")
            after.latency_ms = int(latency_ms)
        if connected is not None:
            after.connected = parse_bool(connected)
        after.updated_at, after.updated_by = utcnow(), actor
        self.store.write_json(self.store.link_state, after.to_dict())
        changed = {k: {"from": getattr(before, k), "to": getattr(after, k)}
                   for k in ("kbps", "latency_ms", "connected") if getattr(before, k) != getattr(after, k)}
        if self.audit is not None:
            self.audit.append("link.change", actor, {"changed": changed, "state": after.to_dict()})
        self.last_flush = None
        if not before.connected and after.connected and self.on_reconnect is not None:
            try:
                self.last_flush = self.on_reconnect(actor)
            except Exception as e:  # noqa: BLE001 - a failed flush must not undo the link change
                log.warning("outbox flush on reconnect failed: %s", e)
                self.last_flush = {"error": str(e)}
        return after
