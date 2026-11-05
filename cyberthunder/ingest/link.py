"""Endpoint observations, intentional offline control, and explicit test emulation."""
from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from cyberthunder.control.identity import require_human
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings.schema import utcnow

log = logging.getLogger(__name__)
OBSERVATION_LIMIT = 64
FRESH_SECONDS = 120
PROBE_SESSION_SECONDS = 900
PROBE_INTERVAL_SECONDS = 30
PROBE_ENDPOINTS = ("https://www.cyber.mil/", "https://dl.dod.cyber.mil/")


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "up", "connected"}:
        return True
    if text in {"0", "false", "no", "off", "down", "disconnected"}:
        return False
    raise ValueError("expected a boolean")


def _stamp(value: str | None) -> float:
    try:
        parsed = datetime.fromisoformat(value or "")
        return parsed.timestamp() if parsed.tzinfo else 0
    except (TypeError, ValueError, OverflowError):
        return 0


def _now() -> float:
    return datetime.now(timezone.utc).timestamp()


def endpoint_label(url: str) -> str:
    """No query strings, fragments or credentials in retained observations."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.hostname or "", parts.path[:512], "", ""))[:640]


@dataclass
class LinkState:
    kbps: float | None = None
    latency_ms: int | None = None
    connected: bool = True
    mode: str = "production"
    offline_override: bool = False
    test_connected: bool = True
    reachability: str = "unknown"
    observed_kbps: float | None = None
    last_observation: dict | None = None
    rate_observation: dict | None = None
    observations: list[dict] = field(default_factory=list)
    probe_enabled: bool = False
    probe_until: float | None = None
    probe_endpoint: str = PROBE_ENDPOINTS[0]
    updated_at: str | None = None
    updated_by: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "LinkState":
        return cls(**{key: value for key, value in data.items() if key in cls.__dataclass_fields__})


def transfer_seconds(nbytes: int, state: LinkState) -> float | None:
    """Test estimate only. Production has no configured transfer-time estimate."""
    if state.mode != "test":
        return None
    if state.kbps is None or not math.isfinite(state.kbps) or state.kbps <= 0:
        raise ValueError("test kbps must be finite and positive")
    return round(nbytes * 8 / (state.kbps * 1000) + (state.latency_ms or 0) / 1000, 3)


class Link:
    def __init__(self, store, settings=None, audit=None, on_reconnect: Callable[[str], Any] | None = None):
        self.store, self.settings, self.audit = store, settings, audit
        self.on_reconnect = on_reconnect
        self.last_flush = None
        self.kill = KillSwitch(store.root, audit)

    def _document(self) -> dict:
        value = self.store.read_json(self.store.link_state, {}) or {}
        if not isinstance(value, dict):
            raise ValueError("invalid link control state")
        return value

    def state(self) -> LinkState:
        data = self._document()
        # Only a versioned, explicitly saved selection enables test behavior.
        modern = data.get("version") == 2
        test = modern and data.get("mode") == "test"
        offline = (data.get("offline_override") is True if modern else data.get("connected") is False)
        offline = offline or getattr(self.settings, "link_connected", True) is False
        offline = offline or getattr(self.settings, "link_offline", False) is True
        history = self.store.read_json(self.store.root / "link-observations.json", [])
        history = history[-OBSERVATION_LIMIT:] if isinstance(history, list) else []
        usable = [item for item in history if isinstance(item, dict) and item.get("test_mode") is test]
        last = usable[-1] if usable else None
        fresh = last is not None and 0 <= _now() - _stamp(last.get("at")) <= FRESH_SECONDS
        reachability = ("reachable" if last.get("reachable") else "unreachable") if fresh else "unknown"
        test_connected = data.get("test_connected", True) is True
        rates = [item for item in usable if item.get("observed_kbps") is not None
                 and 0 <= _now() - _stamp(item.get("at")) <= FRESH_SECONDS]
        return LinkState(
            kbps=data.get("kbps", 56.0) if test else None,
            latency_ms=data.get("latency_ms", 500) if test else None,
            mode="test" if test else "production", offline_override=offline, test_connected=test_connected,
            connected=not offline and (test_connected if test else reachability != "unreachable"),
            reachability="operator_offline" if offline else ("test_connected" if test_connected else "test_disconnected") if test else reachability,
            observed_kbps=rates[-1]["observed_kbps"] if rates else None,
            last_observation=last, rate_observation=rates[-1] if rates else None, observations=history,
            probe_enabled=modern and data.get("probe_enabled") is True and (data.get("probe_until") or 0) > _now(),
            probe_until=data.get("probe_until"), probe_endpoint=data.get("probe_endpoint", PROBE_ENDPOINTS[0]),
            updated_at=data.get("updated_at"), updated_by=data.get("updated_by"))

    @property
    def connected(self) -> bool:
        """Permission to attempt a request; unknown is not a claim of reachability."""
        return self.state().connected

    def transfer_seconds(self, nbytes: int) -> float | None:
        return transfer_seconds(nbytes, self.state())

    def _reconnect(self, before: LinkState, after: LinkState, actor: str) -> None:
        self.last_flush = None
        if not before.connected and after.connected and self.on_reconnect:
            self.kill.guard("link.reconnect", actor)
            try:
                self.last_flush = self.on_reconnect(actor)
            except Exception as exc:
                log.warning("reconnect processing failed: %s", type(exc).__name__)
                self.last_flush = {"error": type(exc).__name__}

    def set(self, *, actor: str, mode=None, kbps=None, latency_ms=None, connected=None,
            offline_override=None, probe_enabled=None, probe_endpoint=None) -> LinkState:
        actor = require_human(actor)
        self.kill.guard("link.change", actor)
        with self.store.lock("link"):
            before = self.state()
            data = self._document()
            after_mode = mode if mode is not None else before.mode
            if after_mode not in {"production", "test"}:
                raise ValueError("mode must be production or test")
            if after_mode == "test" and self.audit is None:
                raise ValueError("test mode requires an audit log")
            if (kbps is not None or latency_ms is not None) and after_mode != "test":
                raise ValueError("configured speed and latency require explicit test mode")
            if kbps is not None and (not math.isfinite(float(kbps)) or not 0 < float(kbps) <= 1_000_000):
                raise ValueError("test kbps must be finite and between 0 and 1000000")
            if latency_ms is not None and (isinstance(latency_ms, bool) or int(latency_ms) != latency_ms or not 0 <= latency_ms <= 60000):
                raise ValueError("test latency_ms must be an integer from 0 to 60000")
            if probe_endpoint is not None and probe_endpoint not in PROBE_ENDPOINTS:
                raise ValueError("probe endpoint must be a fixed official source")
            offline = before.offline_override if offline_override is None else parse_bool(offline_override)
            # Old connected setters still mean intentional operator offline in production.
            if connected is not None and after_mode == "production":
                if offline_override is not None:
                    raise ValueError("use offline_override or connected, not both")
                offline = not parse_bool(connected)
            modern = data.get("version") == 2
            data = {"version": 2, "mode": after_mode, "offline_override": offline,
                    "kbps": float(kbps) if kbps is not None else (data.get("kbps", 56.0) if modern else 56.0),
                    "latency_ms": int(latency_ms) if latency_ms is not None else (data.get("latency_ms", 500) if modern else 500),
                    "test_connected": parse_bool(connected) if connected is not None and after_mode == "test" else (data.get("test_connected", True) if modern else True),
                    "probe_enabled": parse_bool(probe_enabled) if probe_enabled is not None else before.probe_enabled,
                    "probe_until": _now() + PROBE_SESSION_SECONDS if probe_enabled is not None and parse_bool(probe_enabled) else before.probe_until,
                    "probe_endpoint": probe_endpoint or before.probe_endpoint,
                    "updated_at": utcnow(), "updated_by": actor}
            self.kill.guard("link.change", actor)
            if self.audit:
                self.audit.append("link.change", actor, {"before": {k: before.to_dict()[k] for k in ("mode", "offline_override", "kbps", "latency_ms")}, "controls": data})
            self.store.write_json(self.store.link_state, data)
            after = self.state()
        self._reconnect(before, after, actor)
        return after

    def observe(self, *, endpoint: str, method: str, application_bytes: int, elapsed_seconds: float,
                success: bool, status: int | None = None, error: str | None = None,
                kind: str = "content", test_mode: bool | None = None, reachable: bool | None = None) -> dict:
        elapsed = max(0.0, float(elapsed_seconds))
        if not math.isfinite(elapsed) or application_bytes < 0:
            raise ValueError("invalid transfer observation")
        with self.store.lock("link"):
            before = self.state()
            test = before.mode == "test" if test_mode is None else test_mode
            item = {"at": utcnow(), "endpoint": endpoint_label(endpoint), "method": method[:10],
                    "kind": kind, "application_bytes": int(application_bytes), "elapsed_seconds": round(elapsed, 6),
                    "success": bool(success), "status": status, "error": (error or "")[:80] or None,
                    "test_mode": test, "reachable": status is not None if reachable is None else reachable,
                    "observed_kbps": round(application_bytes * 8 / elapsed / 1000, 3)
                    if success and elapsed > 0 and application_bytes > 0 and kind == "content" else None}
            history = self.store.read_json(self.store.root / "link-observations.json", [])
            self.store.write_json(self.store.root / "link-observations.json", [*history[-(OBSERVATION_LIMIT - 1):], item])
        # Passive observations do not launch additional network calls or flushes.
        return item

    def probe(self, *, actor: str, background: bool = False) -> dict | None:
        from cyberthunder.ingest.probe import bounded_probe
        self.kill.guard("link.probe", actor)
        schedule = self.store.root / "link-probe-schedule.json"
        # Reserve briefly; never hold SQLite's write transaction during network I/O.
        with self.store.lock("link-probe"):
            before = self.state()
            if before.offline_override or (before.mode == "test" and not before.test_connected):
                raise ValueError("probe blocked by operator offline or test disconnect")
            prior = self.store.read_json(schedule, {})
            if background and (not before.probe_enabled or _now() < prior.get("next_at", 0)):
                return None
            if _now() < prior.get("busy_until", 0):
                raise ValueError("a probe is already running")
            reservation = _now()
            self.store.write_json(schedule, {"next_at": reservation + PROBE_INTERVAL_SECONDS,
                                            "busy_until": reservation + 10, "reservation": reservation})
        try:
            def guard():
                self.kill.guard("link.probe", actor)
                state = self.state()
                if state.offline_override or (state.mode == "test" and not state.test_connected):
                    raise ValueError("probe stopped by link control")
                if state.mode != before.mode or state.probe_endpoint != before.probe_endpoint:
                    raise ValueError("probe controls changed")
                if background and not state.probe_enabled:
                    raise ValueError("probe monitoring disabled or expired")
            result = bounded_probe(before.probe_endpoint, guard=guard)
            guard()
            observation = self.observe(endpoint=before.probe_endpoint, method="HEAD", application_bytes=0,
                elapsed_seconds=result["elapsed_seconds"], success=result["success"], status=result.get("status"),
                error=result.get("error"), kind="probe", test_mode=before.mode == "test", reachable=result["success"])
            if self.audit:
                self.audit.append("link.probe", actor, observation, outcome="ok" if result["success"] else "failed")
            self._reconnect(before, self.state(), actor)
            return observation
        finally:
            with self.store.lock("link-probe"):
                current = self.store.read_json(schedule, {})
                if current.get("reservation") == reservation:
                    current["busy_until"] = 0
                    self.store.write_json(schedule, current)
