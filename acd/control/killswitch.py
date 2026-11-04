"""Kill switch: halts the agent and blocks every pending state-changing action.

Three independent ways to stop it, any one wins:
  1. state file  <state_dir>/killswitch.json {"engaged": true}   (UI button / `acd kill engage`)
  2. env var     ACD_KILL=1                                        (operator shell)
  3. sentinel    <state_dir>/KILL                                  (touch a file, no tooling needed)
Every state-changing code path must call `guard()` immediately before acting.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from acd.audit.chain import AuditLog
from acd.findings.schema import utcnow


class KillSwitchEngaged(RuntimeError):
    pass


class KillSwitch:
    def __init__(self, state_dir: str | Path, audit: AuditLog | None = None):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.dir / "killswitch.json"
        self.sentinel = self.dir / "KILL"
        self.audit = audit

    def status(self) -> dict:
        st: dict = {"engaged": False, "by": None, "reason": None, "at": None, "via": None}
        if os.environ.get("ACD_KILL", "").strip().lower() in {"1", "true", "yes", "on"}:
            st.update(engaged=True, via="env:ACD_KILL")
            return st
        if self.sentinel.exists():
            st.update(engaged=True, via=f"sentinel:{self.sentinel}")
            return st
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {"engaged": True, "reason": "unreadable state file (fail closed)"}
            if data.get("engaged"):
                st.update(engaged=True, by=data.get("by"), reason=data.get("reason"),
                          at=data.get("at"), via="state_file")
        return st

    def is_engaged(self) -> bool:
        return bool(self.status()["engaged"])

    def engage(self, actor: str, reason: str = "") -> dict:
        data = {"engaged": True, "by": actor, "reason": reason, "at": utcnow()}
        self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        if self.audit is not None:
            self.audit.append("killswitch.engage", actor, {"reason": reason})
        return data

    def release(self, actor: str, reason: str = "") -> dict:
        data = {"engaged": False, "by": actor, "reason": reason, "at": utcnow()}
        self.state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        if self.sentinel.exists():
            self.sentinel.unlink()
        if self.audit is not None:
            self.audit.append("killswitch.release", actor, {"reason": reason})
        return data

    def guard(self, action: str, actor: str = "agent") -> None:
        """Call before any state change. Logs the block and raises if engaged."""
        st = self.status()
        if st["engaged"]:
            if self.audit is not None:
                self.audit.append("action.blocked", actor, {"action": action, "killswitch": st}, outcome="blocked")
            raise KillSwitchEngaged(f"kill switch engaged via {st['via']}; refusing: {action}")
