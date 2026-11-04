"""Approval gate: the only path from a proposed fix to an applied one.

State machine (every edge is audit-logged; apply/rollback edges are kill-switch guarded):

  PROPOSED --approve--> APPROVED --apply--> APPLYING --applied--> APPLIED --verify--> VERIFIED --rollback--> ROLLED_BACK
      |                     |                  |                      |
    deny                 cancel              fail                 verify-fail
      v                     v                  v                      v
   DENIED              CANCELLED            FAILED --rollback--> ROLLED_BACK   (APPLIED -> ROLLED_BACK too)

Nothing is ever executed from PROPOSED. The agent/LLM can only create proposals; it cannot approve them.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from cyberthunder.audit.chain import AuditLog
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings.schema import utcnow


class ProposalState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    APPLYING = "applying"
    APPLIED = "applied"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


TRANSITIONS: dict[ProposalState, set[ProposalState]] = {
    ProposalState.PROPOSED: {ProposalState.APPROVED, ProposalState.DENIED, ProposalState.CANCELLED},
    ProposalState.APPROVED: {ProposalState.APPLYING, ProposalState.CANCELLED},
    ProposalState.APPLYING: {ProposalState.APPLIED, ProposalState.FAILED},
    ProposalState.APPLIED: {ProposalState.VERIFIED, ProposalState.FAILED, ProposalState.ROLLED_BACK},
    ProposalState.FAILED: {ProposalState.ROLLED_BACK},
    ProposalState.VERIFIED: {ProposalState.ROLLED_BACK},     # operator may undo a verified change later
    ProposalState.DENIED: set(),
    ProposalState.CANCELLED: set(),
    ProposalState.ROLLED_BACK: set(),
}
GUARDED = {ProposalState.APPLYING, ProposalState.ROLLED_BACK}      # edges that touch host state
HUMAN_ONLY = {ProposalState.APPROVED, ProposalState.DENIED}         # edges only a human may take
AGENT_ACTORS = {"agent", "llm", "system"}


class IllegalTransition(RuntimeError):
    pass


@dataclass
class Proposal:
    finding_id: str
    host: str
    title: str
    fix_ref: str                    # id in the vetted remediation library (never free-form shell)
    fix_preview: str                # exactly what will run / change, shown to the approver
    rollback_plan: str
    risk: str                       # plain-English, cited; produced by the explain layer
    citations: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: ProposalState = ProposalState.PROPOSED
    created_at: str = field(default_factory=utcnow)
    decided_by: str | None = None
    decided_at: str | None = None
    decision_note: str | None = None
    before_state_ref: str | None = None   # snapshot/backup handle captured before apply
    history: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Proposal":
        d = dict(d)
        d["state"] = ProposalState(d["state"])
        return cls(**d)


class ApprovalGate:
    def __init__(self, store: str | Path, audit: AuditLog, killswitch: KillSwitch):
        self.store = Path(store)
        self.audit = audit
        self.ks = killswitch
        self._items: dict[str, Proposal] = {}
        if self.store.exists():
            for d in json.loads(self.store.read_text(encoding="utf-8")):
                p = Proposal.from_dict(d)
                self._items[p.id] = p

    # -- persistence ---------------------------------------------------------
    def _save(self) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_suffix(".tmp")
        tmp.write_text(json.dumps([p.to_dict() for p in self._items.values()], indent=2), encoding="utf-8")
        tmp.replace(self.store)

    def get(self, pid: str) -> Proposal:
        return self._items[pid]

    def list(self, state: ProposalState | None = None) -> list[Proposal]:
        return [p for p in self._items.values() if state is None or p.state == state]

    # -- lifecycle -----------------------------------------------------------
    def propose(self, *, actor: str = "agent", meta: dict | None = None, **kwargs) -> Proposal:
        """Create a proposal. `meta` (risk tags, severity, asset type) rides in the first history entry and
        in the audit record so the approver's view and the log carry the same facts."""
        p = Proposal(**kwargs)
        self._items[p.id] = p
        entry = {"ts": p.created_at, "state": p.state.value, "actor": actor, "note": None}
        if meta:
            entry["meta"] = dict(meta)
        p.history.append(entry)
        self.audit.append("proposal.create", actor, {"proposal": p.to_dict(), "meta": dict(meta or {})}, subject=p.id)
        self._save()
        return p

    def _move(self, pid: str, new: ProposalState, actor: str, note: str | None = None, **details) -> Proposal:
        p = self.get(pid)
        if new not in TRANSITIONS[p.state]:
            self.audit.append(f"proposal.{new.value}", actor, {"from": p.state.value, "note": note},
                              subject=pid, outcome="rejected")
            raise IllegalTransition(f"{p.state.value} -> {new.value} not allowed for {pid}")
        if new in HUMAN_ONLY and actor.lower() in AGENT_ACTORS:
            self.audit.append(f"proposal.{new.value}", actor, {"from": p.state.value},
                              subject=pid, outcome="rejected")
            raise PermissionError("agent may not approve or deny proposals")
        if new in GUARDED:
            self.ks.guard(f"proposal.{new.value}:{pid}", actor)
        old = p.state
        p.state = new
        if new in HUMAN_ONLY:
            p.decided_by, p.decided_at, p.decision_note = actor, utcnow(), note
        for k, v in details.items():
            setattr(p, k, v)
        p.history.append({"ts": utcnow(), "state": new.value, "actor": actor, "note": note})
        self.audit.append(f"proposal.{new.value}", actor, {"from": old.value, "note": note, **details}, subject=pid)
        self._save()
        return p

    def approve(self, pid: str, actor: str, note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.APPROVED, actor, note)

    def deny(self, pid: str, actor: str, note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.DENIED, actor, note)

    def cancel(self, pid: str, actor: str, note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.CANCELLED, actor, note)

    def start_apply(self, pid: str, actor: str = "agent", before_state_ref: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.APPLYING, actor, before_state_ref=before_state_ref)

    def applied(self, pid: str, actor: str = "agent", note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.APPLIED, actor, note)

    def verified(self, pid: str, actor: str = "agent", note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.VERIFIED, actor, note)

    def failed(self, pid: str, actor: str = "agent", note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.FAILED, actor, note)

    def rolled_back(self, pid: str, actor: str = "agent", note: str | None = None) -> Proposal:
        return self._move(pid, ProposalState.ROLLED_BACK, actor, note)
