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
import os
import threading
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from enum import Enum
from pathlib import Path
from time import sleep

from cyberthunder.audit.chain import AuditLog, file_lock
from cyberthunder.control.identity import (MACHINE_ACTORS, POLICY_PREFIX, is_machine, is_policy_actor,
                                           normalize_actor, require_human)
from cyberthunder.control.killswitch import KillSwitch
from cyberthunder.findings.schema import utcnow
from cyberthunder.state.json_files import replace_file


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
TERMINAL = {"denied", "cancelled", "verified", "rolled_back"}      # states that end a proposal's life
AGENT_ACTORS = set(MACHINE_ACTORS)       # bare machine names; identity.require_human is the full check
EDGE_OUTCOME = {ProposalState.FAILED: "failed", ProposalState.ROLLED_BACK: "reverted"}


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
    decided_principal: dict | None = None  # verified account evidence; legacy decisions retain None
    decided_at: str | None = None
    decision_note: str | None = None
    before_state_ref: str | None = None   # snapshot/backup handle captured before apply
    history: list[dict] = field(default_factory=list)
    assessment: dict | None = None   # immutable receipt reference reviewed by the approving person
    authorization_scope: dict | None = None

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
    """Proposals live in one JSON file shared by every process (API server, CLI). Each public operation
    re-reads the file, and every change happens under a cross-process lock: the transition is checked
    against the state on disk, the audit record is written first, then the file. A stale in-memory copy
    is never written over a newer file."""

    def __init__(self, store: str | Path, audit: AuditLog, killswitch: KillSwitch,
                 policy_path: str | Path | None = None):
        self.store = Path(store)
        self.audit = audit
        self.ks = killswitch
        self.policy_path = Path(policy_path) if policy_path else None
        self.assessment_validator = None
        self.authorizer = None
        self.resource_scope = None
        self.artifact_authorizer = None
        self._items: dict[str, Proposal] = {}
        self._sig: tuple[int, int] | None = None
        self._tlock = threading.RLock()
        self._depth = 0
        self._reload(force=True)

    # -- persistence ---------------------------------------------------------
    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.store.stat()
        except FileNotFoundError:
            return None
        return st.st_mtime_ns, st.st_size

    def _reload(self, force: bool = False) -> None:
        """Bring the in-memory view in line with the file. Existing Proposal objects are updated in place so
        references held by callers see the new state."""
        # Windows may allow stat but refuse the read while another process replaces the file.
        # Match the bounded write retry; an inaccessible file must never authorize cached state.
        for attempt in range(20):
            try:
                sig = self._file_sig()
                if not force and sig == self._sig:
                    return
                data = json.loads(self.store.read_text(encoding="utf-8")) if sig is not None else []
                break
            except PermissionError:
                if attempt == 19:
                    raise
                sleep(0.05)
        fresh: dict[str, Proposal] = {}
        for d in data:
            p = Proposal.from_dict(d)
            cur = self._items.get(p.id)
            if cur is not None:
                _copy_into(cur, p)
                p = cur
            fresh[p.id] = p
        self._items, self._sig = fresh, sig

    @contextmanager
    def _locked(self):
        with self._tlock:
            if self._depth:
                yield
                return
            with file_lock(self.store.with_name(self.store.name + ".lock")):
                self._depth += 1
                try:
                    self._reload(force=True)
                    yield
                finally:
                    self._depth -= 1

    def _save(self, items: list[Proposal] | None = None) -> None:
        self.store.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.store.with_name(f"{self.store.name}.{os.getpid()}.tmp")   # never shared with another process
        rows = [p.to_dict() for p in (items if items is not None else self._items.values())]
        tmp.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        replace_file(tmp, self.store)      # another process may be reading the file at this moment (Windows)
        self._sig = self._file_sig()

    def get(self, pid: str) -> Proposal:
        with self._tlock:
            self._reload()
            return self._items[pid]

    def list(self, state: ProposalState | None = None) -> list[Proposal]:
        with self._tlock:
            self._reload()
            return [p for p in self._items.values() if state is None or p.state == state]

    # -- lifecycle -----------------------------------------------------------
    def propose(self, *, actor: str = "agent", meta: dict | None = None, one_live_per_finding: bool = False,
                **kwargs) -> Proposal:
        """Create a proposal. `meta` (risk tags, severity, asset type) rides in the first history entry and
        in the audit record so the approver's view and the log carry the same facts. With
        `one_live_per_finding`, a proposal that is still live for the same finding is returned instead of a
        second one being created; the check runs under the cross-process lock, so two workers proposing for
        the same finding at the same moment end up with one proposal between them."""
        if self.authorizer:
            self.authorizer("propose", target=kwargs.get("host"))
        with self._locked():
            if one_live_per_finding and kwargs.get("finding_id"):
                live = [p for p in self._items.values()
                        if p.finding_id == kwargs["finding_id"] and p.state.value not in TERMINAL]
                if live:
                    return live[-1]
            p = Proposal(**kwargs)
            if self.resource_scope is not None:
                p.authorization_scope = self.resource_scope(p.host)
            entry = {"ts": p.created_at, "state": p.state.value, "actor": actor, "note": None}
            _add_principal(entry)
            if meta:
                entry["meta"] = dict(meta)
            p.history.append(entry)
            self.audit.append("proposal.create", actor, {"proposal": p.to_dict(), "meta": dict(meta or {})}, subject=p.id)
            self._save([*self._items.values(), p])
            self._items[p.id] = p
            return p

    def _policy_on_file(self, signer: str) -> str | None:
        """None when the policy on disk is enabled and signed by `signer`, a named person; else why not."""
        if self.policy_path is None or not self.policy_path.exists():
            return "no standing approval policy on file"
        try:
            pol = json.loads(self.policy_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "standing approval policy unreadable"
        return _policy_reason(pol.get("enabled"), pol.get("signed_by"), signer)

    def _check_actor(self, new: ProposalState, actor: str, policy_checked: bool) -> str:
        """The actor to record on this edge; PermissionError when a machine takes a human-only edge."""
        if new not in HUMAN_ONLY:
            return actor
        if is_policy_actor(actor):
            if self.authorizer:
                raise PermissionError("standing approval requires a verifiable policy signature")
            if new is not ProposalState.APPROVED:
                raise PermissionError("a standing policy may approve, never deny")
            if not policy_checked:
                why = self._policy_on_file(actor[len(POLICY_PREFIX):])
                if why:
                    raise PermissionError(f"policy approval refused: {why}")
            return actor
        return require_human(actor)

    def _authorize(self, action: str, actor: str | None, proposal: Proposal) -> None:
        if self.artifact_authorizer:
            self.artifact_authorizer(proposal, action)
        if self.authorizer:
            self.authorizer(action, actor=actor, target=proposal.host)

    def _move(self, pid: str, new: ProposalState, actor: str, note: str | None = None, *,
              _policy_checked: bool = False, **details) -> Proposal:
        actor = normalize_actor(actor) or actor
        with self._locked():
            p = self._items[pid]          # state as it is on disk right now
            if new in HUMAN_ONLY or new == ProposalState.CANCELLED:
                self._authorize({ProposalState.APPROVED: "approve", ProposalState.DENIED: "deny",
                                 ProposalState.CANCELLED: "cancel"}[new], actor, p)
            elif self.authorizer:
                from cyberthunder.control.principal import current_operation
                action = {ProposalState.APPLYING: "apply", ProposalState.APPLIED: "apply",
                          ProposalState.VERIFIED: "verify", ProposalState.ROLLED_BACK: "rollback",
                          ProposalState.FAILED: "apply"}[new]
                # Engine completion records may use its service label. The initiating
                # verified account must still hold the operation's target permission.
                if new != ProposalState.APPLYING and current_operation() in {"apply", "verify", "rollback"}:
                    action = current_operation()
                self._authorize(action, actor if new == ProposalState.APPLYING or not is_machine(actor) else None, p)
            if new not in TRANSITIONS[p.state]:
                self.audit.append(f"proposal.{new.value}", actor, {"from": p.state.value, "note": note},
                                  subject=pid, outcome="rejected")
                raise IllegalTransition(f"{p.state.value} -> {new.value} not allowed for {pid}")
            try:
                actor = self._check_actor(new, actor, _policy_checked)
            except PermissionError as e:
                self.audit.append(f"proposal.{new.value}", actor, {"from": p.state.value, "reason": str(e)},
                                  subject=pid, outcome="rejected")
                raise
            if new in GUARDED:
                self.ks.guard(f"proposal.{new.value}:{pid}", actor)
            old = p.state
            # audit first: if the log cannot be written, the proposal does not change
            self.audit.append(f"proposal.{new.value}", actor, {"from": old.value, "note": note, **details},
                              subject=pid, outcome=EDGE_OUTCOME.get(new, "ok"))
            q = Proposal.from_dict(p.to_dict())
            q.state = new
            if new in HUMAN_ONLY:
                q.decided_by, q.decided_at, q.decision_note = actor, utcnow(), note
                evidence = {}
                _add_principal(evidence)
                q.decided_principal = evidence.get("principal")
            for k, v in details.items():
                setattr(q, k, v)
            entry = {"ts": utcnow(), "state": new.value, "actor": actor, "note": note}
            _add_principal(entry)
            q.history.append(entry)
            self._save([q if x.id == pid else x for x in self._items.values()])
            _copy_into(p, q)
            return p

    def approve(self, pid: str, actor: str, note: str | None = None, *,
                assessment_id: str | None = None, assessment_note: str | None = None) -> Proposal:
        actor = normalize_actor(actor) or actor
        with self._locked():
            p = self._items[pid]
            self._authorize("approve", actor, p)
            try:
                self._check_actor(ProposalState.APPROVED, actor, False)
                if assessment_id and is_policy_actor(actor):
                    raise PermissionError("assessment review requires a named human decision")
            except PermissionError as exc:
                self.audit.append("proposal.approved", actor, {"from": p.state.value, "reason": str(exc)},
                                  subject=pid, outcome="rejected")
                raise
            if assessment_id and self.assessment_validator is None:
                raise IllegalTransition("dependency assessment service unavailable")
            try:
                assessment = (self.assessment_validator(pid, assessment_id, assessment_note)
                              if self.assessment_validator else
                              {"status": "not_assessed", "id": None, "note": assessment_note or
                               "No dependency assessment was attached to this decision."})
            except Exception:
                self.audit.append("proposal.approved", actor,
                                  {"from": p.state.value, "reason": "dependency assessment rejected"},
                                  subject=pid, outcome="rejected")
                raise
            return self._move(pid, ProposalState.APPROVED, actor, note, assessment=assessment)

    def review_assessment(self, pid: str, actor: str, assessment_id: str,
                          note: str | None = None) -> Proposal:
        """Refresh a named human's receipt on an approved, not-yet-started change."""
        actor = require_human(actor)
        if not assessment_id:
            raise ValueError("an assessment receipt is required to review an approved change")
        with self._locked():
            p = self._items[pid]
            self._authorize("review", actor, p)
            if p.state != ProposalState.APPROVED:
                raise IllegalTransition("only an approved, not-yet-started proposal can be re-reviewed")
            if self.assessment_validator is None:
                raise IllegalTransition("dependency assessment service unavailable")
            assessment = self.assessment_validator(pid, assessment_id, note)
            self.audit.append("proposal.assessment_reviewed", actor, {"assessment": assessment}, subject=pid)
            q = Proposal.from_dict(p.to_dict())
            q.assessment = assessment
            entry = {"ts": utcnow(), "state": q.state.value, "actor": actor,
                     "note": "Dependency assessment reviewed", "assessment_id": assessment_id}
            _add_principal(entry)
            q.history.append(entry)
            self._save([q if x.id == pid else x for x in self._items.values()])
            _copy_into(p, q)
            return p

    def approve_by_policy(self, pid: str, policy, note: str | None = None) -> Proposal:
        """Approve under a standing policy. The policy must be enabled and signed by a named person (and match
        the policy on file when the gate knows where that is); the approval is recorded as 'policy:<signer>'."""
        signer = normalize_actor(getattr(policy, "signed_by", None))
        why = _policy_reason(getattr(policy, "enabled", False), signer, signer)
        if why is None and self.policy_path is not None:
            why = self._policy_on_file(signer)
        if why:
            self.audit.append("proposal.approved", f"{POLICY_PREFIX}{signer or '?'}", {"reason": why},
                              subject=pid, outcome="rejected")
            raise PermissionError(f"policy approval refused: {why}")
        return self._move(pid, ProposalState.APPROVED, f"{POLICY_PREFIX}{signer}", note, _policy_checked=True,
                          assessment={"status": "not_assessed", "id": None,
                                      "note": "Standing policy approval; dependency assessment was not reviewed."})

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


def _add_principal(entry: dict) -> None:
    from cyberthunder.control.principal import current_principal
    principal = current_principal()
    if principal is not None and principal.verified:
        entry["principal"] = principal.evidence()


def _copy_into(dst: Proposal, src: Proposal) -> None:
    for f in fields(Proposal):
        setattr(dst, f.name, getattr(src, f.name))


def _policy_reason(enabled, signed_by, expected: str) -> str | None:
    """Why a policy may not approve on behalf of `expected`, or None when it may."""
    signer = normalize_actor(signed_by)
    if not enabled:
        return "standing approval policy is disabled"
    if not signer:
        return "standing approval policy has no signer"
    if is_machine(signer) or is_policy_actor(signer):
        return f"standing approval policy signer {signer!r} is not a named person"
    if signer.casefold() != normalize_actor(expected).casefold():
        return f"standing approval policy is signed by {signer!r}, not {normalize_actor(expected)!r}"
    return None
