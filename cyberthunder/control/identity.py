"""Who may take a human-only decision.

One check shared by the approval gate, the kill switch, the policy signer and the CLI. Actor names are
compared after stripping and casefolding, so ' agent', 'AGENT\t', 'agent:planner', 'agent-svc' and
'llm-1' are all machine identities. 'policy:<name>' is reserved for approvals made under a signed
standing policy; only the gate writes it, and only after checking the policy (ApprovalGate.approve_by_policy).
"""
from __future__ import annotations

import re

MACHINE_ACTORS = frozenset({"agent", "llm", "system"})
POLICY_PREFIX = "policy:"
# a machine name, optionally followed by a separator or digit: agent, agent:planner, agent-svc, llm-1, system2
_MACHINE_RE = re.compile(r"^(?:agent|llm|system)(?:[^a-z]|$)")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_ACTOR_LEN = 128


def normalize_actor(actor: str | None) -> str:
    return (actor or "").strip()


def is_machine(actor: str | None) -> bool:
    """True for empty actors and for agent/llm/system identities in any spelling."""
    a = normalize_actor(actor).casefold()
    return not a or a in MACHINE_ACTORS or bool(_MACHINE_RE.match(a))


def is_policy_actor(actor: str | None) -> bool:
    return normalize_actor(actor).casefold().startswith(POLICY_PREFIX)


def require_human(actor: str | None) -> str:
    """Return the stripped actor name, or raise PermissionError if it is empty, a machine identity,
    the reserved 'policy:' form, or carries control characters."""
    a = normalize_actor(actor)
    if not a:
        raise PermissionError("an operator identity is required")
    if _CONTROL_RE.search(a):
        raise PermissionError("actor name contains control characters")
    if len(a) > MAX_ACTOR_LEN:
        raise PermissionError("actor name too long")
    if is_machine(a):
        raise PermissionError(f"actor {a!r} is reserved for the machine; a named operator must decide this")
    if is_policy_actor(a):
        raise PermissionError(f"actor {a!r} is reserved for standing-policy approvals made by the engine")
    return a
