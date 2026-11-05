"""Cooperative target serialization and bounded manual-restore preconditions.

No StateStore transaction is held across target I/O. These locks coordinate this node's
workers, not other administrators, agents on other nodes, or aliases for the same host.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import stat

from cyberthunder.findings.lifecycle import ReviewConflict, _lock_path
from cyberthunder.inventory.targets import ScopeViolation, Target
from cyberthunder.remediation import snapshot
from cyberthunder.remediation.rollback_scope import inventory_document, inventory_text


class RollbackBlocked(PermissionError):
    """No restore was attempted; inspect the recorded preflight before retrying."""


def _inventory_text(path):
    return inventory_text(path)


def inventory_target(ctx, target_id):
    """Require fresh persisted scope, except for an explicitly path=None memory inventory.

    This guard does not change Inventory's caching semantics or hash inventory/credential data. Parser
    diagnostics are deliberately not exposed: malformed documents can contain credentials.
    """
    inventory = ctx.inventory
    if inventory.path is None:
        return inventory.assert_in_scope(target_id)
    try:
        path = Path(inventory.path)
        text = _inventory_text(path)
        document = inventory_document(text, path)
        rows = {}
        for row in document["targets"]:
            if not isinstance(row, dict):
                raise ValueError("target shape")
            for key in ("id", "name", "asset_type"):
                if not isinstance(row.get(key), str) or not row[key].strip():
                    raise ValueError("target identity")
            for key in ("in_scope", "sudo", "simulated"):
                if key in row and type(row[key]) is not bool:
                    raise ValueError("target flag")
            if type(row.get("in_scope")) is not bool:
                raise ValueError("missing explicit persisted scope")
            for key in ("address", "username", "credential_ref", "last_scan"):
                if row.get(key) is not None and not isinstance(row[key], str):
                    raise ValueError("target field")
            if "options" in row and not isinstance(row["options"], dict):
                raise ValueError("target options")
            if "tags" in row and (not isinstance(row["tags"], list) or any(not isinstance(tag, str) for tag in row["tags"])):
                raise ValueError("target tags")
            for key in ("notes", "added_at"):
                if key in row and not isinstance(row[key], str):
                    raise ValueError("target metadata")
            if row.get("port") is not None and (type(row["port"]) is not int or not 1 <= row["port"] <= 65535):
                raise ValueError("target port")
            target = Target.from_dict(row)  # validates required fields and supported types/transports
            if target.id in rows:
                raise ValueError("duplicate target")
            rows[target.id] = target
    except Exception:  # malformed YAML/JSON, unreadable, missing or non-file inventory all fail closed
        raise ScopeViolation("persisted inventory is missing, unreadable or invalid; no target action is authorized") from None
    persisted = rows.get(target_id)
    if persisted is None or persisted.in_scope is not True:
        raise ScopeViolation(f"target {target_id!r} is not in scope in the persisted inventory")
    try:
        # Do not invoke the cache's implicit file reader: a replacement FIFO could block it.
        # This read-only cache check preserves unsaved revocations without treating cache as scope proof.
        current = inventory._targets.get(target_id)
        if current is None or current.in_scope is not True:
            raise ScopeViolation(f"target {target_id!r} is absent or out of scope in the current inventory")
        if _inventory_text(path) != text:
            raise ScopeViolation("persisted inventory changed during the action boundary; retry with current scope")
    except ScopeViolation:
        raise
    except Exception:
        raise ScopeViolation("persisted inventory is missing, unreadable or invalid; no target action is authorized") from None
    # Compare private values directly; do not publish a password/options digest or resolve environment secrets.
    fields = ("id", "asset_type", "transport", "address", "port", "username", "credential_ref",
              "sudo", "simulated", "options", "added_at")
    if any(getattr(current, key) != getattr(persisted, key) for key in fields):
        raise ScopeViolation("target connection identity changed without matching persisted inventory")
    return current


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _connection_file(path, label):
    """Metadata/readability only: never read or hash credential/configuration file contents."""
    try:
        source = Path(path).expanduser()
        info = source.stat()
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        with source.open("rb") as stream:
            info = os.fstat(stream.fileno())
        return {"path": str(source.resolve()), "size": info.st_size, "mtime_ns": info.st_mtime_ns,
                "mode": stat.S_IMODE(info.st_mode), "device": info.st_dev, "file_id": info.st_ino}
    except (OSError, ValueError, TypeError):
        raise RollbackBlocked(f"required connection file {label} is missing, unreadable or invalid") from None


def identity(target) -> dict:
    """Nonsecret endpoint declarations; no credential-rotation or privilege attestation.

    Unknown option values are excluded even from hashes. Allowed paths/context are declarations,
    not file contents; environment values and agent/keyring credentials are never resolved here.
    """
    options = {}
    for key in ("fixture_dir", "config_path", "key_file", "kubeconfig", "context", "kubectl", "ca_trust_path"):
        value = target.options.get(key)
        if value is not None:
            if not isinstance(value, str):
                raise RollbackBlocked(f"connection declaration {key} must be a string")
            options[key] = value
    for key, allowed in (("transport", {"ntlm", "kerberos", "basic", "credssp"}),
                         ("cert_validation", {"validate", "ignore"})):
        value = target.options.get(key)
        if value is not None:
            if not isinstance(value, str) or value.lower() not in allowed:
                raise RollbackBlocked(f"connection declaration {key} is invalid")
            options[key] = value.lower()
    if target.options.get("ssl") is not None:
        if type(target.options["ssl"]) is not bool:
            raise RollbackBlocked("connection declaration ssl must be a boolean")
        options["ssl"] = target.options["ssl"]
    files = {}
    if target.transport == "ssh":
        if options.get("key_file"):
            files["key_file"] = _connection_file(options["key_file"], "key_file")
        elif target.credential_ref and Path(target.credential_ref).expanduser().exists():
            files["credential_ref"] = _connection_file(target.credential_ref, "credential_ref")
    if target.transport == "kubeconfig":
        files["kubeconfig"] = _connection_file(options.get("kubeconfig"), "kubeconfig")
    if target.transport == "winrm" and options.get("ca_trust_path"):
        files["ca_trust_path"] = _connection_file(options["ca_trust_path"], "ca_trust_path")
    return {"binding_version": 2, **{key: getattr(target, key) for key in
               ("id", "asset_type", "transport", "address", "port", "username", "simulated", "added_at",
                "credential_ref", "sudo")}, "connection_options": options, "connection_files": files}


@contextmanager
def target_operation(root, target_id):
    """Nonblocking OS file lock. Contention is retryable and same-thread nesting is refused."""
    path = root / "target_operations" / (hashlib.sha256(target_id.encode()).hexdigest() + ".lock")
    with _lock_path(path):
        yield


def serialized(method):
    @wraps(method)
    def call(engine, proposal_id, *, actor, **kwargs):
        p = engine.ctx.gate.get(proposal_id)
        entered = False
        try:
            with target_operation(engine.ctx.store.root, p.host):
                entered = True
                engine._target(p, method.__name__, actor)
                return method(engine, proposal_id, actor=actor, **kwargs)
        except ReviewConflict:
            if entered:
                raise
            engine.ctx.audit.append("remediation.target_busy", actor, {"target_id": p.host, "operation": method.__name__},
                                    subject=p.id, outcome="blocked")
            raise ReviewConflict(f"target {p.host} has an active remediation operation; retry when it finishes") from None
    return call


def _save_bound(ctx, p, name, data):
    ctx.audit.append(f"remediation.{name}", "agent", {"sha256": digest(data), "target_id": p.host}, subject=p.id)
    snapshot.save_once(ctx.store.snapshot_dir(p.id), name, data)


def bind_execution(ctx, p, target, fix):
    _save_bound(ctx, p, "execution", {"version": 1, "target": identity(target), "fix_sha256": digest(fix.to_dict())})


def capture_post_apply(ctx, p, target, adapter, transport, fix, before):
    hook = getattr(adapter, "rollback_file_state", None)
    state = {"coverage": "unsupported", "resources": {}, "reasons": ["adapter has no live drift comparison"]}
    if hook and fix.rollback_kind == "restore_files":
        try:
            state = hook(target, transport, fix, before)
        except Exception as exc:  # missing post-state must not fabricate a baseline
            state = {"coverage": "unavailable", "resources": {}, "reasons": [str(exc)]}
    data = {"version": 1, "target": identity(target), "before_sha256": digest(before.to_dict()),
            "fix_sha256": digest(fix.to_dict()), "captured_at": datetime.now(timezone.utc).isoformat(), **state}
    _save_bound(ctx, p, "post_apply", data)


def _evidence(ctx, p, name, records):
    data = snapshot.load_result(ctx.store.snapshots_dir / p.id, name)
    if data is None:
        return None
    hashes = [r["details"].get("sha256") for r in records
              if r["action"] == f"remediation.{name}" and r.get("subject") == p.id]
    if not isinstance(data, dict) or not hashes or digest(data) != hashes[-1]:
        raise ValueError(f"{name} evidence does not match its audit binding")
    return data


def check_execution_target(ctx, p, target):
    """Final endpoint check shared with immediate recovery, without imposing manual drift policy."""
    try:
        binding = _evidence(ctx, p, "execution", list(ctx.audit.records()))
    except (OSError, ValueError) as exc:
        raise RollbackBlocked(str(exc)) from None
    if binding and binding.get("target") != identity(target):
        raise RollbackBlocked("target connection identity changed before restore")


def inspect(ctx, p, target, fix, before, *, adapter=None, transport=None, live=False, require_baseline=True):
    """Static checks plus optional file comparison; never return an unqualified 'safe'."""
    result = {"status": "not_checked", "coverage": "unsupported", "live_checked": False,
              "identity_bound": False, "conflicting_proposals": [], "reasons": [],
              "transition_allowed": p.state.value in {"applied", "verified", "failed"},
              "limitations": ["Cooperating operations on this node only; external writers and target aliases are not locked.",
                              "Endpoint declarations and connection-file metadata only; no credential-rotation, privilege or remote-host attestation.",
                              "Unknown option contents and credential/configuration file contents are excluded from the identity binding."]}
    reasons = result["reasons"]
    try:
        current_target = inventory_target(ctx, p.host)
        current_identity = identity(current_target)
    except (ScopeViolation, RollbackBlocked) as exc:
        result.update(status="blocked", reasons=[str(exc)])
        return result
    records = list(ctx.audit.records())
    try:
        binding = _evidence(ctx, p, "execution", records)
        post = _evidence(ctx, p, "post_apply", records)
    except (OSError, ValueError) as exc:
        result.update(status="blocked", reasons=[str(exc)])
        return result
    if binding:
        result["identity_bound"] = True
        if binding.get("target") != current_identity:
            reasons.append("target connection identity changed since execution")
        if binding.get("fix_sha256") != digest(fix.to_dict()):
            reasons.append("saved fix differs from the executed fix")
    else:
        result["limitations"].append("Legacy execution: no recorded endpoint identity binding.")
    if before and (before.target_id != p.host or before.fix_ref != p.fix_ref):
        reasons.append("before-state target or fix does not match this proposal")
    # Audit order distinguishes same-second attempts; failed/applying attempts are conservative blockers.
    props = {q.id: q for q in ctx.gate.list()}
    recorded_targets = {r.get("subject"): r.get("details", {}).get("proposal", {}).get("host")
                        for r in records if r["action"] == "proposal.create"}
    starts = [r["seq"] for r in records if r["action"] == "proposal.applying"
              and r.get("subject") == p.id and r.get("outcome") == "ok"]
    if not starts:
        reasons.append("no ordered apply event is available for this proposal")
    else:
        anchor = starts[-1]
        conflicts = set()
        for event in records:
            other = props.get(event.get("subject"))
            host = (event.get("details", {}).get("target_id") or recorded_targets.get(event.get("subject"))
                    or (other.host if other else None))
            if (event["seq"] > anchor and host == p.host and event.get("subject") != p.id
                    and event["action"] in {"proposal.applying", "remediation.rollback_started", "remediation.rollback"}
                    and event.get("outcome") not in {"blocked", "rejected"}):
                conflicts.add(event["subject"])
        # An applying/failed proposal without ordered evidence is unsafe to assume older.
        ordered = {r.get("subject") for r in records if r["action"] == "proposal.applying" and r.get("outcome") == "ok"}
        conflicts.update(q.id for q in props.values() if q.id != p.id and q.host == p.host
                         and q.state.value in {"applying", "applied", "verified", "failed", "rolled_back"} and q.id not in ordered)
        result["conflicting_proposals"] = sorted(conflicts)
        if conflicts:
            reasons.append("later or unordered same-target change attempts: " + ", ".join(sorted(conflicts)))
    hook = getattr(adapter, "rollback_file_state", None)
    requires_files = target.asset_type == "linux" and fix.rollback_kind == "restore_files" and hook is not None
    if post:
        result["coverage"] = post.get("coverage", "unsupported")
        result["limitations"].extend(post.get("limitations", []))
        if post.get("target") != current_identity:
            reasons.append("post-apply target connection identity changed")
        if post.get("before_sha256") != digest(before.to_dict() if before else None):
            reasons.append("before-state differs from the immutable post-apply binding")
    if requires_files and require_baseline:
        if not binding:
            reasons.append("Linux file rollback requires a recorded execution identity")
        if not post or post.get("coverage") not in {"files", "partial"} or not post.get("resources"):
            reasons.append("Linux file rollback requires a complete readable post-apply file baseline")
        elif live and not reasons:
            try:
                current = hook(target, transport, fix, before)
                result["live_checked"] = True
                if current.get("coverage") not in {"files", "partial"}:
                    reasons.extend(current.get("reasons") or ["live file state unavailable"])
                if current.get("resources") != post["resources"]:
                    reasons.append("live restoration files differ from their post-apply hashes, type, mode or ownership")
            except Exception as exc:
                reasons.append(f"cannot read live restoration files: {exc}")
    elif not requires_files:
        result["limitations"].append("Live platform drift detection is unsupported; older restores can overwrite newer external changes.")
    if live and not ctx.audit.verify().ok:
        reasons.append("audit chain verification failed")
    result["status"] = "blocked" if reasons else ("checked_files" if result["live_checked"] else "limited" if live else "not_checked")
    return result


def preflight(ctx, p, target, fix, before, *, actor, adapter, transport=None, live=False,
              require_baseline=True, record=True):
    result = inspect(ctx, p, target, fix, before, adapter=adapter, transport=transport, live=live,
                     require_baseline=require_baseline)
    result["checked_at"] = datetime.now(timezone.utc).isoformat()
    if record or result["status"] == "blocked":
        snapshot.save_result(ctx.store.snapshot_dir(p.id), "rollback_preflight", result)
        ctx.audit.append("remediation.rollback_preflight", actor, result, subject=p.id,
                         outcome="blocked" if result["status"] == "blocked" else "ok")
    if result["status"] == "blocked":
        raise RollbackBlocked("rollback blocked: " + "; ".join(result["reasons"]))
    return result
