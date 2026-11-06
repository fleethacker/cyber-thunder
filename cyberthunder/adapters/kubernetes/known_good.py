"""Persistent known-good exceptions for Kubernetes scan findings.

The scanner still records the finding, but a matching exception turns it into
not_applicable before summaries and auto-proposals are computed.
"""
from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from cyberthunder.findings.schema import Finding, Status, utcnow

from .kubectl import OBJ_TAG

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.store import StateStore

SCHEMA_VERSION = "1.0"


@dataclass
class KnownGoodException:
    id: str
    target_id: str | None = None
    rule_id: str | None = None
    rule_version: str | None = None
    group_id: str | None = None
    object: str | None = None
    object_prefix: str | None = None
    reason: str = ""
    created_by: str = "operator"
    created_at: str = field(default_factory=utcnow)
    enabled: bool = True
    expires_at: str | None = None
    finding_id: str | None = None
    title: str | None = None
    last_matched_at: str | None = None
    match_count: int = 0
    target_scope: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KnownGoodException":
        allowed = set(cls.__dataclass_fields__)  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in dict(data).items() if k in allowed})


def finding_object(finding: Finding) -> str | None:
    for tag in finding.tags:
        if tag.startswith(OBJ_TAG):
            return tag[len(OBJ_TAG):]
    return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _expired(value: str | None) -> bool:
    ts = _parse_time(value)
    return bool(ts and ts <= datetime.now(timezone.utc))


def _default_object_prefix(obj: str | None) -> str | None:
    """Stable-ish pod prefix for generated names, used only when an operator asks for prefix scope."""
    if not obj:
        return None
    parts = obj.split("/")
    if len(parts) < 3 or parts[1] != "pod":
        return obj
    name = parts[2]
    if "-" not in name:
        return obj
    parts[2] = name.rsplit("-", 1)[0] + "-"
    return "/".join(parts)


class KubernetesKnownGoodState:
    def __init__(self, store: "StateStore", path: str | Path = "cluster/known_good.json", *, ctx=None):
        self.store = store
        self.path = store.root / path
        self.ctx = ctx

    def _verified(self) -> bool:
        mode = getattr(getattr(self.ctx, "settings", None), "auth_mode", "dev")
        try:
            from cyberthunder.control.principal import current_principal
        except ModuleNotFoundError as exc:
            if exc.name != "cyberthunder.control.principal":
                raise
            principal = None  # Standalone development builds have no identity provider.
        else:
            principal = current_principal()
        if getattr(principal, "verified", False) and (self.ctx is None or mode == "dev"):
            raise PermissionError("known-good exceptions require the authenticated application context")
        return mode != "dev"

    @staticmethod
    def _scope(item: KnownGoodException) -> dict | None:
        scope = item.target_scope
        if (not isinstance(scope, dict)
                or set(scope) != {"version", "target_id", "environment", "authorization_id"}
                or type(scope["version"]) is not int or scope["version"] != 1
                or any(not isinstance(scope[k], str) or not scope[k]
                       for k in ("target_id", "environment", "authorization_id"))
                or scope["target_id"] != item.target_id):
            return None
        return scope

    def _authorize_change(self, target_id: str | None, actor: str | None) -> None:
        if self._verified():
            if not isinstance(actor, str) or not actor or not target_id:
                raise PermissionError("known-good changes require an actor and target")
            from cyberthunder.control.principal import authorize
            authorize(self.ctx, "admin", actor=actor, target=target_id)

    def _visible(self, item: KnownGoodException, action: str) -> bool:
        if not self._verified():
            return True
        from cyberthunder.security.resources import visible_artifact
        return visible_artifact(self.ctx, self._scope(item), action)

    def _exceptions(self, *, include_disabled: bool = True) -> list[KnownGoodException]:
        self._verified()  # Missing context must fail before reading any exception records.
        exceptions = [KnownGoodException.from_dict(e) for e in self._read().get("exceptions") or []]
        if not include_disabled:
            exceptions = [e for e in exceptions if e.enabled and not _expired(e.expires_at)]
        return exceptions

    def _read(self) -> dict:
        doc = self.store.read_json(self.path, None)
        if not doc:
            return {"schema_version": SCHEMA_VERSION, "exceptions": []}
        return {"schema_version": doc.get("schema_version") or SCHEMA_VERSION,
                "exceptions": list(doc.get("exceptions") or [])}

    def _write(self, doc: dict) -> None:
        doc = dict(doc)
        doc["schema_version"] = SCHEMA_VERSION
        doc["updated_at"] = utcnow()
        self.store.write_json(self.path, doc)

    def list(self, *, include_disabled: bool = True) -> list[KnownGoodException]:
        return [e for e in self._exceptions(include_disabled=include_disabled) if self._visible(e, "read")]

    def add(self, *, actor: str, reason: str, target_id: str | None = None, rule_id: str | None = None,
            rule_version: str | None = None, group_id: str | None = None, object: str | None = None,
            object_prefix: str | None = None, expires_at: str | None = None, finding_id: str | None = None,
            title: str | None = None) -> KnownGoodException:
        item = KnownGoodException(id=f"kg-{secrets.token_hex(6)}", target_id=target_id, rule_id=rule_id,
                                  rule_version=rule_version, group_id=group_id, object=object,
                                  object_prefix=object_prefix, reason=reason, created_by=actor,
                                  expires_at=expires_at, finding_id=finding_id, title=title)
        return self._save_new(item)

    def _save_new(self, item: KnownGoodException, *, finding: Finding | None = None) -> KnownGoodException:
        verified = self._verified()
        self._authorize_change(item.target_id, item.created_by)
        if not item.reason or not item.reason.strip():
            raise ValueError("known-good exceptions require a reason")
        if item.expires_at and _parse_time(item.expires_at) is None:
            raise ValueError("expires_at is not an ISO timestamp")
        if not any((item.rule_id, item.rule_version, item.group_id)):
            raise ValueError("known-good exceptions require rule_id, rule_version, or group_id")
        if not item.target_id:
            raise ValueError("known-good exceptions require target_id")
        item.reason = item.reason.strip()
        if self.ctx is not None:
            from cyberthunder.inventory.host import persisted_target
            target = persisted_target(self.ctx.inventory, item.target_id)
            if target.asset_type != "kubernetes":
                raise ValueError("known-good exceptions require a Kubernetes target")
            try:
                from cyberthunder.security.resources import target_scope
            except ModuleNotFoundError as exc:
                if verified or exc.name != "cyberthunder.security.resources":
                    raise
            else:
                item.target_scope = target_scope(target)
        if verified and finding is not None:
            from cyberthunder.security.resources import check_record, object_scopes
            check_record(self.ctx, finding, "admin")
            if object_scopes(finding) != item.target_scope:
                raise PermissionError("finding belongs to an unavailable or changed target")
        with self.store.lock("kubernetes_known_good"):
            if verified:
                from cyberthunder.security.resources import authorize_artifact
                self._authorize_change(item.target_id, item.created_by)
                authorize_artifact(self.ctx, self._scope(item), "admin")
            doc = self._read()
            rows = doc.setdefault("exceptions", [])
            rows.append(item.to_dict())
            self._write(doc)
        return item

    def add_from_finding(self, finding: Finding, *, actor: str, reason: str, scope: str = "object",
                         expires_at: str | None = None) -> KnownGoodException:
        self._authorize_change(finding.host, actor)
        if finding.asset_type != "kubernetes":
            raise ValueError(f"finding {finding.id} is not a Kubernetes finding")
        obj = finding_object(finding)
        object_exact = obj if scope == "object" else None
        object_prefix = _default_object_prefix(obj) if scope == "object_prefix" else None
        if scope not in {"object", "object_prefix", "rule"}:
            raise ValueError("scope must be one of: object, object_prefix, rule")
        rule_id = None if (finding.rule_version or finding.group_id) else finding.rule_id
        item = KnownGoodException(id=f"kg-{secrets.token_hex(6)}", created_by=actor, reason=reason,
                                  target_id=finding.host, rule_id=rule_id, rule_version=finding.rule_version,
                                  group_id=finding.group_id, object=object_exact, object_prefix=object_prefix,
                                  expires_at=expires_at, finding_id=finding.id, title=finding.title)
        return self._save_new(item, finding=finding)

    def delete(self, exception_id: str, *, actor: str | None = None) -> bool:
        verified = self._verified()
        with self.store.lock("kubernetes_known_good"):
            doc = self._read()
            rows = list(doc.get("exceptions") or [])
            selected = [e for e in rows if e.get("id") == exception_id]
            if verified and selected:
                if len(selected) != 1:
                    raise PermissionError("ambiguous known-good exception identity")
                from cyberthunder.security.resources import authorize_artifact
                item = KnownGoodException.from_dict(selected[0])
                self._authorize_change(item.target_id, actor)
                authorize_artifact(self.ctx, self._scope(item), "admin")
            keep = [e for e in rows if e.get("id") != exception_id]
            if len(keep) == len(rows):
                return False
            doc["exceptions"] = keep
            self._write(doc)
            return True

    def match(self, finding: Finding) -> KnownGoodException | None:
        if finding.asset_type != "kubernetes":
            return None
        obj = finding_object(finding)
        for item in self._exceptions(include_disabled=False):
            if self._matches(item, finding, obj) and self._visible(item, "scan"):
                return item
        return None

    @staticmethod
    def _matches(item: KnownGoodException, finding: Finding, obj: str | None) -> bool:
        if item.target_id and item.target_id != finding.host:
            return False
        for field in ("rule_id", "rule_version", "group_id"):
            wanted = getattr(item, field)
            if wanted and wanted != getattr(finding, field):
                return False
        if item.object and item.object != obj:
            return False
        if item.object_prefix and not (obj or "").startswith(item.object_prefix):
            return False
        return True

    def apply(self, findings: list[Finding]) -> list[str]:
        self._verified()
        # Serialize suppression with exception edits, including usage counters. Ownership is
        # captured only on creation; legacy or stale rows must never be rebound by a scan.
        with self.store.lock("kubernetes_known_good"):
            return self._apply_locked(findings)

    def _apply_locked(self, findings: list[Finding]) -> list[str]:
        matched: list[str] = []
        changed = False
        now = utcnow()
        doc = self._read()
        rows = doc.get("exceptions") or []
        exceptions = [(row, KnownGoodException.from_dict(row)) for row in rows]
        for finding in findings:
            if not finding.is_open or finding.asset_type != "kubernetes":
                continue
            obj = finding_object(finding)
            match = next(((row, e) for row, e in exceptions if e.enabled and not _expired(e.expires_at)
                          and self._matches(e, finding, obj) and self._visible(e, "scan")), None)
            if match is None:
                continue
            row, item = match
            finding.status = Status.NOT_APPLICABLE
            finding.tags = [*finding.tags, f"known-good:{item.id}"]
            note = f"Known-good exception {item.id}: {item.reason}"
            finding.evidence = f"{finding.evidence}\n{note}" if finding.evidence else note
            matched.append(item.id)
            item.match_count += 1
            item.last_matched_at = now
            row["match_count"] = item.match_count
            row["last_matched_at"] = now
            changed = True
        if changed:
            self._write(doc)
        return matched
