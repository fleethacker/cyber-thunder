"""Finite protected maintenance windows and explicit, request-bound human exceptions.

An exception is an expectation of current facts, never a bearer credential or approval.
All decisions are reloaded; no policy failure falls back to an unrestricted schedule.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re

from cyberthunder.control.access import (
    AccessDenied, _constant, _depth, _fields, _identifier, _object, _strings, read_protected_policy,
)
from cyberthunder.control.principal import authorize, require_current
from cyberthunder.inventory.host import persisted_target
from cyberthunder.security.resources import target_scope
from cyberthunder.security.step_up import StepUpPolicy, freshness_clock

OVERRIDE_SECONDS = 120
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z")


class MaintenanceBlocked(PermissionError):
    """Apply was refused before any payload execution."""


def timestamp(value):
    if (not isinstance(value, str) or not _TIMESTAMP.fullmatch(value) or value.endswith('-00:00')):
        raise ValueError("maintenance timestamps require an explicit known timezone")
    # datetime accepts oversized offset minutes by normalization; reject them explicitly.
    if not value.endswith('Z') and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise ValueError("invalid maintenance timezone")
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def iso(value):
    return value.isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def parse(raw):
    _depth(raw)
    doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)
    _fields(doc, {'version', 'rules'})
    if type(doc['version']) is not int or doc['version'] != 1:
        raise ValueError("unsupported maintenance policy version")
    if not isinstance(doc['rules'], list) or not 1 <= len(doc['rules']) <= 256:
        raise ValueError("maintenance policy requires bounded explicit rules")
    rules, ids, selectors, total = [], set(), set(), 0
    for rule in doc['rules']:
        _fields(rule, {'id', 'windows'}, {'target_ids', 'environments'})
        rid = _identifier(rule['id'])
        targets = _strings(rule['target_ids']) if 'target_ids' in rule else None
        environments = _strings(rule['environments']) if 'environments' in rule else None
        if (targets is None and environments is None) or rid in ids or (targets, environments) in selectors:
            raise ValueError("maintenance applicability must be explicit and unique")
        ids.add(rid)
        selectors.add((targets, environments))
        if not isinstance(rule['windows'], list):
            raise ValueError("invalid maintenance windows")
        total += len(rule['windows'])
        if total > 2048:
            raise ValueError("maintenance window limit")
        windows = []
        for window in rule['windows']:
            _fields(window, {'start', 'end'})
            start, end = timestamp(window['start']), timestamp(window['end'])
            if start >= end:
                raise ValueError("maintenance window must have a finite positive duration")
            windows.append((start, end))
        windows.sort()
        if any(a[1] > b[0] for a, b in zip(windows, windows[1:])):
            raise ValueError("overlapping or duplicate maintenance windows")
        rules.append((rid, targets, environments, windows))
    return rules


class MaintenanceService:
    def __init__(self, ctx):
        self.ctx = ctx

    def _now(self):
        now = freshness_clock(self.ctx).now()
        if not math.isfinite(now):
            raise MaintenanceBlocked("Maintenance time is unavailable; apply is held.")
        try:
            return datetime.fromtimestamp(now, timezone.utc)
        except (ValueError, OverflowError, OSError):
            raise MaintenanceBlocked("Maintenance time is unavailable; apply is held.") from None

    def _decision(self, proposal):
        configured = getattr(self.ctx.settings, 'maintenance_policy', None)
        result = dict(status='unconfigured', allowed=True, checked_at=None, current_window=None,
                      next_eligible_at=None, policy_sha256=None, applicable_rules=[],
                      reason='No maintenance policy is configured; no time restriction is imposed.')
        if configured is None:
            result['checked_at'] = iso(datetime.now(timezone.utc))
            return result
        try:
            if not isinstance(configured, str) or not configured or configured != configured.strip():
                raise ValueError()
            rules, sha = read_protected_policy(Path(configured), parse)
        except (AccessDenied, ValueError, TypeError, OverflowError):
            raise MaintenanceBlocked("Maintenance policy is unavailable or invalid; apply is held.") from None
        try:
            target = persisted_target(self.ctx.inventory, proposal.host)
        except (KeyError, ValueError, TypeError, OSError):
            raise MaintenanceBlocked("Maintenance target ownership is unavailable; apply is held.") from None
        scope = target_scope(target)
        if proposal.authorization_scope != scope:
            raise MaintenanceBlocked("Original target ownership is unavailable or changed; request a new proposal before applying.")
        # Protected filesystem and ownership reads can take time. Observe time after them.
        now = self._now()
        result['checked_at'] = iso(now)
        applicable = [(rid, windows) for rid, tids, envs, windows in rules
                      if (tids is None or target.id in tids) and (envs is None or target.environment in envs)]
        result.update(policy_sha256=sha, applicable_rules=[rid for rid, _ in applicable])
        if not applicable:
            result.update(status='not_applicable', reason='No maintenance rule applies to this target and environment.')
            return result
        # Intersect applicable rules. A target-specific rule cannot widen an enclave restriction.
        eligible = applicable[0][1]
        for _, windows in applicable[1:]:
            eligible = [(max(a, c), min(b, d)) for a, b in eligible for c, d in windows if max(a, c) < min(b, d)]
        current = next(((a, b) for a, b in eligible if a <= now < b), None)
        future = [a for a, _ in eligible if a > now]
        result.update(status='open' if current else 'held', allowed=bool(current),
                      current_window=dict(start=iso(current[0]), end=iso(current[1])) if current else None,
                      next_eligible_at=iso(min(future)) if future else None,
                      reason='Maintenance window is open; all other apply checks remain required.' if current else
                      'Outside maintenance window; apply is held.')
        return result

    def _binding(self, proposal, decision, expires_at):
        from cyberthunder.remediation.plan import _bound_fix
        from cyberthunder.remediation.rollback_guard import identity
        if getattr(self.ctx.settings, 'auth_mode', 'dev') == 'dev':
            raise MaintenanceBlocked("Maintenance override requires a verified human account.")
        principal = require_current('maintenance.override')
        target = persisted_target(self.ctx.inventory, proposal.host, require_scope=True)
        self.ctx.access.require(principal, 'maintenance.override', target)
        if proposal.authorization_scope != target_scope(target):
            raise MaintenanceBlocked("Original target ownership is required for a maintenance override.")
        _, fix_sha, approved_sha = _bound_fix(self.ctx.engine, proposal, None, target)
        if approved_sha is None:
            raise MaintenanceBlocked("A bound proposal payload is required for a maintenance override.")
        source = self.ctx.access.approval_identity_source()
        association = source.association(principal.issuer, principal.subject) if source.policy_version == 2 else None
        stable = proposal.to_dict()
        for key in ('state', 'before_state_ref', 'history'):
            stable.pop(key)
        return digest(dict(proposal=stable, fix_sha256=fix_sha, approved_sha256=approved_sha,
                           ownership=target_scope(target), target_identity=identity(target),
                           policy_sha256=decision['policy_sha256'],
                           access_sha256=source.policy_sha256, association=association,
                           account=[principal.issuer, principal.subject],
                           assurance=vars(StepUpPolicy.from_settings(self.ctx.settings)),
                           expires_at=expires_at))

    def summary(self, proposal):
        try:
            result = self._decision(proposal)
        except MaintenanceBlocked as exc:
            result = dict(status='invalid', allowed=False, reason=str(exc), checked_at=None,
                          current_window=None, next_eligible_at=None, policy_sha256=None, applicable_rules=[])
        result['override'] = None
        if result['status'] == 'held' and proposal.state.value == 'approved':
            try:
                expires = iso(timestamp(result['checked_at']) + timedelta(seconds=OVERRIDE_SECONDS))
                result['override'] = dict(binding=self._binding(proposal, result, expires), expires_at=expires)
            except (PermissionError, ValueError, KeyError, RuntimeError, OverflowError):
                pass  # Visibility is not authority; an incomplete binding never offers an override.
        return result

    def _check(self, proposal, actor, override, expected):
        result = self._decision(proposal)
        if expected is not None and result['policy_sha256'] != expected['policy_sha256']:
            raise MaintenanceBlocked("Maintenance policy changed during apply; review it and submit again.")
        if override is not None:
            try:
                _fields(override, {'binding', 'expires_at', 'reason'})
                reason = override['reason']
                if (not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000
                        or any(ord(c) < 32 or ord(c) == 127 for c in reason)):
                    raise ValueError()
                expires = timestamp(override['expires_at'])
                now = self._now()
                if not now < expires <= now + timedelta(seconds=OVERRIDE_SECONDS):
                    raise ValueError()
            except (ValueError, TypeError, OverflowError):
                raise MaintenanceBlocked("Maintenance override needs a reason and an unexpired review of at most two minutes.") from None
            if result['status'] not in {'held', 'open'}:
                raise MaintenanceBlocked("Maintenance applicability changed; review the proposal and submit again.")
            authorize(self.ctx, 'maintenance.override', actor=actor, target=proposal.host)
            try:
                binding = self._binding(proposal, result, override['expires_at'])
            except (ValueError, KeyError, RuntimeError, OSError):
                raise MaintenanceBlocked("Maintenance override binding is unavailable; review the current change.") from None
            if override['binding'] != binding:
                raise MaintenanceBlocked("Maintenance override review is stale; review the current change and submit again.")
            fresh = self._decision(proposal)
            if fresh['policy_sha256'] != result['policy_sha256']:
                raise MaintenanceBlocked("Maintenance policy changed during apply; review it and submit again.")
            principal = require_current('maintenance.override', actor)
            StepUpPolicy.from_settings(self.ctx.settings).require(principal, now=freshness_clock(self.ctx).now())
            if self._now() >= expires:
                raise MaintenanceBlocked("Maintenance override expired during validation; review and submit again.")
            result = fresh
        elif not result['allowed']:
            raise MaintenanceBlocked(result['reason'])
        return result

    def guard(self, proposal, *, actor, override=None, expected=None, boundary='admission', record=True):
        try:
            result = self._check(proposal, actor, override, expected)
        except MaintenanceBlocked as exc:
            try:
                self.ctx.audit.append('maintenance.blocked', actor, {'reason': str(exc), 'boundary': boundary},
                                      subject=proposal.id, outcome='blocked')
            except Exception:
                raise MaintenanceBlocked('Maintenance refusal could not be audited; apply is held.') from None
            raise
        if record and (result['status'] != 'unconfigured' or override is not None):
            try:
                self.ctx.audit.append('maintenance.override' if override is not None else 'maintenance.checked', actor,
                                      {'boundary': boundary, 'decision': result, 'override': override},
                                      subject=proposal.id, outcome='pending')
            except Exception:
                raise MaintenanceBlocked("Maintenance decision could not be audited; apply is held.") from None
            # Audit IO cannot make an expired window, revoked grant or stale binding valid.
            result = self._check(proposal, actor, override, result)
        return result
