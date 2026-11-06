"""Synchronous assessment sidecar with immutable receipts and read-only freshness.

Public API: assess(proposal_id, *, actor, live=True), latest(proposal_id), get(id),
freshness(receipt), readiness(proposal_id, assessment_id=None). Reads never collect,
call a model, write state or append audit records. A fresh receipt is advisory only.
"""
from __future__ import annotations
from cyberthunder.control.principal import authorize, operation

from copy import deepcopy
from contextvars import copy_context
from datetime import datetime, timedelta, timezone
import math
import threading
import time
from uuid import UUID, uuid4

from cyberthunder.control.identity import require_human
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.explain.backends import make_backend
from cyberthunder.explain.service import finding_fingerprint
from cyberthunder.remediation.dependencies import collect_dependencies, current_target, target_binding_sha256
from cyberthunder.remediation.engine import EngineError
from cyberthunder.remediation.plan import _bound_fix
from cyberthunder.security.resources import check_record

from .packet import (LEVELS, TTL_SECONDS, PacketError, digest, evidence_digest, fix_allowlist,
                     identifier, sanitize_packet, timestamp)
from .validator import build_prompt, validate_response
from .bindings import evidence_times as _time_state, finish_readiness, validate_receipt_binding
from .input import COVERAGE_UNKNOWN, prepare_model_input
from .selection import generate_selected, isolated_backend, selected_identity

MODEL_TIMEOUT_S = 300.0
PROBE_TIMEOUT_S = 3.0
MAX_GENERATE_ATTEMPTS = 2
# Bound outstanding calls. Caller timeouts discard late results, but guards can
# still access state; the owning service retains each thread until it has exited.
_MODEL_SLOTS = threading.BoundedSemaphore(4)
_PUBLICATION_LOCK = threading.Lock()


class ImpactError(EngineError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _bounded_call(call, timeout, *, owner):
    if timeout <= 0 or not _MODEL_SLOTS.acquire(blocking=False):
        return None, "model_busy"
    done, result = threading.Event(), []
    deadline = time.monotonic() + timeout

    def work():
        try:
            result.append((None, "model_timeout") if time.monotonic() >= deadline else (call(), None))
        except PermissionError as exc:
            # A rejected identity is not a model failure eligible for fallback.
            result.append((None, exc))
        except Exception:
            result.append((None, "model_error"))
        finally:
            _MODEL_SLOTS.release()
            done.set()

    try:
        owner._start_worker(work)
    except BaseException:
        _MODEL_SLOTS.release()
        raise
    if not done.wait(timeout):
        return None, "model_timeout"
    if isinstance(result[0][1], PermissionError):
        raise result[0][1]
    return result[0]


def _model_label(value):
    try:
        return identifier(value) if value is not None else None
    except PacketError:
        return "unspecified"


def _assessment(packet, model):
    risks = deepcopy(packet["risks"])
    if model:
        for i, risk in enumerate(model["risks"]):
            risks.append({"id": f"model-{i + 1}", "deterministic": False, **deepcopy(risk)})
    floor = max((LEVELS[r["severity"]] for r in risks), default=0)
    level = max(floor, LEVELS[model["risk_level"]] if model else 0)
    out = {"advisory_only": True, "approval_authority": False,
           "source": "model_advisory" if model else "deterministic_fallback",
           "risk_level": next(k for k, v in LEVELS.items() if v == level),
           "summary": model["summary"] if model else
           "Deterministic assessment only; review the recorded risks and unresolved dependencies before a human decision.",
           "evidence_ids": model["evidence_ids"] if model else [e["id"] for e in packet["evidence"]],
           "risks": risks, "dependencies": deepcopy(packet["dependencies"]), "complete": packet["complete"]}
    for key in ("unknowns", "required_checks", "rollback_limits"):
        out[key] = list(dict.fromkeys([*packet[key], *(model[key] if model else [])]))
    return out


class ImpactService:
    def __init__(self, ctx):
        self.ctx = ctx
        self.directory = ctx.store.root / "change_assessments"
        self._workers_lock = threading.Lock()
        self._workers: list[threading.Thread] = []

    def _start_worker(self, work):
        # Start and register under the snapshot lock, so cleanup never observes an
        # unstarted thread as completed. The caller remains an owned producer.
        with self._workers_lock:
            self._workers = [t for t in self._workers if t.is_alive()]
            thread = threading.Thread(target=copy_context().run, args=(work,),
                                      daemon=True, name="impact-model")
            thread.start()
            self._workers.append(thread)

    def worker_threads(self):
        """Snapshot actual workers, including calls whose caller already timed out."""
        with self._workers_lock:
            self._workers = [t for t in self._workers if t.is_alive()]
            return tuple(self._workers)

    def _snapshot(self, proposal_id, *, action="read"):
        """Local bindings only; avoids static_plan's audit and historical finding fallback."""
        proposal = deepcopy(self.ctx.gate.get(proposal_id))
        check_record(self.ctx, proposal, action)
        target = current_target(self.ctx, proposal.host)
        current = next((f for f in self.ctx.store.current_findings() if f.id == proposal.finding_id), None)
        if current is not None:
            check_record(self.ctx, current, action)
        if current is not None and current.host != proposal.host:
            raise ImpactError("current finding target differs from proposal")
        fix, fix_hash, recorded_hash = _bound_fix(self.ctx.engine, proposal, current, target)
        if recorded_hash is None:
            raise ImpactError("proposal lacks a full fix binding; create a new proposal")
        if fix.asset_type != target.asset_type:
            raise ImpactError("fix asset type differs from target")
        bindings = {"proposal_id": proposal.id, "target_id": target.id, "fix_sha256": fix_hash,
                    "target_binding_sha256": target_binding_sha256(target), "finding_id": proposal.finding_id,
                    "finding_fingerprint": finding_fingerprint(current) if current else None,
                    "finding_binding_sha256": digest(current.to_dict()) if current else None,
                    "proposal_binding_sha256": digest([proposal.id, proposal.host, proposal.finding_id,
                                                       proposal.fix_ref, proposal.fix_preview, recorded_hash])}
        return bindings, fix, target, current

    def _guard(self, proposal_id, actor, expected=None):
        require_human(actor)
        check_record(self.ctx, self.ctx.gate.get(proposal_id), "plan")
        authorize(self.ctx, "plan", actor=actor, target=self.ctx.gate.get(proposal_id).host)
        # guard() includes the entire operator-provided kill reason in its audit. Use
        # the same status check here and emit only our fixed error code in assess().
        if self.ctx.killswitch.is_engaged():
            raise KillSwitchEngaged("kill switch engaged; assessment stopped")
        snapshot = self._snapshot(proposal_id, action="plan")
        if expected is not None and snapshot[0] != expected:
            raise ImpactError("assessment bindings changed; collect a new assessment")
        return snapshot

    def _backend(self):
        explain = getattr(self.ctx, "explain", None)
        return explain.backend if explain is not None else make_backend(self.ctx.settings)

    def _config(self, backend):
        settings = self.ctx.settings
        return digest({"settings": [getattr(settings, key, None) for key in
                       ("llm_backend", "llm_url", "llm_model", "llm_fallback_model", "llm_timeout_s")],
                       "backend": [getattr(backend, key, None) for key in
                                   ("name", "url", "configured_model", "fallback_model", "probe_timeout")],
                       "configured_name": getattr(backend, "configured_model", getattr(backend, "model", None))})

    def _check_config(self, source, config):
        explain = getattr(self.ctx, "explain", None)
        if ((explain is not None and explain.backend is not source) or self._config(source) != config):
            raise ImpactError("model configuration changed; collect a new assessment")

    def _model(self, packet, fix, backend, guard, model_packet):
        status = {"backend": _model_label(getattr(backend, "name", None)),
                  "name": None,
                  "used": False, "validated": False, "fallback_reason": None, "attempts": 0}
        _, reason = _time_state(packet, _now())
        if not packet["evidence"]:
            reason = "evidence_missing"
        if model_packet is None:
            reason = reason or "model_input_unavailable"
        if backend is None:
            reason = reason or "backend_not_isolatable"
        if getattr(backend, "name", None) == "template":
            reason = reason or "model_not_configured"
        if reason:
            status["fallback_reason"] = reason
            return None, status
        configured = float(getattr(self.ctx.settings, "llm_timeout_s", 180))
        budget = min(MODEL_TIMEOUT_S, max(0, configured)) if math.isfinite(configured) else MODEL_TIMEOUT_S
        if budget <= 0:
            status["fallback_reason"] = "model_timeout"
            return None, status
        deadline = time.monotonic() + budget

        def checked_call(call):
            # Recheck in the worker immediately before its bounded backend IO.
            guard()
            return call()

        guard()
        available, error = _bounded_call(lambda: checked_call(backend.available),
                                        min(PROBE_TIMEOUT_S, max(0, deadline - time.monotonic())), owner=self)
        guard()
        if error or not isinstance(available, tuple) or not available or available[0] is not True:
            status["fallback_reason"] = error or "probe_unavailable"
            return None, status
        identity = selected_identity(backend)
        status["name"] = _model_label(identity[1])
        prompt = build_prompt(model_packet, fix)
        # A backend which negotiates JSON mode already spends the single retry
        # internally. Do not add a service retry on top of that negotiation.
        attempts = min(MAX_GENERATE_ATTEMPTS, 1 if getattr(backend, "json_mode_supported", False) else 2)
        for attempt in range(attempts):
            guard()
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                status["fallback_reason"] = "model_timeout"
                break
            status["attempts"] = attempt + 1
            response, error = _bounded_call(
                lambda: checked_call(lambda: generate_selected(backend, identity, prompt, timeout)), timeout,
                owner=self)
            guard()
            if selected_identity(backend) != identity or (response is not None and not response[1]):
                status.update(name=None, fallback_reason="model_selection_changed")
                break
            raw = response[0] if response is not None else None
            if error or raw is None:
                status["fallback_reason"] = error or ("model_timeout" if time.monotonic() >= deadline else "model_unavailable")
                break
            validated = validate_response(raw, model_packet)
            if validated is not None:
                status.update(used=True, validated=True, fallback_reason=None)
                return validated, status
            status["fallback_reason"] = "invalid_response"
            # Do not feed untrusted rejected output back into the retry prompt.
            # Reuse the bounded prompt; rejected output never enters a retry.
        return None, status

    @operation("plan")
    def assess(self, proposal_id, *, actor, live=True):
        """Collect, assess and publish one immutable UUID receipt; never change a proposal."""
        actor = require_human(actor)
        identifier(proposal_id)
        if type(live) is not bool:
            raise ValueError("live must be a boolean")
        audit = {"proposal_id": proposal_id}
        self.ctx.audit.append("impact.start", actor, audit, subject=proposal_id)
        try:
            bindings, fix, target, finding = self._guard(proposal_id, actor)
            audit.update({k: bindings[k] for k in ("target_id", "fix_sha256", "target_binding_sha256")})
            source = self._backend()
            config = self._config(source)
            backend = isolated_backend(source)

            def guard():
                self._guard(proposal_id, actor, bindings)
                self._check_config(source, config)

            allowed_fix = fix_allowlist(fix, bindings["fix_sha256"])
            guard()
            raw = collect_dependencies(self.ctx.engine, proposal_id, actor=actor, live=live)
            guard()
            packet = sanitize_packet(raw)
            for key in ("proposal_id", "target_id", "fix_sha256", "target_binding_sha256"):
                if packet[key] != bindings[key]:
                    raise ImpactError("collector binding differs from assessment")
            if packet["mode"] != ("live" if live else "stored"):
                raise ImpactError("collector mode differs from requested mode")
            unknowns = []
            if not packet["complete"]:
                unknowns.append("Dependency evidence is incomplete; unobserved dependencies remain unknown.")
            if not packet["evidence"]:
                unknowns.append("Dependency evidence is missing; no operational safety can be inferred.")
            if not live:
                unknowns.append("Stored metadata does not establish current dependency state.")
            if target.simulated or target.transport in {"simulated", "fixture"}:
                unknowns.append("Simulated or fixture evidence does not establish live operational readiness.")
            if finding is None or not finding.is_open:
                unknowns.append("A matching open current finding is unavailable.")
            unknowns.append("Only declared fix metadata is assessed; payload-specific effects beyond collected facts remain unknown.")
            packet["unknowns"] = list(dict.fromkeys([*packet["unknowns"], *unknowns]))
            model_packet, coverage = prepare_model_input(packet, allowed_fix)
            if coverage["limited"]:
                packet["unknowns"].append(COVERAGE_UNKNOWN)
            packet["evidence_sha256"] = evidence_digest(packet)
            model, status = self._model(packet, allowed_fix, backend, guard, model_packet)
            if backend is None:
                status["backend"] = _model_label(getattr(source, "name", None))
            status["input_coverage"] = coverage
            # Approval validators read StateStore while holding the reentrant gate.
            # Match that gate -> store order; no collection/model work occurs here.
            with self.ctx.gate._locked(), _PUBLICATION_LOCK, self.ctx.store.lock("change-assessments"):
                guard()
                now = _now()
                valid_until, reason = _time_state(packet, now)
                if reason and model is not None:
                    model = None
                    status.update(used=False, validated=False, fallback_reason=reason)
                receipt = {"version": 1, "id": str(uuid4()), "generated_at": now.isoformat(),
                           "valid_until": min(valid_until, now + timedelta(seconds=TTL_SECONDS)).isoformat(),
                           **bindings, "evidence_sha256": packet["evidence_sha256"],
                           "collector_evidence_sha256": raw["evidence_sha256"], "config_sha256": config,
                           "evidence_packet": packet, "fix": allowed_fix,
                           "assessment": _assessment(packet, model), "model": status}
                path = self._path(receipt["id"])
                if self.ctx.store.read_json(path) is not None:
                    raise ImpactError("assessment ID collision; retry")
                guard()
                self.ctx.store.write_json(path, receipt)
            audit.update({"assessment_id": receipt["id"], "evidence_sha256": packet["evidence_sha256"],
                          "model_used": status["used"], "model_validated": status["validated"],
                          "fallback_reason": status["fallback_reason"]})
            self.ctx.audit.append("impact.finish", actor, audit, subject=proposal_id)
            return self._view(receipt)
        except Exception as exc:
            # Fixed classifications only: backend exceptions may contain credentials.
            code = "kill_engaged" if isinstance(exc, KillSwitchEngaged) else (
                "scope_or_actor" if isinstance(exc, PermissionError) else (
                    "invalid_evidence" if isinstance(exc, PacketError) else "assessment_failed"))
            self.ctx.audit.append("impact.error", actor, {**audit, "error": code}, subject=proposal_id, outcome="failed")
            raise

    def _path(self, assessment_id):
        try:
            if str(UUID(assessment_id)) != assessment_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError("invalid assessment ID") from None
        return self.directory / f"{assessment_id}.json"

    def get(self, assessment_id):
        receipt = self.ctx.store.read_json(self._path(assessment_id))
        return self._view(receipt) if receipt is not None else None

    def latest(self, proposal_id):
        identifier(proposal_id)
        receipts = [self.ctx.store.read_json(path) for path in self.ctx.store.list_json(self.directory)]
        receipts = [r for r in receipts if isinstance(r, dict) and r.get("proposal_id") == proposal_id]
        # No mutable latest pointer: a slow older collection cannot clobber a newer
        # evidence collection. Publication time and UUID break ties deterministically.
        earliest = datetime.min.replace(tzinfo=timezone.utc)
        receipt = max(receipts, key=lambda r: (timestamp(r["evidence_packet"]["generated_at"]) or earliest,
                                              timestamp(r["generated_at"]) or earliest, r["id"]), default=None)
        return self._view(receipt) if receipt is not None else None

    def _view(self, receipt):
        result = deepcopy(receipt)
        result["freshness"] = self.freshness(receipt)
        return result

    def freshness(self, receipt):
        """Local reads only; ready describes receipt binding, never approval authority."""
        bindings, target, finding = None, None, None
        control_reasons = []
        try:
            if self.ctx.killswitch.is_engaged():
                control_reasons.append("kill_engaged")
            bindings, _, target, finding = self._snapshot(receipt["proposal_id"])
            bindings["config_sha256"] = self._config(self._backend())
        except (KeyError, ValueError, TypeError, OSError, PermissionError, EngineError):
            control_reasons.append("binding_unavailable")
        result = validate_receipt_binding(receipt, bindings, now=_now())
        result["reasons"].extend(control_reasons)
        if finding is None or not finding.is_open:
            result["unknowns"].append("current_finding_unavailable")
            result["reasons"].append("current_finding_unavailable")
        if target is not None and (target.simulated or target.transport in {"simulated", "fixture"}):
            result["unknowns"].append("simulated_evidence")
        return finish_readiness(result)

    def readiness(self, proposal_id, assessment_id=None):
        """Return {ready, reasons, ...} for an explicit receipt (or latest for display).

        Approval callers must pass assessment_id. ready permits human review of
        a bound receipt; unknowns, stored/simulated data and fallback need separate
        acknowledgment. Only local state is read. No audit, collection or model call.
        """
        receipt = self.get(assessment_id) if assessment_id else self.latest(proposal_id)
        if receipt is None or receipt["proposal_id"] != proposal_id:
            result = validate_receipt_binding(None, None, now=_now())
            result.update(proposal_id=proposal_id, assessment_id=assessment_id)
            if receipt is not None:
                result["reasons"] = ["proposal_mismatch"]
            return result
        return receipt["freshness"]
