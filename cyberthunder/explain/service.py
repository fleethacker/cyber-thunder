"""Explain layer: turns one Finding into commander-level language with citations.

The model never sees a shell and never chooses an action. It receives the finding and returns JSON
{risk, impact, plan, citations}. The validator normalises citations with the schema regexes, drops any
identifier not present in Finding.citations (plus the fix_ref), and retries once if nothing survives.
If no local model is reachable, a deterministic template produces the same shape (fallback=True) so the
pipeline never blocks on inference. Explanations are cached per finding id under store.explanations/, with a
fingerprint of the finding; a changed severity, status, evidence, rule or fix makes the cached text stale.

Backends (settings.llm_backend): "ollama" (POST {llm_url}/api/generate, format=json),
"openai" (POST {llm_url}/v1/chat/completions, any OpenAI-compatible local server), "template".
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Iterable

from cyberthunder.findings.schema import Finding, Severity, utcnow
from cyberthunder.remediation.library import FixEntry

from .backends import Backend, TemplateBackend, make_backend
from .prompts import build_prompt, build_strict_prompt
from .validator import clamp, validate

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

log = logging.getLogger(__name__)

AUDIT_ACTOR = "agent"
_SENTENCE = re.compile(r"(?<=[.!?])\s+")

ASSET_WORDS = {
    "linux": "Linux server",
    "windows": "Windows host",
    "cisco_ios": "network device",
    "kubernetes": "Kubernetes cluster",
    "containers": "container host",
}


@dataclass
class Explanation:
    finding_id: str
    risk: str                      # two sentences a commanding officer can act on
    impact: str                    # one sentence on mission impact
    plan: str                      # one sentence: the proposed fix and that it needs approval
    citations: list[str] = field(default_factory=list)   # validated identifiers only
    backend: str = "template"
    model: str | None = None
    generated_at: str = field(default_factory=utcnow)
    validated: bool = True
    dropped_citations: list[str] = field(default_factory=list)
    fallback: bool = False         # True when the template produced it (no model)
    latency_s: float | None = None
    attempts: int = 1
    fingerprint: str | None = None  # finding_fingerprint() of the finding this text was written for

    def to_dict(self) -> dict: return asdict(self)
    @classmethod
    def from_dict(cls, d: dict) -> "Explanation":
        d = {k: v for k, v in d.items() if k != "saved_at"}
        return cls(**d)


def finding_fingerprint(finding: Finding) -> str:
    """Hash of the finding fields an explanation depends on. Finding ids are stable per (host, source, rule),
    so a cached explanation is only reused while severity, status, evidence, rule and fix are unchanged."""
    parts = [finding.severity.value, finding.status.value, finding.evidence, finding.rule_version,
             finding.benchmark_release, finding.fix_ref]
    return hashlib.sha256(json.dumps(parts).encode("utf-8")).hexdigest()


def _first_sentence(text: str | None) -> str:
    t = " ".join((text or "").split())
    if not t:
        return ""
    return _SENTENCE.split(t, 1)[0].rstrip(".!?") + "."


def template_explanation(finding: Finding, fix: FixEntry | None) -> dict:
    """Deterministic explanation built only from fields of the finding and the fix."""
    sev = finding.severity
    cat = sev.cat if sev.cat != "-" else f"{sev.value} severity"
    asset = ASSET_WORDS.get(finding.asset_type or "", "system")
    title = " ".join(finding.title.split()).rstrip(".")
    first = _first_sentence(finding.description)
    risk = f"{cat} finding on {finding.host}: {title}."
    risk += f" {first}" if first else " Left open, it weakens the security baseline this system is accredited against."
    if sev == Severity.HIGH:
        impact = (f"A {cat} weakness on a {asset} can give an adversary direct access or control, putting the "
                  f"mission systems that depend on {finding.host} at immediate risk.")
    elif sev == Severity.MEDIUM:
        impact = (f"A {cat} weakness on a {asset} lowers the effort an adversary needs to gain a foothold "
                  f"or move further into the shipboard network.")
    else:
        impact = (f"A {cat} weakness on a {asset} adds to overall exposure and should be closed during normal "
                  f"maintenance.")
    fix_name = f"the vetted fix \"{fix.title}\"" if fix else "a vetted fix"
    plan = f"Apply {fix_name} to {finding.host} once an authorised operator approves it; it is verified and can be rolled back."
    return {"risk": clamp(risk, 600), "impact": clamp(impact, 300), "plan": clamp(plan, 300),
            "citations": list(finding.citations[:3])}


class ExplainService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx
        self._backend: Backend | None = None
        self._lock = threading.Lock()
        self._worker = None

    # -- backend -----------------------------------------------------------------------
    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = make_backend(self.ctx.settings)
        return self._backend

    @backend.setter
    def backend(self, value: Backend) -> None:
        self._backend = value

    def _fix_for(self, finding: Finding) -> FixEntry | None:
        lib = getattr(self.ctx, "library", None)
        if lib is None:
            return None
        try:
            if finding.fix_ref:
                fix = lib.get(finding.fix_ref)
                if fix:
                    return fix
            return lib.resolve(finding)
        except Exception as e:  # noqa: BLE001  a library problem must not stop an explanation
            log.warning("fix lookup failed for %s: %s", finding.id, e)
            return None

    # -- public API --------------------------------------------------------------------
    def get(self, finding_id: str) -> Explanation | None:
        d = self.ctx.store.load_explanation(finding_id)
        return Explanation.from_dict(d) if d else None

    def explain(self, finding: Finding, *, force: bool = False) -> Explanation:
        """Return cached explanation unless force; otherwise call the backend, validate, cache, audit 'explain.generate'."""
        fp = finding_fingerprint(finding)
        if not force:
            cached = self.get(finding.id)
            if cached is not None and cached.fingerprint == fp:
                return cached
        fix = self._fix_for(finding)
        backend = self.backend
        t0 = time.monotonic()
        result: dict | None = None
        dropped: list[str] = []
        attempts = 0
        detail = ""
        is_template = isinstance(backend, TemplateBackend)
        ok, detail = (True, "template") if is_template else self._available(backend)

        if ok and not is_template:
            timeout = int(getattr(self.ctx.settings, "llm_timeout_s", 180) or 180)
            for prompt in (build_prompt(finding, fix), build_strict_prompt(finding, fix)):
                attempts += 1
                try:
                    text = backend.generate(prompt, json_mode=True, timeout=timeout)
                except Exception as e:  # noqa: BLE001  a backend must never take the pipeline down
                    log.warning("backend %s raised: %s", getattr(backend, "name", "?"), e)
                    text = None
                result, d = validate(text, finding, fix)
                for x in d:
                    if x not in dropped:
                        dropped.append(x)
                if result is not None:
                    break

        latency = round(time.monotonic() - t0, 3)
        model = getattr(backend, "model", None)
        if result is not None:
            exp = Explanation(finding_id=finding.id, risk=result["risk"], impact=result["impact"], plan=result["plan"],
                              citations=result["citations"], backend=backend.name, model=model, validated=True,
                              dropped_citations=dropped, fallback=False, latency_s=latency, attempts=attempts)
        else:
            t = template_explanation(finding, fix)
            # the template is trusted text; it is "validated" unless a model was tried and failed
            exp = Explanation(finding_id=finding.id, risk=t["risk"], impact=t["impact"], plan=t["plan"],
                              citations=t["citations"], backend="template", model=None,
                              validated=attempts == 0, dropped_citations=dropped, fallback=True,
                              latency_s=latency, attempts=max(attempts, 1))
        exp.fingerprint = fp
        self.ctx.store.save_explanation(finding.id, exp.to_dict())
        details = {"finding_id": finding.id, "backend": exp.backend, "requested_backend": backend.name,
                   "model": model, "latency_s": latency, "validated": exp.validated, "fallback": exp.fallback,
                   "dropped": len(dropped), "attempts": exp.attempts, "citations": exp.citations}
        if getattr(backend, "using_fallback", False):
            details["fallback_model"] = model
        if exp.fallback and not is_template:
            details["reason"] = detail if not ok else "model output failed validation"
        self.ctx.audit.append("explain.generate", AUDIT_ACTOR, details, subject=finding.id,
                              outcome="ok" if exp.validated else "fallback")
        return exp

    def _available(self, backend: Backend) -> tuple[bool, str]:
        try:
            return backend.available()
        except Exception as e:  # noqa: BLE001
            return False, f"availability check failed: {e}"

    # -- precompute --------------------------------------------------------------------
    def plan_precompute(self, findings: Iterable[Finding]) -> list[Finding]:
        """Findings that still need an explanation: deduped, open first, then by severity."""
        seen: set[str] = set()
        todo: list[Finding] = []
        for f in findings:
            if f.id in seen:
                continue
            seen.add(f.id)
            cached = self.ctx.store.load_explanation(f.id)
            if cached is not None and cached.get("fingerprint") == finding_fingerprint(f):
                continue
            todo.append(f)
        todo.sort(key=lambda f: (0 if f.is_open else 1, -f.severity.rank))
        return todo

    @property
    def worker(self):
        with self._lock:
            if self._worker is None:
                from .worker import ExplainWorker
                self._worker = ExplainWorker(self.explain)
            return self._worker

    def precompute(self, findings: Iterable[Finding], *, background: bool = True) -> int:
        """Queue explanations for findings without one (open findings first, by severity). Returns count queued."""
        todo = self.plan_precompute(findings)
        if not background:
            for f in todo:
                try:
                    self.explain(f)
                except Exception as e:  # noqa: BLE001
                    log.warning("precompute failed for %s: %s", f.id, e)
            return len(todo)
        w = self.worker
        return sum(1 for f in todo if w.submit(f))

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the background queue to drain. True when idle."""
        return self._worker.wait_idle(timeout) if self._worker is not None else True

    def shutdown(self, timeout: float = 5.0) -> None:
        if self._worker is not None:
            self._worker.stop(timeout)

    def status(self) -> dict:
        """{'backend': str, 'model': str, 'available': bool, 'detail': str, 'queue': int, 'fallback_model': str|None}"""
        backend = self.backend
        ok, detail = self._available(backend)
        return {
            "backend": backend.name,
            "model": getattr(backend, "model", None),
            "available": ok,
            "detail": detail,
            "queue": self._worker.pending() if self._worker is not None else 0,
            "fallback_model": getattr(self.ctx.settings, "llm_fallback_model", None) or None,
            "using_fallback": bool(getattr(backend, "using_fallback", False)),
        }
