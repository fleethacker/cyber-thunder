"""Explain layer: turns one Finding into commander-level language with citations.

The model never sees a shell and never chooses an action. It receives the finding and returns JSON
{risk, impact, plan, citations}. The validator normalises citations with the schema regexes, drops any
identifier not present in Finding.citations (plus the fix_ref), and retries once if nothing survives.
If no local model is reachable, a deterministic template produces the same shape (fallback=True) so the
pipeline never blocks on inference. Explanations are cached per finding id under store.explanations/.

Backends (settings.llm_backend): "ollama" (POST {llm_url}/api/generate, format=json),
"openai" (POST {llm_url}/v1/chat/completions, any OpenAI-compatible local server), "template".
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Iterable

from cyberthunder.findings.schema import Finding, utcnow

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext


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

    def to_dict(self) -> dict: return asdict(self)
    @classmethod
    def from_dict(cls, d: dict) -> "Explanation":
        d = {k: v for k, v in d.items() if k != "saved_at"}
        return cls(**d)


class ExplainService:
    def __init__(self, ctx: "AppContext"):
        self.ctx = ctx

    def get(self, finding_id: str) -> Explanation | None:
        d = self.ctx.store.load_explanation(finding_id)
        return Explanation.from_dict(d) if d else None

    def explain(self, finding: Finding, *, force: bool = False) -> Explanation:
        """Return cached explanation unless force; otherwise call the backend, validate, cache, audit 'explain.generate'."""
        raise NotImplementedError("explain layer not built yet")

    def precompute(self, findings: Iterable[Finding], *, background: bool = True) -> int:
        """Queue explanations for findings without one (open findings first, by severity). Returns count queued."""
        raise NotImplementedError

    def status(self) -> dict:
        """{'backend': str, 'model': str, 'available': bool, 'detail': str, 'queue': int}"""
        raise NotImplementedError
