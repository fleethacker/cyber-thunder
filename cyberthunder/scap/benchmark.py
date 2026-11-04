"""Evaluate a benchmark's rules from collected data and turn the results into findings.

Per selected rule:
  1. platform applicability: each '#platform' the rule names is a CPE logical test over OVAL definitions; a
     platform that evaluates false makes the rule notapplicable (for example a domain-member-only rule on a
     standalone workstation)
  2. a rule whose definition needs a test type we do not implement is notchecked, and the evidence names the
     test types; it is never passed silently
  3. otherwise the OVAL definition is evaluated: true -> pass, false -> fail (inverted for vulnerability and
     patch definitions), unknown / error / not evaluated -> notchecked, not applicable -> notapplicable

Finding status: pass -> not_a_finding, fail -> open, notapplicable -> not_applicable, anything else ->
not_reviewed. Evidence lists the item values that decided each test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from cyberthunder.findings.schema import Finding

from .datastream import Benchmark, Datastream, Rule
from .oval.evaluator import (ERROR, FALSE, NOT_APPLICABLE, NOT_EVALUATED, TRUE, UNKNOWN, Evaluator, combine,
                             negate)
from .oval.model import OvalDocument
from .oval.windows_probes import SUPPORTED, make_collector, summarize_item

SOURCE = "windows-scap"
MAX_EVIDENCE = 1800
STATUS = {"pass": "not_a_finding", "fail": "open", "notapplicable": "not_applicable"}


@dataclass
class RuleResult:
    rule: Rule
    result: str                          # pass | fail | notchecked | notapplicable | error | unknown
    oval: str | None = None              # OVAL definition result
    evidence: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return STATUS.get(self.result, "not_reviewed")

    def to_dict(self) -> dict:
        return {"rule_id": self.rule.id, "stig_id": self.rule.version, "title": self.rule.title,
                "severity": self.rule.severity.value, "result": self.result, "oval": self.oval,
                "status": self.status, "unsupported": self.unsupported, "evidence": self.evidence}


class BenchmarkEvaluator:
    def __init__(self, ds: Datastream, data: dict, *, supported=SUPPORTED,
                 collector_factory: Callable[[dict], Callable] = make_collector):
        self.ds = ds
        self.data = data
        self.supported = supported
        self._collector = collector_factory(data)
        self._evaluators: dict[str, Evaluator] = {}

    def evaluator(self, component: str) -> Evaluator | None:
        if component not in self._evaluators:
            doc = self.ds.oval.get(component)
            if doc is None:
                return None
            self._evaluators[component] = Evaluator(doc, self._collector)
        return self._evaluators[component]

    def platform(self, b: Benchmark, rule: Rule) -> tuple[bool, list[str]]:
        """(applicable, notes)."""
        notes = []
        for pid in rule.platforms:
            if not pid.startswith("#"):
                continue
            pl = b.platforms.get(pid[1:])
            if pl is None or not pl.facts:
                continue
            results = []
            for f in pl.facts:
                ev = self.evaluator(f.component) if f.component else None
                if ev is None or not f.name:
                    results.append(UNKNOWN)
                    continue
                doc: OvalDocument = ev.doc
                if doc.probes([f.name]) - set(self.supported):
                    results.append(NOT_EVALUATED)
                    continue
                results.append(ev.definition(f.name))
            r = combine(pl.operator, results)
            if pl.negate:
                r = negate(r)
            if r == FALSE:
                return False, [f"platform '{pl.title}' does not apply to this host"]
            if r != TRUE:
                notes.append(f"platform '{pl.title}' could not be determined ({r}); the rule was evaluated")
        return True, notes

    def rule(self, rule: Rule) -> RuleResult:
        b = self.ds.benchmark
        sup = self.ds.support(rule, self.supported)
        if not sup.supported:
            return RuleResult(rule, "notchecked", evidence=[f"not checked: {sup.reason}"],
                              unsupported=sorted(p + "_test" for p in sup.unsupported))
        applicable, notes = self.platform(b, rule)
        if not applicable:
            return RuleResult(rule, "notapplicable", NOT_APPLICABLE, evidence=notes)
        chk = rule.oval_check
        ev = self.evaluator(chk.component)
        res = ev.definition(chk.name)
        d = ev.doc.definitions.get(chk.name)
        vuln = d is not None and d.cls in ("vulnerability", "patch")
        if res == TRUE:
            result = "fail" if vuln else "pass"
        elif res == FALSE:
            result = "pass" if vuln else "fail"
        elif res == NOT_APPLICABLE:
            result = "notapplicable"
        elif res == ERROR:
            result = "error"
        else:
            result = "notchecked" if res == NOT_EVALUATED else "unknown"
        evidence = list(notes) + self._evidence(ev, chk.name)
        evidence.append(f"OVAL definition {chk.name} evaluated {res}")
        return RuleResult(rule, result, res, evidence)

    @staticmethod
    def _evidence(ev: Evaluator, def_id: str) -> list[str]:
        lines = []
        for t in ev.traces_for(def_id):
            probe = t.type[:-5] if t.type.endswith("_test") else t.type
            label = t.comment or t.test_id
            test = ev.doc.tests.get(t.test_id)
            fields = []
            for sid in (test.state_refs if test else []):
                st = ev.doc.states.get(sid)
                fields += [e.name for e in (st.entities if st else []) if e.name not in fields]
            if t.items:
                shown = []
                for it in t.items[:3]:
                    if probe in ("registry", "wmi57", "wmi", "userright", "sid_sid", "user_sid55") or not fields:
                        shown.append(summarize_item(probe, it))
                    else:
                        # policy items carry many fields; show the ones this test's states compare
                        shown.append(", ".join(f"{k}={it[k]}" for k in fields if k in it)
                                     or f"{', '.join(fields)} not set")
                more = f" (+{len(t.items) - 3} more)" if len(t.items) > 3 else ""
                lines.append(f"{t.type} ({label}): {t.result}; " + "; ".join(shown) + more)
            else:
                why = t.note if t.note and t.note != "planned" else (t.flag or "no items")
                lines.append(f"{t.type} ({label}): {t.result}; no matching item ({why})")
        return lines

    def evaluate(self, rules: list[Rule]) -> list[RuleResult]:
        return [self.rule(r) for r in rules]


def evaluate(ds: Datastream, rules: list[Rule], data: dict) -> list[RuleResult]:
    return BenchmarkEvaluator(ds, data).evaluate(rules)


def evidence_text(lines: list[str]) -> str:
    text = " | ".join(lines)
    return text if len(text) <= MAX_EVIDENCE else text[:MAX_EVIDENCE - 3] + "..."


def to_findings(target, ds: Datastream, results: list[RuleResult], *, source: str = SOURCE,
                collected_at: str | None = None, raw_ref: str | None = None) -> list[Finding]:
    from cyberthunder.adapters.base import make_finding

    b = ds.benchmark
    out = []
    for rr in results:
        r = rr.rule
        chk = r.oval_check
        check_text = r.check_text or (f"Automated: OVAL definition {chk.name} in {chk.href}" if chk else None)
        out.append(make_finding(
            target=target, source=source, rule_id=r.short_id, title=r.title, severity=r.severity,
            status=rr.status, description=r.description, evidence=evidence_text(rr.evidence),
            references=[ref.id for ref in r.references], check_text=check_text, fix_text=r.fix_text,
            rule_version=r.version, group_id=r.group_id, benchmark=b.title, benchmark_release=b.release,
            tags=["stig", "scap", f"scap:{rr.result}", *(["scap:unsupported"] if rr.unsupported else [])],
            raw_ref=raw_ref, collected_at=collected_at))
    return out
