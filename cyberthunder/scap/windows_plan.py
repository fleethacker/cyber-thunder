"""Collection plan for Windows benchmarks: from the rules a profile selects to one windows_collect.ps1 run.

The planner walks every definition the selected rules reach (through extend_definition, criteria, tests, sets,
filters and local variables) and asks each object's probe what it needs. Requests are merged into one plan:

  {"schema": 1,
   "registry": [{"hive": "HKLM", "key": "SOFTWARE\\...", "names": ["Name", ...] | ["*"] | [], "depth": 0}],
   "secedit": true, "auditpol": true, "accounts": true,
   "files": [{"path": "C:\\Windows\\...", "pattern": "" | "*"}],
   "services": ["Name", ...] | ["*"],
   "wmi": [{"namespace": "root\\cimv2", "wql": "SELECT ... FROM ..."}]}

names [] reads only whether the key exists, ["*"] reads every value; depth > 0 also enumerates subkeys that
many levels down (for keys given as patterns). Some objects can only be located once other objects are
collected (a registry key built by a local variable from another key's name). collect_benchmark() runs the
script again for those, at most MAX_ROUNDS times; each run is the same script with a smaller plan.

The plan is data. windows_collect.ps1 reads it from $CtParams and treats every path, name and query as a value.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable

from .datastream import Datastream, Rule
from .oval.evaluator import NOT_COLLECTED, EvalError, Evaluator, Unsupported
from .oval.model import ObjectDef, OvalDocument
from .oval.windows_probes import SUPPORTED, Request, probe_for

SCRIPT_PATH = Path(__file__).resolve().parent / "windows_collect.ps1"
SCRIPT_MARKER = "# cyberthunder-script: scap-collect"
MAX_ROUNDS = 3


@lru_cache(maxsize=1)
def script_template() -> str:
    text = SCRIPT_PATH.read_text(encoding="utf-8")
    if not text.startswith(SCRIPT_MARKER):
        raise ValueError(f"{SCRIPT_PATH.name} does not start with {SCRIPT_MARKER!r}")
    return text


@dataclass
class Plan:
    requests: dict[str, Request] = field(default_factory=dict)
    unplanned: dict[str, str] = field(default_factory=dict)      # object id -> why it cannot be collected

    def add(self, reqs: Iterable[Request]) -> None:
        for r in reqs:
            self.requests.setdefault(r.id, r)

    def only(self, ids: Iterable[str]) -> "Plan":
        keep = set(ids)
        return Plan({k: v for k, v in self.requests.items() if k in keep}, dict(self.unplanned))

    def __len__(self) -> int:
        return len(self.requests)

    def to_params(self) -> dict:
        out: dict = {"schema": 1}
        reg: dict[tuple, dict] = {}
        for r in self.requests.values():
            if r.section == "registry":
                hive, key, names, depth = r.payload
                e = reg.setdefault((hive, key.lower(), depth), {"hive": hive, "key": key, "names": [], "depth": depth})
                if "*" in e["names"] or "*" in names:
                    e["names"] = ["*"]
                else:
                    for n in names:
                        if n.lower() not in (x.lower() for x in e["names"]):
                            e["names"].append(n)
            elif r.section in ("secedit", "auditpol", "accounts"):
                out[r.section] = True
            elif r.section == "files":
                path, pattern = r.payload
                out.setdefault("files", []).append({"path": path, "pattern": pattern})
            elif r.section == "services":
                svc = out.setdefault("services", [])
                if r.payload[0] == "*" or "*" in svc:
                    out["services"] = ["*"]
                elif r.payload[0] not in svc:
                    svc.append(r.payload[0])
            elif r.section == "wmi":
                ns, wql = r.payload
                out.setdefault("wmi", []).append({"namespace": ns, "wql": wql})
        if reg:
            out["registry"] = sorted(reg.values(), key=lambda e: (e["hive"], e["key"].lower(), e["depth"]))
        return out

    def summary(self) -> dict:
        p = self.to_params()
        return {"registry_keys": len(p.get("registry", [])),
                "registry_values": sum(len(e["names"]) for e in p.get("registry", [])),
                "security_policy": bool(p.get("secedit")), "audit_policy": bool(p.get("auditpol")),
                "accounts": bool(p.get("accounts")), "files": len(p.get("files", [])),
                "services": p.get("services", []), "wmi_queries": len(p.get("wmi", [])),
                "unplanned": len(self.unplanned)}


def selected_definitions(ds: Datastream, rules: Iterable[Rule]) -> dict[str, list[str]]:
    """OVAL component -> definition ids for the given rules (unsupported rules included; the planner skips
    objects it cannot collect) plus the platform definitions those rules depend on."""
    out: dict[str, list[str]] = {}
    b = ds.benchmark
    for r in rules:
        chk = r.oval_check
        if chk and chk.component:
            out.setdefault(chk.component, []).append(chk.name)
        for pid in r.platforms:
            pl = b.platforms.get(pid.lstrip("#"))
            for f in (pl.facts if pl else []):
                if f.component and f.name:
                    out.setdefault(f.component, []).append(f.name)
    return {k: list(dict.fromkeys(v)) for k, v in out.items()}


def _plan_doc(doc: OvalDocument, def_ids: list[str], data: dict, done: set[str], plan: Plan) -> None:
    def collector(o: ObjectDef, resolved: dict):
        try:
            p = probe_for(o)
        except Unsupported:
            plan.unplanned[o.id] = f"{o.probe}_test is not supported"
            raise
        try:
            reqs = p.requests(o, resolved)
        except EvalError as e:
            plan.unplanned[o.id] = str(e)
            raise
        missing = [r for r in reqs if r.id not in done]
        if missing:
            plan.add(missing)
            return NOT_COLLECTED, [], "planned"
        return p.items(o, resolved, data)

    ev = Evaluator(doc, collector)
    closure = doc.closure(def_ids)
    for oid in sorted(closure["objects"]):
        ev.items(oid)
    for vid in sorted(closure["variables"]):
        ev.variable(vid)


def build_plan(ds: Datastream, rules: Iterable[Rule], data: dict | None = None, done: set[str] | None = None) -> Plan:
    """Requests still needed for the rules, given what has been collected (data) under request ids `done`."""
    plan = Plan()
    data = data or {}
    done = done or set()
    for comp, defs in selected_definitions(ds, list(rules)).items():
        doc = ds.oval.get(comp)
        if doc is not None:
            _plan_doc(doc, defs, data, done, plan)
    for k in list(plan.requests):
        if k in done:
            del plan.requests[k]
    return plan


def merge_data(into: dict, more: dict) -> dict:
    """Combine two collection outputs (lists are appended, sections are unioned)."""
    for k, v in (more or {}).items():
        if k in ("schema",):
            continue
        if isinstance(v, list):
            into.setdefault(k, [])
            if isinstance(into[k], list):
                into[k].extend(v)
        elif isinstance(v, dict) and isinstance(into.get(k), dict):
            into[k].update(v)
        else:
            into[k] = v
    return into


Runner = Callable[[dict], dict]


def collect_benchmark(ds: Datastream, rules: list[Rule], run: Runner, *, max_rounds: int = MAX_ROUNDS) -> tuple[dict, list[dict]]:
    """Run the collection script until every collectable object has data. Returns (data, rounds) where rounds
    lists each run's plan summary."""
    data: dict = {"schema": 1}
    done: set[str] = set()
    rounds: list[dict] = []
    for _ in range(max_rounds):
        plan = build_plan(ds, rules, data, done)
        if not plan.requests:
            break
        params = plan.to_params()
        out = run(params)
        merge_data(data, out)
        done |= set(plan.requests)
        rounds.append(plan.summary())
    data["requests_done"] = sorted(done)
    return data, rounds


def script_for(params: dict) -> str:
    """The collection script with the plan inserted as data after the marker line."""
    from cyberthunder.adapters.windows.scripts import with_data
    return with_data(script_template(), "CtParams", params)


def plan_json(ds: Datastream, rules: list[Rule]) -> str:
    return json.dumps(build_plan(ds, rules).to_params(), indent=1)


def supported_rules(ds: Datastream, rules: Iterable[Rule]) -> list[Rule]:
    return [r for r in rules if ds.support(r, SUPPORTED).supported]
