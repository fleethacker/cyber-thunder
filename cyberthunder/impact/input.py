"""Bound the complete model prompt while retaining the full evidence receipt."""
from __future__ import annotations

from copy import deepcopy

from .packet import LEVELS, digest
from .validator import build_prompt

# Includes instructions, output shape, exact fix allowlist and selected facts.
# With the backend's 300-token output cap this also fits a 4K context even under
# the conservative bound of one token per ASCII byte, leaving wrapper headroom.
MAX_PROMPT_BYTES = 3072
COVERAGE_UNKNOWN = "Model input was bounded; some collected facts or constraints were omitted from model review. Consult the full evidence receipt."


def prepare_model_input(packet, fix):
    """Greedily retain severe-risk evidence and its graph before lower priorities.

    Every selected evidence record stays intact. No graph edge may refer to an
    omitted evidence ID. The full deterministic risk floor survives selection.
    """
    floor = max((LEVELS[r["severity"]] for r in packet["risks"]), default=0)
    view = {"generated_at": packet["generated_at"], "mode": packet["mode"], "complete": packet["complete"],
            "risk_floor": next(k for k, v in LEVELS.items() if v == floor), "evidence": [], "dependencies": [],
            "risks": [], "unknowns": [], "required_checks": [], "rollback_limits": []}

    def size():
        return len(build_prompt(view, fix).encode("utf-8"))

    def add(key, row):
        view[key].append(deepcopy(row))
        if size() > MAX_PROMPT_BYTES - 8:
            view[key].pop()
            return False
        return True

    priorities = {e["id"]: 0 for e in packet["evidence"]}
    for risk in packet["risks"]:
        for eid in risk["evidence_ids"]:
            priorities[eid] = max(priorities.get(eid, 0), LEVELS[risk["severity"]])
    degree = {eid: sum(eid in d["evidence_ids"] for d in packet["dependencies"]) for eid in priorities}
    selected, edges = set(), set()
    for evidence in sorted(packet["evidence"], key=lambda e: (-priorities[e["id"]], -degree[e["id"]])):
        if not add("evidence", evidence):
            continue
        selected.add(evidence["id"])
        for edge in packet["dependencies"]:
            if edge["id"] not in edges and set(edge["evidence_ids"]) <= selected and add("dependencies", edge):
                edges.add(edge["id"])
    for risk in sorted(packet["risks"], key=lambda r: -LEVELS[r["severity"]]):
        if set(risk["evidence_ids"]) <= selected:
            # Risk IDs are receipt/UI keys, not evidence citations. Excluding them
            # prevents the model from relabeling their hash suffixes as evidence IDs.
            add("risks", {key: risk[key] for key in ("severity", "summary", "evidence_ids")})
    for key in ("unknowns", "required_checks", "rollback_limits"):
        for detail in packet[key]:
            add(key, detail)
    counts = {key: {"included": len(view[key]), "total": len(packet[key])} for key in
              ("evidence", "dependencies", "risks", "unknowns", "required_checks", "rollback_limits")}
    limited = any(v["included"] < v["total"] for v in counts.values())
    if limited:
        view["complete"] = False
    coverage = {"limited": limited, "counts": counts, "prompt_bytes": size(),
                "evidence_ids": [e["id"] for e in view["evidence"]],
                "dependency_ids": [e["id"] for e in view["dependencies"]],
                "input_sha256": digest({"fix": fix, "evidence_packet": view})}
    if size() > MAX_PROMPT_BYTES or not view["evidence"]:
        coverage["limited"] = True
        return None, coverage
    return view, coverage
