"""Benchmark local models for the explain layer on THIS machine.

  python scripts/bench_llm.py gemma3:4b qwen2.5:3b [--url http://localhost:11434]

Measures tokens/sec, load time, wall time, and whether the model kept the required citations and
returned valid JSON. That last column is what matters: the explain layer rejects any output whose
citations are not in the finding.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request

PROMPT = """You are the explain module of a Navy cyber defense agent on an isolated shipboard network.
Given ONE finding, return ONLY a JSON object with keys:
  "risk": 2 sentences a commanding officer can act on,
  "impact": 1 sentence on mission impact,
  "plan": 1 sentence on the proposed fix and that it requires approval,
  "citations": list of identifiers you used.
Rules: cite only identifiers from the finding. No markdown. No extra keys.

FINDING:
host: acd-target-01
rule_id: SV-257985r925942_rule
stig_id: RHEL-09-255045
group: V-257985
severity: CAT II
title: RHEL 9 must not permit direct logons to the root account using remote access via SSH.
status: open
evidence: PermitRootLogin yes in /etc/ssh/sshd_config
references: CCI-000770
fix_ref: ssg:sshd_disable_root_login
"""

ALLOWED = {"SV-257985r925942_rule", "RHEL-09-255045", "V-257985", "CCI-000770", "ssg:sshd_disable_root_login"}


def run(model: str, url: str, num_predict: int) -> dict:
    body = json.dumps({"model": model, "prompt": PROMPT, "stream": False, "format": "json",
                       "options": {"num_predict": num_predict, "temperature": 0.2}}).encode()
    t0 = time.time()
    req = urllib.request.Request(f"{url}/api/generate", body, {"Content-Type": "application/json"})
    d = json.loads(urllib.request.urlopen(req, timeout=900).read())
    wall = time.time() - t0
    text = d.get("response", "")
    ok_json, cites_ok, bad = False, False, []
    try:
        obj = json.loads(text)
        ok_json = all(k in obj for k in ("risk", "impact", "plan", "citations"))
        cites = set(map(str, obj.get("citations", [])))
        bad = sorted(c for c in cites if c not in ALLOWED)
        cites_ok = bool(cites) and not bad
    except json.JSONDecodeError:
        pass
    return {
        "model": model,
        "tok_s": d["eval_count"] / (d["eval_duration"] / 1e9),
        "load_s": d.get("load_duration", 0) / 1e9,
        "wall_s": wall,
        "tokens": d["eval_count"],
        "json_ok": ok_json,
        "citations_ok": cites_ok,
        "bad_citations": bad,
        "sample": re.sub(r"\s+", " ", text)[:220],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("models", nargs="+")
    ap.add_argument("--url", default="http://localhost:11434")
    ap.add_argument("--num-predict", type=int, default=220)
    a = ap.parse_args()
    print(f"{'model':22s} {'tok/s':>6s} {'load':>5s} {'wall':>6s} {'toks':>5s}  json  cites")
    for m in a.models:
        try:
            r = run(m, a.url, a.num_predict)
        except Exception as e:  # noqa: BLE001
            print(f"{m:22s} ERROR {e}")
            continue
        print(f"{r['model']:22s} {r['tok_s']:6.1f} {r['load_s']:5.1f} {r['wall_s']:6.1f} {r['tokens']:5d}  "
              f"{'yes' if r['json_ok'] else 'NO ':4s}  {'yes' if r['citations_ok'] else 'NO'}"
              f"{(' bad=' + ','.join(r['bad_citations'])) if r['bad_citations'] else ''}")
        print(f"    {r['sample']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
