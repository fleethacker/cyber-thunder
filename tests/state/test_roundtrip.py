"""`state migrate` on a state directory the simulated range populated: demo targets loaded, a scan with its
findings and proposals, template explanations, a few decisions. Every document must come back identical after
going to the other backend and back, and the files around them (audit chain, proposals, snapshots, simulated
hosts, scanner working files) must not change. The state_dir fixture runs it from each backend."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cyberthunder import demo
from cyberthunder.audit.chain import verify_file
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.state import is_document
from cyberthunder.state.migrate import canonical, migrate
from cyberthunder.store import StateStore

SKIP = ("state.db", ".lock", ".tmp")


def _documents(store: StateStore) -> dict[str, str]:
    return {p: canonical(store.docs.get(p)) for p, _ in store.docs.documents()}


def _files(root: Path) -> dict[str, str]:
    out = {}
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and not is_document(rel) and not any(rel.endswith(s) or s in rel for s in SKIP):
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_range_state_round_trips(state_dir, monkeypatch):
    monkeypatch.setenv("CT_EXPLAIN_PRECOMPUTE", "0")
    monkeypatch.setenv("CT_LLM_BACKEND", "template")
    ctx = AppContext(Settings.from_env(state_dir=state_dir))
    here = ctx.store.backend_name
    other = "sqlite" if here == "json" else "json"
    targets = demo.load(ctx, "sailor1")
    linux = [t.id for t in targets if t.asset_type == "linux"]
    run = ctx.scanner.start(linux, trigger="demo", requested_by="sailor1", background=False)
    assert run.status == "done" and run.findings_count > 0
    findings = ctx.store.load_findings(run.id)
    assert ctx.explain.precompute(findings, background=False) == len({f.id for f in findings})
    proposals = ctx.gate.list()
    assert len(proposals) >= 3
    ctx.gate.approve(proposals[0].id, "sailor1", "ok")
    ctx.gate.deny(proposals[1].id, "sailor1", "not now")
    ctx.ingest.set_link(actor="sailor1", connected=False)
    before_docs, before_files = _documents(ctx.store), _files(state_dir)
    proposals_before = json.loads((state_dir / "proposals.json").read_text(encoding="utf-8"))
    assert len(before_docs) >= 8 and any(p.startswith("explanations/") for p in before_docs)
    assert "link.json" in before_docs and f"scans/{run.id}/findings.json" in before_docs
    ctx.store.close()

    rep = migrate(state_dir, other, prune=True, sample=0)
    assert rep.ok, rep.problems
    assert rep.copied == len(before_docs) and rep.compared == len(before_docs) and rep.pruned == len(before_docs)
    assert rep.audit_ok
    moved = StateStore(state_dir, backend=other)
    assert _documents(moved) == before_docs
    assert moved.load_scan_run(run.id)["findings_count"] == run.findings_count
    assert len(moved.load_findings(run.id)) == len(findings)
    moved.close()
    assert _files(state_dir) == before_files                       # nothing but documents moved
    assert json.loads((state_dir / "proposals.json").read_text(encoding="utf-8")) == proposals_before

    back = migrate(state_dir, here, prune=True, sample=0)
    assert back.ok and back.copied == len(before_docs) and back.pruned == len(before_docs)
    again = StateStore(state_dir, backend=here)
    assert _documents(again) == before_docs
    again.close()
    assert _files(state_dir) == before_files
    assert verify_file(state_dir / "audit.jsonl").ok
    fresh = AppContext(Settings.from_env(state_dir=state_dir))
    assert len(fresh.gate.list()) == len(proposals) and fresh.store.latest_scan_id() == run.id
    print(f"\nround trip[{here}->{other}->{here}]: {len(before_docs)} documents, {len(before_files)} files unchanged, "
          f"{len(proposals)} proposals, audit {verify_file(state_dir / 'audit.jsonl').count} records")
