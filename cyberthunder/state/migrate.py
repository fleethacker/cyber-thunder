"""Move documents between the json and sqlite backends, and describe a state directory.

migrate() copies every document of the source backend into the target, then checks the copy: every source
path is present, a sample (or all) of the documents compare equal, and the audit chain next to them still
verifies (the chain is a file and is never touched; the check is the reassurance the operator wants before
switching CT_STATE_BACKEND). Running it again is harmless: a target that already holds exactly what the
source holds is accepted, one that holds different or extra documents is refused unless `force` is set.
The source is left in place unless `prune` is set and the copy verified.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cyberthunder.state import BACKENDS, Backend, StateError, is_document, open_backend, validate_backend

SAMPLE_DEFAULT = 50


def canonical(doc: Any) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def other_backend(name: str) -> str:
    return "sqlite" if validate_backend(name) == "json" else "json"


@dataclass
class MigrationReport:
    root: str
    source: str
    target: str
    source_documents: int = 0
    copied: int = 0
    unchanged: int = 0
    present_after: int = 0
    compared: int = 0
    pruned: int = 0
    audit: str = ""
    audit_ok: bool | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["ok"] = self.ok
        return d

    def lines(self) -> list[str]:
        out = [f"migrate {self.source} -> {self.target} under {self.root}",
               f"  source documents   {self.source_documents}",
               f"  copied             {self.copied}   (unchanged {self.unchanged})",
               f"  verified           {self.present_after} of {self.source_documents} present, "
               f"{self.compared} compared one by one",
               f"  audit chain        {self.audit}"]
        if self.pruned:
            out.append(f"  pruned             {self.pruned} source documents removed")
        out.append("  result             " + ("OK" if self.ok else "FAILED: " + "; ".join(self.problems)))
        return out


def _documents(be: Backend) -> dict[str, float]:
    return {p: m for p, m in be.list() if is_document(p)}


def migrate(root: str | Path, to: str, source: str | None = None, *, force: bool = False,
            prune: bool = False, sample: int = SAMPLE_DEFAULT) -> MigrationReport:
    to = validate_backend(to)
    source = validate_backend(source) if source else other_backend(to)
    if source == to:
        raise StateError(f"source and target are both {to}; choose --to {other_backend(to)}")
    root = Path(root)
    if not root.is_dir():
        raise StateError(f"state directory {root} does not exist")
    report = MigrationReport(root=str(root), source=source, target=to)
    src, dst = open_backend(source, root), open_backend(to, root)
    try:
        src_docs = _documents(src)
        report.source_documents = len(src_docs)
        dst_docs = _documents(dst)
        if dst_docs and not force:
            extra = [p for p in dst_docs if p not in src_docs]
            differ = [p for p in dst_docs if p in src_docs and canonical(dst.get(p)) != canonical(src.get(p))]
            if extra or differ:
                raise StateError(
                    f"the {to} backend already holds {len(dst_docs)} documents under {root}: {len(extra)} not in "
                    f"the {source} source and {len(differ)} with different content; run again with --force to "
                    f"overwrite them (documents only the target holds are kept)")
        with dst.lock("migrate"):
            for path, mtime in sorted(src_docs.items()):
                doc = src.get(path)
                if doc is None:
                    report.problems.append(f"source document vanished during the copy: {path}")
                    continue
                if path in dst_docs and canonical(dst.get(path)) == canonical(doc):
                    report.unchanged += 1
                    continue
                dst.put(path, doc, mtime=mtime)
                report.copied += 1
        after = _documents(dst)
        missing = sorted(p for p in src_docs if p not in after)
        report.present_after = len(src_docs) - len(missing)
        if missing:
            report.problems.append(f"{len(missing)} documents missing after the copy, first: {missing[:3]}")
        paths = sorted(src_docs)
        n = len(paths) if sample <= 0 else min(sample, len(paths))
        picks = [paths[i * len(paths) // n] for i in range(n)] if n else []
        for p in picks:
            if canonical(src.get(p)) != canonical(dst.get(p)):
                report.problems.append(f"document differs after the copy: {p}")
        report.compared = len(picks)
        from cyberthunder.audit.chain import verify_file
        v = verify_file(root / "audit.jsonl")
        report.audit, report.audit_ok = str(v), v.ok
        if not v.ok:
            report.problems.append(f"audit chain does not verify: {v}")
        if prune and report.ok:
            for p in paths:
                if src.delete(p):
                    report.pruned += 1
    finally:
        src.close()
        dst.close()
    return report


def info(root: str | Path, backend: str) -> dict:
    """Backend, location, document count and size for `state info`, plus the other backend's documents when
    it holds any, which is how an unmigrated directory shows itself."""
    from cyberthunder.state.sqlite import SqliteBackend
    backend = validate_backend(backend)
    root = Path(root)
    out: dict[str, Any] = {"root": str(root), "backend": backend, "backends": list(BACKENDS)}
    if backend == "sqlite" and not SqliteBackend.exists(root):
        out.update(location=f"{root / SqliteBackend.FILENAME} (not created yet)", documents=0, bytes=0)
    else:
        be = open_backend(backend, root)
        try:
            out.update(location=be.location(), documents=be.count(), bytes=be.size_bytes())
            if backend == "sqlite":
                out["meta"] = be.meta()          # type: ignore[attr-defined]
        finally:
            be.close()
    other = other_backend(backend)
    if other == "json" or SqliteBackend.exists(root):
        ob = open_backend(other, root)
        try:
            n = ob.count()
            if n:
                out["other"] = {"backend": other, "documents": n, "location": ob.location(),
                                "note": f"{n} documents are held by the {other} backend, which is not the configured "
                                        f"one; run 'cyberthunder state migrate --to {backend}' to bring them over"}
        finally:
            ob.close()
    from cyberthunder.audit.chain import verify_file
    v = verify_file(root / "audit.jsonl")
    out["audit"] = {"records": v.count, "verified": v.ok, "detail": str(v)}
    return out
