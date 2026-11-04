"""Compression for what crosses the constrained link.

Methods: lzma (default, best ratio in the standard library), zlib (fast), external. External runs the
command in CT_COMPRESSOR, which reads raw bytes on stdin and writes compressed bytes on stdout; that is
how a site compressor (for example a context-mixing compressor built for this link) plugs in. Any failure
of the external command falls back to lzma so a transfer is never blocked by a missing tool.
"""
from __future__ import annotations

import json
import logging
import lzma
import os
import shlex
import subprocess
import zlib
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.ingest.delta import DeltaReport
    from cyberthunder.parsers.xccdf import RuleMeta

log = logging.getLogger(__name__)

METHODS = ("lzma", "zlib", "external")
EXTERNAL_TIMEOUT_S = 120


def _external(data: bytes) -> bytes:
    cmd = os.environ.get("CT_COMPRESSOR", "").strip()
    if not cmd:
        raise RuntimeError("CT_COMPRESSOR is not set")
    argv = shlex.split(cmd, posix=os.name != "nt")
    if os.name == "nt":   # non-POSIX splitting keeps the quotes around "C:\Program Files\..." paths
        argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a for a in argv]
    proc = subprocess.run(argv, input=data, capture_output=True, timeout=EXTERNAL_TIMEOUT_S, check=False)
    if proc.returncode != 0 or not proc.stdout:
        raise RuntimeError(f"compressor exited {proc.returncode}: {proc.stderr[:200]!r}")
    return proc.stdout


def encode(data: bytes, method: str = "lzma") -> tuple[bytes, str]:
    """Compress `data`. Returns (compressed, method actually used)."""
    if method not in METHODS:
        raise ValueError(f"unknown method {method!r}; expected one of {METHODS}")
    if method == "external":
        try:
            return _external(data), "external"
        except Exception as e:  # noqa: BLE001 - any failure falls back
            log.warning("external compressor unavailable, using lzma: %s", e)
            method = "lzma"
    if method == "zlib":
        return zlib.compress(data, 9), "zlib"
    return lzma.compress(data, preset=9 | lzma.PRESET_EXTREME), "lzma"


def decode(data: bytes, method: str) -> bytes:
    """Inverse of encode for the standard-library methods (the far side runs its own external decoder)."""
    if method == "lzma":
        return lzma.decompress(data)
    if method == "zlib":
        return zlib.decompress(data)
    raise ValueError(f"cannot decode {method!r} locally")


def _rule_body(key: str, meta: "RuleMeta", change: list[str] | None) -> dict:
    d = {"key": key, "rule_id": meta.rule_id, "stig_id": meta.rule_version, "group_id": meta.group_id,
         "title": meta.title, "severity": getattr(meta.severity, "value", str(meta.severity)),
         "description": meta.description, "check_text": meta.check_text, "fix_text": meta.fix_text,
         "references": [r.id for r in meta.references]}
    if change:
        d["change"] = change
    return {k: v for k, v in d.items() if v not in (None, "", [])}


def delta_payload(delta: "DeltaReport", new_rules: Mapping[str, "RuleMeta"]) -> bytes:
    """Compact JSON with only the added and changed rules (with their text) and the removed keys:
    everything the far side needs to bring its catalog from old_release to new_release."""
    from cyberthunder.ingest.delta import rule_key
    by_rule_id = {m.rule_id: (k, m) for k, m in new_rules.items()}
    rules = []
    for ref, change in [(r, None) for r in delta.rules_added] + [(r, r.changes) for r in delta.rules_changed]:
        hit = new_rules.get(ref.stig_id or "") or (by_rule_id.get(ref.rule_id) or (None, None))[1]
        if hit is not None:
            rules.append(_rule_body(rule_key(hit), hit, change))
    doc = {"benchmark_id": delta.benchmark_id, "old_release": delta.old_release, "new_release": delta.new_release,
           "removed": [r.stig_id or r.rule_id for r in delta.rules_removed], "rules": rules}
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")


def compare(full_bytes: bytes, delta_bytes: bytes, method: str = "lzma") -> dict:
    """Sizes for the link: full download vs the compressed delta. ratio = full / compressed delta."""
    packed, used = encode(delta_bytes, method)
    n = max(len(packed), 1)
    return {"full_bytes": len(full_bytes), "delta_bytes": len(delta_bytes), "compressed_bytes": len(packed),
            "ratio": round(len(full_bytes) / n, 2), "method": used}
