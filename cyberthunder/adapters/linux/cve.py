"""Known-vulnerability findings for Linux hosts, from Trivy output collected on the host."""
from __future__ import annotations

from cyberthunder.adapters.base import Collected
from cyberthunder.findings.schema import Finding
from cyberthunder.parsers.trivy import parse_trivy


def run_cve(target, c: Collected) -> list[Finding]:
    path = c.path("trivy")
    if not path or not path.exists():
        return []
    try:
        return parse_trivy(path, target=target)
    except (OSError, ValueError) as e:
        c.errors.append(f"trivy results: {e}")
        return []
