"""Linux host adapter: OpenSCAP + native STIG checks, intrusion hunt, Trivy CVEs, a vetted fix library,
and a stateful simulated host for the offline demo. See adapter.py for the contract implementation.
"""
from __future__ import annotations

from .adapter import LinuxAdapter

__all__ = ["LinuxAdapter"]
