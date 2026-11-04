"""Asset discovery and enumeration.

Finds what is actually on the enclave, types it from evidence, and proposes inventory entries for a
human to accept into scope. Discovery never adds anything to the inventory or to scope by itself: it
proposes, a named operator accepts, and that acceptance is audited as a scope decision.

Sweeps run only inside operator-configured scopes (CIDRs), which are audited when set. Public address
space is refused unless a scope was saved with allow_public and a reason. The kill switch stops a sweep
between scopes and between hosts.
"""
from __future__ import annotations

from .models import DiscoveredAsset, DiscoveryRun, DiscoveryScope, OpenPort

__all__ = ["DiscoveredAsset", "DiscoveryRun", "DiscoveryScope", "DiscoveryService", "OpenPort"]


def __getattr__(name: str):
    # The service pulls in the application context; import it lazily so the parsers stay light.
    if name == "DiscoveryService":
        from .service import DiscoveryService
        return DiscoveryService
    raise AttributeError(name)
