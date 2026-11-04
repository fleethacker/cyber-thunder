"""Asset adapters. One per asset type; all speak the same five verbs (discover, collect, check, fix, verify)
plus hunt, health and rollback. See base.py for the contract and docs/ARCHITECTURE.md for the recipe.
"""
from __future__ import annotations

import importlib
import logging

from .base import Adapter, AdapterRegistry, Collected, AssetFacts, make_finding, registry, register

log = logging.getLogger(__name__)

# Fixed list on purpose: adding an adapter means adding a package here, nothing else changes.
ADAPTER_MODULES = (
    "cyberthunder.adapters.linux",
    "cyberthunder.adapters.windows",
    "cyberthunder.adapters.cisco",
    "cyberthunder.adapters.kubernetes",
    "cyberthunder.adapters.containers",
)

_loaded = False


def load_all() -> AdapterRegistry:
    """Import every adapter package that exists. Missing ones are skipped (they may not be built yet)."""
    global _loaded
    if not _loaded:
        for mod in ADAPTER_MODULES:
            try:
                importlib.import_module(mod)
            except ModuleNotFoundError as e:
                if e.name and e.name.startswith(mod):
                    log.debug("adapter not present: %s", mod)
                else:
                    log.warning("adapter %s failed to import: %s", mod, e)
            except Exception as e:  # noqa: BLE001
                log.warning("adapter %s failed to import: %s", mod, e)
        _loaded = True
    return registry


__all__ = ["Adapter", "AdapterRegistry", "Collected", "AssetFacts", "make_finding", "registry", "register", "load_all"]
