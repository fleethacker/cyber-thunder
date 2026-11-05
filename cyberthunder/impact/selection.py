"""Assessment-private model selection using the existing backend implementations."""
from __future__ import annotations

from copy import copy
from types import SimpleNamespace

from cyberthunder.explain.backends import make_backend

_BUILTIN_MODULE = make_backend.__module__

def isolated_backend(source):
    """Never probe or generate on the shared explain backend.

    Built-ins are recreated by their existing factory with the configured endpoint
    and primary/fallback choices. Protocol extensions must have ordinary bound
    methods and independently assignable selection attributes; otherwise fail
    closed instead of claiming provenance for a shared closure or cached probe.
    """
    if type(source).__module__ == _BUILTIN_MODULE:
        settings = SimpleNamespace(llm_backend=source.name, llm_url=getattr(source, "url", ""),
                                   llm_model=getattr(source, "configured_model", source.model),
                                   llm_fallback_model=getattr(source, "fallback_model", None))
        backend = make_backend(settings)
        if hasattr(source, "probe_timeout"):
            backend.probe_timeout = source.probe_timeout
        return backend
    try:
        if hasattr(source, "_avail"):
            return None  # opaque shared availability caches cannot attest selection
        backend = copy(source)
        if backend is source or not hasattr(backend, "__dict__"):
            return None
        for key in ("name", "model", "configured_model", "fallback_model", "url"):
            if hasattr(source, key):
                if isinstance(getattr(type(source), key, None), property):
                    return None  # selection must not resolve through shared descriptor state
                value = getattr(source, key)
                if value is not None and not isinstance(value, str):
                    return None
                backend.__dict__[key] = value
                if getattr(backend, key) != value:
                    return None
        if any(getattr(getattr(backend, method), "__self__", None) is not backend
               for method in ("available", "generate")):
            return None
        return backend
    except (AttributeError, TypeError, ValueError):
        return None


def selected_identity(backend):
    return (backend.name, backend.model, getattr(backend, "url", None))


def generate_selected(backend, identity, prompt, timeout):
    """Check the private selection at request entry and result exit, never relabel."""
    if selected_identity(backend) != identity:
        return None, False
    raw = backend.generate(prompt, json_mode=True, timeout=timeout)
    return raw, selected_identity(backend) == identity
