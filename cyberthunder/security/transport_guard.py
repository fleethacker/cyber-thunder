"""Attach authorization checks without changing adapter-specific transport types."""
from __future__ import annotations

from functools import wraps


def protect_transport(transport, guard, *, sudo_allowed: bool, command_guard=None):
    """Preserve isinstance dispatch used by adapters and bounded dependency collectors.

    Concrete SSH/WinRM implementations also guard protocol I/O and internal read
    fallbacks. Closing a connection is always allowed after revocation.
    """
    for name in ("run", "read_file", "write_file", "fetch", "check_output", "read_config", "write_config",
                 "connect", "connect_client", "open_shell", "build_argv"):
        original = getattr(transport, name, None)
        if not callable(original):
            continue

        def wrap(fn, method):
            @wraps(fn)
            def checked(*args, **kwargs):
                guard()
                if kwargs.get("sudo") and not sudo_allowed:
                    raise PermissionError("the selected account is not authorized for privilege elevation")
                if command_guard is not None and method in {"run", "check_output", "build_argv"}:
                    command_guard(args[0] if args else kwargs.get("command"))
                result = fn(*args, **kwargs)
                guard()
                return result
            return checked

        setattr(transport, name, wrap(original, name))
    return transport
