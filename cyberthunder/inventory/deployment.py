"""Local runtime hints only. This module never resolves names, contacts a host or reads credentials."""
from __future__ import annotations

import os
from pathlib import Path
import sys


def runtime_context():
    runtime_os = {"win32": "windows", "linux": "linux", "darwin": "darwin"}.get(sys.platform, "unknown")
    kind, detection = "native", "no_container_markers"
    try:
        if "KUBERNETES_SERVICE_HOST" in os.environ:
            kind, detection = "kubernetes", "local_markers"
        elif (Path("/.dockerenv").is_file() or Path("/run/.containerenv").is_file()
              or bool(os.environ.get("container"))):
            kind, detection = "container", "local_markers"
        elif runtime_os == "unknown":
            kind, detection = "unknown", "unknown"
    except OSError:
        kind, detection = "unknown", "unknown"
    boundary = "container" if kind in {"container", "kubernetes"} else "unknown" if kind == "unknown" else "runtime"
    description = ("Local transport runs inside this container, not on its physical host."
                   if boundary == "container" else "Local transport runs in this process's environment; its physical host is not attested.")
    return {"kind": kind, "detection": detection, "runtime_os": runtime_os, "physical_host_os": "unknown",
            "host_address": None, "host_address_required": True,
            "local_transport": {"boundary": boundary, "description": description},
            "supported_host_transports": ["ssh", "winrm"],
            "hints": [{"code": "explicit_host_address", "message": "Supply an authorized host address reachable from this runtime."},
                      {"code": "existing_access", "message": "Use an existing authorized SSH or WinRM service and credential reference."},
                      {"code": "physical_host_unknown", "message": "Runtime markers do not identify the physical host OS, Windows/WSL boundary, or Kubernetes node."}]}
