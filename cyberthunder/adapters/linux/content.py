"""Select an installed SSG filename only when observed OS identity supports it."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

SSG_DIRECTORY = "/usr/share/xml/scap/ssg/content/"


def select_datastream(paths, facts) -> str | None:
    if facts is None:
        return None
    ident = str(facts.model or "").strip().lower()
    version = str(facts.os_version or "").strip()
    # Compatibility families used for product recommendations are not execution applicability.
    # In particular, Rocky/Alma/CentOS do not silently inherit a RHEL benchmark here.
    prefix = {"rhel": "rhel", "ol": "ol", "ubuntu": "ubuntu", "debian": "debian",
              "fedora": "fedora", "sles": "sle", "centos": "centos", "rocky": "rl",
              "almalinux": "almalinux"}.get(ident)
    if not prefix:
        return None
    major = re.fullmatch(r"(\d+)(?:\.\d+)*", version)
    if not major:
        return None
    release = major.group(1)
    if ident == "ubuntu":
        match = re.fullmatch(r"(\d{2})\.(\d{2})(?:\.\d+)?", version)
        if not match:
            return None
        release = match.group(1) + match.group(2)
    expected = f"ssg-{prefix}{release}-ds.xml"
    matches = {p for p in paths if p.startswith(SSG_DIRECTORY)
               and str(PurePosixPath(p).parent) + "/" == SSG_DIRECTORY
               and PurePosixPath(p).name == expected}
    return next(iter(matches)) if len(matches) == 1 else None
