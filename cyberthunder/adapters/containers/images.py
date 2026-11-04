"""Container image reference helpers shared by the Kubernetes and container-host adapters.

Image references follow the Docker distribution rules: a first path component containing '.' or ':'
(or equal to 'localhost') is a registry host; otherwise the image lives on docker.io, and single-name
images live under docker.io/library.
"""
from __future__ import annotations

import re
from typing import Iterable

# Conservative image reference shape. Anything outside it is never placed on a command line.
RE_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")


def split_image(image: str) -> tuple[str, str | None, str | None]:
    """Return (repository path with registry, tag, digest). Tag is None when untagged."""
    ref, _, digest = image.partition("@")
    tag = None
    head, sep, last = ref.rpartition("/")
    if ":" in last:
        last, tag = last.split(":", 1)
    ref = f"{head}{sep}{last}"
    parts = ref.split("/")
    if len(parts) == 1:
        full = f"docker.io/library/{parts[0]}"
    elif "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        full = ref
    else:
        full = f"docker.io/{ref}"
    return full, tag, (digest or None)


def image_repository(image: str) -> str:
    return split_image(image)[0]


def image_registry(image: str) -> str:
    return image_repository(image).split("/", 1)[0]


def image_tag(image: str) -> str | None:
    return split_image(image)[1]


def uses_latest_or_untagged(image: str) -> bool:
    """True for ':latest' or an image with neither tag nor digest (which resolves to latest)."""
    _, tag, digest = split_image(image)
    if digest:
        return False
    return tag is None or tag == "latest"


def registry_allowed(image: str, allowed: Iterable[str]) -> bool:
    """Allowed entries are registry hosts ('registry.local') or repository prefixes ('docker.io/library')."""
    full = image_repository(image)
    for a in allowed:
        a = a.strip().rstrip("/")
        if a and (full == a or full.startswith(a + "/")):
            return True
    return False


def safe_image(image: str) -> bool:
    return bool(RE_IMAGE.match(image or ""))
