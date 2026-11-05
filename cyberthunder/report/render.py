"""Shared Jinja2 environment for every report template (inline CSS only, no external assets)."""
from __future__ import annotations

import html
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = Path(__file__).parent / "templates"
FORMATS = ("html", "md")


class ReportError(RuntimeError):
    """A report could not be produced; the message says what to do about it."""


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=lambda name: bool(name) and name.endswith(".html.j2"),
        trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
    )
    env.filters["md_cell"] = _md_cell
    return env


def _md_cell(value) -> str:
    """Keep scanner evidence and reviewer text literal inside Markdown reports."""
    text = html.escape(str(value), quote=False)
    for char in ("\\", "`", "*", "[", "]", "|"):
        text = text.replace(char, "\\" + char)
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def render(name: str, fmt: str, **data) -> str:
    """Render templates/<name>.<fmt>.j2."""
    if fmt not in FORMATS:
        raise ReportError(f"unknown format {fmt!r}; expected one of {FORMATS}")
    return _env().get_template(f"{name}.{fmt}.j2").render(**data)


def find_doc(ctx, filename: str) -> Path:
    """Locate docs/<filename>: a copy in <state_dir>/docs wins (site-specific edits), then the repository docs."""
    candidates = []
    if ctx is not None:
        candidates.append(Path(ctx.store.root) / "docs" / filename)
    candidates.append(Path(__file__).resolve().parents[2] / "docs" / filename)
    for c in candidates:
        if c.exists():
            return c
    raise ReportError(f"{filename} not found; looked in: " + ", ".join(str(c.parent) for c in candidates))
