"""Every `python -m cyberthunder ...` line in a fenced block of the README, the demo runbook and the range
notes must parse with the real CLI, so a rehearsal from the documents cannot stop on a usage error."""
from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from cyberthunder.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent.parent
DOCS = ["README.md", "docs/DEMO.md", "range/README.md"]
FENCE = re.compile(r"```(?:bash|sh)?\n(.*?)```", re.S)
TAIL = re.compile(r"`(python -m cyberthunder [^`]+)`")


def _commands() -> list[tuple[str, str]]:
    out = []
    for rel in DOCS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        lines = [ln for block in FENCE.findall(text) for ln in block.splitlines()]
        lines += TAIL.findall(text)
        for ln in lines:
            ln = ln.strip()
            if ln.startswith("python -m cyberthunder") and "<cmd>" not in ln:
                out.append((rel, ln))
    return out


def _argv(line: str) -> list[str]:
    line = re.sub(r"<[^>]+>", "x", line)
    line = re.sub(r"\[[^\]]*\]", "", line)
    return shlex.split(line)[3:]


def test_docs_have_commands():
    assert len(_commands()) >= 15


@pytest.mark.parametrize("rel,line", _commands())
def test_documented_command_parses(rel, line, capsys):
    try:
        build_parser().parse_args(_argv(line))
    except SystemExit as e:  # argparse exits 2 on a usage error and 0 on --help
        assert e.code in (0, None), f"{rel}: `{line}` is rejected by the CLI: {capsys.readouterr().err.strip()[-200:]}"


def test_scans_needs_a_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scans"])
