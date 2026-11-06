"""The web UI source against the repository and the API: every import resolves to a tracked file, every
client call names a route the server has, and the workflows the demo runbook clicks through exist."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("CT_STATE_DIR", tempfile.mkdtemp(prefix="ct-ui-"))

ROOT = Path(__file__).resolve().parents[2]
UI = ROOT / "cyberthunder" / "ui"
SRC = UI / "src"
CLIENT = (SRC / "api" / "client.ts").read_text(encoding="utf-8")

IMPORT_RE = re.compile(r"""(?:import|export)\s[^'"]*?from\s+['"](\.{1,2}/[^'"]+)['"]""")
EXTS = ("", ".ts", ".tsx", "/index.ts", "/index.tsx")


def _sources() -> list[Path]:
    return sorted(p for p in SRC.rglob("*") if p.suffix in (".ts", ".tsx"))


def _resolve(base: Path, spec: str) -> Path | None:
    for ext in EXTS:
        cand = (base.parent / (spec + ext)).resolve()
        if cand.is_file():
            return cand
    return None


def test_relative_imports_resolve():
    missing = []
    for f in _sources():
        for spec in IMPORT_RE.findall(f.read_text(encoding="utf-8")):
            if spec.endswith(".css"):
                continue
            if _resolve(f, spec) is None:
                missing.append(f"{f.relative_to(SRC)} -> {spec}")
    assert not missing, missing


@pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")
def test_no_ui_source_is_git_ignored():
    # The UI must build from a clean clone: a runtime-state ignore rule once swallowed src/state/.
    files = [str(p.relative_to(ROOT)).replace("\\", "/") for p in _sources()]
    r = subprocess.run(["git", "check-ignore", "--no-index", *files], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode in (0, 1), r.stderr
    assert r.stdout.strip() == "", f"ignored UI sources: {r.stdout.split()}"
    assert (SRC / "state" / "AppState.tsx").is_file()


def _client_routes() -> set[tuple[str, str]]:
    out = set()
    calls = re.finditer(r"""\b(get|post|put|del)<[^(]*?>\(\s*[`'](/[^`']*)[`']"""
                        r"""|request<[^(]*?>\(\s*'([A-Z]+)',\s*[`'](/[^`']*)[`']""", CLIENT)
    for m in calls:
        method = (m.group(1) or m.group(3)).upper().replace("DEL", "DELETE")
        path = re.sub(r"\$\{[^}]+\}", "{}", m.group(2) or m.group(4))
        out.add((method, path))
    return out


def test_client_calls_match_api_routes(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.api.app import API_PREFIX, create_app
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext

    app = create_app(AppContext(Settings.from_env(state_dir=str(state_dir))))
    server = set()
    for path, ops in app.openapi()["paths"].items():
        if not path.startswith(API_PREFIX):
            continue
        norm = re.sub(r"\{[^}]+\}", "{}", path[len(API_PREFIX):])
        server.update((m.upper(), norm) for m in ops)
    client = _client_routes()
    assert len(client) > 40
    unknown = sorted(c for c in client if c not in server)
    assert not unknown, f"client calls with no server route: {unknown}"


def test_client_covers_the_discovery_workflow():
    client = _client_routes()
    for route in [("GET", "/discovery"), ("PUT", "/discovery/scopes"), ("POST", "/discovery/sweep"),
                  ("POST", "/discovery/scopes/preview"), ("PUT", "/discovery/scopes/ranges"),
                  ("GET", "/discovery/runs/{}"), ("GET", "/discovery/assets"),
                  ("POST", "/discovery/assets/{}/accept"), ("POST", "/discovery/assets/{}/ignore"),
                  ("GET", "/discovery/findings")]:
        assert route in client, route


def _tsx_text() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in _sources() if p.suffix == ".tsx")


def test_discovery_panel_is_wired_to_the_routes():
    panel = (SRC / "components" / "DiscoveryPanel.tsx").read_text(encoding="utf-8")
    for call in ("api.sweep(", "api.discoveredAssets(", "api.acceptAsset(",
                 "api.ignoreAsset(", "api.discoveryFindings(", "api.discoveryRun("):
        assert call in panel, call
    assert "<ScopeEditor" in panel
    editor = (SRC / "components" / "ScopeEditor.tsx").read_text(encoding="utf-8")
    assert "scopeRecipesApi.preview(" in editor and "scopeRecipesApi.save(" in editor
    assert "in_scope: scope === 'in'" in panel          # explicit decision, never a default
    assert "placeholder" not in panel.splitlines()[0].lower()


def test_diff_and_verify_are_reachable_from_the_ui():
    text = _tsx_text()
    assert "api.diff(" in text
    assert "api.verify(" in text
    card = (SRC / "components" / "ProposalCard.tsx").read_text(encoding="utf-8")
    assert "<DiffButton" in card and "actions.verify" in card


def test_findings_source_filter_is_not_a_fixed_list():
    page = (SRC / "pages" / "Findings.tsx").read_text(encoding="utf-8")
    assert "const SOURCES" not in page
    assert "'openscap', 'scc'" not in page
    # Source options now use the shared facet controls. Unknown sources and options beyond the
    # first page are covered behaviorally in tests/api/test_findings_query.py.


def test_dist_index_points_at_built_assets():
    index = (UI / "dist" / "index.html").read_text(encoding="utf-8")
    refs = re.findall(r'(?:src|href)="(?:\./|/)?(assets/[^"]+)"', index)
    assert refs and all((UI / "dist" / r).is_file() for r in refs), refs
