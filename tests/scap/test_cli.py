"""`scap info|plan|eval|subset` through the module's own register_cli."""
import argparse
import json
from pathlib import Path

import pytest

from cyberthunder.scap.cli import register_cli

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "scap" / "w11_subset-ds.xml"


def _run(state_dir, *argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir", default=str(state_dir))
    ap.add_argument("--actor", default="it2.jones")
    register_cli(ap.add_subparsers(dest="cmd", required=True))
    a = ap.parse_args(["scap", *argv])
    return a.fn(a)


def test_info(state_dir, capsys):
    assert _run(state_dir, "info", str(FIXTURE)) == 0
    out = capsys.readouterr().out
    assert "xccdf_mil.disa.stig_profile_MAC-1_Classified" in out
    assert "24 evaluated by our OVAL engine, 1 not checked" in out
    assert "fileeffectiverights53_test" in out
    assert _run(state_dir, "info", str(FIXTURE), "--json", "--profile", "xccdf_mil.disa.stig_profile_CAT_I_Only") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["selected_rules"] == 6 and d["counts"]["rules"] == 25
    assert _run(state_dir, "info", str(FIXTURE), "--profile", "nope") == 2


def test_plan(state_dir, capsys):
    assert _run(state_dir, "plan", str(FIXTURE), "--rule", "WN11-UR-000010") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["rules"] == 1 and d["plan"] == {"schema": 1, "secedit": True}


def test_subset(state_dir, tmp_path, capsys):
    out = tmp_path / "one.xml"
    assert _run(state_dir, "subset", str(FIXTURE), "--rule", "WN11-SO-000205", "--out", str(out)) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["rules"] == 1
    assert _run(state_dir, "subset", str(FIXTURE), "--rule", "WN11-XX-0", "--out", str(out)) == 2


@pytest.fixture
def ctx(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    from cyberthunder.adapters.windows.adapter import WindowsAdapter
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    c = AppContext(Settings.from_env(state_dir=str(state_dir)))
    t = WindowsAdapter().demo_targets()[0]
    t.options = {**t.options, "scap_datastream": str(FIXTURE)}
    c.inventory.add(t)
    c.inventory.save()
    return c


def test_eval_on_simulated_target(ctx, state_dir, tmp_path, capsys):
    out = tmp_path / "findings.json"
    assert _run(state_dir, "eval", "--target", "sim-win-01", "--out", str(out)) == 0
    text = capsys.readouterr().out
    assert "WN11-SO-000205" in text and "fail" in text
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert len(doc["findings"]) == 25 and doc["meta"]["benchmark"].endswith("Windows_11_STIG")
    assert all(f["references"] for f in doc["findings"])
    lines = ctx.store.audit_log.read_text(encoding="utf-8").splitlines()
    assert any(json.loads(line).get("action") == "scap.eval" for line in lines if line.strip())


def test_eval_refuses_out_of_scope_and_non_windows(ctx, state_dir, capsys):
    assert _run(state_dir, "eval", "--target", "nobody") == 2
    ctx.inventory.update("sim-win-01", in_scope=False)
    ctx.inventory.save()
    assert _run(state_dir, "eval", "--target", "sim-win-01") == 2
    assert "refused" in capsys.readouterr().err
