import json

from cyberthunder.explain import cli as explain_cli

from .helpers import cron_finding, make_ctx, ssh_root_finding


def _parser():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--state-dir")
    sp = ap.add_subparsers(dest="cmd", required=True)
    explain_cli.register_cli(sp)
    return ap


def _run(argv):
    a = _parser().parse_args(argv)
    return a.fn(a)


def test_cli_explain_status_precompute(state_dir, monkeypatch, capsys):
    monkeypatch.setenv("CT_LLM_BACKEND", "template")
    ctx = make_ctx(state_dir)
    f1, f2 = ssh_root_finding(), cron_finding()
    ctx.store.save_findings("scan-1", [f1, f2])
    ctx.store.save_scan_run({"id": "scan-1", "started_at": "2026-11-04T00:00:00+00:00"})
    sd = str(state_dir)

    assert _run(["--state-dir", sd, "explain-precompute"]) == 0
    assert "2 of 2" in capsys.readouterr().out

    assert _run(["--state-dir", sd, "explain", f1.id]) == 0
    out = capsys.readouterr().out
    assert "RISK" in out and "CITES" in out and "RHEL-09-255045" in out

    assert _run(["--state-dir", sd, "explain", "nope"]) == 2
    capsys.readouterr()

    assert _run(["--state-dir", sd, "explain-precompute", "--scan-id", "scan-1", "--wait", "--timeout", "10"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["queued"] == 1 and res["finished"] is True

    assert _run(["--state-dir", sd, "explain-status"]) == 0
    assert json.loads(capsys.readouterr().out)["backend"] == "template"
