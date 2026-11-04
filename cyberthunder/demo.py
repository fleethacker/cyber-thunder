"""Offline demo support (`cyberthunder demo ...`).

Each adapter can offer simulated targets (a stateful emulator seeded with known problems). This module puts
them in the inventory, puts them back to their seeded state between runs, and keeps one switch the
presenter uses to force the next verification to fail so the automatic rollback can be shown live.

Nothing here talks to a real host. Every action is written to the audit log.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

from cyberthunder.inventory.targets import Target

if TYPE_CHECKING:  # pragma: no cover
    from cyberthunder.context import AppContext

DEMO_FILE = "demo.json"


# -- the verify-fail switch ----------------------------------------------------------------------
def _read_flag(ctx: "AppContext") -> bool:
    path = ctx.store.root / DEMO_FILE
    try:
        return bool(json.loads(path.read_text(encoding="utf-8")).get("simulate_verify_fail_next", False))
    except (OSError, ValueError):
        return False


def _write_flag(ctx: "AppContext", flag: bool) -> None:
    ctx.store.write_json(ctx.store.root / DEMO_FILE, {"simulate_verify_fail_next": bool(flag)})


def set_simulate_verify_fail_next(ctx: "AppContext", flag: bool, actor: str) -> bool:
    """Arm (or disarm) a forced verification failure for the next applied fix. Persisted and audited."""
    _write_flag(ctx, flag)
    ctx.audit.append("demo.simulate_verify_fail", actor, {"armed": bool(flag)})
    return bool(flag)


def consume_simulate_verify_fail(ctx: "AppContext") -> bool:
    """Return True once if the switch was armed, and clear it so only one verification is affected."""
    if not _read_flag(ctx):
        return False
    _write_flag(ctx, False)
    ctx.audit.append("demo.simulate_verify_fail.consumed", "agent", {"armed": False})
    return True


# -- demo targets ------------------------------------------------------------------------------
def _demo_targets(ctx: "AppContext") -> list[tuple[object, Target]]:
    pairs: list[tuple[object, Target]] = []
    for adapter in ctx.adapters.all():
        for t in adapter.demo_targets():
            pairs.append((adapter, t))
    return pairs


def load(ctx: "AppContext", actor: str) -> list[Target]:
    """Add every adapter's demo targets that are not already in the inventory. Returns all demo targets."""
    existing = {t.id for t in ctx.inventory.all()}
    added: list[str] = []
    demo: list[Target] = []
    for _adapter, t in _demo_targets(ctx):
        if t.id not in existing:
            ctx.inventory.add(t)
            added.append(t.id)
            existing.add(t.id)
        demo.append(ctx.inventory.get(t.id))
    ctx.save_inventory(actor, "demo.load", {"added": added, "targets": [t.id for t in demo]})
    return demo


_OPEN = ("proposed", "approved")                   # not yet applied: cancelled when their host is reset
_ON_HOST = ("applying", "applied", "verified", "failed")  # before-state was captured from the old host state


def reset(ctx: "AppContext", actor: str) -> dict:
    """Return every in-scope demo target to its seeded state.

    Result maps target id to True/False (False = no simulation, or skipped). A reset changes host state, so it
    stops at the kill switch and never touches a target that is not in the inventory with in_scope set.
    Proposals on a reset host that were not applied yet are cancelled; ones already applied are reported in
    `stale_proposals`, because their captured before-state no longer matches the host.
    """
    ctx.killswitch.guard("demo.reset", actor)
    results: dict[str, bool] = {}
    skipped: list[str] = []
    for adapter, t in _demo_targets(ctx):
        if not ctx.inventory.in_scope(t.id):
            results[t.id] = False
            skipped.append(t.id)
            continue
        try:
            results[t.id] = bool(adapter.reset_simulated(t, ctx.settings))
        except Exception as e:  # noqa: BLE001  - one broken emulator must not stop the others being reset
            results[t.id] = False
            ctx.audit.append("demo.reset.error", actor, {"target": t.id, "error": str(e)}, outcome="error", subject=t.id)
    reset_ids = {tid for tid, ok in results.items() if ok}
    cancelled: list[str] = []
    stale: list[str] = []
    for p in ctx.gate.list():
        if p.host not in reset_ids:
            continue
        if p.state.value in _OPEN:
            ctx.gate.cancel(p.id, actor, "demo reset returned the host to its seeded state")
            cancelled.append(p.id)
        elif p.state.value in _ON_HOST:
            stale.append(p.id)
    details: dict = {"results": results}
    out: dict = {"reset": results}
    for key, val in (("skipped_out_of_scope", skipped), ("cancelled_proposals", cancelled), ("stale_proposals", stale)):
        if val:
            details[key] = val
            out[key] = val
    ctx.audit.append("demo.reset", actor, details)
    return out


def status(ctx: "AppContext") -> dict:
    demo_ids = [t.id for _a, t in _demo_targets(ctx)]
    present = {t.id for t in ctx.inventory.all()}
    return {
        "available": bool(demo_ids),
        "loaded": bool(demo_ids) and all(i in present for i in demo_ids),
        "targets": demo_ids,
        "simulate_verify_fail_next": _read_flag(ctx),
    }


# -- command line ------------------------------------------------------------------------------
def _ctx(a: argparse.Namespace):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=a.state_dir))


def cmd_load(a: argparse.Namespace) -> int:
    targets = load(_ctx(a), a.actor)
    if not targets:
        print("no adapter offers demo targets in this build")
        return 1
    for t in targets:
        print(f"{t.id}  {t.label}")
    return 0


def cmd_reset(a: argparse.Namespace) -> int:
    out = reset(_ctx(a), a.actor)
    print(json.dumps(out, indent=2))
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    print(json.dumps(status(_ctx(a)), indent=2))
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    ctx = _ctx(a)
    targets = load(ctx, a.actor)
    if not targets:
        print("no adapter offers demo targets in this build", file=sys.stderr)
        return 1
    try:
        run = ctx.scanner.start([t.id for t in targets], trigger="demo", requested_by=a.actor, background=False)
    except NotImplementedError:
        print("the scanner is not built in this checkout yet, so the demo cannot scan. "
              "The demo targets are loaded; run the scan once the scanner is available.", file=sys.stderr)
        return 1
    s = run.summary or {}
    print(f"scan {run.id}: {run.status}, {run.findings_count} findings on {len(run.targets)} target(s)")
    if s:
        print("summary: " + json.dumps(s, sort_keys=True))
    print(f"proposals: {len(ctx.gate.list())}")
    return 0 if run.status in ("done", "completed") else 1


def register_cli(subparsers) -> None:
    p = subparsers.add_parser("demo", help="offline demo: simulated targets with seeded problems")
    sub = p.add_subparsers(dest="demo_cmd", required=True)
    for name, fn, text in (("load", cmd_load, "add the simulated targets to the inventory"),
                           ("reset", cmd_reset, "return simulated targets to their seeded state"),
                           ("status", cmd_status, "show whether the demo is available and loaded"),
                           ("run", cmd_run, "load, scan, and report findings and proposals")):
        s = sub.add_parser(name, help=text)
        s.set_defaults(fn=fn)
