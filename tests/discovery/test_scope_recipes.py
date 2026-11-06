"""Recipe persistence, exact review binding and competing operators on both state backends."""
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.control.killswitch import KillSwitchEngaged
from cyberthunder.discovery.recipes import ScopeRevisionConflict, editable
from cyberthunder.discovery.service import DiscoveryService
from cyberthunder.inventory.targets import Target


def recipe(id="range-a", **changes):
    return {"id": id, "name": "Enclave A", "include": ["10.1.0.1-10.1.0.9"], "exclude": ["10.1.0.4"],
            "allow_public": False, "scanner_target": None, "acknowledge_normalization": False, **changes}


def commit(svc, recipes, revision=None):
    revision = revision or svc.scope_recipes()["revision"]
    preview = svc.preview_scope_recipes(recipes, revision)
    return svc.save_scope_recipes(recipes, revision, preview["fingerprint"], "IT1 Jones", "Reviewed exact recipes")


def scanner(ctx):
    ctx.inventory.add_new(Target("scanner-b", "Scanner B", "linux", in_scope=True, address="10.2.0.10"))


def test_roundtrip_original_expressions_and_mixed_policies(ctx):
    scanner(ctx)
    svc = DiscoveryService(ctx)
    rows = [recipe(name="Réseau 北", include=[" 10.1.0.1 - 10.1.0.9 "], exclude=["10.1.0.4"]),
            recipe("range-b", name="Public lab", include=["203.0.113.8", "fd00::1-fd00::4"], exclude=["fd00::2"],
                   allow_public=True, scanner_target="scanner-b")]
    before_targets = [t.to_dict() for t in ctx.inventory.all()]
    saved = commit(svc, rows)
    restarted_ctx = AppContext(Settings.from_env(state_dir=str(ctx.store.root)))
    restarted = DiscoveryService(restarted_ctx).scope_recipes()
    assert restarted == {k: saved[k] for k in ("revision", "recipes", "scopes")}
    assert [editable(r) for r in restarted["recipes"]] == rows
    assert all(r["original_expressions_known"] for r in restarted["recipes"])
    assert all(not s["allow_public"] and s["scanner_target"] is None for s in saved["scopes"] if s["cidr"].startswith("10."))
    assert all(s["allow_public"] and s["scanner_target"] == "scanner-b" for s in saved["scopes"] if not s["cidr"].startswith("10."))
    assert [t.to_dict() for t in ctx.inventory.all()] == before_targets
    assert svc.runs() == [] and svc.list_assets() == []
    event = [r for r in ctx.audit.records() if r["action"] == "discovery.scopes"][-1]
    assert event["details"]["recipes"] == rows and event["details"]["revision"] == saved["revision"]
    assert ctx.audit.verify().ok
    restarted_ctx.store.close()


def test_edit_one_recipe_preserves_other_grants_and_exclusions(ctx):
    scanner(ctx)
    svc = DiscoveryService(ctx)
    first = commit(svc, [recipe(), recipe("range-b", include=["fd00::/124"], exclude=["fd00::8/125"], scanner_target="scanner-b")])
    rows = [editable(r) for r in first["recipes"]]
    rows[0]["include"] = ["10.1.0.8-10.1.0.10"]
    second = commit(svc, rows, first["revision"])
    assert second["recipes"][1] == first["recipes"][1]
    assert [s for s in second["scopes"] if s["scanner_target"]] == [s for s in first["scopes"] if s["scanner_target"]]
    assert second["recipes"][1]["networks"] == ["fd00::/125"]
    assert not any(s.contains("fd00::8") for s in svc.scopes())
    with pytest.raises(ValueError, match="not inside"):
        svc._sweep_scopes(["fd00::8/128"], "quick")


@pytest.mark.parametrize("raw", [["10.1.0.0/24"], [{"cidr": "10.1.0.0/24", "allow_public": False}], []])
def test_legacy_load_never_invents_expressions_or_writes_state(ctx, raw):
    svc = DiscoveryService(ctx)
    ctx.store.write_json(svc.scopes_file, raw)
    first = svc.scope_recipes()
    assert svc.scope_recipes() == first
    assert ctx.store.read_json(svc.scopes_file) == raw
    for r in first["recipes"]:
        assert r["include"] is None and r["exclude"] is None and not r["original_expressions_known"]
    saved = commit(svc, [editable(r) for r in first["recipes"]])
    for r in saved["recipes"]:
        assert r["include"] is None and r["exclude"] is None


def test_legacy_conversion_is_explicit_and_other_legacy_policies_survive(ctx):
    svc = DiscoveryService(ctx)
    svc.set_scopes(["10.1.0.0/24", "10.2.0.0/24"], "IT1 Jones", "Existing plan")
    old = svc.scope_recipes()
    rows = [editable(r) for r in old["recipes"]]
    rows[0]["allow_public"] = True
    with pytest.raises(ValueError, match="explicitly converted"):
        commit(svc, rows)
    rows[0].update(include=["10.1.0.0/24"], exclude=["10.1.0.0/25"])
    new = commit(svc, rows)
    assert new["recipes"][0]["original_expressions_known"]
    assert new["recipes"][1] == old["recipes"][1]


@pytest.mark.parametrize("change", [{"include": ["10.1.0.0/24"]}, {"exclude": []}, {"allow_public": True},
                                     {"name": "Renamed"}, {"acknowledge_normalization": True}])
def test_preview_cannot_be_reused_after_input_mutation(ctx, change):
    svc = DiscoveryService(ctx)
    revision = svc.scope_recipes()["revision"]
    rows = [recipe()]
    p = svc.preview_scope_recipes(rows, revision)
    rows[0].update(change)
    with pytest.raises(ValueError, match="preview does not match"):
        svc.save_scope_recipes(rows, revision, p["fingerprint"], "IT1 Jones", "Reason")
    assert svc.scope_recipes()["revision"] == revision and svc.scopes() == []


def test_stale_revision_replay_and_compatibility_writer_refused(ctx):
    svc = DiscoveryService(ctx)
    revision = svc.scope_recipes()["revision"]
    p = svc.preview_scope_recipes([recipe()], revision)
    svc.set_scopes(["10.2.0.0/24"], "IT1 Other", "Another decision")
    current = svc.scope_recipes()
    with pytest.raises(ScopeRevisionConflict):
        svc.save_scope_recipes([recipe()], revision, p["fingerprint"], "IT1 Jones", "Stale decision")
    with pytest.raises(ScopeRevisionConflict):
        svc.preview_scope_recipes([recipe()], revision)
    assert svc.scope_recipes() == current


def test_concurrent_edit_conflicts_then_reload_preserves_both_changes(ctx):
    svc = DiscoveryService(ctx)
    saved = commit(svc, [recipe(), recipe("range-b", include=["10.2.0.1"], exclude=[])])
    barrier = Barrier(2)

    def edit(index):
        other_ctx = AppContext(Settings.from_env(state_dir=str(ctx.store.root)))
        other = DiscoveryService(other_ctx)
        rows = [editable(r) for r in saved["recipes"]]
        rows[index]["name"] = f"Operator {index} edit"
        preview = other.preview_scope_recipes(rows, saved["revision"])
        barrier.wait(timeout=10)
        try:
            other.save_scope_recipes(rows, saved["revision"], preview["fingerprint"], f"Operator {index}", "Concurrent review")
            return index, True
        except ScopeRevisionConflict:
            return index, False
        finally:
            other_ctx.store.close()

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(edit, (0, 1)))
    assert sorted(success for _, success in results) == [False, True]
    loser = next(index for index, success in results if not success)
    current = svc.scope_recipes()
    rows = [editable(r) for r in current["recipes"]]
    rows[loser]["name"] = f"Operator {loser} edit"
    final = commit(svc, rows, current["revision"])
    assert [r["name"] for r in final["recipes"]] == ["Operator 0 edit", "Operator 1 edit"]
    assert final["scopes"] == saved["scopes"]
    assert ctx.audit.verify().ok


@pytest.mark.parametrize("field,entries", [("include", ["10.1.0.9/24"]), ("exclude", ["10.1.0.5/30"])])
def test_host_bit_broadening_refused_until_exact_acknowledgement(ctx, field, entries):
    svc = DiscoveryService(ctx)
    rows = [recipe(**{field: entries})]
    p = svc.preview_scope_recipes(rows, svc.scope_recipes()["revision"])
    assert not p["preview"]["can_save"] and p["preview"]["normalizations"][0]["recipe_id"] == "range-a"
    with pytest.raises(ValueError, match="normalization"):
        commit(svc, rows)
    rows[0]["acknowledge_normalization"] = True
    assert commit(svc, rows)["recipes"][0][field] == entries


@pytest.mark.parametrize("value", ["１０.1.0.1", "10.1.0.1\u200b", "\u00a010.1.0.1", "fd00::1–fd00::4", "10.1.0.1\x00",
                                   "10.1.0.1\n", "fe80::1%eth0", "host.example", "10.1.0.9-10.1.0.1", 123, None])
def test_invalid_unicode_and_non_ip_expressions_never_persist(ctx, value):
    svc = DiscoveryService(ctx)
    before = svc.scope_recipes()
    with pytest.raises(ValueError):
        commit(svc, [recipe(include=[value])])
    assert svc.scope_recipes() == before


@pytest.mark.parametrize("changes", [{"allow_public": "false"}, {"acknowledge_normalization": 1}, {"id": "../x"},
                                     {"name": "\ud800"}, {"name": ""}, {"exclude": None}, {"scanner_target": ""}])
def test_invalid_recipe_metadata_fails_closed(ctx, changes):
    svc = DiscoveryService(ctx)
    with pytest.raises(ValueError):
        commit(svc, [recipe(**changes)])
    assert svc.scopes() == []


def test_public_policy_overlap_and_aggregate_limits(ctx):
    svc = DiscoveryService(ctx)
    with pytest.raises(ValueError, match="public address"):
        commit(svc, [recipe(include=["203.0.113.8"], exclude=[])])
    with pytest.raises(ValueError, match="conflicting"):
        commit(svc, [recipe(), recipe("range-b", allow_public=True)])
    with pytest.raises(ValueError, match="65536"):
        commit(svc, [recipe(include=["10.1.0.0/16"], exclude=[]), recipe("range-b", include=["fd00::1"], exclude=[])])
    with pytest.raises(ValueError, match="128"):
        commit(svc, [recipe(include=["10.1.0.1"] * 65, exclude=[]), recipe("range-b", include=["fd00::1"] * 64, exclude=[])])


def test_large_ipv6_counts_and_truncation_stay_exact(ctx):
    svc = DiscoveryService(ctx)
    rows = [recipe(include=["::/0"], exclude=["fd00::1"], allow_public=True)]
    p = svc.preview_scope_recipes(rows, svc.scope_recipes()["revision"])["preview"]
    assert p["address_count"] == str(2**128 - 1) and p["excluded_address_count"] == "1"
    assert not p["can_save"]
    fragmented = [recipe(f"range-{i}", include=["::/0"], exclude=["fd00::1"], allow_public=True) for i in range(3)]
    p = svc.preview_scope_recipes(fragmented, svc.scope_recipes()["revision"])["preview"]
    assert p["truncated"] and len(p["networks"]) == 256 and p["network_count"] > 256
    assert p["address_count"] == str(2**128 - 1) and not p["can_save"]


def test_exclusions_are_local_and_conflicting_overlaps_fail_closed(ctx):
    svc = DiscoveryService(ctx)
    rows = [recipe(include=["10.1.0.0/24"], exclude=["10.1.0.0/25"]),
            recipe("range-b", include=["10.1.0.0/25"], exclude=[], allow_public=True)]
    saved = commit(svc, rows)
    assert saved["preview"]["address_count"] == "256" and saved["preview"]["excluded_address_count"] == "0"
    assert len(saved["scopes"]) == 2
    rows[0]["exclude"] = []
    with pytest.raises(ValueError, match="conflicting"):
        commit(svc, rows)


def test_scanner_revocation_kill_and_actor_refusal_never_write(ctx):
    scanner(ctx)
    svc = DiscoveryService(ctx)
    rows = [recipe(scanner_target="scanner-b")]
    revision = svc.scope_recipes()["revision"]
    p = svc.preview_scope_recipes(rows, revision)
    ctx.inventory.update("scanner-b", in_scope=False)
    ctx.inventory.save()
    with pytest.raises(ValueError):
        svc.save_scope_recipes(rows, revision, p["fingerprint"], "IT1 Jones", "Reason")
    ctx.inventory.update("scanner-b", in_scope=True)
    ctx.inventory.save()
    for actor, reason in [("agent", "Reason"), ("IT1 Jones", " ")]:
        with pytest.raises((PermissionError, ValueError)):
            svc.save_scope_recipes(rows, revision, p["fingerprint"], actor, reason)
    ctx.killswitch.engage("IT1 Other", "Stop")
    with pytest.raises(KillSwitchEngaged):
        svc.save_scope_recipes(rows, revision, p["fingerprint"], "IT1 Jones", "Reason")
    assert svc.scope_recipes()["revision"] == revision and svc.scopes() == []


def test_deleting_one_recipe_or_clearing_is_explicit(ctx):
    svc = DiscoveryService(ctx)
    saved = commit(svc, [recipe(), recipe("range-b", include=["fd00::1"], exclude=[])])
    with pytest.raises(ValueError, match="entire included"):
        commit(svc, [recipe(include=["10.1.0.1"], exclude=["10.1.0.1"])])
    remaining = commit(svc, [editable(saved["recipes"][1])])
    assert remaining["scopes"] == [s for s in saved["scopes"] if s["cidr"].startswith("fd00")]
    assert commit(svc, [])["scopes"] == []


@pytest.mark.parametrize("change", ["remove", "broaden", "scanner", "public", "exclude"])
def test_active_grant_is_revoked_by_exact_scope_or_policy_replacement(ctx, change):
    scanner(ctx)
    svc = DiscoveryService(ctx)
    saved = commit(svc, [recipe(include=["10.1.0.0/28"], exclude=[])])
    chosen = svc._sweep_scopes(["10.1.0.1/32"], "quick")[0]
    rows = [editable(r) for r in saved["recipes"]]
    if change == "remove":
        rows = []
    elif change == "broaden":
        rows[0]["include"] = ["10.1.0.0/24"]
    elif change == "scanner":
        rows[0]["scanner_target"] = "scanner-b"
    elif change == "public":
        rows[0]["allow_public"] = True
    else:
        rows[0]["exclude"] = ["10.1.0.1"]
    commit(svc, rows)
    assert chosen.cidr == "10.1.0.1/32" and chosen.scanner_target is None
    with pytest.raises(PermissionError, match="revoked or replaced"):
        svc._guard_scope(chosen, "IT1 Jones")


def test_unrelated_recipe_edit_preserves_active_grant_and_sweep_scanner_cannot_be_overridden(ctx):
    svc = DiscoveryService(ctx)
    saved = commit(svc, [recipe(include=["10.1.0.0/28"], exclude=[]), recipe("range-b", include=["fd00::1"], exclude=[])])
    chosen = svc._sweep_scopes(["10.1.0.1/32"], "quick")[0]
    rows = [editable(r) for r in saved["recipes"]]
    rows[1]["include"] = ["fd00::2"]
    commit(svc, rows)
    svc._guard_scope(chosen, "IT1 Jones")
    with pytest.raises(ValueError, match="cannot override"):
        svc._sweep_scopes([{"cidr": "10.1.0.1/32", "scanner_target": "other-scanner"}], "quick")


def test_revocation_between_ping_and_ports_blocks_next_command(ctx, monkeypatch):
    from cyberthunder.discovery.models import DiscoveryRun
    from cyberthunder.discovery.service import SCOPE_PARTIAL
    from cyberthunder.discovery.sources import nmap
    svc = DiscoveryService(ctx)
    commit(svc, [recipe(include=["10.1.0.0/28"], exclude=[])])
    chosen = svc._sweep_scopes(None, "quick")[0]
    calls = []

    class NoNetwork:
        def close(self):
            calls.append("closed")

    svc.local_transport_factory = NoNetwork

    def ping(*args, **kwargs):
        calls.append("ping")
        commit(svc, [])
        return '<nmaprun><host><status state="up"/><address addr="10.1.0.1" addrtype="ipv4"/></host></nmaprun>'

    monkeypatch.setattr(nmap, "run_nmap", ping)
    run = DiscoveryRun(id="fixture-run", requested_by="IT1 Jones")
    _, state = svc._nmap(chosen, run)
    assert state == SCOPE_PARTIAL and calls == ["ping", "closed"]
    assert any("revoked or replaced" in e for e in run.errors)


@pytest.mark.parametrize("reason", ["Bad\x00reason", "Bad\ud800reason", "x" * 1001])
def test_invalid_reason_cannot_write_then_break_audit(ctx, reason):
    svc = DiscoveryService(ctx)
    before = svc.scope_recipes()
    p = svc.preview_scope_recipes([recipe()], before["revision"])
    with pytest.raises(ValueError):
        svc.save_scope_recipes([recipe()], before["revision"], p["fingerprint"], "IT1 Jones", reason)
    assert svc.scope_recipes() == before


def test_same_policy_duplicates_do_not_duplicate_effective_grants(ctx):
    svc = DiscoveryService(ctx)
    saved = commit(svc, [recipe(), recipe("range-b")])
    assert len(saved["recipes"]) == 2
    assert len(saved["scopes"]) == len(saved["recipes"][0]["networks"])


def test_regrant_of_identical_scope_in_same_timestamp_does_not_revive_running_sweep(ctx, monkeypatch):
    from cyberthunder.discovery import recipes
    from cyberthunder.discovery.models import DiscoveryScope
    monkeypatch.setattr(recipes, "DiscoveryScope", lambda **kwargs: DiscoveryScope(**kwargs, added_at="2026-11-05T12:00:00Z"))
    svc = DiscoveryService(ctx)
    first = commit(svc, [recipe(include=["10.1.0.1"], exclude=[])])
    chosen = svc._sweep_scopes(None, "quick")[0]
    commit(svc, [])
    second = commit(svc, [recipe(include=["10.1.0.1"], exclude=[])])
    assert first["scopes"][0]["added_at"] == second["scopes"][0]["added_at"]
    assert first["scopes"][0]["grant_id"] != second["scopes"][0]["grant_id"]
    with pytest.raises(PermissionError, match="revoked or replaced"):
        svc._guard_scope(chosen, "IT1 Jones")
