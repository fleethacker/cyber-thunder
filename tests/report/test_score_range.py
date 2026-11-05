"""Detection score against the real answer keys: one simulated scan plus one simulated discovery sweep must
find every seeded item in every key under range/answer_key.

Not scored: the router section nested inside cisco_ios.json (target rtr-01, a file-transport host that the
demo inventory does not load) and linux.json `also_seeded` (secondary indicators without an item id).
"""
import json

import pytest

from cyberthunder import demo
from cyberthunder.config import Settings
from cyberthunder.context import AppContext
from cyberthunder.findings.schema import Finding
from cyberthunder.report.score import _matches, load_answer_keys, score

from .conftest import FIX

KEYS = FIX.parents[2] / "range" / "answer_key"


@pytest.fixture(scope="module")
def simulated(tmp_path_factory):
    state = tmp_path_factory.mktemp("state")
    mp = pytest.MonkeyPatch()
    mp.setenv("CT_STATE_DIR", str(state))
    mp.delenv("CT_KILL", raising=False)
    mp.delenv("CT_ANSWER_KEY_DIR", raising=False)
    try:
        # Scoring consumes deterministic scan output, not background model work.
        ctx = AppContext(Settings.from_env(state_dir=state, explain_precompute=False, llm_backend="template"))
        demo.load(ctx, "sailor1")
        run = ctx.scanner.start(requested_by="sailor1", background=False)
        ctx.discovery.sweep(mode="simulated", actor="sailor1", background=False)
        yield ctx, run.id
    finally:
        mp.undo()


def test_every_answer_key_item_is_found_on_the_simulated_range(simulated):
    ctx, sid = simulated
    res = score(ctx, sid, KEYS)
    missed = [(i["key"], i["id"], i["what"]) for i in res["items"] if not i["found"]]
    assert missed == []
    assert res["not_scanned"] == 0
    keys = {i["key"] for i in res["items"]}
    assert keys == {"cisco_ios", "containers", "discovery", "kubernetes", "linux", "windows"}
    assert res["share"] == 1.0 and all(k["share"] == 1.0 for k in res["by_kind"].values())


@pytest.mark.parametrize("key", ["cisco_ios", "containers", "discovery", "kubernetes", "linux", "windows"])
def test_each_key_scores_full_marks(simulated, key):
    ctx, sid = simulated
    items = [i for i in score(ctx, sid, KEYS)["items"] if i["key"] == key]
    assert items and all(i["found"] for i in items), [i["id"] for i in items if not i["found"]]
    # an item names one seeded thing: it is credited to findings on that object, not to a whole class
    if key in ("containers", "kubernetes"):
        assert all(len(i["finding_ids"]) == 1 for i in items)


def test_linux_hunt_items_match_by_check_prefix(simulated):
    ctx, sid = simulated
    by = {i["id"]: i for i in score(ctx, sid, KEYS)["items"] if i["key"] == "linux"}
    found = {f.id: f for f in ctx.store.load_findings(sid)}
    for n in range(1, 7):
        it = by[f"I{n}"]
        assert it["found"]
        assert all(found[x].rule_id.startswith("hunt:linux:") for x in it["finding_ids"])


def test_discovery_items_need_a_finished_sweep(tmp_path, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(tmp_path))
    ctx = AppContext(Settings.from_env(state_dir=tmp_path, explain_precompute=False, llm_backend="template"))
    demo.load(ctx, "sailor1")
    sid = ctx.scanner.start(["sim-linux-01"], requested_by="sailor1", background=False).id
    res = score(ctx, sid, KEYS)
    disc = [i for i in res["items"] if i["key"] == "discovery"]
    assert disc and not any(i["found"] for i in disc) and not any(i["scanned"] for i in disc)
    # hosts this scan did not cover are reported as not scanned, never matched against another host
    other = [i for i in res["items"] if i["key"] in ("windows", "kubernetes", "containers")]
    assert other and not any(i["found"] or i["scanned"] for i in other)
    assert all(i["found"] for i in res["items"] if i["key"] == "linux")


# -- the matching rule ---------------------------------------------------------------------------
def _f(rule_id, rule_version=None, refs=(), host="h", tags=()):
    from cyberthunder.findings.schema import extract_references
    return Finding(host=host, source="t", rule_id=rule_id, rule_version=rule_version, title="t", severity="high",
                   status="open", references=extract_references([rule_id, *refs]), tags=list(tags))


def _item(**kw):
    base = {"check_id": None, "detector": None, "fix_ref": None, "qualifier": None, "address": None}
    return {**base, **kw}


@pytest.mark.parametrize("item, finding, ok", [
    (_item(check_id="RHEL-09-255045"), _f("xccdf_rule_x", "RHEL-09-255045"), True),          # rule_version
    (_item(check_id="hunt:cisco:http_server"), _f("hunt:cisco:http_server"), True),           # rule_id
    (_item(check_id="CNTR-K8-000360"), _f("k8s:CNTR-K8-000360"), True),                       # ":" + id suffix
    (_item(check_id="hunt:linux:rogue_unit"), _f("hunt:linux:rogue_unit:kworkerd.service"), True),  # prefix
    (_item(check_id="hunt:linux:rogue"), _f("hunt:linux:rogue_unit:kworkerd.service"), False),      # not a word prefix
    (_item(check_id="CVE-2026-1111"), _f("cve:x", refs=["CVE-2026-1111"]), True),             # citation
    (_item(check_id="RHEL-09-232xxx"), _f("x", "RHEL-09-232261"), True),                      # wildcard
    (_item(check_id="CIS-Docker-5.4", qualifier="ops-agent"),
     _f("containers:cis:5.4:ops-agent", "CIS-Docker-5.4"), True),
    (_item(check_id="CIS-Docker-5.4", qualifier="ops-agent"),
     _f("containers:cis:5.4:other", "CIS-Docker-5.4"), False),                                # wrong container
    (_item(check_id="k8s:hunt:host-escape", qualifier="apps/pod/kube-proxy-helper"),
     _f("k8s:hunt:host-escape:apps/pod/kube-proxy-helper", "k8s:hunt:host-escape"), True),
    (_item(check_id="discovery:unknown_asset", address="192.168.56.66"),
     _f("discovery:unknown_asset", host="discovered:192.168.56.66"), True),
    (_item(check_id="discovery:unknown_asset", address="192.168.56.66"),
     _f("discovery:unknown_asset", host="discovered:192.168.56.3"), False),
    (_item(check_id="discovery:new_listener", address="first linux target"),
     _f("discovery:new_listener", host="sim-linux-01"), True),
    (_item(detector="hunt.accounts"), _f("hunt.accounts.uid0_dup"), True),
    (_item(detector="hunt.admin_member", fix_ref="windows:hunt:remove_admin_member"),
     Finding(host="h", source="t", rule_id="win:hunt:admin_member:x", title="t", severity="high", status="open",
             fix_ref="windows:hunt:remove_admin_member"), True),
])
def test_matches(item, finding, ok):
    assert _matches(item, finding) is ok


def test_loader_reads_rule_object_and_container_fields(tmp_path):
    (tmp_path / "k.json").write_text(json.dumps({"target": "t", "sim_target": "s", "items": [
        {"id": "A", "rule": "k8s:cis:5.2.2", "object": "apps/deployment/web"},
        {"id": "B", "rule": "CIS-Docker-5.4", "container": "ops-agent"}]}), encoding="utf-8")
    items, _ = load_answer_keys(tmp_path)
    assert [(i["check_id"], i["qualifier"], i["sim_target"]) for i in items] == [
        ("k8s:cis:5.2.2", "apps/deployment/web", "s"), ("CIS-Docker-5.4", "ops-agent", "s")]


def test_target_scope_never_falls_back_to_other_hosts(node, tmp_path):
    from .conftest import SCAN
    d = tmp_path / "keys"
    d.mkdir()
    (d / "a.json").write_text(json.dumps({"target": "ghost-01", "items": [
        {"id": "G1", "check_id": "RHEL-09-255040", "what": "only on rhel-01"}]}), encoding="utf-8")
    (d / "b.json").write_text(json.dumps({"target": "acd-target-01", "sim_target": "sw-01", "items": [
        {"id": "S1", "check_id": "CCI-000196", "what": "on sw-01"},
        {"id": "S2", "check_id": "RHEL-09-255040", "what": "on rhel-01, not sw-01"}]}), encoding="utf-8")
    sw = node.findings["sw"]
    node.store.save_findings(SCAN, [f for f in node.findings.values() if f.id != sw.id]
                             + [Finding.from_dict({**sw.to_dict(), "status": "not_a_finding"})])
    res = score(node, SCAN, d)
    by = {i["id"]: i for i in res["items"]}
    assert not by["G1"]["found"] and not by["G1"]["scanned"] and res["not_scanned"] == 1
    # sw-01 is scanned and fully remediated: its items miss rather than borrow rhel-01's findings
    assert by["S1"]["scanned"] and not by["S1"]["found"] and not by["S2"]["found"]
