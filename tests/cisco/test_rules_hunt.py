import json

import pytest

from cyberthunder.adapters.cisco import CiscoIOSAdapter
from cyberthunder.adapters.cisco.hunt import hunt_config
from cyberthunder.adapters.cisco.parser import parse_config
from cyberthunder.adapters.cisco.rules import RULES_JSON, applicable_rules, evaluate, load_rules
from cyberthunder.adapters.cisco.snippet import apply_snippet
from cyberthunder.findings.schema import RE_CCI, RE_GROUP_ID, RE_STIG_RULE

from .helpers import CLEAN_ROUTER, CLEAN_SWITCH, ROUTER_OPTS, SEEDED_ROUTER, SEEDED_SWITCH, read

SW_OPTS = CiscoIOSAdapter().demo_targets()[0].options


def _results(path, opts):
    return {r.stig_id: (p, e) for r, p, e in evaluate(parse_config(read(path)), opts)}


def test_rules_load_from_research_file():
    rules = load_rules()
    data = json.loads(RULES_JSON.read_text(encoding="utf-8"))
    assert len(rules) == len(data) == 30
    fams = [r.family for r in rules]
    assert fams.count("NDM") == 20 and fams.count("L2S") == 5 and fams.count("RTR") == 5
    for r in rules:
        assert RE_GROUP_ID.fullmatch(r.group_id) and RE_STIG_RULE.fullmatch(r.rule_id)
        assert r.cci and all(RE_CCI.fullmatch(c) for c in r.cci)
        assert r.severity in ("high", "medium", "low") and r.disruption in ("low", "medium")


def test_device_role_selects_families():
    assert {r.family for r in applicable_rules(parse_config(read(SEEDED_SWITCH)))} == {"NDM", "L2S"}
    assert {r.family for r in applicable_rules(parse_config(read(SEEDED_ROUTER)))} == {"NDM", "RTR"}


def test_every_rule_fails_on_a_seeded_config_and_passes_on_clean():
    seeded = {**_results(SEEDED_SWITCH, SW_OPTS), **{k: v for k, v in _results(SEEDED_ROUTER, ROUTER_OPTS).items()
                                                     if v[0] is False}}
    clean = {**_results(CLEAN_SWITCH, SW_OPTS), **_results(CLEAN_ROUTER, ROUTER_OPTS)}
    for r in load_rules():
        assert seeded[r.stig_id][0] is False, f"{r.stig_id} should fail on a seeded config"
        assert clean[r.stig_id][0] is True, f"{r.stig_id} should pass on clean: {clean[r.stig_id][1]}"


def test_seeded_switch_fails_at_least_twelve():
    fails = [k for k, (p, _) in _results(SEEDED_SWITCH, SW_OPTS).items() if p is False]
    assert len(fails) >= 12


@pytest.mark.parametrize("path,opts", [(SEEDED_SWITCH, SW_OPTS), (SEEDED_ROUTER, ROUTER_OPTS)])
def test_fixing_every_rule_reaches_compliance_and_fixes_are_idempotent(path, opts):
    cur = read(path)
    for r in applicable_rules(parse_config(cur), opts):
        m = parse_config(cur)
        if r.check(m, opts)[0] is False:
            snip = r.fix_snippet(m, opts)
            assert snip, r.stig_id
            nxt = apply_snippet(cur, snip)
            assert apply_snippet(nxt, snip) == nxt, f"{r.stig_id} fix not idempotent"
            assert r.check(parse_config(nxt), opts)[0] is True, r.stig_id
            back = apply_snippet(nxt, r.rollback_snippet(m, opts))
            assert r.check(parse_config(back), opts)[0] is False, f"{r.stig_id} rollback snippet did not undo"
            cur = nxt
    assert all(p is True for _, p, _ in evaluate(parse_config(cur), opts))


def test_external_rules_undecided_without_external_interface():
    cfg = read(SEEDED_ROUTER).replace("description WAN uplink to fleet NOC - EXTERNAL", "description core link")
    res = _results_text(cfg, {})
    assert res["CISC-RT-000190"][0] is None and res["CISC-RT-000330"][0] is None
    res2 = _results_text(cfg, {"external_interfaces": ["GigabitEthernet0/0/0"]})
    assert res2["CISC-RT-000190"][0] is False


def _results_text(text, opts):
    return {r.stig_id: (p, e) for r, p, e in evaluate(parse_config(text), opts)}


def test_missing_org_values_give_empty_fix():
    m = parse_config(read(SEEDED_SWITCH))
    rule = next(r for r in load_rules() if r.stig_id == "CISC-ND-001030")
    assert rule.fix_snippet(m, {}) == ""
    assert "ntp server 10.1.2.10 key 1" in rule.fix_snippet(m, SW_OPTS)


EXPECTED_SWITCH_HUNT = {
    "hunt:cisco:unknown_user:netops2": "T1136.001",
    "hunt:cisco:snmp_community:private": "T1602.001",
    "hunt:cisco:snmp_community:public": "T1602.001",
    "hunt:cisco:http_server": "T1190",
    "hunt:cisco:eem_applet:CFG-BACKUP": "T1053",
    "hunt:cisco:static_route:10.10.10.0/24": "T1599",
    "hunt:cisco:log_host:10.10.10.10": "T1020",
    "hunt:cisco:telnet_vty:vty_0_4": "T1021",
    "hunt:cisco:telnet_vty:vty_5_15": "T1021",
}


def test_hunt_finds_every_switch_seed():
    hits = {h.rule_id: h for h in hunt_config(parse_config(read(SEEDED_SWITCH)), SW_OPTS)}
    assert set(hits) == set(EXPECTED_SWITCH_HUNT)
    for rid, tech in EXPECTED_SWITCH_HUNT.items():
        assert tech in hits[rid].attack and hits[rid].remove_lines
    assert "T1602.002" in hits["hunt:cisco:eem_applet:CFG-BACKUP"].attack


def test_hunt_router_seeds_and_clean_configs():
    hits = {h.rule_id for h in hunt_config(parse_config(read(SEEDED_ROUTER)), ROUTER_OPTS)}
    assert hits == {"hunt:cisco:tunnel:Tunnel99", "hunt:cisco:acl_permit_any:EXTERNAL-IN"}
    assert hunt_config(parse_config(read(CLEAN_SWITCH)), SW_OPTS) == []
    assert hunt_config(parse_config(read(CLEAN_ROUTER)), ROUTER_OPTS) == []


def test_hunt_kron_tclsh_and_logging_disabled():
    cfg = ("hostname x\nusername admin privilege 15 secret 9 $9$x\nno logging on\n"
           "kron policy-list NIGHT\n cli tclsh flash:/beacon.tcl\nkron occurrence RUN at 2:00 recurring\n"
           " policy-list NIGHT\nevent manager applet OK\n event syslog pattern LINK\n action 1.0 syslog msg hi\n")
    hits = {h.rule_id: h for h in hunt_config(parse_config(cfg), {"known_users": ["admin"]})}
    assert "T1059" in hits["hunt:cisco:kron:NIGHT"].attack
    assert hits["hunt:cisco:kron:NIGHT"].remove_lines == ["no kron occurrence RUN", "no kron policy-list NIGHT"]
    assert hits["hunt:cisco:logging_disabled"].remove_lines == ["logging on"]
    assert "hunt:cisco:eem_applet:OK" not in hits          # a benign applet is not flagged
    fixed = apply_snippet(cfg, "\n".join(hits["hunt:cisco:kron:NIGHT"].remove_lines))
    assert "kron" not in fixed


def test_hunt_priv15_without_known_list_and_unsafe_names():
    cfg = "hostname x\nusername admin privilege 15 secret 9 $9$x\nusername ops privilege 1 secret 9 $9$y\n"
    hits = hunt_config(parse_config(cfg), {})
    assert [h.item for h in hits] == ["admin"]          # only privilege 15 is suspicious without a list
