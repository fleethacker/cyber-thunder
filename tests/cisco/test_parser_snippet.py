from cyberthunder.adapters.cisco.parser import format_vlan_list, parse_config, parse_vlan_list, render, tokenize
from cyberthunder.adapters.cisco.snippet import apply_snippet, inverse_snippet, setting_key, unified_diff

from .helpers import CLEAN_ROUTER, CLEAN_SWITCH, SEEDED_ROUTER, SEEDED_SWITCH, read


def test_round_trip_is_byte_exact():
    for p in (SEEDED_SWITCH, CLEAN_SWITCH, SEEDED_ROUTER, CLEAN_ROUTER):
        text = read(p)
        assert render(tokenize(text)) == text, p.name


def test_seeded_switch_model():
    m = parse_config(read(SEEDED_SWITCH))
    assert m.hostname == "swi-01" and m.version == "17.9"
    assert [u.name for u in m.users] == ["admin", "netops2"]
    assert m.users[1].privilege == 15 and m.users[1].secret_type == "5"
    assert m.enable_password and m.enable_secret
    assert m.aaa_new_model and m.aaa_servers[0].address == "10.1.1.20"
    vty = {b.name: b for b in m.vty_lines}
    assert vty["vty 0 4"].exec_timeout == (30, 0) and vty["vty 0 4"].transport_input == ["telnet", "ssh"]
    assert vty["vty 0 4"].access_class_in == "MGMT-ONLY" and vty["vty 5 15"].exec_timeout is None
    assert m.line("con")[0].exec_timeout == (0, 0)
    gi2 = m.interfaces["GigabitEthernet1/0/2"]
    assert gi2.switchport_mode == "access" and gi2.access_vlan == 20 and gi2.portfast and not gi2.bpduguard
    assert m.interfaces["GigabitEthernet1/0/1"].switchport_mode == "trunk"
    assert m.interfaces["GigabitEthernet1/0/5"].shutdown
    assert m.interfaces["Vlan10"].ip_address == "10.1.1.2"
    assert {c.name: c.access for c in m.snmp_communities} == {"public": "RO", "private": "RW"}
    assert m.snmp_groups[0].level == "auth"
    assert [s.address for s in m.ntp_servers] == ["10.1.1.10"] and m.ntp_trusted_keys == ["1"]
    assert not m.ntp_authenticate
    assert [h.address for h in m.logging_hosts] == ["10.10.10.10"] and m.logging_buffered == 4096
    assert "motd" in m.banners and "login" not in m.banners
    assert m.http_server and m.http_auth == "local" and m.ssh_version == 2
    assert m.applets[0].name == "CFG-BACKUP" and "tftp" in " ".join(m.applets[0].actions)
    assert [r.prefix for r in m.routes] == ["0.0.0.0/0", "10.10.10.0/24"]
    assert m.acls["MGMT-ONLY"].kind == "standard"
    assert m.vtp["mode"] == "transparent" and m.spanning_tree["mode"] == "rapid-pvst"


def test_clean_switch_and_router_models():
    c = parse_config(read(CLEAN_SWITCH))
    assert c.archive_log_enabled and c.login_block_for == {"block_for": 900, "attempts": 3, "within": 120}
    assert c.common_criteria_min_length == 15 and c.ntp_authenticate and len(c.ntp_servers) == 2
    assert "U.S. Government" in c.banners["login"] and c.dhcp_snooping and c.dhcp_snooping_vlans == {20, 30}
    assert c.ssh_mac == ["hmac-sha2-512", "hmac-sha2-256"] and not c.http_server
    r = parse_config(read(SEEDED_ROUTER))
    t = r.interfaces["Tunnel99"]
    assert t.is_tunnel and t.tunnel_destination == "198.51.100.77" and t.tunnel_source == "GigabitEthernet0/0/0"
    assert r.interfaces["GigabitEthernet0/0/1"].directed_broadcast
    wan = r.interfaces["GigabitEthernet0/0/0"]
    assert wan.proxy_arp and wan.redirects and wan.ip_access_group_in is None
    assert "permit ip any any" in r.acls["EXTERNAL-IN"].entries and r.acls["EXTERNAL-IN"].kind == "extended"
    assert r.logging_buffered is None and r.logging_trap == 6


def test_parse_extras_kron_numbered_acl_and_vlan_lists():
    m = parse_config("hostname x\naccess-list 10 permit 10.0.0.0 0.0.0.255\naccess-list 101 permit ip any any\n"
                     "kron policy-list P\n cli copy running-config tftp://1.2.3.4/x\n"
                     "kron occurrence O at 3:00 recurring\n policy-list P\nno logging on\nlogging trap alerts\n")
    assert m.acls["10"].kind == "standard" and m.acls["101"].kind == "extended" and m.acls["101"].numbered
    assert m.kron_policies[0].cli == ["copy running-config tftp://1.2.3.4/x"]
    assert m.kron_occurrences[0].policies == ["P"] and not m.logging_on and m.logging_trap == 1
    assert parse_vlan_list("1-3,10") == {1, 2, 3, 10} and len(parse_vlan_list(None)) == 4094
    assert format_vlan_list({1, 2, 3, 10, 12, 13}) == "1-3,10,12-13"
    assert parse_vlan_list("except 1") == set(range(2, 4095))


BASE = "hostname r1\n!\nip http server\nservice timestamps log datetime msec\n!\ninterface Gi1\n ip address 10.0.0.1 " \
       "255.255.255.0\n!\nline vty 0 4\n exec-timeout 30 0\n transport input telnet ssh\n!\nend\n"


def test_apply_global_block_and_no_forms():
    out = apply_snippet(BASE, "no ip http server\nservice password-encryption\nline vty 0 4\n exec-timeout 5 0\n"
                              " transport input ssh\ninterface Gi1\n no ip proxy-arp")
    m = parse_config(out)
    assert not m.http_server and "no ip http server" in m.global_lines
    assert m.services["password-encryption"]
    assert m.vty_lines[0].exec_timeout == (5, 0) and m.vty_lines[0].transport_input == ["ssh"]
    assert not m.interfaces["Gi1"].proxy_arp
    assert out.index("service password-encryption") < out.index("line vty")       # placed with its peers
    assert out.rstrip().endswith("end")


def test_apply_is_idempotent_and_creates_missing_blocks():
    snip = "interface Gi9\n shutdown\narchive\n log config\n  logging enable\nlogging host 10.1.1.5"
    once = apply_snippet(BASE, snip)
    assert apply_snippet(once, snip) == once
    m = parse_config(once)
    assert m.interfaces["Gi9"].shutdown and m.archive_log_enabled and m.logging_hosts[0].address == "10.1.1.5"
    assert once.index("interface Gi9") < once.index("line vty")


def test_no_removes_whole_stanza_and_keyed_lines():
    cfg = BASE + "interface Tunnel9\n ip address 1.1.1.1 255.255.255.252\nusername bob privilege 15 secret 5 $1$x\n"
    out = apply_snippet(cfg, "no interface Tunnel9\nno username bob")
    assert "Tunnel9" not in out and "username bob" not in out and "ip address 1.1.1.1" not in out


def test_banner_replace():
    out = apply_snippet(BASE, "banner login ^C\nUSG notice\n^C")
    assert parse_config(out).banners["login"] == "USG notice"
    again = apply_snippet(out, "banner login ^C\nnew text\n^C")
    assert parse_config(again).banners["login"] == "new text" and again.count("banner login") == 1


def test_inverse_restores_settings():
    snip = "no ip http server\nline vty 0 4\n exec-timeout 5 0\n transport input ssh\ninterface Gi1\n no ip proxy-arp"
    after = apply_snippet(BASE, snip)
    inv = inverse_snippet(BASE, after)
    back = apply_snippet(after, inv)
    a, b = parse_config(BASE), parse_config(back)
    assert b.http_server == a.http_server and b.vty_lines[0].exec_timeout == (30, 0)
    assert b.vty_lines[0].transport_input == ["telnet", "ssh"] and b.interfaces["Gi1"].proxy_arp
    assert sorted(b.global_lines) == sorted(a.global_lines)


def test_setting_key_and_diff():
    assert setting_key("exec-timeout 5 0") == setting_key("exec-timeout 30 0") == "exec-timeout"
    assert setting_key("username a privilege 15") == "username a"
    assert setting_key("ip access-group X in") != setting_key("ip access-group X out")
    assert setting_key("ip route 1.0.0.0 255.0.0.0 2.2.2.2") is None
    d = unified_diff(BASE, apply_snippet(BASE, "no ip http server"))
    assert "-ip http server" in d and "+no ip http server" in d
    assert unified_diff(BASE, BASE) == ""


def test_crlf_config_is_preserved():
    crlf = BASE.replace("\n", "\r\n")
    out = apply_snippet(crlf, "service password-encryption")
    assert "\r\n" in out and "\n" not in out.replace("\r\n", "")


def test_inverse_keeps_same_child_line_under_two_blocks():
    from cyberthunder.adapters.cisco.snippet import apply_snippet, inverse_snippet
    before = ("hostname r1\n!\nip access-list extended OUTSIDE-IN\n permit ip any any\n deny ip any any log\n"
              "ip access-list extended WAN-IN\n permit ip any any\n deny ip any any log\n!\nend\n")
    snip = ("ip access-list extended OUTSIDE-IN\n no permit ip any any\n"
            "ip access-list extended WAN-IN\n no permit ip any any")
    inv = inverse_snippet(before, apply_snippet(before, snip)).split("\n")
    assert inv.count(" permit ip any any") == 2
    assert inv.index("ip access-list extended WAN-IN") < len(inv) - 1
