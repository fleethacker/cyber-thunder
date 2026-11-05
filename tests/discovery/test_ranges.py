"""Scope preview uses interval arithmetic, never host enumeration or DNS."""
import ipaddress

import pytest

from cyberthunder.discovery.ranges import preview_ranges
from cyberthunder.discovery.models import DiscoveryScope
from cyberthunder.discovery.sources.nmap import build_command, build_ping_command


def test_overlap_exclusions_and_single_addresses():
    result = preview_ranges(["192.168.1.1/24", "192.168.1.8-192.168.1.20", "192.168.2.1"],
                            ["192.168.1.0/25", "192.168.1.128-192.168.1.254", "10.0.0.1"], acknowledge_normalization=True)
    assert result["networks"] == ["192.168.1.255/32", "192.168.2.1/32"]
    assert result["input_address_count"] == "257" and result["excluded_address_count"] == "255"
    assert result["address_count"] == "2" and result["can_save"]


def test_ipv6_and_mixed_family_counts_without_enumeration(monkeypatch):
    monkeypatch.setattr(ipaddress.IPv6Network, "__iter__", lambda *args: pytest.fail("enumerated IPv6 hosts"))
    monkeypatch.setattr(ipaddress.IPv6Network, "hosts", lambda *args: pytest.fail("enumerated IPv6 hosts"))
    result = preview_ranges(["fd00::/64", "10.0.0.1"], ["fd00::1-fd00::ffff"])
    assert result["input_address_count"] == str(2**64 + 1)
    assert result["excluded_address_count"] == "65535"
    assert result["address_count"] == str(2**64 - 65534)
    assert not result["can_save"] and len(result["networks"]) <= 256
    small = preview_ranges(["fd00::1-fd00::4", "10.0.0.1"], ["fd00::2"])
    assert small["can_save"] and small["address_count"] == "4"
    assert small["networks"] == ["10.0.0.1/32", "fd00::1/128", "fd00::3/128", "fd00::4/128"]


def test_huge_exclusions_can_reduce_scope_to_bounded_effective_space():
    result = preview_ranges(["::/0"], ["::-fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fd00::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"])
    assert result["networks"] == ["fd00::/128"] and result["address_count"] == "1" and result["can_save"]


def test_fragmented_output_is_bounded():
    exclusions = [str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fd00::")) + (i << 64) + 1)) for i in range(120)]
    result = preview_ranges(["fd00::/8"], exclusions)
    assert result["network_count"] > 256 and len(result["networks"]) == 256
    assert result["truncated"] and not result["can_save"]


@pytest.mark.parametrize("entry", ["host.example", "8.8.8.8; id", "10.0.0.5-10.0.0.1", "10.0.0.1-::1",
                                  "fe80::1%eth0", "10.0.0.1,10.0.0.2", "", "x" * 257])
def test_invalid_scope_syntax(entry):
    with pytest.raises(ValueError):
        preview_ranges([entry])


def test_limits_public_decision_and_explicit_clear():
    assert not preview_ranges(["8.8.8.8"])["can_save"]
    assert preview_ranges(["8.8.8.8"], allow_public=True)["can_save"]
    assert preview_ranges(["10.0.0.0/16"])["can_save"]
    assert not preview_ranges(["10.0.0.0/16", "10.2.0.1"])["can_save"]
    assert preview_ranges([])["can_save"] and preview_ranges([])["address_count"] == "0"
    assert not preview_ranges(["10.0.0.1"], ["10.0.0.1"])["can_save"]
    assert not preview_ranges([], ["10.0.0.1"])["can_save"]
    with pytest.raises(ValueError):
        preview_ranges(["10.0.0.1"] * 129)
    with pytest.raises(ValueError):
        preview_ranges(["10.0.0.1"], allow_public="true")


def test_effective_networks_drive_existing_nmap_commands():
    preview = preview_ranges(["fd00::/124"], ["fd00::8/125"])
    scopes = [DiscoveryScope(cidr=n) for n in preview["networks"]]
    assert preview["networks"] == ["fd00::/125"]
    assert "-6" in build_ping_command(scopes) and "fd00::/125" in build_command(scopes)
    with pytest.raises(ValueError, match="outside"):
        build_command(scopes, hosts=["fd00::8"])
    with pytest.raises(ValueError, match="separate"):
        build_ping_command([*scopes, DiscoveryScope("10.0.0.0/24")])
    assert "-6" not in build_ping_command(["10.0.0.0/24"])


@pytest.mark.parametrize("entry,canonical", [("192.168.1.20/24", "192.168.1.0/24"), ("fd00::1234/112", "fd00::/112")])
def test_host_bit_normalization_is_explicit_and_requires_acknowledgment(entry, canonical):
    result = preview_ranges([entry])
    assert result["normalizations"] == [{"field": "include", "input": entry, "normalized": canonical}]
    assert result["requires_normalization_acknowledgment"] and not result["can_save"]
    assert preview_ranges([entry], acknowledge_normalization=True)["can_save"]
    assert not preview_ranges([canonical])["requires_normalization_acknowledgment"]


def test_exclusion_host_bits_also_require_acknowledgment():
    result = preview_ranges(["10.0.0.0/24"], ["10.0.0.9/28"])
    assert result["normalizations"] == [{"field": "exclude", "input": "10.0.0.9/28", "normalized": "10.0.0.0/28"}]
    assert not result["can_save"] and result["address_count"] == "240"
