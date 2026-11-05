"""LinuxAdapter running a DISA datastream already on the host (options.benchmark_path) through recorded
`oscap info` / `oscap xccdf eval` output."""
import shutil
from pathlib import Path

import pytest

from cyberthunder.adapters.linux import LinuxAdapter
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.fixture import FixtureTransport

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "scap" / "linux_disa"
DISA_DS = "/var/lib/cyberthunder/scap/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml"


@pytest.fixture
def transport(tmp_path):
    root = tmp_path / "fixture"
    shutil.copytree(FIXTURE, root)        # the fixture transport logs unmatched commands into its directory
    # the results file oscap writes on the host (kept at the fixture root: tmp/ paths are not committed)
    (root / "files" / "tmp").mkdir(parents=True)
    shutil.copyfile(root / "oscap_results.xml", root / "files" / "tmp" / "ct-oscap-results.xml")
    return FixtureTransport(root)


def _target(**options):
    return Target(id="rhel9-01", name="rhel9-01", asset_type="linux", transport="fixture", options=options)


def _evals(transport):
    return [c for c in transport.calls if c.startswith("oscap xccdf eval")]


def test_benchmark_path_runs_disa_datastream_with_profile_from_oscap_info(transport, tmp_path):
    adapter = LinuxAdapter()
    target = _target(benchmark_path=DISA_DS)
    col = adapter.collect(target, transport, tmp_path / "w", modules=["check"])
    evals = _evals(transport)
    assert len(evals) == 1
    assert "--profile xccdf_mil.disa.stig_profile_MAC-1_Classified " in evals[0]
    assert evals[0].endswith(DISA_DS)
    assert f"oscap info {DISA_DS}" in transport.calls
    assert not any(c.startswith("ls /usr/share/xml/scap/ssg") for c in transport.calls)
    assert col.raw["oscap"] == {"datastream": DISA_DS, "profile": "xccdf_mil.disa.stig_profile_MAC-1_Classified",
                                "source": "benchmark_path"}
    findings = [f for f in adapter.check(target, col) if f.source == "openscap"]
    by = {f.rule_version: f for f in findings}
    assert by["RHEL-09-611025"].status.value == "open"
    assert by["RHEL-09-211015"].status.value == "not_a_finding"
    assert all(f.references for f in findings)


def test_explicit_profile_skips_oscap_info(transport, tmp_path):
    adapter = LinuxAdapter()
    target = _target(benchmark_path=DISA_DS, profile="xccdf_mil.disa.stig_profile_MAC-2_Public")
    adapter.collect(target, transport, tmp_path / "w", modules=["check"])
    assert "--profile xccdf_mil.disa.stig_profile_MAC-2_Public " in _evals(transport)[0]
    assert not any(c.startswith("oscap info") for c in transport.calls)


def test_unreadable_benchmark_path_is_reported_not_scanned(transport, tmp_path):
    adapter = LinuxAdapter()
    col = adapter.collect(_target(benchmark_path="/root/missing-ds.xml"), transport, tmp_path / "w", modules=["check"])
    assert not _evals(transport)
    assert any("benchmark_path /root/missing-ds.xml is not readable" in e for e in col.errors)


def test_without_benchmark_path_the_ssg_content_and_stig_profile_are_used(transport, tmp_path, monkeypatch):
    from cyberthunder.adapters.base import AssetFacts
    adapter = LinuxAdapter()
    monkeypatch.setattr(adapter, "_facts_from", lambda commands: AssetFacts(model="rhel", os_version="9.4"))
    adapter.collect(_target(), transport, tmp_path / "w", modules=["check"])
    ev = _evals(transport)[0]
    assert "--profile xccdf_org.ssgproject.content_profile_stig " in ev
    assert ev.endswith("/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")


@pytest.mark.parametrize("info, expected", [
    ("Id: xccdf_mil.disa.stig_profile_CAT_I_Only\nId: xccdf_mil.disa.stig_profile_MAC-3_Public\n",
     "xccdf_mil.disa.stig_profile_MAC-3_Public"),
    ("Id: xccdf_mil.disa.stig_profile_CAT_I_Only\n", "xccdf_mil.disa.stig_profile_CAT_I_Only"),
    ("Id: xccdf_org.ssgproject.content_profile_cis\n", "xccdf_org.ssgproject.content_profile_cis"),
    ("Id: xccdf_com.example_profile_baseline\n", "xccdf_com.example_profile_baseline"),
])
def test_profile_choice(info, expected):
    class T:
        def run(self, cmd, **kw):
            from cyberthunder.transport.base import CommandResult
            return CommandResult(cmd, 0, info, "")
    assert LinuxAdapter()._oscap_profile(T(), "/x.xml") == expected
