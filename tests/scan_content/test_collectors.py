import pytest

from cyberthunder.adapters.base import AssetFacts, Collected
from cyberthunder.adapters.linux import LinuxAdapter
from cyberthunder.adapters.linux.content import SSG_DIRECTORY, select_datastream
from cyberthunder.adapters.windows import WindowsAdapter
from cyberthunder.inventory.targets import Target
from cyberthunder.transport.base import CommandResult


@pytest.mark.parametrize("ident,version,wanted", [
    ("rhel", "9.4", "rhel9"), ("rhel", "8.10", "rhel8"), ("ubuntu", "22.04.3", "ubuntu2204"),
    ("ubuntu", "24.04", "ubuntu2404"), ("ol", "9.4", "ol9"), ("sles", "15.6", "sle15"),
    ("rocky", "9.4", None), ("almalinux", "9.4", None), (None, "9", None),
    ("rhel", None, None), ("ubuntu", "22", None), ("rhel", "9; command", None),
])
def test_datastream_requires_observed_distro_release_not_first_path(ident, version, wanted):
    paths = [SSG_DIRECTORY + "ssg-" + name + "-ds.xml" for name in
             ["ubuntu2404", "rhel8", "ol9", "rhel9", "ubuntu2204", "sle15"]]
    expected = SSG_DIRECTORY + f"ssg-{wanted}-ds.xml" if wanted else None
    assert select_datastream(paths, AssetFacts(model=ident, os_version=version)) == expected
    assert select_datastream(reversed(paths), AssetFacts(model=ident, os_version=version)) == expected


def test_datastream_rejects_unknown_facts_wrong_major_and_arbitrary_paths():
    facts = AssetFacts(model="rhel", os_version="9")
    assert select_datastream([SSG_DIRECTORY + "ssg-rhel8-ds.xml"], facts) is None
    assert select_datastream(["/tmp/ssg-rhel9-ds.xml"], facts) is None
    assert select_datastream([SSG_DIRECTORY + "../ssg-rhel9-ds.xml"], facts) is None
    assert select_datastream([SSG_DIRECTORY + "ssg-rhel9-ds.xml"], None) is None


class Transport:
    def __init__(self, *, engine=True, readable=True, info="Id: xccdf_example_profile_stig", exit_code=0, fetch=True):
        self.engine, self.readable, self.info, self.exit_code, self.fetch_ok = engine, readable, info, exit_code, fetch
        self.calls = []

    def run(self, command, **kwargs):
        self.calls.append(command)
        code, output = 0, ""
        if command == "command -v oscap":
            code = 0 if self.engine else 1
        elif command.startswith("test -r"):
            code = 0 if self.readable else 1
        elif command.startswith("oscap info"):
            output = self.info
        elif command.startswith("oscap xccdf eval"):
            code = self.exit_code
        return CommandResult(command, code, output, "")

    def fetch(self, remote, local):
        self.calls.append("fetch")
        if not self.fetch_ok:
            raise OSError("missing result")
        from pathlib import Path
        Path(local).write_text("<results/>", encoding="utf-8")


@pytest.mark.parametrize("settings,status,content", [
    ({"engine": False}, "unavailable", "unknown"),
    ({"readable": False}, "available", "unavailable"),
    ({"info": ""}, "error", "readable"),
    ({"exit_code": 1}, "error", "readable"),
    ({"exit_code": 2}, "collected", "readable"),
    ({"fetch": False}, "error", "readable"),
])
def test_linux_actual_missing_engine_content_and_eval_failures_reported(tmp_path, settings, status, content):
    target = Target(id="host", name="Host", asset_type="linux", options={"benchmark_path": "/configured.xml"})
    col = Collected("host", "linux", str(tmp_path), modules=["check"])
    transport = Transport(**settings)
    LinuxAdapter()._maybe_oscap(target, transport, tmp_path, col, None)
    assert col.raw["scanner_coverage"]["status"] == status
    assert col.raw["scanner_coverage"]["content_status"] == content
    assert col.raw["scanner_coverage"]["applicability"] == "unverified"
    if status == "collected":
        assert not col.errors
    else:
        assert col.errors
    if settings.get("exit_code") == 1:
        assert "fetch" not in transport.calls
        assert not col.artifacts


def test_hunt_only_never_runs_oscap(tmp_path):
    target = Target(id="host", name="Host", asset_type="linux")
    col = Collected("host", "linux", str(tmp_path), modules=["hunt"])
    transport = Transport()
    LinuxAdapter()._maybe_oscap(target, transport, tmp_path, col, None)
    assert not transport.calls
    assert col.raw["scanner_coverage"]["status"] == "not_requested"


def test_windows_optional_benchmark_absence_is_explicit(tmp_path):
    target = Target(id="host", name="Host", asset_type="windows")
    col = Collected("host", "windows", str(tmp_path))
    WindowsAdapter()._collect_scap(target, None, tmp_path, col)
    assert col.raw["scanner_coverage"]["status"] == "not_configured"
    assert col.errors == []  # optional content does not prevent native collection


def test_windows_invalid_configured_benchmark_is_not_clean(tmp_path):
    target = Target(id="host", name="Host", asset_type="windows", options={"scap_datastream": str(tmp_path / "absent.xml")})
    col = Collected("host", "windows", str(tmp_path))
    WindowsAdapter()._collect_scap(target, None, tmp_path, col)
    assert col.raw["scanner_coverage"]["status"] == "error"
    assert col.errors
