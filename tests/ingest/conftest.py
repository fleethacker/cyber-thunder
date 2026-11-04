"""Fixtures for the ingest tests: a benchmark pair derived from the shared sample, and a context on a temp state dir."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

SAMPLE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_results.xccdf.xml"
INGEST_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "ingest"

NEW_RULE = """
  <Group id="V-258000">
    <title>SRG-OS-000023-GPOS-00006</title>
    <Rule id="SV-258000r926000_rule" severity="medium">
      <version>RHEL-09-211020</version>
      <title>RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner.</title>
      <ident system="http://cyber.mil/cci">CCI-000048</ident>
      <fixtext fixref="F-61600r926000_fix">Configure the banner in /etc/issue.</fixtext>
      <check system="C-61600r926000_chk"><check-content>Verify /etc/issue contains the banner.</check-content></check>
    </Rule>
  </Group>
"""


def _benchmark_only(text: str) -> str:
    # Strip the TestResult so the documents are plain benchmarks, as DISA ships them.
    start = text.index("<TestResult")
    end = text.index("</TestResult>") + len("</TestResult>")
    return text[:start] + text[end:]


def make_pair(dirpath: Path) -> tuple[Path, Path]:
    """old: the sample as is (release 0.1.76). new: release 0.1.77 with
    - RHEL-09-255045 retitled                      (changed: title)
    - RHEL-09-255100 fixtext edited                (changed: fix)
    - RHEL-09-211020 added
    - na_thing removed."""
    old = _benchmark_only(SAMPLE.read_text(encoding="utf-8"))
    new = old.replace("<version>0.1.76</version>", "<version>0.1.77</version>", 1)
    new = new.replace("<title>Disable SSH Root Login</title>", "<title>Disable SSH root login over the network</title>")
    new = new.replace("Set ClientAliveInterval 600 in /etc/ssh/sshd_config.",
                      "Set ClientAliveInterval 600 and ClientAliveCountMax 1 in /etc/ssh/sshd_config.")
    na = new.index('<Group id="xccdf_org.ssgproject.content_group_na">')
    na_end = new.index("</Group>", na) + len("</Group>")
    new = new[:na] + NEW_RULE + new[na_end:]
    assert new != old
    o, n = dirpath / "old-xccdf.xml", dirpath / "new-xccdf.xml"
    o.write_text(old, encoding="utf-8")
    n.write_text(new, encoding="utf-8")
    return o, n


@pytest.fixture
def bench_pair(tmp_path) -> tuple[Path, Path]:
    d = tmp_path / "bench"
    d.mkdir()
    return make_pair(d)


@pytest.fixture
def ctx(state_dir, monkeypatch):
    monkeypatch.setenv("CT_STATE_DIR", str(state_dir))
    monkeypatch.delenv("CT_COMPRESSOR", raising=False)
    for k in ("CT_LINK_KBPS", "CT_LINK_LATENCY_MS", "CT_LINK_CONNECTED"):
        monkeypatch.delenv(k, raising=False)
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    return AppContext(Settings.from_env(state_dir=str(state_dir)))


def write_collected(store, scan_id: str, target_id: str, packages: list[dict], os_name="Rocky Linux",
                    os_version="9.4") -> Path:
    d = store.scan_dir(scan_id) / "raw" / target_id
    d.mkdir(parents=True, exist_ok=True)
    doc = {"target_id": target_id, "asset_type": "linux", "workdir": str(d), "collected_at": "2026-11-04T12:00:00+00:00",
           "facts": {"hostname": target_id, "os_name": os_name, "os_version": os_version},
           "artifacts": {}, "raw": {"packages": packages}, "errors": [], "modules": ["check", "hunt", "cve"],
           "rule_filter": None}
    p = d / "collected.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def add_targets(ctx, *target_ids: str) -> None:
    """Put fixture hosts in the inventory: bulletins only match hosts that are in scope."""
    from cyberthunder.inventory.targets import Target
    for tid in target_ids:
        ctx.inventory.add(Target(id=tid, name=tid, asset_type="linux", transport="fixture"))


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch):
    """Content updates reach out on reconnect; in tests only loopback resolves."""
    from tests.ingest.content_helpers import guard_network
    guard_network(monkeypatch)


@pytest.fixture
def file_server():
    from tests.ingest.content_helpers import FileServer
    srv = FileServer().start()
    yield srv
    srv.stop()
