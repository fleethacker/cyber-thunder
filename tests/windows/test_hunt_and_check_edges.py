"""Edge cases in the Windows hunt path matching and registry check decisions."""
import pytest

from cyberthunder.adapters.windows import checks as C
from cyberthunder.adapters.windows import hunt as H

NOW = "2026-11-04T12:00:00Z"


@pytest.mark.parametrize("path", [
    r"C:\Users\Public\windefend.exe",
    r"C:\Users\bob\AppData\Roaming\upd.exe",
    r"C:\Windows\Temp\x.exe",
    r"C:\ProgramData\x\y.exe",
])
def test_user_writable_matches_expanded_paths(path):
    assert H.user_writable(path)


@pytest.mark.parametrize("path", [
    r"C:\Windows\System32\svchost.exe -k netsvcs",
    r'"C:\Program Files\Vendor\agent.exe"',
])
def test_user_writable_ignores_system_paths(path):
    assert not H.user_writable(path)


def test_service_in_user_writable_path_flagged_without_install_event():
    state = {"now": NOW, "service_installs": [], "services": [{
        "name": "WinDefendSvc2", "display": "Windows Defender Service", "path": r"C:\Users\Public\windefend.exe",
        "start_type": "Automatic", "status": "Running", "account": "LocalSystem"}]}
    hits = H.services(state, {})
    assert [h.params["name"] for h in hits] == ["WinDefendSvc2"]
    assert "user-writable" in hits[0].evidence


def test_run_key_with_expanded_user_path_flagged():
    state = {"now": NOW, "run_keys": [{
        "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name": "Updater",
        "value": r"C:\Users\Public\upd.exe"}]}
    hits = H.run_keys(state, {})
    assert len(hits) == 1 and "user-writable" in hits[0].evidence


@pytest.mark.parametrize("key,path", [
    ("no_lm_hash", C.LSA + r"\NoLMHash"),
    ("uac_enabled", C.POL_SYSTEM + r"\EnableLUA"),
])
def test_absent_registry_value_is_a_finding(key, path):
    ok, evidence = C.BY_KEY[key].decide({"registry": {path: None}}, {})
    assert ok is False
    assert "not set" in evidence
    ok, _ = C.BY_KEY[key].decide({"registry": {path: 1}}, {})
    assert ok is True
