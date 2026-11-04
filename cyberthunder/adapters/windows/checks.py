r"""Windows 11 STIG checks decided from registry, local security policy, service and audit state.

checks.ps1 collects raw state as one JSON document; this module decides pass/fail. The decision logic is
pure Python so it runs identically on live output, recorded fixtures and the simulated host.

checks.ps1 output (schema 1):
  registry  {"HKLM\<key path>\<value name>": <value or null when absent>}   one entry per REG_VALUES item
  secpol    {"MinimumPasswordLength": "14", ...}   [System Access] section of `secedit /export`
  smb       {"server_smb1": true|false|null}       Get-SmbServerConfiguration
  firewall  {"Domain": bool, "Private": bool, "Public": bool}
  services  {"RemoteRegistry": {"start_type": "Disabled", "status": "Stopped"} | null}
  defender  {"realtime": true|false|null}           Get-MpComputerStatus
  audit     {"logon": "Success and Failure" | "Success" | "Failure" | "No Auditing" | null}

Rule text, titles and severities come from the DISA Windows 11 benchmark (w11_catalog.json, trimmed from the
public release). Two checks have no Windows 11 STIG rule (RDP network level authentication and the Remote
Registry service); they are reported with a local id, cite a CCI and an ATT&CK technique, and say so.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

CATALOG_PATH = Path(__file__).resolve().parent / "w11_catalog.json"
SOURCE = "windows-stig"

# Registry values read by checks.ps1. The script carries the same list; a unit test keeps them in step.
LANMAN = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
MRXSMB10 = r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"
POL_SYSTEM = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
POL_EXPLORER = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
RDP_TCP = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
SBL = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
WDIGEST = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"

REG_VALUES = (
    LANMAN + r"\SMB1",
    MRXSMB10 + r"\Start",
    POL_SYSTEM + r"\EnableLUA",
    RDP_TCP + r"\UserAuthentication",
    POL_EXPLORER + r"\NoDriveTypeAutoRun",
    LSA + r"\NoLMHash",
    LSA + r"\LmCompatibilityLevel",
    SBL + r"\EnableScriptBlockLogging",
    WDIGEST + r"\UseLogonCredential",
)

LOGON_AUDIT_GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}"   # Logon/Logoff - Logon subcategory


@lru_cache(maxsize=1)
def catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def rule_meta(stig_id: str | None) -> dict | None:
    if not stig_id:
        return None
    return catalog()["rules"].get(stig_id)


def _int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(str(v).strip().strip('"'))
    except ValueError:
        return None


def _str(v) -> str | None:
    return None if v is None else str(v).strip().strip('"')


# A decision returns (passed, evidence). passed None means the state could not be read.
Decision = tuple[bool | None, str]


@dataclass(frozen=True)
class CheckDef:
    key: str
    title: str                      # used when the rule is not in the catalog
    stig_id: str | None             # WN11-xx-xxxxxx, None when no Windows 11 STIG rule exists
    decide: Callable[[dict, dict], Decision]
    fix_ref: str | None = None
    severity: str = "medium"        # used when the rule is not in the catalog
    refs: tuple[str, ...] = ()      # extra citations (CCI / ATT&CK) for non-benchmark checks
    note: str = ""

    @property
    def rule_id(self) -> str:
        m = rule_meta(self.stig_id)
        if m and m.get("rule_id"):
            return m["rule_id"]
        return f"win:{self.stig_id or self.key}"


def _reg(state: dict, path: str):
    return (state.get("registry") or {}).get(path)


def _reg_equals(path: str, want: int):
    def decide(state: dict, opts: dict) -> Decision:
        reg = state.get("registry") or {}
        if path not in reg:
            return None, f"{path} was not collected"
        v = _int(reg[path])
        if v is None:
            # The STIG check text makes an absent value a finding, even where the OS default would comply.
            return False, f"{path} is not set (required {want})"
        return v == want, f"{path} = {v} (required {want})"
    return decide


def _secpol(key: str, ok: Callable[[int], bool], want: str):
    def decide(state: dict, opts: dict) -> Decision:
        sp = state.get("secpol") or {}
        if not sp:
            return None, "local security policy was not collected"
        v = _int(sp.get(key))
        if v is None:
            return False, f"{key} is not defined (required {want})"
        return ok(v), f"{key} = {v} (required {want})"
    return decide


def _smb1_server(state: dict, opts: dict) -> Decision:
    smb = (state.get("smb") or {}).get("server_smb1")
    path = LANMAN + r"\SMB1"
    reg = _int(_reg(state, path))
    if smb is not None:
        return (not smb), f"Get-SmbServerConfiguration EnableSMB1Protocol = {smb}; {path} = {reg}"
    if reg is None:
        return False, f"{path} is not set and the SMB server configuration could not be read"
    return reg == 0, f"{path} = {reg} (required 0)"


def _smb1_client(state: dict, opts: dict) -> Decision:
    reg = state.get("registry") or {}
    path = MRXSMB10 + r"\Start"
    if path not in reg:
        return None, f"{path} was not collected"
    v = _int(reg[path])
    if v is None:
        return True, "mrxsmb10 driver is not installed (SMBv1 client removed)"
    return v == 4, f"{path} = {v} (required 4, disabled)"


def _admin_renamed(state: dict, opts: dict) -> Decision:
    sp = state.get("secpol") or {}
    if not sp:
        return None, "local security policy was not collected"
    name = _str(sp.get("NewAdministratorName"))
    if not name:
        return None, "NewAdministratorName not present in the exported policy"
    return name.lower() != "administrator", f"built-in administrator account name is {name!r}"


def _max_age(state: dict, opts: dict) -> Decision:
    limit = int(opts.get("max_password_age_days", 180))
    return _secpol("MaximumPasswordAge", lambda v: 0 < v <= limit, f"1..{limit} days")(state, opts)


def _firewall(state: dict, opts: dict) -> Decision:
    fw = state.get("firewall") or {}
    if not fw:
        return None, "firewall profiles were not collected"
    off = [p for p in ("Domain", "Private", "Public") if fw.get(p) is not True]
    ev = ", ".join(f"{p}={'on' if fw.get(p) else 'off'}" for p in ("Domain", "Private", "Public"))
    return (not off), f"Windows Defender Firewall profiles: {ev}"


def _remote_registry(state: dict, opts: dict) -> Decision:
    svcs = state.get("services") or {}
    if "RemoteRegistry" not in svcs:
        return None, "RemoteRegistry service state was not collected"
    s = svcs["RemoteRegistry"]
    if s is None:
        return True, "RemoteRegistry service is not installed"
    return s.get("start_type") == "Disabled", f"RemoteRegistry start type {s.get('start_type')}, status {s.get('status')}"


def _defender(state: dict, opts: dict) -> Decision:
    rt = (state.get("defender") or {}).get("realtime")
    if rt is None:
        return None, ("Microsoft Defender status could not be read (another antivirus product may be "
                      "installed; verify manually)")
    return bool(rt), "Microsoft Defender real-time protection " + ("on" if rt else "off")


def _audit(want: str):
    def decide(state: dict, opts: dict) -> Decision:
        v = (state.get("audit") or {}).get("logon")
        if v is None:
            return None, "audit policy for Logon was not collected"
        s = str(v).lower()
        ok = want in s
        return ok, f"auditpol Logon/Logoff - Logon = {v!r} (required to include {want})"
    return decide


CHECKS: tuple[CheckDef, ...] = (
    CheckDef("smb1_server", "SMBv1 disabled on the SMB server", "WN11-00-000165", _smb1_server, "windows:smb1_server"),
    CheckDef("smb1_client", "SMBv1 disabled on the SMB client", "WN11-00-000170", _smb1_client, "windows:smb1_client"),
    CheckDef("guest_disabled", "Guest account disabled", "WN11-SO-000010",
             _secpol("EnableGuestAccount", lambda v: v == 0, "0"), "windows:guest_disabled"),
    CheckDef("admin_renamed", "Built-in Administrator renamed", "WN11-SO-000020", _admin_renamed, "windows:admin_renamed"),
    CheckDef("min_password_length", "Minimum password length 14", "WN11-AC-000035",
             _secpol("MinimumPasswordLength", lambda v: v >= 14, ">= 14"), "windows:min_password_length"),
    CheckDef("lockout_threshold", "Account lockout threshold 3 or less", "WN11-AC-000010",
             _secpol("LockoutBadCount", lambda v: 0 < v <= 3, "1..3"), "windows:lockout_threshold"),
    CheckDef("password_history", "Password history 24", "WN11-AC-000020",
             _secpol("PasswordHistorySize", lambda v: v >= 24, ">= 24"), "windows:password_history"),
    CheckDef("max_password_age", "Maximum password age", "WN11-AC-000025", _max_age, "windows:max_password_age"),
    CheckDef("uac_enabled", "UAC Admin Approval Mode (EnableLUA)", "WN11-SO-000270",
             _reg_equals(POL_SYSTEM + r"\EnableLUA", 1), "windows:uac_enabled"),
    CheckDef("rdp_nla", "Remote Desktop requires Network Level Authentication", None,
             _reg_equals(RDP_TCP + r"\UserAuthentication", 1), "windows:rdp_nla", severity="medium",
             refs=("CCI-000366", "T1021.001"),
             note="No Windows 11 STIG rule covers RDP network level authentication; this check is cited against "
                  "CCI-000366 (security configuration settings) and ATT&CK T1021.001 instead. Without NLA the "
                  "logon screen is reachable before the user authenticates, which exposes the host to "
                  "pre-authentication attacks and password spraying over RDP."),
    CheckDef("firewall_on", "Windows Defender Firewall on for all profiles", "WN11-00-000135", _firewall, "windows:firewall_on"),
    CheckDef("autoplay_off", "AutoPlay disabled for all drives", "WN11-CC-000190",
             _reg_equals(POL_EXPLORER + r"\NoDriveTypeAutoRun", 255), "windows:autoplay_off"),
    CheckDef("anon_sid_translation", "Anonymous SID/Name translation not allowed", "WN11-SO-000140",
             _secpol("LSAAnonymousNameLookup", lambda v: v == 0, "0"), "windows:anon_sid_translation"),
    CheckDef("no_lm_hash", "LAN Manager hash not stored", "WN11-SO-000195",
             _reg_equals(LSA + r"\NoLMHash", 1), "windows:no_lm_hash"),
    CheckDef("lm_compat", "LAN Manager authentication level NTLMv2 only", "WN11-SO-000205",
             _reg_equals(LSA + r"\LmCompatibilityLevel", 5), "windows:lm_compat"),
    CheckDef("script_block_logging", "PowerShell script block logging", "WN11-CC-000326",
             _reg_equals(SBL + r"\EnableScriptBlockLogging", 1), "windows:script_block_logging"),
    CheckDef("wdigest_off", "WDigest authentication disabled", "WN11-CC-000038",
             _reg_equals(WDIGEST + r"\UseLogonCredential", 0), "windows:wdigest_off"),
    CheckDef("remote_registry_disabled", "Remote Registry service disabled", None, _remote_registry,
             "windows:remote_registry_disabled", severity="medium", refs=("CCI-000381", "T1012"),
             note="No Windows 11 STIG rule disables Remote Registry; this check is cited against CCI-000381 "
                  "(least functionality) and ATT&CK T1012 (Query Registry) instead. A running Remote Registry "
                  "service lets anyone with network credentials read and change registry settings remotely."),
    CheckDef("defender_realtime", "Antivirus real-time protection on", "WN11-00-000045", _defender, "windows:defender_realtime"),
    CheckDef("audit_logon_failure", "Audit Logon failures", "WN11-AU-000070", _audit("failure"), "windows:audit_logon"),
    CheckDef("audit_logon_success", "Audit Logon successes", "WN11-AU-000075", _audit("success"), "windows:audit_logon"),
)

BY_KEY = {c.key: c for c in CHECKS}


def by_rule(rule: str | None) -> CheckDef | None:
    if not rule:
        return None
    for c in CHECKS:
        if rule in (c.rule_id, c.stig_id, c.key):
            return c
    return None


def evaluate(target, state: dict, *, collected_at: str | None = None, raw_ref: str | None = None,
             rule_filter: list[str] | None = None) -> list:
    """One Finding per check: open, not_a_finding, or not_reviewed when the state could not be read."""
    from cyberthunder.adapters.base import make_finding

    opts = target.options or {}
    cat = catalog()
    out = []
    for c in CHECKS:
        if rule_filter and not ({c.rule_id, c.stig_id, c.key} & set(rule_filter)):
            continue
        try:
            passed, evidence = c.decide(state, opts)
        except Exception as e:  # noqa: BLE001  bad data for one check must not hide the others
            passed, evidence = None, f"check could not be evaluated: {e}"
        status = "not_reviewed" if passed is None else ("not_a_finding" if passed else "open")
        m = rule_meta(c.stig_id) or {}
        refs = [*c.refs, *m.get("ccis", [])]
        out.append(make_finding(
            target=target, source=SOURCE, rule_id=c.rule_id, title=m.get("title") or c.title,
            severity=m.get("severity") or c.severity, status=status,
            description=m.get("description") or c.note, evidence=evidence, references=refs,
            check_text=m.get("check_text"), fix_text=m.get("fix_text"), rule_version=c.stig_id,
            group_id=m.get("group_id"), benchmark=cat.get("benchmark") if m else None,
            benchmark_release=cat.get("release") if m else None, fix_ref=c.fix_ref,
            tags=["windows", "stig", f"check:{c.key}"], raw_ref=raw_ref, collected_at=collected_at,
        ))
    return out

