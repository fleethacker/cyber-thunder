r"""Windows OVAL probes: what each test type needs collected and how collected data becomes OVAL items.

Each probe has two halves:

  requests(obj, resolved)        the collection requests one object needs (keys of the collection plan sent to
                                 windows_collect.ps1); raising Unsupported marks the object as not collectable
  items(obj, resolved, data)     the OVAL items for that object, built from the collected JSON

Collected JSON (windows_collect.ps1 output, schema 1) has these sections; a section is present only when the
plan asked for it, and anything that does not exist on the host is simply absent:

  registry        [{"hive": "HKLM", "key": "SOFTWARE\...", "values": [{"name", "kind", "value"}]}]
                  one entry per existing key read or enumerated; kind is the .NET RegistryValueKind
                  (DWord, QWord, String, ExpandString, MultiString, Binary, None); Binary values are hex text
  system_access   {"MinimumPasswordLength": "14", ...}     [System Access] of `secedit /export`
  net_accounts    {"Lockout threshold": "3", ...}           `net accounts`, used when secedit could not run
  rights          {"SeNetworkLogonRight": [{"sid", "name"}]} [Privilege Rights] with SIDs resolved to names
  audit           [{"subcategory", "guid", "setting"}]     `auditpol /get /category:* /r`
  accounts        {"computer", "users": [{"name", "sid", "enabled"}], "groups": [{"name", "sid", "members": [...]}]}
  files           [{"path", "exists", "size", "version", "product_version", "company"}]
  services        [{"name", "display", "start_type", "status", "account", "path", "service_type"}]
  wmi             [{"namespace", "wql", "rows": [{property: value}], "error"}]

Supported probes (test types): registry, passwordpolicy, lockoutpolicy, auditeventpolicysubcategories,
auditeventpolicy, userright, accesstoken, file, service, sid_sid, user_sid55, user_sid, wmi57, wmi and the
independent family test. Registry behaviors (recurse_direction, max_depth, windows_view) are noted and
ignored except that max_depth bounds subkey enumeration for key patterns.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

from .evaluator import (COMPLETE, DOES_NOT_EXIST, FLAG_ERROR, NOT_COLLECTED, UNAVAILABLE, EvalError, ResolvedEntity,
                        Unsupported, compile_pattern)
from .model import ObjectDef

log = logging.getLogger(__name__)

HIVES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKLM": "HKLM", "HKEY_USERS": "HKU", "HKU": "HKU",
         "HKEY_CURRENT_USER": "HKCU", "HKCU": "HKCU", "HKEY_CLASSES_ROOT": "HKCR", "HKCR": "HKCR",
         "HKEY_CURRENT_CONFIG": "HKCC", "HKCC": "HKCC"}
LONG_HIVE = {"HKLM": "HKEY_LOCAL_MACHINE", "HKU": "HKEY_USERS", "HKCU": "HKEY_CURRENT_USER",
             "HKCR": "HKEY_CLASSES_ROOT", "HKCC": "HKEY_CURRENT_CONFIG"}
REG_KIND = {"dword": "reg_dword", "qword": "reg_qword", "string": "reg_sz", "expandstring": "reg_expand_sz",
            "multistring": "reg_multi_sz", "binary": "reg_binary", "none": "reg_none", "unknown": "reg_none"}
MAX_KEY_DEPTH = 3

# OVAL userright names (the Windows SE_*_NAME constants) and the secedit [Privilege Rights] names they denote.
USER_RIGHTS = {
    "SE_ASSIGNPRIMARYTOKEN_NAME": "SeAssignPrimaryTokenPrivilege", "SE_AUDIT_NAME": "SeAuditPrivilege",
    "SE_BACKUP_NAME": "SeBackupPrivilege", "SE_CHANGE_NOTIFY_NAME": "SeChangeNotifyPrivilege",
    "SE_CREATE_GLOBAL_NAME": "SeCreateGlobalPrivilege", "SE_CREATE_PAGEFILE_NAME": "SeCreatePagefilePrivilege",
    "SE_CREATE_PERMANENT_NAME": "SeCreatePermanentPrivilege",
    "SE_CREATE_SYMBOLIC_LINK_NAME": "SeCreateSymbolicLinkPrivilege", "SE_CREATE_TOKEN_NAME": "SeCreateTokenPrivilege",
    "SE_DEBUG_NAME": "SeDebugPrivilege", "SE_ENABLE_DELEGATION_NAME": "SeEnableDelegationPrivilege",
    "SE_IMPERSONATE_NAME": "SeImpersonatePrivilege", "SE_INC_BASE_PRIORITY_NAME": "SeIncreaseBasePriorityPrivilege",
    "SE_INCREASE_QUOTA_NAME": "SeIncreaseQuotaPrivilege", "SE_INC_WORKING_SET_NAME": "SeIncreaseWorkingSetPrivilege",
    "SE_LOAD_DRIVER_NAME": "SeLoadDriverPrivilege", "SE_LOCK_MEMORY_NAME": "SeLockMemoryPrivilege",
    "SE_MACHINE_ACCOUNT_NAME": "SeMachineAccountPrivilege", "SE_MANAGE_VOLUME_NAME": "SeManageVolumePrivilege",
    "SE_PROF_SINGLE_PROCESS_NAME": "SeProfileSingleProcessPrivilege", "SE_RELABEL_NAME": "SeRelabelPrivilege",
    "SE_REMOTE_SHUTDOWN_NAME": "SeRemoteShutdownPrivilege", "SE_RESTORE_NAME": "SeRestorePrivilege",
    "SE_SECURITY_NAME": "SeSecurityPrivilege", "SE_SHUTDOWN_NAME": "SeShutdownPrivilege",
    "SE_SYNC_AGENT_NAME": "SeSyncAgentPrivilege", "SE_SYSTEM_ENVIRONMENT_NAME": "SeSystemEnvironmentPrivilege",
    "SE_SYSTEM_PROFILE_NAME": "SeSystemProfilePrivilege", "SE_SYSTEMTIME_NAME": "SeSystemtimePrivilege",
    "SE_TAKE_OWNERSHIP_NAME": "SeTakeOwnershipPrivilege", "SE_TCB_NAME": "SeTcbPrivilege",
    "SE_TIME_ZONE_NAME": "SeTimeZonePrivilege", "SE_TRUSTED_CREDMAN_ACCESS_NAME": "SeTrustedCredManAccessPrivilege",
    "SE_UNDOCK_NAME": "SeUndockPrivilege", "SE_UNSOLICITED_INPUT_NAME": "SeUnsolicitedInputPrivilege",
    "SE_BATCH_LOGON_NAME": "SeBatchLogonRight", "SE_DENY_BATCH_LOGON_NAME": "SeDenyBatchLogonRight",
    "SE_DENY_INTERACTIVE_LOGON_NAME": "SeDenyInteractiveLogonRight",
    "SE_DENY_NETWORK_LOGON_NAME": "SeDenyNetworkLogonRight",
    "SE_DENY_REMOTE_INTERACTIVE_LOGON_NAME": "SeDenyRemoteInteractiveLogonRight",
    "SE_DENY_SERVICE_LOGON_NAME": "SeDenyServiceLogonRight", "SE_INTERACTIVE_LOGON_NAME": "SeInteractiveLogonRight",
    "SE_NETWORK_LOGON_NAME": "SeNetworkLogonRight", "SE_REMOTE_INTERACTIVE_LOGON_NAME": "SeRemoteInteractiveLogonRight",
    "SE_SERVICE_LOGON_NAME": "SeServiceLogonRight", "SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME":
        "SeDelegateSessionUserImpersonatePrivilege",
}

# auditpol subcategory names whose OVAL field name is not the plain snake_case of the name
AUDIT_FIELD_OVERRIDES = {"plug and play events": "pnp_activity", "central policy staging": "central_access_policy_staging",
                         "token right adjusted events": "token_right_adjusted",
                         "user / device claims": "user_device_claims"}
AUDIT_CATEGORIES = {
    "account_logon": ("credential_validation", "kerberos_authentication_service",
                      "kerberos_service_ticket_operations", "other_account_logon_events"),
    "account_management": ("application_group_management", "computer_account_management",
                           "distribution_group_management", "other_account_management_events",
                           "security_group_management", "user_account_management"),
    "detailed_tracking": ("dpapi_activity", "pnp_activity", "process_creation", "process_termination",
                          "rpc_events", "token_right_adjusted"),
    "directory_service_access": ("directory_service_access", "directory_service_changes",
                                 "directory_service_replication", "detailed_directory_service_replication"),
    "logon": ("account_lockout", "ipsec_extended_mode", "ipsec_main_mode", "ipsec_quick_mode", "logoff", "logon",
              "network_policy_server", "other_logon_logoff_events", "special_logon", "user_device_claims",
              "group_membership"),
    "object_access": ("application_generated", "certification_services", "detailed_file_share", "file_share",
                      "file_system", "filtering_platform_connection", "filtering_platform_packet_drop",
                      "handle_manipulation", "kernel_object", "other_object_access_events", "registry",
                      "removable_storage", "sam", "central_access_policy_staging"),
    "policy_change": ("audit_policy_change", "authentication_policy_change", "authorization_policy_change",
                      "filtering_platform_policy_change", "mpssvc_rule_level_policy_change",
                      "other_policy_change_events"),
    "privilege_use": ("non_sensitive_privilege_use", "other_privilege_use_events", "sensitive_privilege_use"),
    "system": ("ipsec_driver", "other_system_events", "security_state_change", "security_system_extension",
               "system_integrity"),
}
AUDIT_SETTING = {"no auditing": "AUDIT_NONE", "success": "AUDIT_SUCCESS", "failure": "AUDIT_FAILURE",
                 "success and failure": "AUDIT_SUCCESS_FAILURE"}

SERVICE_START = {"auto": "SERVICE_AUTO_START", "automatic": "SERVICE_AUTO_START", "manual": "SERVICE_DEMAND_START",
                 "disabled": "SERVICE_DISABLED", "boot": "SERVICE_BOOT_START", "system": "SERVICE_SYSTEM_START"}
SERVICE_STATE = {"running": "SERVICE_RUNNING", "stopped": "SERVICE_STOPPED", "paused": "SERVICE_PAUSED",
                 "startpending": "SERVICE_START_PENDING", "stoppending": "SERVICE_STOP_PENDING",
                 "continuepending": "SERVICE_CONTINUE_PENDING", "pausepending": "SERVICE_PAUSE_PENDING"}

WQL_RE = re.compile(r"(?is)^\s*SELECT\s+[\w\s,*]+\s+FROM\s+\w+(\s+WHERE\s+[^;`$|&<>]+)?\s*$")
NAMESPACE_RE = re.compile(r"(?i)^root(\\[\w]+)*$")


@dataclass(frozen=True)
class Request:
    """One unit of collection. `id` is stable so the planner can tell what has already been collected."""
    id: str
    section: str
    payload: tuple = ()


@dataclass
class Probe:
    name: str
    requests: Callable[[ObjectDef, dict], list[Request]]
    items: Callable[[ObjectDef, dict, dict], tuple]
    summary: Callable[[dict], str] = field(default=lambda it: ", ".join(f"{k}={v}" for k, v in it.items()))


def _ent(resolved: dict, name: str) -> ResolvedEntity | None:
    return resolved.get(name)


def _literal(r: ResolvedEntity | None) -> str | None:
    if r is None or r.nil:
        return None
    return str(r.values[0]) if r.literal and r.values[0] is not None else None


def _match(r: ResolvedEntity | None, value, *, ci: bool = False) -> bool:
    return True if r is None else r.matches(value, case_insensitive=ci)


# -- registry ---------------------------------------------------------------------------------------------------
def _hive(resolved: dict) -> str:
    h = _ent(resolved, "hive")
    lit = _literal(h)
    if lit is None:
        raise EvalError("registry hives given as patterns are not collected")
    hv = HIVES.get(lit.upper())
    if hv is None:
        raise EvalError(f"unknown registry hive {lit!r}")
    return hv


def key_pattern_prefix(pattern: str, max_depth: int | None = None) -> tuple[str, int]:
    """Literal key prefix of a key pattern and how many levels below it to enumerate."""
    p = re.sub(r"^\^?(\(\?[imsx]+\))?\^?", "", pattern)
    p = p.rstrip("$")
    # split on escaped backslashes (a literal '\' in the key), but not inside a character class
    segs, cur, i, in_class = [], "", 0, False
    while i < len(p):
        if p.startswith("\\\\", i) and not in_class:
            segs.append(cur)
            cur, i = "", i + 2
            continue
        ch = p[i]
        if ch == "\\" and i + 1 < len(p):
            cur += p[i:i + 2]
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        cur += ch
        i += 1
    segs.append(cur)
    prefix: list[str] = []
    for s in segs:
        if re.search(r"[\[\](){}.*+?^$|\\]", s):
            break
        prefix.append(s)
    remaining = len(segs) - len(prefix)
    depth = max(1, remaining)
    if max_depth is not None and max_depth >= 0:
        depth = min(depth, max_depth) if max_depth else depth
    return "\\".join(prefix), min(depth, MAX_KEY_DEPTH)


def _registry_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    hive = _hive(resolved)
    key = _ent(resolved, "key")
    name = _ent(resolved, "name")
    if key is None or key.nil:
        raise EvalError("registry object without a key")
    if name is None or name.nil:
        names: tuple = ()
    elif name.literal:
        names = (str(name.values[0]),)
    else:
        names = ("*",)
    out = []
    if key.literal or (key.entity.operation in ("equals", "case insensitive equals")):
        for k in key.values:
            out.append(Request(f"registry|{hive}|{str(k).lower()}|0|{'|'.join(n.lower() for n in names)}",
                               "registry", (hive, str(k), names, 0)))
    elif key.entity.operation == "pattern match":
        md = o.behaviors.get("max_depth")
        for k in key.values:
            prefix, depth = key_pattern_prefix(str(k), int(md) if md not in (None, "") else None)
            out.append(Request(f"registry|{hive}|{prefix.lower()}|{depth}|{'|'.join(n.lower() for n in names)}",
                               "registry", (hive, prefix, names, depth)))
    else:
        raise EvalError(f"registry keys compared with {key.entity.operation!r} are not collected")
    return out


def _reg_value(kind: str, value):
    k = REG_KIND.get(str(kind).lower(), "reg_sz")
    if k in ("reg_dword", "reg_qword"):
        try:
            return k, int(value)
        except (TypeError, ValueError):
            return k, value
    if k == "reg_multi_sz":
        return k, [str(v) for v in (value if isinstance(value, list) else [value])] if value is not None else []
    if k == "reg_binary":
        return k, re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return k, "" if value is None else str(value)


def _registry_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "registry" not in data:
        return NOT_COLLECTED, []
    hive = _hive(resolved)
    key = _ent(resolved, "key")
    name = _ent(resolved, "name")
    items = []
    for entry in data.get("registry") or []:
        if HIVES.get(str(entry.get("hive", "")).upper()) != hive:
            continue
        k = str(entry.get("key", ""))
        if not key.matches(k, case_insensitive=True):
            continue
        base = {"hive": LONG_HIVE[hive], "key": k, "windows_view": "64_bit"}
        if name is None or name.nil:
            items.append({**base, "name": None})
            continue
        for v in entry.get("values") or []:
            vn = str(v.get("name", ""))
            if not name.matches(vn, case_insensitive=name.entity.operation in ("equals", "not equal")):
                continue
            t, val = _reg_value(v.get("kind", "String"), v.get("value"))
            items.append({**base, "name": vn, "type": t, "value": val})
    return COMPLETE, items


def _registry_summary(it: dict) -> str:
    path = f"{it.get('hive')}\\{it.get('key')}"
    if it.get("name") is None:
        return f"{path} (key exists)"
    return f"{path}\\{it.get('name')} = {it.get('value')!r} ({it.get('type')})"


# -- account and audit policy ---------------------------------------------------------------------------------
def _num(v) -> int | None:
    try:
        return int(str(v).strip().strip('"'))
    except (TypeError, ValueError):
        return None


NET_ACCOUNTS = {"MinimumPasswordAge": ("Minimum password age (days)", 1), "MaximumPasswordAge":
                ("Maximum password age (days)", 1), "MinimumPasswordLength": ("Minimum password length", 1),
                "PasswordHistorySize": ("Length of password history maintained", 1),
                "LockoutBadCount": ("Lockout threshold", 1), "LockoutDuration": ("Lockout duration (minutes)", 1),
                "ResetLockoutCount": ("Lockout observation window (minutes)", 1)}


def _policy_value(data: dict, key: str) -> int | None:
    sa = data.get("system_access") or {}
    if key in sa:
        return _num(sa[key])
    na = data.get("net_accounts") or {}
    label = NET_ACCOUNTS.get(key, (None,))[0]
    if label and label in na:
        raw = str(na[label]).strip().lower()
        if raw in ("never", "unlimited"):
            return -1
        if raw == "none":
            return 0
        return _num(raw)
    return None


def _policy_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    return [Request("secedit", "secedit")]


def _days(v: int | None) -> int | None:
    if v is None:
        return None
    return -1 if v < 0 else v * 86400


def _minutes(v: int | None) -> int | None:
    if v is None:
        return None
    return -1 if v < 0 else v * 60


def _passwordpolicy_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "system_access" not in data and "net_accounts" not in data:
        return NOT_COLLECTED, []
    pv = lambda k: _policy_value(data, k)  # noqa: E731
    fields = {"max_passwd_age": _days(pv("MaximumPasswordAge")), "min_passwd_age": _days(pv("MinimumPasswordAge")),
              "min_passwd_len": pv("MinimumPasswordLength"), "password_hist_len": pv("PasswordHistorySize"),
              "password_complexity": None if pv("PasswordComplexity") is None else pv("PasswordComplexity") == 1,
              "reversible_encryption": None if pv("ClearTextPassword") is None else pv("ClearTextPassword") == 1,
              "anonymous_name_lookup": None if pv("LSAAnonymousNameLookup") is None
              else pv("LSAAnonymousNameLookup") == 1}
    return COMPLETE, [_policy_item(data, fields)]


def _policy_item(data: dict, fields: dict) -> dict:
    """Fields with a value; when secedit was not collected, the missing ones are unavailable, not unset."""
    item = {k: v for k, v in fields.items() if v is not None}
    if "system_access" not in data:
        missing = sorted(k for k, v in fields.items() if v is None)
        if missing:
            item[UNAVAILABLE] = missing
    return item


def _lockoutpolicy_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "system_access" not in data and "net_accounts" not in data:
        return NOT_COLLECTED, []
    pv = lambda k: _policy_value(data, k)  # noqa: E731
    fields = {"lockout_threshold": pv("LockoutBadCount"), "lockout_duration": _minutes(pv("LockoutDuration")),
              "lockout_observation_window": _minutes(pv("ResetLockoutCount"))}
    flo = pv("ForceLogoffWhenHourExpire")
    if flo is not None:
        fields["force_logoff"] = 0 if flo == 1 else -1
    elif "system_access" not in data:
        fields["force_logoff"] = None
    return COMPLETE, [_policy_item(data, fields)]


def audit_field(subcategory: str) -> str:
    n = subcategory.strip().lower()
    if n in AUDIT_FIELD_OVERRIDES:
        return AUDIT_FIELD_OVERRIDES[n]
    return re.sub(r"[^a-z0-9]+", "_", n).strip("_")


def _audit_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    return [Request("auditpol", "auditpol")]


def _audit_subcategories(data: dict) -> dict[str, str]:
    out = {}
    for row in data.get("audit") or []:
        name = row.get("subcategory") or ""
        if not name:
            continue
        out[audit_field(name)] = AUDIT_SETTING.get(str(row.get("setting", "")).strip().lower(), "AUDIT_NONE")
    return out


def _auditsub_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "audit" not in data:
        return NOT_COLLECTED, []
    subs = _audit_subcategories(data)
    # an empty audit policy listing means auditpol could not be read, never "nothing is audited"
    return (COMPLETE, [subs]) if subs else (FLAG_ERROR, [])


def _auditcat_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    """Legacy category audit policy, derived from the subcategories: a category audits success (failure)
    when any of its subcategories does."""
    if "audit" not in data:
        return NOT_COLLECTED, []
    subs = _audit_subcategories(data)
    if not subs:
        return FLAG_ERROR, []
    item = {}
    for cat, members in AUDIT_CATEGORIES.items():
        vals = [subs[m] for m in members if m in subs]
        if not vals:
            continue
        s = any(v in ("AUDIT_SUCCESS", "AUDIT_SUCCESS_FAILURE") for v in vals)
        f = any(v in ("AUDIT_FAILURE", "AUDIT_SUCCESS_FAILURE") for v in vals)
        item[cat] = {(True, True): "AUDIT_SUCCESS_FAILURE", (True, False): "AUDIT_SUCCESS",
                     (False, True): "AUDIT_FAILURE", (False, False): "AUDIT_NONE"}[(s, f)]
    return COMPLETE, [item]


# -- user rights ------------------------------------------------------------------------------------------------
_PREFIXES = ("builtin\\", "nt authority\\", "nt service\\")


def trustee_name(name: str) -> str:
    """Names as OVAL content writes them: 'Administrators', 'LOCAL SERVICE', 'RESTRICTED SERVICES\\X';
    the BUILTIN and NT AUTHORITY domains are dropped, other domains kept."""
    n = str(name or "")
    for p in _PREFIXES[:2]:
        if n.lower().startswith(p):
            return n[len(p):]
    return n


def _rights_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    return [Request("secedit", "secedit")]


def _userright_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "rights" not in data:
        return NOT_COLLECTED, []
    ur = _ent(resolved, "userright")
    rights = data.get("rights") or {}
    items = []
    for oval_name, se_name in USER_RIGHTS.items():
        if ur is not None and not ur.matches(oval_name):
            continue
        holders = rights.get(se_name) or []
        if not holders:
            # nobody holds the right: one item with empty trustee fields, which is what DISA content
            # tests for 'must not be assigned to any groups or accounts'
            if ur is not None and ur.literal:
                items.append({"userright": oval_name, "trustee_sid": "", "trustee_name": ""})
            continue
        for h in holders:
            items.append({"userright": oval_name, "trustee_sid": str(h.get("sid") or ""),
                          "trustee_name": trustee_name(h.get("name") or h.get("sid") or "")})
    return COMPLETE, items


def _accesstoken_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "rights" not in data:
        return NOT_COLLECTED, []
    sp = _ent(resolved, "security_principle")
    rights = data.get("rights") or {}
    principals: dict[str, dict] = {}
    for se_name, holders in rights.items():
        for h in holders or []:
            full = str(h.get("name") or h.get("sid") or "")
            p = principals.setdefault(full.lower(), {"name": full, "sid": str(h.get("sid") or ""), "rights": set()})
            p["rights"].add(se_name.lower())
    items = []
    for p in principals.values():
        names = {p["name"], trustee_name(p["name"]), p["sid"]}
        if sp is not None and not any(sp.matches(n, case_insensitive=True) for n in names if n):
            continue
        it = {"security_principle": p["name"]}
        for se in USER_RIGHTS.values():
            it[se.lower()] = se.lower() in p["rights"]
        items.append(it)
    return COMPLETE, items


# -- accounts ---------------------------------------------------------------------------------------------------
def _accounts_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    return [Request("accounts", "accounts")]


def _principals(data: dict) -> list[dict]:
    acc = data.get("accounts") or {}
    comp = acc.get("computer") or ""
    out = []
    for u in acc.get("users") or []:
        out.append({"sid": str(u.get("sid", "")), "name": str(u.get("name", "")),
                    "domain": str(u.get("domain") or comp), "kind": "user", "enabled": u.get("enabled")})
    for g in acc.get("groups") or []:
        out.append({"sid": str(g.get("sid", "")), "name": str(g.get("name", "")),
                    "domain": str(g.get("domain") or "BUILTIN"), "kind": "group", "members": g.get("members") or []})
    return out


def _sid_sid_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "accounts" not in data:
        return NOT_COLLECTED, []
    ts = _ent(resolved, "trustee_sid")
    items = [{"trustee_sid": p["sid"], "trustee_name": p["name"], "trustee_domain": p["domain"]}
             for p in _principals(data) if _match(ts, p["sid"])]
    return COMPLETE, items


def _groups_of(data: dict, sid: str) -> list[str]:
    out = []
    for p in _principals(data):
        if p["kind"] == "group" and any(str(m.get("sid", "")).upper() == sid.upper() for m in p["members"]):
            out.append(p["sid"])
    return out


def _user_sid_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "accounts" not in data:
        return NOT_COLLECTED, []
    us = _ent(resolved, "user_sid")
    items = []
    for p in _principals(data):
        if p["kind"] != "user" or not _match(us, p["sid"]):
            continue
        it = {"user_sid": p["sid"], "group_sid": _groups_of(data, p["sid"])}
        if p.get("enabled") is not None:
            it["enabled"] = bool(p["enabled"])
        items.append(it)
    return COMPLETE, items


# -- files and services -----------------------------------------------------------------------------------------
def _file_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    fp, path, fn = _ent(resolved, "filepath"), _ent(resolved, "path"), _ent(resolved, "filename")
    if fp is not None and not fp.nil:
        if not fp.literal and fp.entity.operation not in ("equals", "case insensitive equals"):
            raise EvalError("file paths given as patterns are not collected")
        return [Request(f"file|{str(v).lower()}", "files", (str(v), "")) for v in fp.values]
    if path is None or path.nil or path.entity.operation not in ("equals", "case insensitive equals"):
        raise EvalError("file paths given as patterns are not collected")
    out = []
    for d in path.values:
        if fn is None or fn.nil:
            out.append(Request(f"file|{str(d).lower()}", "files", (str(d), "")))
        elif fn.literal:
            out.append(Request(f"file|{str(d).lower()}\\{str(fn.values[0]).lower()}", "files",
                               (str(d).rstrip("\\") + "\\" + str(fn.values[0]), "")))
        else:
            out.append(Request(f"dir|{str(d).lower()}", "files", (str(d), "*")))
    return out


def _version(v) -> str | None:
    if not v:
        return None
    m = re.match(r"\s*([\d]+(?:[.,][\d]+)*)", str(v))
    return m.group(1).replace(",", ".") if m else str(v)


def _file_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "files" not in data:
        return NOT_COLLECTED, []
    fp, path, fn = _ent(resolved, "filepath"), _ent(resolved, "path"), _ent(resolved, "filename")
    items = []
    for f in data.get("files") or []:
        if not f.get("exists"):
            continue
        full = str(f.get("path", ""))
        d, _, name = full.rpartition("\\")
        if fp is not None and not fp.nil:
            if not fp.matches(full, case_insensitive=True):
                continue
        else:
            if path is not None and not path.matches(d, case_insensitive=True):
                if not (fn is None or fn.nil) or not path.matches(full, case_insensitive=True):
                    continue
            if fn is not None and not fn.nil and not fn.matches(name, case_insensitive=True):
                continue
        it = {"filepath": full, "path": d, "filename": name, "type": "FILE_TYPE_DISK"}
        for k in ("size", "company", "owner"):
            if f.get(k) is not None:
                it[k] = f[k]
        if f.get("version"):
            it["version"] = _version(f["version"])
        if f.get("product_version"):
            it["product_version"] = _version(f["product_version"])
        if f.get("modified") is not None:
            it["m_time"] = f["modified"]
        items.append(it)
    return COMPLETE, items


def _service_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    sn = _ent(resolved, "service_name")
    if sn is not None and sn.literal:
        return [Request(f"service|{str(sn.values[0]).lower()}", "services", (str(sn.values[0]),))]
    return [Request("service|*", "services", ("*",))]


def _service_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "services" not in data:
        return NOT_COLLECTED, []
    sn = _ent(resolved, "service_name")
    items = []
    for s in data.get("services") or []:
        name = str(s.get("name", ""))
        if not _match(sn, name, ci=True):
            continue
        it = {"service_name": name, "display_name": str(s.get("display") or ""),
              "start_type": SERVICE_START.get(str(s.get("start_type", "")).lower(), str(s.get("start_type", ""))),
              "current_state": SERVICE_STATE.get(str(s.get("status", "")).lower().replace(" ", ""),
                                                 str(s.get("status", "")))}
        if s.get("account"):
            it["start_name"] = s["account"]
        if s.get("path"):
            it["path"] = s["path"]
        if s.get("service_type"):
            it["service_type"] = s["service_type"]
        items.append(it)
    return COMPLETE, items


# -- WMI --------------------------------------------------------------------------------------------------------
def check_wql(namespace: str, wql: str) -> None:
    if not NAMESPACE_RE.match(namespace or ""):
        raise EvalError(f"WMI namespace {namespace!r} is not collected")
    if not WQL_RE.match(wql or ""):
        raise EvalError("only plain SELECT ... FROM ... [WHERE ...] WQL queries are collected")


def _wmi_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    ns, wql = _literal(_ent(resolved, "namespace")), _literal(_ent(resolved, "wql"))
    if ns is None or wql is None:
        raise EvalError("WMI namespace and query must be literal values")
    check_wql(ns, wql)
    return [Request(f"wmi|{ns.lower()}|{' '.join(wql.split()).lower()}", "wmi", (ns, wql))]


def _wmi_rows(data: dict, ns: str, wql: str):
    norm = " ".join(wql.split()).lower()
    for w in data.get("wmi") or []:
        if str(w.get("namespace", "")).lower() == ns.lower() and " ".join(str(w.get("wql", "")).split()).lower() == norm:
            return w
    return None


def _wmi_value(v):
    # WMI booleans become "1" / "0": DISA content compares TPM and feature flags with string states of 1 / -1
    # and the boolean datatype accepts 1 and 0 as well
    if isinstance(v, bool):
        return "1" if v else "0"
    return v


def _wmi57_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    if "wmi" not in data:
        return NOT_COLLECTED, []
    ns, wql = _literal(_ent(resolved, "namespace")), _literal(_ent(resolved, "wql"))
    w = _wmi_rows(data, ns or "", wql or "")
    if w is None:
        return NOT_COLLECTED, []
    if w.get("error"):
        return FLAG_ERROR, []
    rows = [{str(k).lower(): _wmi_value(v) for k, v in (r or {}).items()} for r in w.get("rows") or []]
    if not rows:
        return DOES_NOT_EXIST, []
    return COMPLETE, [{"namespace": ns, "wql": wql, "result": rows}]


def _wmi_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    flag, items = _wmi57_items(o, resolved, data)
    if flag != COMPLETE:
        return flag, items
    m = re.match(r"(?is)^\s*SELECT\s+(\w+)", items[0]["wql"])
    prop = m.group(1).lower() if m else ""
    return COMPLETE, [{"namespace": items[0]["namespace"], "wql": items[0]["wql"],
                       "result": [r.get(prop) for r in items[0]["result"] if prop in r]}]


def _wmi_summary(it: dict) -> str:
    return f"WMI {it.get('namespace')}: {it.get('wql')} -> {it.get('result')}"


# -- independent ------------------------------------------------------------------------------------------------
def _no_requests(o: ObjectDef, resolved: dict) -> list[Request]:
    return []


def _family_items(o: ObjectDef, resolved: dict, data: dict) -> tuple:
    return COMPLETE, [{"family": "windows"}]


PROBES: dict[str, Probe] = {
    "registry": Probe("registry", _registry_requests, _registry_items, _registry_summary),
    "passwordpolicy": Probe("passwordpolicy", _policy_requests, _passwordpolicy_items),
    "lockoutpolicy": Probe("lockoutpolicy", _policy_requests, _lockoutpolicy_items),
    "auditeventpolicysubcategories": Probe("auditeventpolicysubcategories", _audit_requests, _auditsub_items,
                                           lambda it: f"{len(it)} audit subcategories"),
    "auditeventpolicy": Probe("auditeventpolicy", _audit_requests, _auditcat_items),
    "userright": Probe("userright", _rights_requests, _userright_items,
                       lambda it: f"{it.get('userright')}: {it.get('trustee_name') or '(no one)'}"),
    "accesstoken": Probe("accesstoken", _rights_requests, _accesstoken_items,
                         lambda it: f"{it.get('security_principle')}: "
                                    + ", ".join(k for k, v in it.items() if v is True)),
    "file": Probe("file", _file_requests, _file_items,
                  lambda it: f"{it.get('filepath')} version {it.get('version') or '-'}"),
    "service": Probe("service", _service_requests, _service_items,
                     lambda it: f"service {it.get('service_name')}: {it.get('start_type')}, {it.get('current_state')}"),
    "sid_sid": Probe("sid_sid", _accounts_requests, _sid_sid_items,
                     lambda it: f"{it.get('trustee_sid')} = {it.get('trustee_domain')}\\{it.get('trustee_name')}"),
    "user_sid55": Probe("user_sid55", _accounts_requests, _user_sid_items,
                        lambda it: f"{it.get('user_sid')} enabled={it.get('enabled')}"),
    "user_sid": Probe("user_sid", _accounts_requests, _user_sid_items,
                      lambda it: f"{it.get('user_sid')} enabled={it.get('enabled')}"),
    "wmi57": Probe("wmi57", _wmi_requests, _wmi57_items, _wmi_summary),
    "wmi": Probe("wmi", _wmi_requests, _wmi_items, _wmi_summary),
    "family": Probe("family", _no_requests, _family_items, lambda it: f"family {it.get('family')}"),
}
SUPPORTED = frozenset(PROBES)


def probe_for(o: ObjectDef) -> Probe:
    p = PROBES.get(o.probe)
    if p is None:
        raise Unsupported(o.probe + "_test")
    return p


def make_collector(data: dict):
    """Evaluator collector answering every object from one host's collected data."""
    def collect(o: ObjectDef, resolved: dict):
        p = probe_for(o)
        if o.behaviors:
            log.debug("object %s behaviors %s are ignored", o.id, o.behaviors)
        return p.items(o, resolved, data)
    return collect


def summarize_item(probe: str, item: dict) -> str:
    p = PROBES.get(probe)
    try:
        return p.summary(item) if p else ", ".join(f"{k}={v}" for k, v in item.items())
    except Exception:  # noqa: BLE001  evidence text must never break evaluation
        return str(item)[:200]


def compile_check(pattern: str) -> None:
    """Raise EvalError when a pattern cannot be used (used by the planner to report bad content early)."""
    compile_pattern(pattern)
