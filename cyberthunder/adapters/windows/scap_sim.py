r"""Answers windows_collect.ps1 (marker 'scap-collect') from the simulated host's state.

The simulated host already models the registry, local security policy, services, users and the Administrators
group for the native checks and the hunt. This module reads the same state so that a fix applied through
the native fix library changes what the benchmark sees, plus a few things only the benchmark reads:

  state["rights"]        {"SeNetworkLogonRight": ["*S-1-5-32-544", ...]}   [Privilege Rights] entries
  state["auditpol"]      {"Credential Validation": "Success and Failure", ...}
                         (Logon comes from state["audit"], which the native audit fix changes)
  state["wmi_results"]   {"<namespace>|<wql>": [{property: value}]}       lower-case, whitespace-collapsed key
  state["scap_files"]    {"c:\\windows\\...": {"size", "version", ...}}

The built-in Administrator (RID 500) and Guest (RID 501) accounts are enabled or disabled by the
EnableAdminAccount / EnableGuestAccount policy values, as on a real host.
"""
from __future__ import annotations

WELL_KNOWN = {
    "S-1-1-0": "Everyone", "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users", "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE", "S-1-5-6": "NT AUTHORITY\\SERVICE",
    "S-1-5-113": "NT AUTHORITY\\Local account", "S-1-5-114": "NT AUTHORITY\\Local account and member of Administrators group",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM", "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
}
GROUP_NAMES = {"S-1-5-32-544": "Administrators", "S-1-5-32-545": "Users", "S-1-5-32-546": "Guests",
               "S-1-5-32-551": "Backup Operators", "S-1-5-32-555": "Remote Desktop Users"}
LOGON_GUID = "{0CCE9215-69AE-11D9-BED3-505054503030}"
START_MODE = {"Automatic": "Auto", "Manual": "Manual", "Disabled": "Disabled"}


def _canon(hive: str, key: str) -> str:
    return f"{hive.upper()}\\{key.strip(chr(92))}".lower()


def _user_enabled(state: dict, user: dict) -> bool:
    sid = str(user.get("sid", ""))
    sp = state.get("secpol") or {}
    if sid.endswith("-500") and "EnableAdminAccount" in sp:
        return str(sp["EnableAdminAccount"]).strip() == "1"
    if sid.endswith("-501") and "EnableGuestAccount" in sp:
        return str(sp["EnableGuestAccount"]).strip() == "1"
    return bool(user.get("enabled"))


def _name_of_sid(state: dict, sid: str) -> str:
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    for name, u in (state.get("users") or {}).items():
        if u.get("sid") == sid:
            return f"{state.get('hostname', 'HOST')}\\{name}"
    return sid


def _sid_of_name(state: dict, name: str) -> str:
    short = name.split("\\")[-1].lower()
    for sid, n in WELL_KNOWN.items():
        if n.split("\\")[-1].lower() == short:
            return sid
    for n, u in (state.get("users") or {}).items():
        if n.lower() == short:
            return u.get("sid", "")
    return ""


def _registry(state: dict, requests: list[dict]) -> list[dict]:
    reg = {k.lower(): (k, v) for k, v in (state.get("registry") or {}).items()}
    out = []
    seen = set()

    def emit(canon: str, shown_key: str, hive: str, names: list[str]) -> None:
        if canon in seen:
            return
        seen.add(canon)
        values = (reg.get(canon) or (None, {}))[1]
        wanted = list(values) if "*" in names else [n for n in values if n.lower() in {x.lower() for x in names}]
        out.append({"hive": hive, "key": shown_key,
                    "values": [{"name": n, "kind": values[n].get("type", "String"), "value": values[n].get("value")}
                               for n in wanted]})

    for r in requests:
        hive, key, names, depth = str(r.get("hive")), str(r.get("key", "")), list(r.get("names") or []), int(r.get("depth") or 0)
        canon = _canon(hive, key)
        exists = canon in reg or any(k.startswith(canon + "\\") for k in reg)
        if not exists:
            continue
        emit(canon, key, hive, names)
        if depth > 0:
            for k, (orig, _) in sorted(reg.items()):
                if not k.startswith(canon + "\\"):
                    continue
                rest = k[len(canon) + 1:].split("\\")
                for level in range(1, min(depth, len(rest)) + 1):
                    sub = canon + "\\" + "\\".join(rest[:level])
                    shown = key.rstrip("\\") + "\\" + "\\".join(orig.split("\\")[-len(rest):][:level])
                    emit(sub, shown, hive, names)
    return out


def _rights(state: dict) -> dict:
    out = {}
    for right, entries in (state.get("rights") or {}).items():
        holders = []
        for e in entries:
            e = str(e).strip()
            if e.startswith("*"):
                holders.append({"sid": e[1:], "name": _name_of_sid(state, e[1:])})
            else:
                holders.append({"sid": _sid_of_name(state, e), "name": e})
        out[right] = holders
    return out


def _audit(state: dict) -> list[dict]:
    rows = [{"subcategory": name, "guid": "", "setting": setting}
            for name, setting in (state.get("auditpol") or {}).items() if name.lower() != "logon"]
    a = (state.get("audit") or {}).get(LOGON_GUID, {})
    logon = {(True, True): "Success and Failure", (True, False): "Success", (False, True): "Failure",
             (False, False): "No Auditing"}[(bool(a.get("success")), bool(a.get("failure")))]
    rows.append({"subcategory": "Logon", "guid": LOGON_GUID, "setting": logon})
    return rows


def _accounts(state: dict) -> dict:
    host = state.get("hostname", "HOST")
    users = [{"name": n, "sid": u.get("sid", ""), "enabled": _user_enabled(state, u)}
             for n, u in (state.get("users") or {}).items()]
    groups = []
    for sid, members in (state.get("groups") or {}).items():
        groups.append({"name": GROUP_NAMES.get(sid, sid), "sid": sid, "domain": "BUILTIN",
                       "members": [{"name": m, "sid": _sid_of_name(state, m)} for m in members]})
    return {"computer": host, "users": users, "groups": groups}


def _files(state: dict, requests: list[dict]) -> list[dict]:
    files = {k.lower(): v for k, v in (state.get("scap_files") or {}).items()}
    out = []
    for r in requests:
        path = str(r.get("path", ""))
        if r.get("pattern") == "*":
            prefix = path.rstrip("\\").lower() + "\\"
            for k, v in files.items():
                if k.startswith(prefix) and "\\" not in k[len(prefix):]:
                    out.append({"path": v.get("path", k), "exists": True, **{a: b for a, b in v.items() if a != "path"}})
        else:
            v = files.get(path.lower())
            out.append({"path": path, "exists": False} if v is None else
                       {"path": path, "exists": True, **{a: b for a, b in v.items() if a != "path"}})
    return out


def _services(state: dict, names: list[str]) -> list[dict]:
    want = {n.lower() for n in names}
    out = []
    for n, s in (state.get("services") or {}).items():
        if "*" not in want and n.lower() not in want:
            continue
        out.append({"name": n, "display": s.get("display", ""), "start_type": START_MODE.get(s.get("start_type"), s.get("start_type")),
                    "status": s.get("status", ""), "account": s.get("account", ""), "path": s.get("path", ""),
                    "service_type": "Own Process"})
    return out


def wmi_key(namespace: str, wql: str) -> str:
    return f"{namespace.lower()}|{' '.join(wql.split()).lower()}"


def _wmi(state: dict, queries: list[dict]) -> list[dict]:
    results = {k.lower(): v for k, v in (state.get("wmi_results") or {}).items()}
    out = []
    for q in queries:
        ns, wql = str(q.get("namespace", "")), str(q.get("wql", ""))
        rows = results.get(wmi_key(ns, wql))
        out.append({"namespace": ns, "wql": wql, "rows": rows or [], "error": None})
    return out


def answer(state: dict, plan: dict) -> dict:
    """The JSON windows_collect.ps1 would print for this plan on the simulated host."""
    out: dict = {"schema": 1, "hostname": state.get("hostname"), "errors": []}
    if plan.get("registry") is not None:
        out["registry"] = _registry(state, plan.get("registry") or [])
    if plan.get("secedit"):
        out["system_access"] = {k: v for k, v in (state.get("secpol") or {}).items()}
        out["rights"] = _rights(state)
    if plan.get("auditpol"):
        out["audit"] = _audit(state)
    if plan.get("accounts"):
        out["accounts"] = _accounts(state)
    if plan.get("files") is not None:
        out["files"] = _files(state, plan.get("files") or [])
    if plan.get("services") is not None:
        out["services"] = _services(state, plan.get("services") or [])
    if plan.get("wmi") is not None:
        out["wmi"] = _wmi(state, plan.get("wmi") or [])
    return out
