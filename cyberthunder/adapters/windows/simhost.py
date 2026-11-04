"""Simulated Windows workstation for the offline demo and the test suite.

SimulatedWindowsHost is a Transport that answers the adapter's own PowerShell scripts from a JSON state file
instead of a real machine. It decodes '-EncodedCommand', recognises a script by its marker line
('# cyberthunder-script: <name>' or '# cyberthunder-fix: <fix_ref>') and returns the same JSON the real
script would print. Fix payloads change the state, so verify and rollback are real state transitions.
It never executes anything.

State persists under <state_dir>/simulated/<target_id>.json so the CLI and the API see the same host.
The seeded state matches range/answer_key/windows.json: six misconfigurations and four intrusion indicators.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cyberthunder.transport.base import CommandResult, Transport, TransportError

from . import checks as C
from .scripts import FILE_RE, data_of, decode_command, marker

ADMINS_SID = "S-1-5-32-544"
HOST = "WS-01"
_lock = threading.Lock()

STARTMODE = {"Automatic": "Auto", "Manual": "Manual", "Disabled": "Disabled"}
ROOTS = {"HKLM": "HKLM", "HKEY_LOCAL_MACHINE": "HKLM", "HKU": "HKU", "HKEY_USERS": "HKU"}
RUN_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canon_key(key: str) -> str:
    k = key.replace("Registry::", "").replace(":\\", "\\").rstrip("\\")
    hive, _, rest = k.partition("\\")
    return f"{ROOTS.get(hive.upper(), hive.upper())}\\{rest}"


def _dw(v: int) -> dict:
    return {"type": "DWord", "value": v}


def seed_state() -> dict:
    """Seeded workstation. Everything is compliant except the answer-key items."""
    now = datetime.now(timezone.utc)
    # Placeholder beacon: the hunt only needs to see an encoded command line; the content is inert text.
    enc = base64.b64encode("Write-Output 'simulated sync task'".encode("utf-16-le")).decode("ascii")
    return {
        "schema": 1,
        "hostname": HOST,
        "facts": {"os_name": "Microsoft Windows 11 Enterprise", "os_version": "10.0.22631", "build": "22631",
                  "addresses": ["192.168.56.21"], "model": "Virtual Machine", "domain": "WORKGROUP"},
        "registry": {
            C.LANMAN: {"SMB1": _dw(1)},                                   # M1 SMBv1 server enabled
            C.MRXSMB10: {"Start": _dw(4)},
            C.POL_SYSTEM: {"EnableLUA": _dw(1)},
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion": {
                "EditionID": {"type": "String", "value": "Enterprise"},
                "CurrentBuild": {"type": "String", "value": "22631"}},
            C.RDP_TCP: {"UserAuthentication": _dw(1)},
            C.POL_EXPLORER: {"NoDriveTypeAutoRun": _dw(255)},
            C.LSA: {"NoLMHash": _dw(1), "LmCompatibilityLevel": _dw(2)},  # M4 LM auth level 2
            C.SBL: {"EnableScriptBlockLogging": _dw(0)},                 # M6 script block logging off
            C.WDIGEST: {"UseLogonCredential": _dw(1)},                   # M3 WDigest caching on
            RUN_KEY: {"SecurityHealth": {"type": "ExpandString", "value": r"%windir%\system32\SecurityHealthSystray.exe"},
                      "WindowsUpdateHelper": {"type": "ExpandString", "value": r"%APPDATA%\upd.exe"}},   # I2
        },
        "secpol": {"MinimumPasswordLength": "8",                         # M5 min length 8
                   "PasswordHistorySize": "24", "MaximumPasswordAge": "60", "MinimumPasswordAge": "1",
                   "LockoutBadCount": "3", "ResetLockoutCount": "15", "LockoutDuration": "15",
                   "EnableGuestAccount": "1",                            # M2 Guest enabled
                   "EnableAdminAccount": "0", "NewAdministratorName": '"ws01adm"', "NewGuestName": '"Guest"',
                   "LSAAnonymousNameLookup": "0", "PasswordComplexity": "1", "ClearTextPassword": "0"},
        "smb": {"server_smb1": True},
        "firewall": {"Domain": True, "Private": True, "Public": True},
        "defender": {"realtime": True, "exclusions": {"paths": [], "processes": [], "extensions": []}},
        "audit": {C.LOGON_AUDIT_GUID: {"success": True, "failure": True}},
        "users": {
            "ws01adm": {"sid": "S-1-5-21-1000-1000-1000-500", "enabled": False, "description": "Built-in account for administering the computer"},
            "Guest": {"sid": "S-1-5-21-1000-1000-1000-501", "enabled": True, "description": "Built-in account for guest access"},
            "itadmin": {"sid": "S-1-5-21-1000-1000-1000-1001", "enabled": True, "description": "IT administrator"},
            "sailor": {"sid": "S-1-5-21-1000-1000-1000-1002", "enabled": True, "description": ""},
            "svc_backup": {"sid": "S-1-5-21-1000-1000-1000-1003", "enabled": True, "description": "Backup service"},
        },
        "groups": {ADMINS_SID: [f"{HOST}\\ws01adm", f"{HOST}\\itadmin", f"{HOST}\\svc_backup"]},   # I1
        "services": {
            "WinRM": {"display": "Windows Remote Management (WS-Management)", "path": r"C:\Windows\System32\svchost.exe -k NetworkService -p",
                      "start_type": "Automatic", "status": "Running", "account": r"NT AUTHORITY\NetworkService"},
            "EventLog": {"display": "Windows Event Log", "path": r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
                         "start_type": "Automatic", "status": "Running", "account": r"NT AUTHORITY\LocalService"},
            "LanmanWorkstation": {"display": "Workstation", "path": r"C:\Windows\System32\svchost.exe -k NetworkService -p",
                                  "start_type": "Automatic", "status": "Running", "account": r"NT AUTHORITY\NetworkService"},
            "Dnscache": {"display": "DNS Client", "path": r"C:\Windows\system32\svchost.exe -k NetworkService -p",
                         "start_type": "Automatic", "status": "Running", "account": r"NT AUTHORITY\NetworkService"},
            "RemoteRegistry": {"display": "Remote Registry", "path": r"C:\Windows\system32\svchost.exe -k localService -p",
                               "start_type": "Disabled", "status": "Stopped", "account": r"NT AUTHORITY\LocalService"},
            "WinDefendSvc2": {"display": "Windows Defender Service Helper", "path": r"C:\Users\Public\windefend.exe",
                              "start_type": "Automatic", "status": "Running", "account": "LocalSystem"},          # I4
        },
        "tasks": [
            {"path": "\\", "name": "OneDriveSync2", "enabled": True, "author": f"{HOST}\\svc_backup",                 # I3
             "actions": [{"execute": "powershell.exe", "arguments": f"-NoProfile -WindowStyle Hidden -EncodedCommand {enc}"}]},
            {"path": "\\", "name": "GoogleUpdateTaskMachineCore", "enabled": True, "author": "",
             "actions": [{"execute": r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe", "arguments": "/c"}]},
        ],
        "events": {
            "4720": [{"time": _iso(now - timedelta(days=3)), "name": "svc_backup", "by": "itadmin"}],
            "7045": [{"time": _iso(now - timedelta(days=3, hours=-1)), "service": "WinDefendSvc2",
                      "image": r"C:\Users\Public\windefend.exe", "account": "LocalSystem"}],
            "4625": [],
        },
        "listeners": [
            {"address": "0.0.0.0", "port": 135, "pid": 1012, "process": "svchost"},
            {"address": "0.0.0.0", "port": 445, "pid": 4, "process": "System"},
            {"address": "0.0.0.0", "port": 3389, "pid": 1220, "process": "svchost"},
            {"address": "0.0.0.0", "port": 5985, "pid": 4, "process": "System"},
            {"address": "0.0.0.0", "port": 49664, "pid": 812, "process": "lsass"},
        ],
        "wmi": [],
        "hidden_accounts": [],
        "rdp": {"enabled": True, "key_last_write": _iso(now - timedelta(days=200))},
        "files": {},
        "applied": [],
        # Read only by the SCAP benchmark evaluation (scap_sim.py). Everything here is compliant, so the
        # 25-rule fixture benchmark fails exactly the six answer-key misconfigurations; the full Windows 11
        # benchmark also reports open rules for registry values this sparse simulated registry does not carry.
        "rights": {
            "SeNetworkLogonRight": ["*S-1-5-32-544", "*S-1-5-32-555"],
            "SeInteractiveLogonRight": ["*S-1-5-32-544", "*S-1-5-32-545"],
            "SeBackupPrivilege": ["*S-1-5-32-544"],
            "SeDebugPrivilege": ["*S-1-5-32-544"],
            "SeDenyNetworkLogonRight": ["*S-1-5-32-546"],
            "SeDenyInteractiveLogonRight": ["*S-1-5-32-546"],
        },
        "auditpol": {"Credential Validation": "Success and Failure", "Security Group Management": "Success",
                     "User Account Management": "Success and Failure", "Process Creation": "Success",
                     "Account Lockout": "Failure", "Special Logon": "Success", "Logoff": "Success",
                     "Sensitive Privilege Use": "Success and Failure", "Audit Policy Change": "Success and Failure",
                     "System Integrity": "Success and Failure"},
        "wmi_results": {
            r"root\cimv2|select domainrole from win32_computersystem": [{"DomainRole": 0}],
            r"root\cimv2|select installstate from win32_optionalfeature where name = 'smb1protocol'": [{"InstallState": 1}],
            r"root\cimv2\security\microsofttpm|select isenabled_initialvalue from win32_tpm": [{"IsEnabled_InitialValue": True}],
            r"root\cimv2\security\microsofttpm|select isactivated_initialvalue from win32_tpm": [{"IsActivated_InitialValue": True}],
            r"root\cimv2\security\microsofttpm|select isowned_initialvalue from win32_tpm": [{"IsOwned_InitialValue": True}],
        },
        "scap_files": {},
    }


def state_path(target_id: str, settings=None) -> Path:
    if settings is None:
        from cyberthunder.config import Settings
        settings = Settings.from_env()
    return Path(settings.state_dir) / "simulated" / f"{target_id}.json"


class SimulatedWindowsHost(Transport):
    kind = "simulated"

    def __init__(self, path: str | Path, target_id: str = "sim-win-01"):
        self.path = Path(path)
        self.target_id = target_id
        self.calls: list[str] = []

    # -- persistence ------------------------------------------------------------------------------------
    def load(self) -> dict:
        if not self.path.exists():
            self.reset()
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=1), encoding="utf-8")
        tmp.replace(self.path)

    def reset(self) -> None:
        self.save(seed_state())

    # -- transport --------------------------------------------------------------------------------------
    def run(self, command: str, *, timeout: int = 120, sudo: bool = False) -> CommandResult:
        t0 = time.time()
        self.calls.append(command)
        script = decode_command(command)
        if script is None:
            m = FILE_RE.match(command)
            if m:
                with _lock:
                    data = self.load()["files"].get(m.group(1).lower())
                script = base64.b64decode(data).decode("utf-8-sig") if data else None
        if script is None:
            simple = command.strip().lower()
            if simple in ("hostname", "whoami", "$env:computername"):
                out = HOST if simple != "whoami" else f"{HOST.lower()}\\itadmin"
                return CommandResult(command, 0, out + "\n", "", time.time() - t0, t0)
            return CommandResult(command, 1, "", "simulated host: unrecognised command", time.time() - t0, t0)
        mk = marker(script)
        if mk is None:
            return CommandResult(command, 1, "", "simulated host: script has no cyberthunder marker", time.time() - t0, t0)
        kind, name = mk
        data = data_of(script)
        with _lock:
            state = self.load()
            try:
                if kind == "script":
                    fn = getattr(self, f"_s_{name.replace('-', '_')}", None)
                    if fn is None:
                        return CommandResult(command, 1, "", f"simulated host: script {name} not available", time.time() - t0, t0)
                    out = fn(state, data)
                else:
                    out = self._fix(state, name, script, data)
                    state["applied"].append({"fix_ref": name, "at": _iso(datetime.now(timezone.utc))})
                    self.save(state)
                if kind == "script" and name == "restore":
                    self.save(state)
            except (KeyError, ValueError, TypeError) as e:
                return CommandResult(command, 1, "", f"simulated host: {e}", time.time() - t0, t0)
        text = out if isinstance(out, str) else json.dumps(out)
        return CommandResult(command, 0, text + "\n", "", time.time() - t0, t0)

    def read_file(self, path: str) -> bytes:
        with _lock:
            data = self.load()["files"].get(path.lower())
        if data is None:
            raise TransportError(f"simulated host has no file {path!r}")
        return base64.b64decode(data)

    def write_file(self, path: str, data: bytes, *, mode: int | None = None, sudo: bool = False) -> None:
        with _lock:
            state = self.load()
            state["files"][path.lower()] = base64.b64encode(data).decode("ascii")
            self.save(state)

    # -- helpers ----------------------------------------------------------------------------------------
    @staticmethod
    def _reg_get(state: dict, key: str, name: str):
        v = state["registry"].get(_canon_key(key), {}).get(name)
        return v

    @staticmethod
    def _reg_set(state: dict, key: str, name: str, type_: str, value) -> None:
        state["registry"].setdefault(_canon_key(key), {})[name] = {"type": type_, "value": value}

    @staticmethod
    def _reg_del(state: dict, key: str, name: str) -> None:
        state["registry"].get(_canon_key(key), {}).pop(name, None)

    @staticmethod
    def _member_present(state: dict, sid: str, member: str) -> bool:
        short = member.split("\\")[-1].lower()
        return any(m.split("\\")[-1].lower() == short for m in state["groups"].get(sid, []))

    @staticmethod
    def _task(state: dict, path: str, name: str) -> dict | None:
        for t in state["tasks"]:
            if t["path"] == path and t["name"] == name:
                return t
        return None

    # -- read-only scripts ------------------------------------------------------------------------------
    def _s_facts(self, state: dict, data: dict) -> dict:
        f = state["facts"]
        return {"schema": 1, "hostname": state["hostname"], "os_name": f["os_name"], "os_version": f["os_version"],
                "build": f["build"], "kernel": f["os_version"], "addresses": f["addresses"], "model": f["model"],
                "domain": f["domain"], "part_of_domain": False, "last_boot": None, "powershell": "5.1", "simulated": True}

    def _s_health(self, state: dict, data: dict) -> dict:
        checks = []
        for n in ("WinRM", "EventLog", "LanmanWorkstation", "Dnscache"):
            s = state["services"].get(n)
            checks.append({"name": f"service:{n}", "ok": bool(s and s["status"] == "Running"),
                           "detail": s["status"] if s else "not installed"})
        checks.append({"name": "os", "ok": True, "detail": state["facts"]["os_name"]})
        return {"schema": 1, "hostname": state["hostname"], "checks": checks}

    def _s_checks(self, state: dict, data: dict) -> dict:
        reg = {}
        for path in C.REG_VALUES:
            key, _, name = path.rpartition("\\")
            v = self._reg_get(state, key, name)
            reg[path] = v["value"] if v else None
        a = state["audit"].get(C.LOGON_AUDIT_GUID, {})
        logon = {(True, True): "Success and Failure", (True, False): "Success",
                 (False, True): "Failure", (False, False): "No Auditing"}[(bool(a.get("success")), bool(a.get("failure")))]
        rr = state["services"].get("RemoteRegistry")
        return {"schema": 1, "registry": reg, "secpol": dict(state["secpol"]), "smb": dict(state["smb"]),
                "firewall": dict(state["firewall"]),
                "services": {"RemoteRegistry": {"start_type": rr["start_type"], "status": rr["status"]} if rr else None},
                "defender": {"realtime": state["defender"]["realtime"]}, "audit": {"logon": logon}}

    def _s_hunt(self, state: dict, data: dict) -> dict:
        admins = []
        for m in state["groups"].get(ADMINS_SID, []):
            u = state["users"].get(m.split("\\")[-1], {})
            admins.append({"name": m, "sid": u.get("sid", ""), "object_class": "User", "source": "Local"})
        run_keys = []
        for key, values in state["registry"].items():
            if re.search(r"\\CurrentVersion\\Run(Once)?$", key, re.I):
                run_keys += [{"key": key, "name": n, "value": v["value"]} for n, v in values.items()]
        return {
            "schema": 1, "now": _iso(datetime.now(timezone.utc)), "admins": admins,
            "users": [{"name": n, "sid": u["sid"], "enabled": u["enabled"], "description": u["description"]}
                      for n, u in state["users"].items()],
            "created_accounts": list(state["events"]["4720"]),
            "run_keys": run_keys,
            "tasks": [{"path": t["path"], "name": t["name"], "state": "Ready" if t["enabled"] else "Disabled",
                       "author": t["author"], "actions": t["actions"]} for t in state["tasks"]],
            "services": [{"name": n, "display": s["display"], "path": s["path"],
                          "start_type": STARTMODE.get(s["start_type"], s["start_type"]), "status": s["status"],
                          "account": s["account"]} for n, s in state["services"].items()],
            "service_installs": list(state["events"]["7045"]),
            "listeners": list(state["listeners"]),
            "wmi": list(state["wmi"]),
            "hidden_accounts": list(state["hidden_accounts"]),
            "rdp": {"enabled": state["rdp"]["enabled"], "key_last_write": state["rdp"]["key_last_write"],
                    "nla": (self._reg_get(state, C.RDP_TCP, "UserAuthentication") or {}).get("value")},
            "failed_logons": list(state["events"]["4625"]),
            "defender_exclusions": copy.deepcopy(state["defender"]["exclusions"]),
        }

    def _s_cleanup(self, state: dict, data: dict) -> str:
        return ""

    def _s_scap_collect(self, state: dict, data: dict) -> dict:
        from .scap_sim import answer
        return answer(state, data.get("CtParams") or {})

    def _s_snapshot(self, state: dict, data: dict) -> dict:
        spec = data.get("CtSpec") or {}
        out: dict = {"schema": 1}
        if spec.get("registry"):
            out["registry"] = []
            for r in spec["registry"]:
                v = self._reg_get(state, r["key"], r["name"])
                out["registry"].append({"key": r["key"], "name": r["name"], "exists": v is not None,
                                        "type": v["type"] if v else None, "value": v["value"] if v else None})
        if spec.get("secpol"):
            out["secpol"] = {k: state["secpol"].get(k) for k in spec["secpol"]}
        if spec.get("services"):
            out["services"] = []
            for n in spec["services"]:
                s = state["services"].get(n)
                out["services"].append({"name": n, "exists": s is not None, "start_type": s and s["start_type"],
                                        "status": s and s["status"]})
        if spec.get("tasks"):
            out["tasks"] = []
            for t in spec["tasks"]:
                st = self._task(state, t["path"], t["name"])
                out["tasks"].append({"path": t["path"], "name": t["name"], "exists": st is not None,
                                     "enabled": st["enabled"] if st else None})
        if spec.get("group_members"):
            out["group_members"] = [{"group_sid": g["group_sid"], "member": g["member"],
                                     "present": self._member_present(state, g["group_sid"], g["member"])}
                                    for g in spec["group_members"]]
        if spec.get("accounts"):
            out["accounts"] = []
            for n in spec["accounts"]:
                u = state["users"].get(n)
                out["accounts"].append({"name": n, "exists": u is not None, "enabled": u["enabled"] if u else None})
        if spec.get("firewall"):
            out["firewall"] = dict(state["firewall"])
        if spec.get("audit"):
            out["audit"] = [{"guid": g, "success": bool(state["audit"].get(g, {}).get("success")),
                             "failure": bool(state["audit"].get(g, {}).get("failure"))} for g in spec["audit"]]
        if spec.get("defender"):
            out["defender"] = {"realtime": state["defender"]["realtime"]}
        if spec.get("smb"):
            out["smb"] = {"server_smb1": state["smb"]["server_smb1"]}
        return out

    def _s_restore(self, state: dict, data: dict) -> dict:
        st = data.get("CtState") or {}
        done = []
        for r in st.get("registry") or []:
            if r["exists"]:
                self._reg_set(state, r["key"], r["name"], r.get("type") or "String", r["value"])
            else:
                self._reg_del(state, r["key"], r["name"])
            done.append(f"registry:{r['key']}\\{r['name']}")
        if st.get("secpol"):
            for k, v in st["secpol"].items():
                if v is not None:
                    state["secpol"][k] = v
            done.append("secpol")
        for s in st.get("services") or []:
            if s.get("exists") and s["name"] in state["services"]:
                state["services"][s["name"]].update(start_type=s["start_type"], status=s["status"])
                done.append(f"service:{s['name']}")
        for t in st.get("tasks") or []:
            task = self._task(state, t["path"], t["name"])
            if t.get("exists") and task:
                task["enabled"] = bool(t["enabled"])
                done.append(f"task:{t['path']}{t['name']}")
        for g in st.get("group_members") or []:
            members = state["groups"].setdefault(g["group_sid"], [])
            present = self._member_present(state, g["group_sid"], g["member"])
            if g["present"] and not present:
                members.append(g["member"])
            if not g["present"] and present:
                short = g["member"].split("\\")[-1].lower()
                members[:] = [m for m in members if m.split("\\")[-1].lower() != short]
            done.append(f"group:{g['group_sid']}:{g['member']}")
        for a in st.get("accounts") or []:
            if a.get("exists") and a["name"] in state["users"]:
                state["users"][a["name"]]["enabled"] = bool(a["enabled"])
                done.append(f"account:{a['name']}")
        if st.get("firewall"):
            state["firewall"].update(st["firewall"])
            done.append("firewall")
        for a in st.get("audit") or []:
            state["audit"][a["guid"]] = {"success": bool(a["success"]), "failure": bool(a["failure"])}
            done.append(f"audit:{a['guid']}")
        if st.get("defender"):
            state["defender"]["realtime"] = bool(st["defender"]["realtime"])
            done.append("defender")
        if st.get("smb"):
            state["smb"]["server_smb1"] = bool(st["smb"]["server_smb1"])
            done.append("smb")
        return {"schema": 1, "restored": done}

    # -- fixes ------------------------------------------------------------------------------------------
    REG_LINE = re.compile(r"New-ItemProperty -Path '([^']+)' -Name '([^']+)' -PropertyType (\w+) -Value (\d+)")
    SECPOL_ITEM = re.compile(r"'(\w+) = ([^']+)'")

    def _fix(self, state: dict, fix_ref: str, script: str, data: dict) -> dict:
        p = data.get("CtParams") or {}
        if fix_ref == "windows:smb1_server":
            state["smb"]["server_smb1"] = False
        elif fix_ref == "windows:firewall_on":
            state["firewall"] = {"Domain": True, "Private": True, "Public": True}
        elif fix_ref == "windows:remote_registry_disabled":
            state["services"]["RemoteRegistry"].update(start_type="Disabled", status="Stopped")
        elif fix_ref == "windows:defender_realtime":
            state["defender"]["realtime"] = True
        elif fix_ref == "windows:audit_logon":
            state["audit"][C.LOGON_AUDIT_GUID] = {"success": True, "failure": True}
        elif fix_ref == "windows:hunt:remove_run_value":
            if self._reg_get(state, p["key"], p["name"]) is None:
                raise KeyError(f"no registry value {p['key']}\\{p['name']}")
            self._reg_del(state, p["key"], p["name"])
        elif fix_ref == "windows:hunt:disable_task":
            t = self._task(state, p["path"], p["name"])
            if t is None:
                raise KeyError(f"no scheduled task {p['path']}{p['name']}")
            t["enabled"] = False
        elif fix_ref == "windows:hunt:disable_service":
            s = state["services"][p["name"]]
            s.update(start_type="Disabled", status="Stopped")
        elif fix_ref == "windows:hunt:remove_admin_member":
            if not self._member_present(state, ADMINS_SID, p["member"]):
                raise KeyError(f"{p['member']} is not a member of Administrators")
            short = p["member"].split("\\")[-1].lower()
            state["groups"][ADMINS_SID] = [m for m in state["groups"][ADMINS_SID] if m.split("\\")[-1].lower() != short]
        elif fix_ref == "windows:hunt:disable_account":
            state["users"][p["name"]]["enabled"] = False
        elif "secedit.exe /configure" in script:
            for k, v in self.SECPOL_ITEM.findall(script):
                state["secpol"][k] = v.strip()
        elif self.REG_LINE.search(script):
            pass
        else:
            raise ValueError(f"fix {fix_ref} is not known to the simulated host")
        # Registry writes in any payload (registry fixes, and the SMB1 value the SMB fix also sets).
        for key, name, type_, val in self.REG_LINE.findall(script):
            self._reg_set(state, key, name, type_, int(val))
        return {"schema": 1, "fix": fix_ref, "ok": True}
