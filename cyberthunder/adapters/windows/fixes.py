"""Vetted Windows remediations.

Every payload is PowerShell whose first line is '# cyberthunder-fix: <fix_ref>'. The approver sees the payload
verbatim. Before a fix runs, the adapter exports exactly the state the payload touches (snapshot.ps1 with the
fix's spec) and keeps it with the proposal; rollback re-imports that export with restore.ps1. Nothing here is
built from finding text: check fixes are fixed strings, and hunt fixes read one structured item (`$CtParams`,
base64 JSON taken from the host's own collected state) as values only.

Snapshot spec (also the shape restore.ps1 and the simulated host understand):
  registry       [{"key": "HKLM\\...", "name": "<value name>"}]
  secpol         ["MinimumPasswordLength", ...]                 [System Access] keys
  services       ["RemoteRegistry", ...]
  tasks          [{"path": "\\", "name": "..."}]
  group_members  [{"group_sid": "S-1-5-32-544", "member": "..."}]
  accounts       ["name", ...]
  firewall       true                                           all three profiles
  audit          ["{0CCE9215-...}"]                              auditpol subcategory GUIDs
  defender       true                                           real-time protection flag
  smb            true                                           SMB server EnableSMB1Protocol
"""
from __future__ import annotations

from cyberthunder.remediation.library import FixEntry

from . import checks as C
from .scripts import load, with_data

ADMINS_SID = "S-1-5-32-544"


def _split(path: str) -> dict:
    key, _, name = path.rpartition("\\")
    return {"key": key, "name": name}


def _reg_payload(fix_ref: str, values: list[tuple[str, int]], extra: str = "") -> str:
    lines = [f"# cyberthunder-fix: {fix_ref}", "$ErrorActionPreference = 'Stop'"]
    for path, val in values:
        key, _, name = path.rpartition("\\")
        ps_key = key.replace("HKLM\\", "HKLM:\\", 1)
        lines += [f"if (-not (Test-Path '{ps_key}')) {{ New-Item -Path '{ps_key}' -Force | Out-Null }}",
                  f"New-ItemProperty -Path '{ps_key}' -Name '{name}' -PropertyType DWord -Value {val} -Force | Out-Null"]
    if extra:
        lines.append(extra)
    return "\n".join(lines) + "\n"


def _secpol_payload(fix_ref: str, settings: dict[str, int | str]) -> str:
    body = ", ".join(f"'{k} = {v}'" for k, v in settings.items())
    return "\n".join([
        f"# cyberthunder-fix: {fix_ref}",
        "$ErrorActionPreference = 'Stop'",
        "$inf = Join-Path $env:TEMP 'ct_secpol_fix.inf'; $db = Join-Path $env:TEMP 'ct_secpol_fix.sdb'",
        "$lines = @('[Unicode]', 'Unicode=yes', '[System Access]', " + body + ", '[Version]', 'signature=\"$CHICAGO$\"', 'Revision=1')",
        "Set-Content -Path $inf -Value $lines -Encoding Unicode",
        "secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null",
        "$rc = $LASTEXITCODE",
        "Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue",
        "if ($rc -ne 0) { throw \"secedit returned $rc\" }",
    ]) + "\n"


def snapshot_command(spec: dict) -> str:
    """The exact PowerShell that exports the state a fix touches (snapshot.ps1 + the spec as data)."""
    return with_data(load("snapshot"), "CtSpec", spec)


def restore_command(state: dict) -> str:
    """The PowerShell that re-imports an exported state (restore.ps1 + the export as data)."""
    return with_data(load("restore"), "CtState", state)


ROLLBACK_STEPS = [
    "Re-import the values exported before the change: run restore.ps1 with the stored export "
    "(the adapter does this automatically on rollback).",
    "Re-run the check for this rule and confirm it reports the pre-change state.",
]


def _check_fix(c: C.CheckDef, title: str, payload: str, spec: dict, *, disruption: str = "low",
               reboot: bool = False, restarts: list[str] | None = None, notes: str = "",
               extra_rules: list[C.CheckDef] = ()) -> FixEntry:
    rules = [c, *extra_rules]
    applies = []
    cites = []
    for r in rules:
        applies += [r.rule_id] + ([r.stig_id] if r.stig_id else [])
        cites += ([r.stig_id] if r.stig_id else []) + list(r.refs) + (C.rule_meta(r.stig_id) or {}).get("ccis", [])
    return FixEntry(
        fix_ref=c.fix_ref, title=title, asset_type="windows", applies_to=applies, kind="powershell", payload=payload,
        disruption=disruption, reboot=reboot, restarts_services=restarts or [], reversible=True,
        rollback_kind="command", rollback_steps=list(ROLLBACK_STEPS),
        before_state={"commands": {"snapshot": snapshot_command(spec)}, "spec": spec},
        verify={"rule_ids": [r.rule_id for r in rules], "module": "check"},
        citations=list(dict.fromkeys(cites)), source="windows", notes=notes)


def _reg_fix(key: str, title: str, values: list[tuple[str, int]], **kw) -> FixEntry:
    c = C.BY_KEY[key]
    spec = {"registry": [_split(p) for p, _ in values]}
    return _check_fix(c, title, _reg_payload(c.fix_ref, values), spec, **kw)


def _secpol_fix(key: str, title: str, settings: dict, **kw) -> FixEntry:
    c = C.BY_KEY[key]
    return _check_fix(c, title, _secpol_payload(c.fix_ref, settings), {"secpol": sorted(settings)}, **kw)


def check_fixes() -> list[FixEntry]:
    by = C.BY_KEY
    fx = [
        _check_fix(by["smb1_server"], "Disable SMBv1 on the SMB server",
                   "\n".join(["# cyberthunder-fix: windows:smb1_server", "$ErrorActionPreference = 'Stop'",
                              "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false",
                              "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                              "-Name 'SMB1' -PropertyType DWord -Value 0 -Force | Out-Null"]) + "\n",
                   {"smb": True, "registry": [_split(C.LANMAN + r"\SMB1")]}, disruption="medium",
                   notes="Legacy devices that only speak SMBv1 (old printers, scanners, embedded controllers) lose "
                         "file-share access. Takes effect for new sessions without a reboot."),
        _reg_fix("smb1_client", "Disable the SMBv1 client driver", [(C.MRXSMB10 + r"\Start", 4)],
                 disruption="medium", reboot=True,
                 notes="Takes effect after a reboot. This host can no longer reach SMBv1-only file servers. "
                       "LanmanWorkstation dependencies are left as they are."),
        _secpol_fix("guest_disabled", "Disable the built-in Guest account", {"EnableGuestAccount": 0}),
        _secpol_fix("min_password_length", "Require passwords of at least 14 characters", {"MinimumPasswordLength": 14},
                    notes="Applies at the next password change; existing passwords keep working."),
        _secpol_fix("lockout_threshold", "Lock accounts after 3 bad logon attempts",
                    {"LockoutBadCount": 3, "ResetLockoutCount": 15, "LockoutDuration": 15}, disruption="medium",
                    notes="Users who mistype three times are locked out for 15 minutes; brief Sailors on the change."),
        _secpol_fix("password_history", "Remember the last 24 passwords", {"PasswordHistorySize": 24}),
        _secpol_fix("max_password_age", "Set maximum password age to 60 days", {"MaximumPasswordAge": 60},
                    notes="60 days is stricter than the benchmark's 180-day limit; accounts with older passwords are "
                          "prompted to change at next logon."),
        _secpol_fix("anon_sid_translation", "Disallow anonymous SID/Name translation", {"LSAAnonymousNameLookup": 0}),
        _reg_fix("uac_enabled", "Enable UAC Admin Approval Mode", [(C.POL_SYSTEM + r"\EnableLUA", 1)],
                 disruption="medium", reboot=True, notes="Requires a reboot; administrators get elevation prompts."),
        _reg_fix("rdp_nla", "Require Network Level Authentication for Remote Desktop",
                 [(C.RDP_TCP + r"\UserAuthentication", 1)],
                 notes="Remote Desktop clients without CredSSP/NLA support can no longer connect."),
        _check_fix(by["firewall_on"], "Turn on Windows Defender Firewall for all profiles",
                   "\n".join(["# cyberthunder-fix: windows:firewall_on", "$ErrorActionPreference = 'Stop'",
                              "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"]) + "\n",
                   {"firewall": True}, disruption="medium",
                   notes="Inbound traffic not allowed by an existing rule is blocked; WinRM and RDP keep their "
                         "built-in rules. Confirm required services have allow rules before approving."),
        _reg_fix("autoplay_off", "Turn off AutoPlay for all drives", [(C.POL_EXPLORER + r"\NoDriveTypeAutoRun", 255)]),
        _reg_fix("no_lm_hash", "Stop storing LAN Manager password hashes", [(C.LSA + r"\NoLMHash", 1)],
                 notes="Existing LM hashes are removed at each user's next password change."),
        _reg_fix("lm_compat", "Send NTLMv2 only; refuse LM and NTLM", [(C.LSA + r"\LmCompatibilityLevel", 5)],
                 disruption="medium", notes="Very old clients and appliances that only do LM/NTLMv1 fail to authenticate."),
        _reg_fix("script_block_logging", "Turn on PowerShell script block logging",
                 [(C.SBL + r"\EnableScriptBlockLogging", 1)],
                 notes="Increases PowerShell/Operational log volume; size the log accordingly."),
        _reg_fix("wdigest_off", "Disable WDigest credential caching", [(C.WDIGEST + r"\UseLogonCredential", 0)],
                 notes="Clear-text credentials stop being cached in LSASS for new logons."),
        _check_fix(by["remote_registry_disabled"], "Stop and disable the Remote Registry service",
                   "\n".join(["# cyberthunder-fix: windows:remote_registry_disabled", "$ErrorActionPreference = 'Stop'",
                              "Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue",
                              "Set-Service -Name RemoteRegistry -StartupType Disabled"]) + "\n",
                   {"services": ["RemoteRegistry"]}, restarts=["RemoteRegistry"],
                   notes="Remote management tools that read the registry over the network stop working."),
        _check_fix(by["defender_realtime"], "Turn on Microsoft Defender real-time protection",
                   "\n".join(["# cyberthunder-fix: windows:defender_realtime", "$ErrorActionPreference = 'Stop'",
                              "Set-MpPreference -DisableRealtimeMonitoring $false"]) + "\n",
                   {"defender": True},
                   notes="Fails if a group policy forces real-time protection off; then fix the policy instead."),
        _check_fix(by["audit_logon_failure"], "Audit Logon successes and failures",
                   "\n".join(["# cyberthunder-fix: windows:audit_logon",
                              f"auditpol.exe /set /subcategory:\"{C.LOGON_AUDIT_GUID}\" /success:enable /failure:enable | Out-Null",
                              "if ($LASTEXITCODE -ne 0) { throw \"auditpol returned $LASTEXITCODE\" }"]) + "\n",
                   {"audit": [C.LOGON_AUDIT_GUID]}, extra_rules=[by["audit_logon_success"]],
                   notes="Security log volume rises slightly. A domain audit policy may override the local setting."),
        FixEntry(
            fix_ref="windows:admin_renamed", title="Rename the built-in Administrator account", asset_type="windows",
            applies_to=[by["admin_renamed"].rule_id, "WN11-SO-000020"], kind="runbook",
            steps=["Choose a site-standard name for the built-in Administrator (SID ending -500) with the ISSM.",
                   "Local Security Policy > Local Policies > Security Options > 'Accounts: Rename administrator "
                   "account' = <chosen name>, or Rename-LocalUser -SID (Get-LocalUser | Where-Object SID -like '*-500').SID -NewName <name>.",
                   "Update break-glass documentation and any scripts that log on as 'Administrator'.",
                   "Re-scan the host to confirm WN11-SO-000020 passes."],
            disruption="low", rollback_kind="manual",
            rollback_steps=["Rename the account back with Rename-LocalUser to the previous name recorded in the before-state."],
            before_state={"commands": {"snapshot": snapshot_command({"secpol": ["NewAdministratorName"]})},
                          "spec": {"secpol": ["NewAdministratorName"]}},
            verify={"rule_ids": [by["admin_renamed"].rule_id], "module": "check"},
            citations=["WN11-SO-000020", "CCI-000366"], source="windows",
            notes="The new name is a site decision, so this is a runbook rather than an automatic change."),
    ]
    return fx


# -- hunt remediations ------------------------------------------------------------------------------------
HUNT_PAYLOADS = {
    "windows:hunt:remove_run_value": [
        "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json",
        "$root = @{ 'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKU' = 'HKEY_USERS'; 'HKCU' = 'HKEY_CURRENT_USER' }",
        "$hive, $rest = $p.key -split '\\\\', 2",
        "Remove-ItemProperty -LiteralPath ('Registry::' + $root[$hive] + '\\' + $rest) -Name $p.name -ErrorAction Stop",
    ],
    "windows:hunt:disable_task": [
        "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json",
        "Disable-ScheduledTask -TaskPath $p.path -TaskName $p.name -ErrorAction Stop | Out-Null",
    ],
    "windows:hunt:disable_service": [
        "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json",
        "Stop-Service -Name $p.name -Force -ErrorAction SilentlyContinue",
        "Set-Service -Name $p.name -StartupType Disabled -ErrorAction Stop",
    ],
    "windows:hunt:remove_admin_member": [
        "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json",
        f"Remove-LocalGroupMember -SID '{ADMINS_SID}' -Member $p.member -ErrorAction Stop",
    ],
    "windows:hunt:disable_account": [
        "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json",
        "Disable-LocalUser -Name $p.name -ErrorAction Stop",
    ],
}


def hunt_payload(fix_ref: str) -> str:
    return "\n".join([f"# cyberthunder-fix: {fix_ref}", "$ErrorActionPreference = 'Stop'", *HUNT_PAYLOADS[fix_ref]]) + "\n"


def hunt_spec(fix_ref: str, params: dict) -> dict:
    """What to export before a hunt fix runs, from the structured item it acts on."""
    if fix_ref == "windows:hunt:remove_run_value":
        return {"registry": [{"key": params["key"], "name": params["name"]}]}
    if fix_ref == "windows:hunt:disable_task":
        return {"tasks": [{"path": params["path"], "name": params["name"]}]}
    if fix_ref == "windows:hunt:disable_service":
        return {"services": [params["name"]]}
    if fix_ref == "windows:hunt:remove_admin_member":
        return {"group_members": [{"group_sid": ADMINS_SID, "member": params["member"]}]}
    if fix_ref == "windows:hunt:disable_account":
        return {"accounts": [params["name"]]}
    raise KeyError(fix_ref)


def hunt_fixes() -> list[FixEntry]:
    common = dict(asset_type="windows", kind="powershell", reversible=True, rollback_kind="command", source="hunt",
                  verify={"module": "hunt"})
    snap = "snapshot.ps1 with the item this fix acts on (resolved from the host's own state at capture time)"
    return [
        FixEntry(fix_ref="windows:hunt:remove_run_value", title="Remove the suspicious Run/RunOnce value",
                 applies_to=["T1547.001"], payload=hunt_payload("windows:hunt:remove_run_value"),
                 disruption="low", rollback_steps=["Re-create the registry value with its exported type and data (restore.ps1)."],
                 before_state={"commands": {"snapshot": snap}, "spec_from": "registry"},
                 citations=["T1547.001"], notes="The program it pointed at is left on disk for forensics.", **common),
        FixEntry(fix_ref="windows:hunt:disable_task", title="Disable the suspicious scheduled task",
                 applies_to=["T1053.005"], payload=hunt_payload("windows:hunt:disable_task"), disruption="low",
                 rollback_steps=["Enable-ScheduledTask on the same task path and name (restore.ps1)."],
                 before_state={"commands": {"snapshot": snap}, "spec_from": "tasks"},
                 citations=["T1053.005"], notes="The task is disabled, not deleted, so its definition stays as evidence.",
                 **common),
        FixEntry(fix_ref="windows:hunt:disable_service", title="Stop and disable the suspicious service",
                 applies_to=["T1543.003"], payload=hunt_payload("windows:hunt:disable_service"), disruption="medium",
                 rollback_steps=["Set the service back to its exported start type and start it if it was running (restore.ps1)."],
                 before_state={"commands": {"snapshot": snap}, "spec_from": "services"},
                 citations=["T1543.003"], notes="Anything that depends on the service stops with it. The binary is not deleted.",
                 restarts_services=["(the flagged service)"], **common),
        FixEntry(fix_ref="windows:hunt:remove_admin_member", title="Remove the unapproved account from local Administrators",
                 applies_to=["T1078.003"], payload=hunt_payload("windows:hunt:remove_admin_member"), disruption="low",
                 rollback_steps=["Add-LocalGroupMember -SID S-1-5-32-544 -Member <the exported member> (restore.ps1)."],
                 before_state={"commands": {"snapshot": snap}, "spec_from": "group_members"},
                 citations=["T1078.003"], notes="The account keeps working as a standard user; disable it separately if needed.",
                 **common),
        FixEntry(fix_ref="windows:hunt:disable_account", title="Disable the suspicious local account",
                 applies_to=["T1136.001", "T1564.002"], payload=hunt_payload("windows:hunt:disable_account"),
                 disruption="low", rollback_steps=["Enable-LocalUser on the same account (restore.ps1)."],
                 before_state={"commands": {"snapshot": snap}, "spec_from": "accounts"},
                 citations=["T1136.001", "T1564.002"], notes="The account is disabled, not deleted.", **common),
    ]


def all_fixes() -> list[FixEntry]:
    return [*check_fixes(), *hunt_fixes()]
