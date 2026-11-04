# Windows range target

`seed_misconfig.ps1` puts the ten items in `range/answer_key/windows.json` on a disposable Windows 11
(or Windows Server) VM so the Windows adapter can be exercised end to end over WinRM. The simulated host
(`cyberthunder/adapters/windows/simhost.py`, target `sim-win-01`) is seeded with the same items for the
offline demo.

| Id | Kind | What | Cited | Fix |
|---|---|---|---|---|
| M1 | misconfig | SMBv1 enabled on the SMB server | WN11-00-000165 | windows:smb1_server |
| M2 | misconfig | Guest account enabled | WN11-SO-000010 | windows:guest_disabled |
| M3 | misconfig | WDigest UseLogonCredential = 1 | WN11-CC-000038 | windows:wdigest_off |
| M4 | misconfig | LmCompatibilityLevel = 2 | WN11-SO-000205 | windows:lm_compat |
| M5 | misconfig | Minimum password length 8 | WN11-AC-000035 | windows:min_password_length |
| M6 | misconfig | Script block logging off | WN11-CC-000326 | windows:script_block_logging |
| I1 | intrusion | `svc_backup` in local Administrators | T1078.003 | windows:hunt:remove_admin_member |
| I2 | intrusion | HKLM Run `WindowsUpdateHelper` -> `%APPDATA%\upd.exe` | T1547.001 | windows:hunt:remove_run_value |
| I3 | intrusion | Task `OneDriveSync2` with `-EncodedCommand` | T1053.005 | windows:hunt:disable_task |
| I4 | intrusion | Service `WinDefendSvc2` from `C:\Users\Public` | T1543.003 | windows:hunt:disable_service |

The indicators are inert: the Run value and the service point at files that do not exist, and the task's
encoded command only prints a line of text.

## Seeding a VM

1. Use a throwaway VM on the isolated range. Name it with the guard prefix, for example `CT-RANGE-WS01`
   (the script refuses to run on any other computer name).
2. Enable WinRM for the adapter: `Enable-PSRemoting -Force` (HTTPS on 5986 is preferred; see below).
3. From an elevated PowerShell: `powershell -ExecutionPolicy Bypass -File .\seed_misconfig.ps1`
4. To put the VM back: `.\seed_misconfig.ps1 -Undo`. Reverting the VM snapshot is quicker still.

## Inventory entry

```yaml
- id: ct-range-ws01
  name: CT-RANGE-WS01
  asset_type: windows
  transport: winrm
  address: 192.168.56.21
  port: 5986
  username: itadmin
  credential_ref: WS01          # password comes from the environment variable CT_CRED_WS01
  sudo: false
  options:
    transport: ntlm             # ntlm | kerberos | basic | credssp
    ssl: true
    cert_validation: validate   # 'ignore' only for a self-signed listener on the isolated range
    known_admins: [itadmin]
    expected_ports: [3389, 5985, 5986]
    # cklb_path: C:\STIG\Checklists\CT-RANGE-WS01.cklb    # merge an existing Evaluate-STIG checklist
    # evaluate_stig_path: C:\Tools\Evaluate-STIG           # run the site's own copy (never copied into this repo)
```

Admin rights on the target are required: `secedit /export`, `auditpol`, the Security event log and
`Get-MpPreference` exclusions are only readable by administrators.
