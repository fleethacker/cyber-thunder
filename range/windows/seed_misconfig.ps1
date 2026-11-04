# Seeds the Windows answer-key items (range/answer_key/windows.json) on a DISPOSABLE Windows 11 or
# Windows Server range VM, so the Windows adapter has something real to find, fix and roll back.
#
# Run as Administrator on the range VM only:
#   powershell -ExecutionPolicy Bypass -File .\seed_misconfig.ps1                  # seed
#   powershell -ExecutionPolicy Bypass -File .\seed_misconfig.ps1 -Undo            # put everything back
#
# Guard: refuses to run unless the computer name starts with -RequiredPrefix (default CT-RANGE-).
# Idempotent: running it twice leaves the same state. All indicators are inert stand-ins: the Run value and
# the service point at files that do not exist, and the scheduled task's encoded command only prints text.
[CmdletBinding()]
param(
  [string]$RequiredPrefix = 'CT-RANGE-',
  [switch]$Undo
)
$ErrorActionPreference = 'Stop'

if (-not $env:COMPUTERNAME.StartsWith($RequiredPrefix, [StringComparison]::OrdinalIgnoreCase)) {
  throw "Refusing to run: computer name '$env:COMPUTERNAME' does not start with '$RequiredPrefix'. This script weakens security and is for disposable range VMs only."
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run from an elevated PowerShell.' }

function Set-Dword($Key, $Name, $Value) {
  if (-not (Test-Path $Key)) { New-Item -Path $Key -Force | Out-Null }
  New-ItemProperty -Path $Key -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}
function Set-SecPol([hashtable]$Settings) {
  $inf = Join-Path $env:TEMP 'ct_seed.inf'; $db = Join-Path $env:TEMP 'ct_seed.sdb'
  $lines = @('[Unicode]', 'Unicode=yes', '[System Access]') + ($Settings.GetEnumerator() | ForEach-Object { "$($_.Key) = $($_.Value)" }) + @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
  Set-Content -Path $inf -Value $lines -Encoding Unicode
  secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
  Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
}

$lanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$wdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
$sbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$run = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

if ($Undo) {
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
  Set-Dword $lanman 'SMB1' 0
  Set-SecPol @{ EnableGuestAccount = 0; MinimumPasswordLength = 14 }
  Set-Dword $wdigest 'UseLogonCredential' 0
  Set-Dword $lsa 'LmCompatibilityLevel' 5
  Set-Dword $sbl 'EnableScriptBlockLogging' 1
  if (Get-LocalUser -Name 'svc_backup' -ErrorAction SilentlyContinue) { Remove-LocalUser -Name 'svc_backup' }
  Remove-ItemProperty -Path $run -Name 'WindowsUpdateHelper' -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName 'OneDriveSync2' -Confirm:$false -ErrorAction SilentlyContinue
  if (Get-Service -Name 'WinDefendSvc2' -ErrorAction SilentlyContinue) { sc.exe delete WinDefendSvc2 | Out-Null }
  Write-Output 'Range seed removed.'
  return
}

# M1 SMBv1 server enabled (WN11-00-000165)
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false -ErrorAction SilentlyContinue
Set-Dword $lanman 'SMB1' 1
# M2 Guest enabled (WN11-SO-000010) and M5 minimum password length 8 (WN11-AC-000035)
Set-SecPol @{ EnableGuestAccount = 1; MinimumPasswordLength = 8 }
# M3 WDigest caching on (WN11-CC-000038)
Set-Dword $wdigest 'UseLogonCredential' 1
# M4 LAN Manager authentication level 2 (WN11-SO-000205)
Set-Dword $lsa 'LmCompatibilityLevel' 2
# M6 PowerShell script block logging off (WN11-CC-000326)
Set-Dword $sbl 'EnableScriptBlockLogging' 0

# I1 rogue local administrator svc_backup (T1078.003, T1136.001). Random password, never written anywhere.
if (-not (Get-LocalUser -Name 'svc_backup' -ErrorAction SilentlyContinue)) {
  $bytes = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $pw = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'a1!') -AsPlainText -Force
  New-LocalUser -Name 'svc_backup' -Password $pw -Description 'Backup service' -PasswordNeverExpires | Out-Null
}
if (-not (Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like '*\svc_backup' })) {
  Add-LocalGroupMember -SID 'S-1-5-32-544' -Member 'svc_backup'
}
# I2 Run value into a user-writable path (T1547.001). The target file does not exist.
New-ItemProperty -Path $run -Name 'WindowsUpdateHelper' -PropertyType ExpandString -Value '%APPDATA%\upd.exe' -Force | Out-Null
# I3 Scheduled task running an encoded command (T1053.005). The command only prints a line of text.
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'range seed task'"))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -EncodedCommand $enc"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName 'OneDriveSync2' -TaskPath '\' -Action $action -Trigger $trigger -Force | Out-Null
# I4 Service with its binary in C:\Users\Public (T1543.003). The binary does not exist, so it never starts;
#    creating it writes System event 7045, which the hunt also reports.
if (-not (Get-Service -Name 'WinDefendSvc2' -ErrorAction SilentlyContinue)) {
  New-Service -Name 'WinDefendSvc2' -DisplayName 'Windows Defender Service Helper' -BinaryPathName 'C:\Users\Public\windefend.exe' -StartupType Automatic | Out-Null
}
Write-Output "Seeded 6 misconfigurations and 4 intrusion indicators on $env:COMPUTERNAME. Undo with -Undo."
