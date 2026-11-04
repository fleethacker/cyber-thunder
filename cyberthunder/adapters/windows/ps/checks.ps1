# cyberthunder-script: checks
# Read-only. Collects the registry, local security policy, service, firewall, Defender and audit state the
# Windows 11 STIG checks are decided from, and prints one JSON document. Decisions are made by checks.py.
$ErrorActionPreference = 'SilentlyContinue'
$out = [ordered]@{ schema = 1 }

$regValues = @(
  'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1',
  'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
  'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication',
  'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun',
  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash',
  'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
  'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging',
  'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
)
$reg = [ordered]@{}
foreach ($v in $regValues) {
  $i = $v.LastIndexOf('\')
  $key = 'Registry::HKEY_LOCAL_MACHINE' + $v.Substring(4, $i - 4)
  $name = $v.Substring($i + 1)
  $val = $null
  $item = Get-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue
  if ($item) { $val = $item.$name }
  $reg[$v] = $val
}
$out.registry = $reg

# [System Access] section of the local security policy
$sp = [ordered]@{}
$inf = Join-Path $env:TEMP ('ct_secpol_' + [guid]::NewGuid().ToString('N') + '.inf')
secedit.exe /export /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
if (Test-Path $inf) {
  $section = ''
  foreach ($line in Get-Content -Path $inf) {
    if ($line -match '^\[(.+)\]') { $section = $Matches[1]; continue }
    if ($section -eq 'System Access' -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $sp[$Matches[1]] = $Matches[2].Trim() }
  }
  Remove-Item $inf -Force
}
$out.secpol = $sp

$smb = Get-SmbServerConfiguration
$out.smb = @{ server_smb1 = $(if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null }) }

$fw = [ordered]@{}
foreach ($p in Get-NetFirewallProfile) { $fw[[string]$p.Name] = ([string]$p.Enabled -eq 'True') }
$out.firewall = $fw

$svc = [ordered]@{}
foreach ($n in @('RemoteRegistry')) {
  $s = Get-Service -Name $n
  if ($s) { $svc[$n] = @{ start_type = [string]$s.StartType; status = [string]$s.Status } } else { $svc[$n] = $null }
}
$out.services = $svc

$mp = Get-MpComputerStatus
$out.defender = @{ realtime = $(if ($mp) { [bool]$mp.RealTimeProtectionEnabled } else { $null }) }

$logon = $null
$csv = auditpol.exe /get /subcategory:'{0CCE9215-69AE-11D9-BED3-505054503030}' /r
if ($LASTEXITCODE -eq 0 -and $csv) { $row = $csv | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1; $logon = $row.'Inclusion Setting' }
$out.audit = @{ logon = $logon }

$out | ConvertTo-Json -Depth 6 -Compress
