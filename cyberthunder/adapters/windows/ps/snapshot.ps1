# cyberthunder-script: snapshot
# Read-only. Exports exactly the state named in $CtSpec (inserted above as base64 JSON) so the change can be
# reversed with restore.ps1. Output is the same shape restore.ps1 reads.
$ErrorActionPreference = 'SilentlyContinue'
$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtSpec)) | ConvertFrom-Json
$root = @{ 'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKU' = 'HKEY_USERS'; 'HKCU' = 'HKEY_CURRENT_USER' }
$out = [ordered]@{ schema = 1 }

if ($spec.registry) {
  $out.registry = @(foreach ($r in $spec.registry) {
    $hive, $rest = $r.key -split '\\', 2
    $k = Get-Item -LiteralPath ('Registry::' + $root[$hive] + '\' + $rest)
    $exists = $false; $type = $null; $value = $null
    if ($k -and ($k.GetValueNames() -contains $r.name)) {
      $exists = $true; $type = [string]$k.GetValueKind($r.name); $value = $k.GetValue($r.name, $null, 'DoNotExpandEnvironmentNames')
    }
    [ordered]@{ key = $r.key; name = $r.name; exists = $exists; type = $type; value = $value }
  })
}
if ($spec.secpol) {
  $inf = Join-Path $env:TEMP ('ct_snap_' + [guid]::NewGuid().ToString('N') + '.inf')
  secedit.exe /export /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
  $all = @{}; $section = ''
  foreach ($line in Get-Content -Path $inf) {
    if ($line -match '^\[(.+)\]') { $section = $Matches[1]; continue }
    if ($section -eq 'System Access' -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $all[$Matches[1]] = $Matches[2].Trim() }
  }
  Remove-Item $inf -Force
  $sp = [ordered]@{}; foreach ($k in $spec.secpol) { $sp[$k] = $all[$k] }
  $out.secpol = $sp
}
if ($spec.services) {
  $out.services = @(foreach ($n in $spec.services) {
    $s = Get-Service -Name $n
    [ordered]@{ name = $n; exists = [bool]$s; start_type = $(if ($s) { [string]$s.StartType }); status = $(if ($s) { [string]$s.Status }) }
  })
}
if ($spec.tasks) {
  $out.tasks = @(foreach ($t in $spec.tasks) {
    $st = Get-ScheduledTask -TaskPath $t.path -TaskName $t.name
    [ordered]@{ path = $t.path; name = $t.name; exists = [bool]$st; enabled = $(if ($st) { [string]$st.State -ne 'Disabled' } else { $null }) }
  })
}
if ($spec.group_members) {
  $out.group_members = @(foreach ($g in $spec.group_members) {
    $names = @(Get-LocalGroupMember -SID $g.group_sid | ForEach-Object { [string]$_.Name })
    $short = $g.member.Split('\')[-1]
    $present = [bool]($names | Where-Object { $_ -eq $g.member -or $_.Split('\')[-1] -eq $short })
    [ordered]@{ group_sid = $g.group_sid; member = $g.member; present = $present }
  })
}
if ($spec.accounts) {
  $out.accounts = @(foreach ($n in $spec.accounts) {
    $u = Get-LocalUser -Name $n
    [ordered]@{ name = $n; exists = [bool]$u; enabled = $(if ($u) { [bool]$u.Enabled } else { $null }) }
  })
}
if ($spec.firewall) {
  $fw = [ordered]@{}; foreach ($p in Get-NetFirewallProfile) { $fw[[string]$p.Name] = ([string]$p.Enabled -eq 'True') }
  $out.firewall = $fw
}
if ($spec.audit) {
  $out.audit = @(foreach ($guid in $spec.audit) {
    $row = auditpol.exe /get /subcategory:$guid /r | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1
    $set = [string]$row.'Inclusion Setting'
    [ordered]@{ guid = $guid; success = ($set -match 'Success'); failure = ($set -match 'Failure') }
  })
}
if ($spec.defender) { $out.defender = @{ realtime = -not [bool](Get-MpPreference).DisableRealtimeMonitoring } }
if ($spec.smb) { $out.smb = @{ server_smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } }

$out | ConvertTo-Json -Depth 6 -Compress
