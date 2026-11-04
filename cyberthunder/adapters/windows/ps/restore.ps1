# cyberthunder-script: restore
# Re-imports a state exported by snapshot.ps1 ($CtState, inserted above as base64 JSON). Values are applied
# as data; nothing in the export is executed. Prints a JSON summary of what was restored.
$ErrorActionPreference = 'Stop'
$st = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtState)) | ConvertFrom-Json
$root = @{ 'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKU' = 'HKEY_USERS'; 'HKCU' = 'HKEY_CURRENT_USER' }
$done = @()

foreach ($r in @($st.registry | Where-Object { $_ })) {
  $hive, $rest = $r.key -split '\\', 2
  $path = 'Registry::' + $root[$hive] + '\' + $rest
  if ($r.exists) {
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
    $type = if ($r.type) { $r.type } else { 'String' }
    New-ItemProperty -LiteralPath $path -Name $r.name -PropertyType $type -Value $r.value -Force | Out-Null
  } elseif (Test-Path -LiteralPath $path) {
    Remove-ItemProperty -LiteralPath $path -Name $r.name -ErrorAction SilentlyContinue
  }
  $done += "registry:$($r.key)\$($r.name)"
}
if ($st.secpol) {
  $lines = @('[Unicode]', 'Unicode=yes', '[System Access]')
  foreach ($p in $st.secpol.PSObject.Properties) { if ($null -ne $p.Value) { $lines += "$($p.Name) = $($p.Value)" } }
  $lines += @('[Version]', 'signature="$CHICAGO$"', 'Revision=1')
  $inf = Join-Path $env:TEMP 'ct_restore.inf'; $db = Join-Path $env:TEMP 'ct_restore.sdb'
  Set-Content -Path $inf -Value $lines -Encoding Unicode
  secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
  $rc = $LASTEXITCODE
  Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
  if ($rc -ne 0) { throw "secedit returned $rc" }
  $done += 'secpol'
}
foreach ($s in @($st.services | Where-Object { $_ -and $_.exists })) {
  Set-Service -Name $s.name -StartupType $s.start_type
  if ($s.status -eq 'Running') { Start-Service -Name $s.name } elseif ($s.status -eq 'Stopped') { Stop-Service -Name $s.name -Force -ErrorAction SilentlyContinue }
  $done += "service:$($s.name)"
}
foreach ($t in @($st.tasks | Where-Object { $_ -and $_.exists })) {
  if ($t.enabled) { Enable-ScheduledTask -TaskPath $t.path -TaskName $t.name | Out-Null } else { Disable-ScheduledTask -TaskPath $t.path -TaskName $t.name | Out-Null }
  $done += "task:$($t.path)$($t.name)"
}
foreach ($g in @($st.group_members | Where-Object { $_ })) {
  $names = @(Get-LocalGroupMember -SID $g.group_sid | ForEach-Object { [string]$_.Name.Split('\')[-1] })
  $short = $g.member.Split('\')[-1]
  if ($g.present -and ($names -notcontains $short)) { Add-LocalGroupMember -SID $g.group_sid -Member $g.member }
  if (-not $g.present -and ($names -contains $short)) { Remove-LocalGroupMember -SID $g.group_sid -Member $g.member }
  $done += "group:$($g.group_sid):$($g.member)"
}
foreach ($a in @($st.accounts | Where-Object { $_ -and $_.exists })) {
  if ($a.enabled) { Enable-LocalUser -Name $a.name } else { Disable-LocalUser -Name $a.name }
  $done += "account:$($a.name)"
}
if ($st.firewall) {
  foreach ($p in $st.firewall.PSObject.Properties) { Set-NetFirewallProfile -Profile $p.Name -Enabled $(if ($p.Value) { 'True' } else { 'False' }) }
  $done += 'firewall'
}
foreach ($a in @($st.audit | Where-Object { $_ })) {
  $s = if ($a.success) { 'enable' } else { 'disable' }; $f = if ($a.failure) { 'enable' } else { 'disable' }
  auditpol.exe /set /subcategory:$($a.guid) /success:$s /failure:$f | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol returned $LASTEXITCODE" }
  $done += "audit:$($a.guid)"
}
if ($st.defender) { Set-MpPreference -DisableRealtimeMonitoring (-not [bool]$st.defender.realtime); $done += 'defender' }
if ($st.smb) { Set-SmbServerConfiguration -EnableSMB1Protocol ([bool]$st.smb.server_smb1) -Force -Confirm:$false; $done += 'smb' }

[ordered]@{ schema = 1; restored = $done } | ConvertTo-Json -Depth 4 -Compress
