# cyberthunder-script: evaluate_stig
# Runs the site's own copy of Evaluate-STIG (NSWC Crane) from the folder named in the inventory and reports
# the CKLB it wrote. Evaluate-STIG is never copied into this repository; it must already be on the host.
$ErrorActionPreference = 'Stop'
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json
$script = Join-Path $p.path 'Evaluate-STIG.ps1'
if (-not (Test-Path -LiteralPath $script)) { throw "Evaluate-STIG.ps1 not found in $($p.path)" }
New-Item -ItemType Directory -Path $p.out -Force | Out-Null
$started = Get-Date
& $script -ScanType Unclassified -Output CKLB -OutputPath $p.out | Out-Null
$cklb = Get-ChildItem -Path $p.out -Filter *.cklb -Recurse | Where-Object { $_.LastWriteTime -ge $started } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
[ordered]@{ schema = 1; cklb = $(if ($cklb) { $cklb.FullName } else { $null }) } | ConvertTo-Json -Compress
