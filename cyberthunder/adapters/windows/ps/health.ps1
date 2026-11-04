# cyberthunder-script: health
# Read-only. Is the host still serving after a change: core services running and the management path up.
$ErrorActionPreference = 'SilentlyContinue'
$checks = @()
foreach ($n in @('WinRM', 'EventLog', 'LanmanWorkstation', 'Dnscache')) {
  $s = Get-Service -Name $n
  $checks += [ordered]@{ name = "service:$n"; ok = ($s -and [string]$s.Status -eq 'Running'); detail = $(if ($s) { [string]$s.Status } else { 'not installed' }) }
}
$os = Get-CimInstance Win32_OperatingSystem
$checks += [ordered]@{ name = 'os'; ok = [bool]$os; detail = [string]$os.Caption }
[ordered]@{ schema = 1; hostname = $env:COMPUTERNAME; checks = $checks } | ConvertTo-Json -Depth 6 -Compress
