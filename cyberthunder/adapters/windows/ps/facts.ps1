# cyberthunder-script: facts
# Read-only. Basic identity of the host as one JSON document.
$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
[ordered]@{
  schema = 1
  hostname = $env:COMPUTERNAME
  os_name = [string]$os.Caption
  os_version = [string]$os.Version
  build = [string]$os.BuildNumber
  kernel = [string]$os.Version
  addresses = $ips
  model = [string]$cs.Model
  domain = [string]$cs.Domain
  part_of_domain = [bool]$cs.PartOfDomain
  last_boot = $(if ($os.LastBootUpTime) { $os.LastBootUpTime.ToUniversalTime().ToString('o') } else { $null })
  powershell = [string]$PSVersionTable.PSVersion
} | ConvertTo-Json -Depth 6 -Compress
