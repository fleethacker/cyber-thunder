# cyberthunder-script: hunt
# Read-only. Inventory of accounts, autoruns, tasks, services, listeners, WMI subscriptions, RDP state,
# failed logons and Defender exclusions, printed as one JSON document. hunt.py decides what is suspicious.
$ErrorActionPreference = 'SilentlyContinue'
$now = (Get-Date).ToUniversalTime()
$since = (Get-Date).AddDays(-30)
function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('o') } else { $null } }
function EvData($e, $name) { (([xml]$e.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq $name }).'#text' }
$out = [ordered]@{ schema = 1; now = $now.ToString('o') }

$out.admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
  [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID; object_class = [string]$_.ObjectClass; source = [string]$_.PrincipalSource } })
$out.users = @(Get-LocalUser | ForEach-Object {
  [ordered]@{ name = $_.Name; sid = [string]$_.SID; enabled = [bool]$_.Enabled; description = $_.Description } })
$out.created_accounts = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = $since } -MaxEvents 200 | ForEach-Object {
  [ordered]@{ time = Iso $_.TimeCreated; name = EvData $_ 'TargetUserName'; by = EvData $_ 'SubjectUserName' } })

$runPaths = @('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
              'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($h in Get-ChildItem -Path 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
  $runPaths += "HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
  $runPaths += "HKEY_USERS\$($h.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
}
$out.run_keys = @(foreach ($p in $runPaths) {
  $k = Get-Item -LiteralPath "Registry::$p"
  if ($k) { foreach ($n in $k.GetValueNames()) { if ($n) {
    [ordered]@{ key = ($p -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_USERS', 'HKU'); name = $n; value = [string]$k.GetValue($n, $null, 'DoNotExpandEnvironmentNames') } } } }
})

$out.tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
  [ordered]@{ path = $_.TaskPath; name = $_.TaskName; state = [string]$_.State; author = $_.Author
              actions = @($_.Actions | ForEach-Object { [ordered]@{ execute = $_.Execute; arguments = $_.Arguments } }) } })

$out.services = @(Get-CimInstance Win32_Service | ForEach-Object {
  [ordered]@{ name = $_.Name; display = $_.DisplayName; path = $_.PathName; start_type = [string]$_.StartMode; status = [string]$_.State; account = $_.StartName } })
$out.service_installs = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 200 | ForEach-Object {
  [ordered]@{ time = Iso $_.TimeCreated; service = EvData $_ 'ServiceName'; image = EvData $_ 'ImagePath'; account = EvData $_ 'AccountName' } })

$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$out.listeners = @(Get-NetTCPConnection -State Listen | ForEach-Object {
  [ordered]@{ address = $_.LocalAddress; port = [int]$_.LocalPort; pid = [int]$_.OwningProcess; process = $procs[[int]$_.OwningProcess] } })

$filters = @{}; Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | ForEach-Object { $filters[$_.Name] = $_.Query }
$out.wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
  $c = $_.Consumer; $f = $_.Filter
  $cons = Get-CimInstance -Namespace root\subscription -ClassName $c.CimClass.CimClassName | Where-Object { $_.Name -eq $c.Name } | Select-Object -First 1
  [ordered]@{ filter = $f.Name; query = $filters[$f.Name]; consumer = $c.Name; consumer_class = $c.CimClass.CimClassName
              command = $(if ($cons.CommandLineTemplate) { $cons.CommandLineTemplate } else { $cons.ScriptText }) } })

$ul = Get-Item -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$out.hidden_accounts = @(if ($ul) { foreach ($n in $ul.GetValueNames()) { [ordered]@{ name = $n; value = [string]$ul.GetValue($n) } } })

$ts = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server'
$lastWrite = $null
try {
  Add-Type -Namespace CtNative -Name Reg -MemberDefinition @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegOpenKeyEx(UIntPtr h, string k, int o, int s, out IntPtr r);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)] public static extern int RegQueryInfoKey(IntPtr h, IntPtr c, IntPtr cl, IntPtr r, IntPtr sk, IntPtr msk, IntPtr mc, IntPtr v, IntPtr mvn, IntPtr mvl, IntPtr sd, out long ft);
[DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr h);
'@
  $hk = [IntPtr]::Zero; $ft = 0
  if ([CtNative.Reg]::RegOpenKeyEx([UIntPtr]0x80000002, 'SYSTEM\CurrentControlSet\Control\Terminal Server', 0, 0x20019, [ref]$hk) -eq 0) {
    if ([CtNative.Reg]::RegQueryInfoKey($hk, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, [ref]$ft) -eq 0) { $lastWrite = [datetime]::FromFileTimeUtc($ft).ToString('o') }
    [void][CtNative.Reg]::RegCloseKey($hk)
  }
} catch { }
$deny = (Get-ItemProperty -LiteralPath $ts -Name fDenyTSConnections).fDenyTSConnections
$nla = (Get-ItemProperty -LiteralPath "$ts\WinStations\RDP-Tcp" -Name UserAuthentication).UserAuthentication
$out.rdp = [ordered]@{ enabled = ($deny -eq 0); key_last_write = $lastWrite; nla = $nla }

$out.failed_logons = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 500 | ForEach-Object {
  [ordered]@{ time = Iso $_.TimeCreated; user = EvData $_ 'TargetUserName'; ip = EvData $_ 'IpAddress' } })

$mp = Get-MpPreference
$out.defender_exclusions = [ordered]@{ paths = @($mp.ExclusionPath | Where-Object { $_ }); processes = @($mp.ExclusionProcess | Where-Object { $_ }); extensions = @($mp.ExclusionExtension | Where-Object { $_ }) }

$out | ConvertTo-Json -Depth 6 -Compress
