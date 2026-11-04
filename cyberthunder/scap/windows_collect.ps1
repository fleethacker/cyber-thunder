# cyberthunder-script: scap-collect
# Collects, in one pass, the items the OVAL definitions of a SCAP benchmark need, and prints one JSON document.
# The collection plan arrives as data in $CtParams (base64 JSON inserted directly after the marker line by the
# adapter). Registry paths, value names, file paths, service names and WQL queries in the plan are values;
# nothing in the plan is executed as code. The script only reads: secedit exports the local policy to a
# temporary file under $env:TEMP, which is deleted before the script ends.
#
# Output (schema 1), sections present only when the plan asked for them:
#   registry       [{hive, key, values: [{name, kind, value}]}]      existing keys only
#   system_access  {MinimumPasswordLength: "14", ...}                 secedit [System Access]
#   net_accounts   {"Lockout threshold": "3", ...}                    net accounts
#   rights         {SeNetworkLogonRight: [{sid, name}]}               secedit [Privilege Rights]
#   audit          [{subcategory, guid, setting}]                     auditpol /get /category:* /r
#   accounts       {computer, users: [{name, sid, enabled}], groups: [{name, sid, members: [{name, sid}]}]}
#   files          [{path, exists, size, version, product_version, company, modified}]
#   services       [{name, display, start_type, status, account, path, service_type}]
#   wmi            [{namespace, wql, rows, error}]
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$plan = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($CtParams)) | ConvertFrom-Json
$out = [ordered]@{ schema = 1; hostname = $env:COMPUTERNAME; errors = @() }

function Add-CtError([string]$m) { $script:out.errors += $m }

# -- registry ------------------------------------------------------------------------------------------------
$hives = @{
    HKLM = [Microsoft.Win32.RegistryHive]::LocalMachine; HKU = [Microsoft.Win32.RegistryHive]::Users
    HKCU = [Microsoft.Win32.RegistryHive]::CurrentUser; HKCR = [Microsoft.Win32.RegistryHive]::ClassesRoot
    HKCC = [Microsoft.Win32.RegistryHive]::CurrentConfig
}
$script:regCount = 0

function ConvertTo-CtRegValue($kind, $v) {
    switch ($kind) {
        'DWord' { return [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$v), 0) }
        'QWord' { return [BitConverter]::ToUInt64([BitConverter]::GetBytes([int64]$v), 0) }
        'Binary' { return (($v | ForEach-Object { $_.ToString('X2') }) -join '') }
        'MultiString' { return ,@($v | ForEach-Object { [string]$_ }) }
        default { if ($null -eq $v) { return '' } else { return [string]$v } }
    }
}

function Read-CtKey($base, [string]$hive, [string]$path, $names, [int]$depth) {
    if ($script:regCount -ge 5000) { return }
    $k = $null
    try { $k = $base.OpenSubKey($path, $false) } catch { Add-CtError "registry ${hive}\${path}: $($_.Exception.Message)"; return }
    if ($null -eq $k) { return }
    try {
        $script:regCount++
        $present = @($k.GetValueNames())
        $wanted = @($names)
        if ($wanted -contains '*') { $wanted = $present }
        $vals = @()
        foreach ($n in $wanted) {
            $actual = $present | Where-Object { $_ -eq $n } | Select-Object -First 1
            if ($null -eq $actual) { continue }
            $kind = $k.GetValueKind($actual).ToString()
            $raw = $k.GetValue($actual, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $vals += [ordered]@{ name = [string]$actual; kind = $kind; value = (ConvertTo-CtRegValue $kind $raw) }
        }
        $script:out.registry += [ordered]@{ hive = $hive; key = $path; values = $vals }
        if ($depth -gt 0) {
            foreach ($sub in $k.GetSubKeyNames()) {
                $child = if ($path) { "$path\$sub" } else { $sub }
                Read-CtKey $base $hive $child $names ($depth - 1)
            }
        }
    } finally { $k.Close() }
}

if ($null -ne $plan.registry) {
    $out.registry = @()
    foreach ($r in @($plan.registry)) {
        $h = $hives[[string]$r.hive]
        if ($null -eq $h) { Add-CtError "registry: unknown hive $($r.hive)"; continue }
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, [Microsoft.Win32.RegistryView]::Registry64)
        try { Read-CtKey $base ([string]$r.hive) ([string]$r.key) @($r.names) ([int]$r.depth) } finally { $base.Close() }
    }
}

# -- local security policy and user rights ---------------------------------------------------------------------
function Resolve-CtTrustee([string]$entry) {
    $e = $entry.Trim()
    if (-not $e) { return $null }
    $sid = $null; $name = $null
    if ($e.StartsWith('*')) {
        $sid = $e.Substring(1)
        try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $sid }
    } else {
        $name = $e
        try { $sid = (New-Object System.Security.Principal.NTAccount($e)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = '' }
    }
    return [ordered]@{ sid = $sid; name = $name }
}

if ($plan.secedit) {
    $tmp = Join-Path $env:TEMP ('ct_secedit_{0}.inf' -f [guid]::NewGuid().ToString('N'))
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1 | Out-Null
        if (-not (Test-Path -LiteralPath $tmp)) {
            throw "export failed (exit $LASTEXITCODE); secedit needs administrator rights"
        }
        $sa = [ordered]@{}; $pr = [ordered]@{}; $section = ''
        foreach ($line in (Get-Content -LiteralPath $tmp -Encoding Unicode)) {
            if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; continue }
            if ($line -match '^\s*([^=;]+?)\s*=\s*(.*?)\s*$') {
                $key = $Matches[1]; $val = $Matches[2]
                if ($section -eq 'System Access') { $sa[$key] = $val }
                elseif ($section -eq 'Privilege Rights') {
                    $pr[$key] = @($val.Split(',') | ForEach-Object { Resolve-CtTrustee $_ } | Where-Object { $_ })
                }
            }
        }
        $out.system_access = $sa
        $out.rights = $pr
    } catch {
        Add-CtError "secedit: $($_.Exception.Message)"
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    try {
        $na = [ordered]@{}
        foreach ($line in (& net.exe accounts 2>$null)) {
            if ($line -match '^(.+?):\s+(\S.*)$') { $na[$Matches[1].Trim()] = $Matches[2].Trim() }
        }
        $out.net_accounts = $na
    } catch { Add-CtError "net accounts: $($_.Exception.Message)" }
}

# -- audit policy ------------------------------------------------------------------------------------------------
if ($plan.auditpol) {
    try {
        $lines = @(& auditpol.exe /get /category:* /r 2>$null | Where-Object { $_ -and $_.Trim() })
        if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 2) {
            throw "exit $LASTEXITCODE"
        }
        $out.audit = @($lines | ConvertFrom-Csv | ForEach-Object {
            [ordered]@{ subcategory = $_.'Subcategory'; guid = $_.'Subcategory GUID'; setting = $_.'Inclusion Setting' } })
    } catch { Add-CtError "auditpol: audit policy could not be read ($($_.Exception.Message.Trim())); auditpol needs administrator rights" }
}

# -- local accounts and groups -----------------------------------------------------------------------------------
if ($plan.accounts) {
    $acc = [ordered]@{ computer = $env:COMPUTERNAME; users = @(); groups = @() }
    try {
        foreach ($u in Get-LocalUser) {
            $acc.users += [ordered]@{ name = $u.Name; sid = $u.SID.Value; enabled = [bool]$u.Enabled }
        }
        foreach ($g in Get-LocalGroup) {
            $members = @()
            try {
                $members = @(Get-LocalGroupMember -SID $g.SID.Value -ErrorAction Stop | ForEach-Object {
                    [ordered]@{ name = [string]$_.Name; sid = [string]$_.SID.Value } })
            } catch { Add-CtError "group $($g.Name): $($_.Exception.Message)" }
            $acc.groups += [ordered]@{ name = $g.Name; sid = $g.SID.Value; domain = 'BUILTIN'; members = $members }
        }
    } catch { Add-CtError "accounts: $($_.Exception.Message)" }
    $out.accounts = $acc
}

# -- files -------------------------------------------------------------------------------------------------------
function Get-CtFile($item) {
    $o = [ordered]@{ path = $item.FullName; exists = $true; modified = $item.LastWriteTimeUtc.ToString('o') }
    if (-not $item.PSIsContainer) {
        $o.size = $item.Length
        $vi = $item.VersionInfo
        if ($vi) { $o.version = $vi.FileVersion; $o.product_version = $vi.ProductVersion; $o.company = $vi.CompanyName }
    }
    return $o
}

if ($null -ne $plan.files) {
    $out.files = @()
    foreach ($f in @($plan.files)) {
        try {
            if ($f.pattern -eq '*') {
                if (Test-Path -LiteralPath $f.path -PathType Container) {
                    foreach ($i in Get-ChildItem -LiteralPath $f.path -File -Force -ErrorAction SilentlyContinue) { $out.files += (Get-CtFile $i) }
                }
            } else {
                $i = Get-Item -LiteralPath $f.path -Force -ErrorAction SilentlyContinue
                if ($null -eq $i) { $out.files += [ordered]@{ path = [string]$f.path; exists = $false } }
                else { $out.files += (Get-CtFile $i) }
            }
        } catch { Add-CtError "file $($f.path): $($_.Exception.Message)" }
    }
}

# -- services ----------------------------------------------------------------------------------------------------
if ($null -ne $plan.services) {
    $out.services = @()
    $want = @($plan.services)
    try {
        foreach ($s in Get-CimInstance -ClassName Win32_Service) {
            if (-not ($want -contains '*') -and -not ($want -contains $s.Name)) { continue }
            $out.services += [ordered]@{ name = $s.Name; display = $s.DisplayName; start_type = $s.StartMode
                status = $s.State; account = $s.StartName; path = $s.PathName; service_type = $s.ServiceType }
        }
    } catch { Add-CtError "services: $($_.Exception.Message)" }
}

# -- WMI ---------------------------------------------------------------------------------------------------------
if ($null -ne $plan.wmi) {
    $out.wmi = @()
    foreach ($q in @($plan.wmi)) {
        $entry = [ordered]@{ namespace = [string]$q.namespace; wql = [string]$q.wql; rows = @(); error = $null }
        if ($entry.wql -notmatch '^\s*SELECT\s' -or $entry.wql -match '[;`$|&<>]' -or $entry.namespace -notmatch '^(?i)root(\\\w+)*$') {
            $entry.error = 'query refused: only plain SELECT queries in a root namespace are run'
        } else {
            try {
                foreach ($row in Get-CimInstance -Namespace $entry.namespace -Query $entry.wql -ErrorAction Stop) {
                    $r = [ordered]@{}
                    foreach ($p in $row.CimInstanceProperties) {
                        if ($null -ne $p.Value -and -not $p.Name.StartsWith('__')) { $r[$p.Name] = $p.Value }
                    }
                    $entry.rows += $r
                }
            } catch { $entry.error = $_.Exception.Message }
        }
        $out.wmi += $entry
    }
}

$out | ConvertTo-Json -Depth 8 -Compress
