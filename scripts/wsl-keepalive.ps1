# Optional per-user WSL session for the local development cluster. No elevation or VM reconfiguration.
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Plan', 'Install', 'Start', 'Stop', 'Remove', 'Run')]
    [string]$Action = 'Status',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Distribution = 'Ubuntu'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:KeepAlivePath = $PSCommandPath

function Get-OperatorSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return $identity.User.Value } finally { $identity.Dispose() }
}

function Get-WslDistributions {
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = Join-Path $env:WINDIR 'System32\wsl.exe'
    $process.StartInfo.Arguments = '--list --quiet'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [Text.Encoding]::Unicode
    $process.StartInfo.StandardErrorEncoding = [Text.Encoding]::Unicode
    try {
        if (-not $process.Start()) { throw 'WSL listing could not start.' }
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw 'WSL listing timed out; no task was changed.'
        }
        if ($process.ExitCode -ne 0) { throw 'WSL listing failed; no task was changed.' }
        $output = $process.StandardOutput.ReadToEnd().Replace([string][char]0, '')
        if ($output.Length -gt 65536) { throw 'WSL listing exceeded the expected size.' }
        return @($output -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } finally { $process.Dispose() }
}

function Get-KeepAlivePlan([string]$Distro) {
    if ($Distro -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'Unsupported distribution name.' }
    $sid = Get-OperatorSid
    $path = [IO.Path]::GetFullPath($script:KeepAlivePath)
    if ($path.Contains('"') -or $path.Contains("`n") -or $path.Contains("`r")) { throw 'Unsupported script path.' }
    $shell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    return [pscustomobject]@{
        TaskName = "Cyber Thunder WSL $sid $Distro"
        TaskPath = '\'
        OwnerSid = $sid
        Distribution = $Distro
        Description = "Cyber Thunder development WSL session v1; owner=$sid; distribution=$Distro"
        Execute = $shell
        Arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -File "' + $path + '" -Action Run -Distribution "' + $Distro + '"'
    }
}

function Get-OwnedKeepAliveTask($Plan) {
    # Enumerating the exact folder distinguishes an absent task from a failed query.
    $tasks = @(Get-ScheduledTask -TaskPath $Plan.TaskPath -ErrorAction Stop |
        Where-Object { $_.TaskName -ceq $Plan.TaskName })
    if ($tasks.Count -eq 0) { return $null }
    if ($tasks.Count -ne 1) { throw 'Task identity is ambiguous.' }
    $task = $tasks[0]
    $owner = $task.Principal.UserId
    if ($owner -notmatch '^S-1-') {
        $owner = (New-Object Security.Principal.NTAccount($owner)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    if ($owner -cne $Plan.OwnerSid -or $task.Description -cne $Plan.Description -or
        [string]$task.Principal.LogonType -ne 'Interactive' -or
        [string]$task.Principal.RunLevel -ne 'Limited' -or
        @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $Plan.Execute -or
        $task.Actions[0].Arguments -cne $Plan.Arguments) {
        throw 'Existing task does not match this operator and script; inspect it in Task Scheduler.'
    }
    return $task
}

function Invoke-KeepAlive([string]$Mode, [string]$Distro) {
    if ($env:OS -ne 'Windows_NT') { throw 'This utility requires Windows.' }
    $plan = Get-KeepAlivePlan $Distro
    if ($Mode -eq 'Run') {
        # Task Scheduler owns this session. Do not restart it after wsl --shutdown.
        $wsl = Join-Path $env:WINDIR 'System32\wsl.exe'
        & $wsl --distribution $Distro --exec sleep infinity
        if ($LASTEXITCODE -ne 0) { throw 'The WSL keep-alive session ended unsuccessfully.' }
        return
    }
    $task = Get-OwnedKeepAliveTask $plan
    if ($Mode -in @('Plan', 'Install', 'Start')) {
        if (@(Get-WslDistributions) -cnotcontains $Distro) { throw 'The selected WSL distribution is not registered for this operator.' }
    }
    if ($Mode -eq 'Plan') { return $plan }
    if ($Mode -eq 'Install') {
        if ($task) { throw 'The matching task is already installed. Remove it explicitly before reinstalling.' }
        $command = New-ScheduledTaskAction -Execute $plan.Execute -Argument $plan.Arguments
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $plan.OwnerSid
        $principal = New-ScheduledTaskPrincipal -UserId $plan.OwnerSid -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
        $definition = New-ScheduledTask -Action $command -Trigger $trigger -Principal $principal -Settings $settings -Description $plan.Description
        Register-ScheduledTask -TaskName $plan.TaskName -TaskPath $plan.TaskPath -InputObject $definition | Out-Null
        # Installation is distinct from starting the distribution.
        $task = Get-OwnedKeepAliveTask $plan
    } elseif ($Mode -eq 'Start') {
        if (-not $task) { throw 'Install the task before starting it.' }
        Start-ScheduledTask -InputObject $task
    } elseif ($Mode -eq 'Stop' -or $Mode -eq 'Remove') {
        if ($task) {
            Stop-ScheduledTask -InputObject $task
            if ($Mode -eq 'Remove') {
                Unregister-ScheduledTask -InputObject $task -Confirm:$false
                $task = $null
            }
        }
    } elseif ($Mode -ne 'Status') { throw 'Unknown action.' }
    if ($task) { $task = Get-OwnedKeepAliveTask $plan }
    return [pscustomobject]@{
        TaskName = $plan.TaskName
        Distribution = $Distro
        Installed = [bool]$task
        TaskState = if ($task) { [string]$task.State } else { 'Absent' }
        RequestedAction = $Mode
        ClusterHealth = 'Not checked'
    }
}

# Dot-sourcing exposes the functions for isolated command-boundary tests.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-KeepAlive $Action $Distribution | ConvertTo-Json -Depth 4 }
    catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 1 }
}
