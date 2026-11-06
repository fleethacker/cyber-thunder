# Optional per-user WSL session for the local development cluster. No elevation or VM reconfiguration.
[CmdletBinding()]
param(
    [ValidateSet('Status', 'Plan', 'Install', 'Start', 'Stop', 'Remove', 'Run')]
    [string]$Action = 'Status',
    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z')]
    [string]$Distribution = 'Ubuntu'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:KeepAlivePath = $PSCommandPath

function Get-OperatorSid {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try { return $identity.User.Value } finally { $identity.Dispose() }
}

function Get-WslExecutable {
    return Join-Path $env:WINDIR 'System32\wsl.exe'
}

function Get-WslDistributions {
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = Get-WslExecutable
    $process.StartInfo.Arguments = '--list --quiet'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.StandardOutputEncoding = [Text.Encoding]::Unicode
    $process.StartInfo.StandardErrorEncoding = [Text.Encoding]::Unicode
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) { throw 'WSL listing could not start.' }
        # Drain both pipes while waiting, with bounded buffers and one deadline.
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $readers = @($process.StandardOutput, $process.StandardError)
        $buffers = @((New-Object char[] 4096), (New-Object char[] 4096))
        $reads = @($readers[0].ReadAsync($buffers[0], 0, 4096), $readers[1].ReadAsync($buffers[1], 0, 4096))
        $lengths = @(0, 0)
        $output = New-Object Text.StringBuilder
        while ($true) {
            for ($i = 0; $i -lt 2; $i++) {
                if ($null -ne $reads[$i] -and $reads[$i].IsCompleted) {
                    $count = $reads[$i].GetAwaiter().GetResult()
                    $lengths[$i] += $count
                    if ($lengths[$i] -gt 65536) { throw 'WSL listing exceeded the expected size.' }
                    if ($i -eq 0) { [void]$output.Append($buffers[$i], 0, $count) }
                    if ($count -eq 0) { $reads[$i] = $null }
                    else { $reads[$i] = $readers[$i].ReadAsync($buffers[$i], 0, 4096) }
                }
            }
            if ($process.HasExited -and $null -eq $reads[0] -and $null -eq $reads[1]) { break }
            if ($watch.ElapsedMilliseconds -ge 10000) { throw 'WSL listing timed out; no task was changed.' }
            Start-Sleep -Milliseconds 10
        }
        if ($process.ExitCode -ne 0) { throw 'WSL listing failed; no task was changed.' }
        return @($output.ToString() -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $process.Kill()
                if (-not $process.WaitForExit(1000)) { throw 'The WSL listing process did not exit after cancellation.' }
            }
        } finally { $process.Dispose() }
    }
}

function Get-KeepAlivePlan([string]$Distro) {
    if ($Distro -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') { throw 'Unsupported distribution name.' }
    $sid = Get-OperatorSid
    $path = [IO.Path]::GetFullPath($script:KeepAlivePath)
    # Task Scheduler expands percent-delimited environment variables in arguments.
    if ($path -match '["%\x00-\x1f]') { throw 'Unsupported script path.' }
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

function Resolve-TaskSid([string]$UserId) {
    if ([string]::IsNullOrWhiteSpace($UserId)) { throw 'Task user identity is missing.' }
    if ($UserId -match '\AS-1-') { return $UserId }
    return (New-Object Security.Principal.NTAccount($UserId)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-OwnedKeepAliveTask($Plan, [switch]$Required) {
    # Enumerating the exact folder distinguishes an absent task from a failed query.
    $tasks = @(Get-ScheduledTask -TaskPath $Plan.TaskPath -ErrorAction Stop |
        Where-Object { $_.TaskPath -eq $Plan.TaskPath -and $_.TaskName -eq $Plan.TaskName })
    if ($tasks.Count -eq 0) {
        if ($Required) { throw 'The expected task disappeared; no further operation was attempted.' }
        return $null
    }
    if ($tasks.Count -ne 1) { throw 'Task identity is ambiguous.' }
    $task = $tasks[0]
    $owner = Resolve-TaskSid $task.Principal.UserId
    if ($task.TaskName -cne $Plan.TaskName -or $task.TaskPath -cne $Plan.TaskPath -or
        $owner -cne $Plan.OwnerSid -or $task.Description -cne $Plan.Description -or
        -not [string]::IsNullOrEmpty($task.Principal.GroupId) -or
        [string]$task.Principal.LogonType -ne 'Interactive' -or
        [string]$task.Principal.RunLevel -ne 'Limited' -or
        @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -cne $Plan.Execute -or
        $task.Actions[0].Arguments -cne $Plan.Arguments -or
        -not [string]::IsNullOrEmpty($task.Actions[0].WorkingDirectory) -or
        @($task.Triggers).Count -ne 1) {
        throw 'Existing task does not match this operator and script; inspect it in Task Scheduler.'
    }
    $trigger = $task.Triggers[0]
    $settings = $task.Settings
    if ($trigger.CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger' -or
        (Resolve-TaskSid $trigger.UserId) -cne $Plan.OwnerSid -or -not $trigger.Enabled -or
        -not [string]::IsNullOrEmpty($trigger.StartBoundary) -or
        -not [string]::IsNullOrEmpty($trigger.EndBoundary) -or
        $trigger.Delay -notin @('', 'PT0S', $null) -or
        $trigger.ExecutionTimeLimit -notin @('', 'PT0S', $null) -or
        ($null -ne $trigger.Repetition -and -not [string]::IsNullOrEmpty($trigger.Repetition.Interval)) -or
        -not $settings.Hidden -or [string]$settings.MultipleInstances -ne 'IgnoreNew' -or
        $settings.ExecutionTimeLimit -ne 'PT0S' -or $settings.RestartCount -ne 0 -or
        -not $settings.AllowHardTerminate -or -not $settings.AllowDemandStart -or
        $settings.WakeToRun -or $settings.StartWhenAvailable) {
        throw 'Existing task has changed trigger or lifetime settings; inspect it in Task Scheduler.'
    }
    return $task
}

function Invoke-KeepAlive([string]$Mode, [string]$Distro) {
    if ($env:OS -ne 'Windows_NT') { throw 'This utility requires Windows.' }
    $plan = Get-KeepAlivePlan $Distro
    if ($Mode -eq 'Run') {
        # Task Scheduler owns this session. Do not restart it after wsl --shutdown.
        $wsl = Get-WslExecutable
        & $wsl --distribution $Distro --exec sleep infinity
        if ($LASTEXITCODE -ne 0) { throw "The WSL keep-alive session ended unsuccessfully (exit $LASTEXITCODE)." }
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
        if (Get-OwnedKeepAliveTask $plan) { throw 'A task appeared during installation; nothing was overwritten.' }
        Register-ScheduledTask -TaskName $plan.TaskName -TaskPath $plan.TaskPath -InputObject $definition | Out-Null
        # Installation is distinct from starting the distribution.
        $task = Get-OwnedKeepAliveTask $plan -Required
    } elseif ($Mode -eq 'Start') {
        if (-not $task) { throw 'Install the task before starting it.' }
        $task = Get-OwnedKeepAliveTask $plan -Required
        Start-ScheduledTask -InputObject $task
    } elseif ($Mode -eq 'Stop' -or $Mode -eq 'Remove') {
        if ($task) {
            $task = Get-OwnedKeepAliveTask $plan -Required
            Stop-ScheduledTask -InputObject $task
            if ($Mode -eq 'Remove') {
                $task = Get-OwnedKeepAliveTask $plan -Required
                Unregister-ScheduledTask -InputObject $task -Confirm:$false
                if (Get-OwnedKeepAliveTask $plan) { throw 'Task removal could not be verified.' }
                $task = $null
            }
        }
    } elseif ($Mode -ne 'Status') { throw 'Unknown action.' }
    $info = $null
    if ($task) {
        $task = Get-OwnedKeepAliveTask $plan -Required
        $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
    }
    return [pscustomobject]@{
        TaskName = $plan.TaskName
        Distribution = $Distro
        Installed = [bool]$task
        TaskState = if ($task) { [string]$task.State } else { 'Absent' }
        LastRunTime = if ($info) { $info.LastRunTime } else { $null }
        LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
        RequestedAction = $Mode
        ClusterHealth = 'Not checked'
    }
}

# Dot-sourcing exposes the functions for isolated command-boundary tests.
if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-KeepAlive $Action $Distribution | ConvertTo-Json -Depth 4 }
    catch { Write-Error $_.Exception.Message -ErrorAction Continue; exit 1 }
}
