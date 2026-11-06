"""Exercise the Windows task boundary without creating tasks or starting WSL."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows PowerShell task-boundary fixture")
def test_keepalive_operator_and_task_boundaries(tmp_path, record_property):
    source = Path(__file__).resolve().parents[2] / "scripts/wsl-keepalive.ps1"
    fixture = tmp_path / "task fixture.ps1"
    fixture.write_text(r'''
param([string]$TargetScript)
$ErrorActionPreference = 'Stop'
# Import before defining mocks: module autoload otherwise replaces mock functions.
Import-Module ScheduledTasks -ErrorAction Stop
Import-Module Microsoft.PowerShell.Utility, Microsoft.PowerShell.Management -ErrorAction Stop
$PSModuleAutoLoadingPreference = 'None'
. $TargetScript
$script:ExistingTask = $null
$script:Calls = New-Object 'System.Collections.Generic.List[string]'
$script:Checks = New-Object 'System.Collections.Generic.List[string]'
$script:QueryFails = $false
$script:Distros = @('Ubuntu')
$script:ExtraTasks = @()
$script:QueryHook = $null
$script:ListingHook = $null
$script:StopHook = $null
$script:NoRemoval = $false
$script:NoRegistration = $false
$script:InfoFails = $false
$script:MutationFailure = ''
$script:NativeListing = (Get-Item function:Get-WslDistributions).ScriptBlock
function Assert($Condition, [string]$Name) {
    if (-not $Condition) { throw "assertion failed: $Name" }
    $script:Checks.Add($Name)
}
function MustRefuse([scriptblock]$Operation, [string]$Name) {
    $caught = $false
    try { & $Operation | Out-Null } catch { $caught = $true }
    Assert $caught $Name
}
function Get-WslDistributions {
    if ($script:ListingHook) { & $script:ListingHook }
    $script:Distros
}
function Get-ScheduledTask {
    param($TaskPath, $ErrorAction)
    Assert ($TaskPath -ceq '\' -and $ErrorAction -eq 'Stop') 'root folder query fails closed'
    if ($script:QueryHook) { & $script:QueryHook }
    if ($script:QueryFails) { throw 'fixture query unavailable' }
    if ($script:ExistingTask) { $script:ExistingTask }
    $script:ExtraTasks
}
function Get-ScheduledTaskInfo {
    param($InputObject, $ErrorAction)
    if ($script:InfoFails) { throw 'fixture history unavailable' }
    [pscustomobject]@{LastTaskResult=73; LastRunTime=[datetime]'2026-01-01'}
}
function New-ScheduledTaskAction {
    param($Execute, $Argument)
    ScheduledTasks\New-ScheduledTaskAction -Execute $Execute -Argument $Argument
}
function New-ScheduledTaskTrigger {
    param([switch]$AtLogOn, $User)
    Assert ([bool]$AtLogOn -and $User -eq (Get-OperatorSid)) 'only current-user logon'
    ScheduledTasks\New-ScheduledTaskTrigger -AtLogOn -User $User
}
function New-ScheduledTaskPrincipal {
    param($UserId, $LogonType, $RunLevel)
    ScheduledTasks\New-ScheduledTaskPrincipal -UserId $UserId -LogonType $LogonType -RunLevel $RunLevel
}
function New-ScheduledTaskSettingsSet {
    param([switch]$Hidden, $MultipleInstances, [TimeSpan]$ExecutionTimeLimit)
    Assert ([bool]$Hidden -and $MultipleInstances -eq 'IgnoreNew' -and
        $ExecutionTimeLimit -eq [TimeSpan]::Zero) 'hidden single task with explicit lifetime'
    ScheduledTasks\New-ScheduledTaskSettingsSet -Hidden -MultipleInstances $MultipleInstances -ExecutionTimeLimit $ExecutionTimeLimit
}
function New-ScheduledTask {
    param($Action, $Trigger, $Principal, $Settings, $Description)
    $native = ScheduledTasks\New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Description $Description
    # Scheduler-owned read-only properties need a mutable envelope for race fixtures.
    [pscustomobject]@{Actions=@($native.Actions); Triggers=@($native.Triggers); Settings=$native.Settings;
        Principal=[pscustomobject]@{UserId=$native.Principal.UserId; GroupId=$native.Principal.GroupId;
            LogonType=[string]$native.Principal.LogonType; RunLevel=[string]$native.Principal.RunLevel};
        Description=$native.Description; TaskName=''; TaskPath=''; State='Ready'}
}
function Register-ScheduledTask {
    param($TaskName, $TaskPath, $InputObject, [switch]$Force)
    Assert (-not $Force -and $null -eq $script:ExistingTask) 'no forced overwrite'
    $script:Calls.Add('register')
    if ($script:MutationFailure -eq 'register') { throw 'fixture register failed' }
    $InputObject.TaskName=$TaskName
    $InputObject.TaskPath=$TaskPath
    $InputObject.State='Ready'
    if (-not $script:NoRegistration) { $script:ExistingTask=$InputObject }
    $InputObject
}
function Start-ScheduledTask {
    param($InputObject)
    $script:Calls.Add('start')
    if ($script:MutationFailure -eq 'start') { throw 'fixture start failed' }
    $InputObject.State='Running'
}
function Stop-ScheduledTask {
    param($InputObject)
    $script:Calls.Add('stop')
    if ($script:MutationFailure -eq 'stop') { throw 'fixture stop failed' }
    $InputObject.State='Ready'
    if ($script:StopHook) { & $script:StopHook }
}
function Unregister-ScheduledTask {
    param($InputObject, [switch]$Confirm)
    Assert (-not $Confirm) 'explicit removal without prompt'
    $script:Calls.Add('remove')
    if ($script:MutationFailure -eq 'remove') { throw 'fixture remove failed' }
    if (-not $script:NoRemoval) { $script:ExistingTask=$null }
}
foreach ($commandName in @('Get-ScheduledTask','Get-ScheduledTaskInfo','Register-ScheduledTask',
    'Start-ScheduledTask','Stop-ScheduledTask','Unregister-ScheduledTask')) {
    Assert ([string]::IsNullOrEmpty((Get-Command $commandName).ModuleName)) "$commandName is an isolated mock"
    Set-Item -LiteralPath ("Function:\" + $commandName) -Options ReadOnly
}
$status = Invoke-KeepAlive Status Ubuntu
Assert (-not $status.Installed -and $script:Calls.Count -eq 0) 'status has no task mutation'
$plan = Invoke-KeepAlive Plan Ubuntu
Assert ($plan.OwnerSid -ceq (Get-OperatorSid) -and
    $plan.TaskName.Contains((Get-OperatorSid))) 'per-Windows-user task identity'
Assert ($plan.Arguments.Contains('-WindowStyle Hidden') -and
    $plan.Arguments.Contains('-File "' + $TargetScript + '"') -and
    -not $plan.Arguments.Contains('ExecutionPolicy')) 'quoted path, hidden window, existing execution policy'
Assert ($script:Calls.Count -eq 0) 'plan does not install or launch'
MustRefuse { Invoke-KeepAlive Start Ubuntu } 'start requires installation'
MustRefuse { Invoke-KeepAlive Install 'Ubuntu";anything' } 'distribution injection refused'
$script:Distros=@('Different')
MustRefuse { Invoke-KeepAlive Install Ubuntu } 'unregistered distribution refused'
$script:Distros=@('Ubuntu')
$installed = Invoke-KeepAlive Install Ubuntu
Assert ($installed.Installed -and ($script:Calls -join ',') -eq 'register') 'install does not start WSL'
$script:Template = $script:ExistingTask
Assert ($script:ExistingTask.Principal.RunLevel -eq 'Limited' -and
    $script:ExistingTask.Principal.LogonType -eq 'Interactive') 'no elevation or stored account password'
MustRefuse { Invoke-KeepAlive Install Ubuntu } 'no implicit overwrite'
$script:ExistingTask.Principal.UserId='S-1-5-21-101-202-303-9999'
foreach($mode in @('Status','Start','Stop','Remove','Install')) {
    MustRefuse { Invoke-KeepAlive $mode Ubuntu } "foreign owner rejected for $mode"
}
Assert (($script:Calls -join ',') -eq 'register') 'foreign task unchanged'
$script:ExistingTask.Principal.UserId=Get-OperatorSid
$script:ExistingTask.Actions[0].Arguments += ' -Unexpected'
MustRefuse { Invoke-KeepAlive Remove Ubuntu } 'changed action is not removed'
$script:ExistingTask.Actions[0].Arguments=$plan.Arguments
$script:QueryFails=$true
MustRefuse { Invoke-KeepAlive Status Ubuntu } 'query failure is not absent'
$script:QueryFails=$false
$running=Invoke-KeepAlive Start Ubuntu
Assert ($running.TaskState -eq 'Running' -and $running.ClusterHealth -eq 'Not checked') 'task status is not cluster health'
Assert ($running.LastTaskResult -eq 73) 'last task exit result is reported'
$stopped=Invoke-KeepAlive Stop Ubuntu
Assert ($stopped.Installed -and $stopped.TaskState -eq 'Ready') 'stop retains task'
$removed=Invoke-KeepAlive Remove Ubuntu
Assert (-not $removed.Installed) 'remove deletes only owned task'
$repeat=Invoke-KeepAlive Remove Ubuntu
Assert (-not $repeat.Installed) 'absent removal is idempotent'
Assert (($script:Calls -join ',') -eq 'register,start,stop,stop,remove') 'exact mutation sequence'
$normalMutations = @($script:Calls)
function Reset([bool]$Installed = $true) {
    $script:Calls.Clear()
    $script:ExistingTask = $null
    $script:ExtraTasks = @()
    $script:QueryFails = $false
    $script:QueryHook = $null
    $script:ListingHook = $null
    $script:StopHook = $null
    $script:NoRemoval = $false
    $script:NoRegistration = $false
    $script:InfoFails = $false
    $script:MutationFailure = ''
    if ($Installed) {
        $command = New-ScheduledTaskAction -Execute $plan.Execute -Argument $plan.Arguments
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $plan.OwnerSid
        $principal = New-ScheduledTaskPrincipal -UserId $plan.OwnerSid -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
        $script:ExistingTask = New-ScheduledTask -Action $command -Trigger $trigger -Principal $principal -Settings $settings -Description $plan.Description
        $script:ExistingTask.TaskName = $plan.TaskName
        $script:ExistingTask.TaskPath = $plan.TaskPath
        $script:ExistingTask.State = 'Ready'
    }
}
Assert ($PSVersionTable.PSVersion.Major -eq 5 -and
    $PSVersionTable.PSVersion.Minor -eq 1) 'native Windows PowerShell 5.1'
foreach ($name in @(('Ubuntu' + [char]10), 'Ubuntu*', '../Ubuntu', '-Ubuntu', '', ('a' * 65))) {
    MustRefuse { Get-KeepAlivePlan $name } 'invalid distribution refused'
}
$savedPath = $script:KeepAlivePath
foreach ($path in @('C:\%TEMP%\keepalive.ps1', ('C:\tab' + [char]9 + 'path\keepalive.ps1'))) {
    $script:KeepAlivePath = $path
    MustRefuse { Get-KeepAlivePlan Ubuntu } 'unsafe scheduler path refused'
}
$script:KeepAlivePath = $savedPath
Reset
$script:ExistingTask.TaskPath = '\Elsewhere\'
$script:ExtraTasks = @($script:ExistingTask)
$script:ExistingTask = $null
Assert (-not (Invoke-KeepAlive Remove Ubuntu).Installed -and $script:Calls.Count -eq 0) 'other folder is untouched'
Reset
$script:ExistingTask.TaskName += ' extra'
Assert (-not (Invoke-KeepAlive Remove Ubuntu).Installed -and $script:Calls.Count -eq 0) 'other name is untouched'
Reset
$script:ExtraTasks = @($script:ExistingTask)
MustRefuse { Invoke-KeepAlive Remove Ubuntu } 'ambiguous identity refused'
Assert ($script:Calls.Count -eq 0) 'ambiguous task unchanged'
Reset
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$script:ExistingTask.Principal.UserId = $account
$script:ExistingTask.Triggers[0].UserId = $account
Assert ((Invoke-KeepAlive Status Ubuntu).Installed) 'native account names resolve to owner SID'

$changes = [ordered]@{
    caseCollision = { $script:ExistingTask.TaskName = $plan.TaskName.ToLowerInvariant() }
    elevated = { $script:ExistingTask.Principal.RunLevel = 'Highest' }
    password = { $script:ExistingTask.Principal.LogonType = 'Password' }
    description = { $script:ExistingTask.Description += ' edited' }
    executable = { $script:ExistingTask.Actions[0].Execute = 'cmd.exe' }
    workingDirectory = { $script:ExistingTask.Actions[0].WorkingDirectory = 'C:\' }
    extraAction = { $script:ExistingTask.Actions += $script:ExistingTask.Actions[0] }
    allUsersTrigger = { $script:ExistingTask.Triggers[0].UserId = '' }
    foreignTrigger = { $script:ExistingTask.Triggers[0].UserId = 'S-1-5-18' }
    extraTrigger = { $script:ExistingTask.Triggers += $script:ExistingTask.Triggers[0] }
    bootTrigger = { $script:ExistingTask.Triggers = @(ScheduledTasks\New-ScheduledTaskTrigger -AtStartup) }
    repetition = {
        $script:ExistingTask.Triggers[0].Repetition =
            (ScheduledTasks\New-ScheduledTaskTrigger -Once -At ([datetime]'2030-01-01') -RepetitionInterval (New-TimeSpan -Minutes 1)).Repetition
    }
    hidden = { $script:ExistingTask.Settings.Hidden = $false }
    lifetime = { $script:ExistingTask.Settings.ExecutionTimeLimit = 'PT1H' }
    concurrent = { $script:ExistingTask.Settings.MultipleInstances = 0 }
    restart = { $script:ExistingTask.Settings.RestartCount = 1 }
    delayedRestart = { $script:ExistingTask.Settings.StartWhenAvailable = $true }
    wake = { $script:ExistingTask.Settings.WakeToRun = $true }
    terminate = { $script:ExistingTask.Settings.AllowHardTerminate = $false }
}
foreach ($change in $changes.Keys) {
    foreach ($mode in @('Status','Start','Stop','Remove','Install')) {
        Reset
        & $changes[$change]
        MustRefuse { Invoke-KeepAlive $mode Ubuntu } "$change refused for $mode"
        Assert ($script:Calls.Count -eq 0) "$change causes no $mode mutation"
    }
}
foreach ($mode in @('Status','Plan','Install','Start','Stop','Remove')) {
    Reset
    $script:QueryFails = $true
    MustRefuse { Invoke-KeepAlive $mode Ubuntu } "query failure for $mode"
    Assert ($script:Calls.Count -eq 0) "failed query causes no $mode mutation"
}
foreach ($mode in @('Plan','Install','Start')) {
    Reset ($mode -eq 'Start')
    $script:ListingHook = { throw 'fixture listing failed' }
    MustRefuse { Invoke-KeepAlive $mode Ubuntu } "listing failure for $mode"
    Assert ($script:Calls.Count -eq 0) "failed listing causes no $mode mutation"
}
foreach ($mode in @('Status','Stop','Remove')) {
    Reset
    $script:ListingHook = { throw 'fixture listing failed' }
    Invoke-KeepAlive $mode Ubuntu | Out-Null
    Assert $true "$mode does not depend on WSL availability"
}
Reset
$script:ListingHook = { $script:ExistingTask.Actions[0].Arguments += ' changed' }
MustRefuse { Invoke-KeepAlive Start Ubuntu } 'replacement during listing refused'
Assert ($script:Calls.Count -eq 0) 'replaced task is not started'
Reset $false
$script:ListingHook = { $script:ExistingTask = $script:Template }
MustRefuse { Invoke-KeepAlive Install Ubuntu } 'task appearing during listing refused'
Assert ($script:Calls.Count -eq 0) 'appearing task not overwritten'
foreach ($mode in @('Start','Stop','Remove')) {
    foreach ($change in @('disappear','replace','queryFailure')) {
        Reset
        $script:Queries = 0
        $script:QueryHook = {
            $script:Queries++
            if ($script:Queries -eq 2) {
                if ($change -eq 'disappear') { $script:ExistingTask = $null }
                elseif ($change -eq 'replace') { $script:ExistingTask.Description = 'unrelated' }
                else { $script:QueryFails = $true }
            }
        }
        MustRefuse { Invoke-KeepAlive $mode Ubuntu } "$change immediately before $mode refused"
        Assert ($script:Calls.Count -eq 0) "$change before $mode causes no mutation"
    }
}
foreach ($change in @('disappear','replace','queryFailure')) {
    Reset
    $script:StopHook = {
        if ($change -eq 'disappear') { $script:ExistingTask = $null }
        elseif ($change -eq 'replace') { $script:ExistingTask.Description = 'unrelated' }
        else { $script:QueryFails = $true }
    }
    MustRefuse { Invoke-KeepAlive Remove Ubuntu } "$change between stop and remove refused"
    Assert (($script:Calls -join ',') -eq 'stop') "$change prevents unregister"
}
Reset $false
$script:NoRegistration = $true
MustRefuse { Invoke-KeepAlive Install Ubuntu } 'registration absence is an error'
Reset
$script:NoRemoval = $true
MustRefuse { Invoke-KeepAlive Remove Ubuntu } 'unverified removal is an error'
foreach ($operation in @('register','start','stop','remove')) {
    Reset ($operation -ne 'register')
    $script:MutationFailure = $operation
    $mode = @{register='Install'; start='Start'; stop='Stop'; remove='Remove'}[$operation]
    MustRefuse { Invoke-KeepAlive $mode Ubuntu } "$operation failure propagates"
    Assert ($script:Calls[$script:Calls.Count - 1] -eq $operation) "$operation failure stops further mutations"
}
Reset
$script:InfoFails = $true
MustRefuse { Invoke-KeepAlive Status Ubuntu } 'failed runtime history query is not success'

# A bounded harmless executable substitutes for wsl.exe, including its UTF-16 pipes.
$script:FakeWsl = Join-Path $PSScriptRoot 'listing fixture.exe'
$env:CT_WSL_FIXTURE_LOG = $script:FakeWsl + '.calls'
$env:CT_WSL_FIXTURE_PID = $script:FakeWsl + '.pid'
Add-Type -OutputAssembly $script:FakeWsl -OutputType ConsoleApplication -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading;
class WslFixture {
    static int Main(string[] args) {
        File.AppendAllText(Environment.GetEnvironmentVariable("CT_WSL_FIXTURE_LOG"), String.Join("|", args) + "\n");
        File.WriteAllText(Environment.GetEnvironmentVariable("CT_WSL_FIXTURE_PID"), System.Diagnostics.Process.GetCurrentProcess().Id.ToString());
        string mode = Environment.GetEnvironmentVariable("CT_WSL_FIXTURE_MODE");
        if (mode == "timeout") { Thread.Sleep(30000); return 0; }
        if (mode == "runtime-fail") { return 73; }
        if (mode == "runtime-ok") { return 0; }
        using (var output = new StreamWriter(Console.OpenStandardOutput(), new UnicodeEncoding(false, false)))
        using (var error = new StreamWriter(Console.OpenStandardError(), new UnicodeEncoding(false, false))) {
            if (mode == "pipes") {
                output.Write(new String('x', 12000) + "\r\n");
                error.Write(new String('e', 12000)); error.Flush();
            }
            if (mode == "oversize") { output.Write(new String('x', 70000)); }
            if (mode == "oversize-error") { error.Write(new String('e', 70000)); }
            output.Write("Ubuntu\r\nOther\r\n");
        }
        return mode == "fail" ? 9 : 0;
    }
}
'@
function Get-WslExecutable { $script:FakeWsl }
foreach ($mode in @('normal','pipes')) {
    $env:CT_WSL_FIXTURE_MODE = $mode
    $listed = @(& $script:NativeListing)
    Assert ($listed -ccontains 'Ubuntu' -and $listed -ccontains 'Other') "$mode drains and decodes listing"
}
foreach ($mode in @('fail','oversize','oversize-error','timeout')) {
    $env:CT_WSL_FIXTURE_MODE = $mode
    $watch = [Diagnostics.Stopwatch]::StartNew()
    MustRefuse { & $script:NativeListing } "native $mode listing refused"
    Assert ($watch.Elapsed.TotalSeconds -lt 15) "$mode listing is bounded"
    $fixturePid = [int][IO.File]::ReadAllText($env:CT_WSL_FIXTURE_PID)
    Assert ($null -eq (Get-Process -Id $fixturePid -ErrorAction SilentlyContinue)) "$mode child process is gone"
}
Reset $false
$env:CT_WSL_FIXTURE_MODE = 'runtime-fail'
MustRefuse { Invoke-KeepAlive Run Ubuntu } 'runtime failure propagates without restart'
$env:CT_WSL_FIXTURE_MODE = 'runtime-ok'
Invoke-KeepAlive Run Ubuntu | Out-Null
Assert ($script:Calls.Count -eq 0) 'runtime does not mutate scheduler'
$invocations = @([IO.File]::ReadAllLines($env:CT_WSL_FIXTURE_LOG))
Assert ($invocations.Count -eq 8 -and
    @($invocations | Where-Object { $_ -ceq '--list|--quiet' }).Count -eq 6 -and
    @($invocations | Where-Object { $_ -ceq '--distribution|Ubuntu|--exec|sleep|infinity' }).Count -eq 2) 'exact native argument vectors and no retry'

# Test -File argument parsing through a harmless probe at a metacharacter path.
$probeFolder = Join-Path $PSScriptRoot ("space [brackets] " + '$dollar & semi; quote'' unicode-' + [char]0xe9)
[void][IO.Directory]::CreateDirectory($probeFolder)
$script:KeepAlivePath = Join-Path $probeFolder 'probe.ps1'
$probe = @'
param([string]$Action, [string]$Distribution)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
@{Action=$Action; Distribution=$Distribution; Path=$PSCommandPath} | ConvertTo-Json -Compress
'@
[IO.File]::WriteAllText($script:KeepAlivePath, $probe)
$probePlan = Get-KeepAlivePlan Ubuntu
$process = New-Object Diagnostics.Process
$process.StartInfo.FileName = $probePlan.Execute
$process.StartInfo.Arguments = $probePlan.Arguments
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.StandardOutputEncoding = [Text.Encoding]::UTF8
$probeStarted = $false
try {
    $probeStarted = $process.Start()
    Assert ($process.WaitForExit(10000) -and $process.ExitCode -eq 0) 'native quoted File invocation succeeds'
    $actual = $process.StandardOutput.ReadToEnd() | ConvertFrom-Json
    Assert ($actual.Action -ceq 'Run' -and $actual.Distribution -ceq 'Ubuntu' -and
        $actual.Path -ceq $script:KeepAlivePath) 'native argument parsing preserves metacharacters literally'
} finally {
    try {
        if ($probeStarted -and -not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(1000) }
    } finally { $process.Dispose() }
}
@{checks=@($script:Checks); mutations=$normalMutations; nativeInvocations=$invocations;
    powershell=$PSVersionTable.PSVersion.ToString()} | ConvertTo-Json -Depth 4 -Compress
''', encoding="utf-8", newline="\n")
    shell = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-File", str(fixture), str(source)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    record_property("native_boundary_receipt", json.dumps(receipt))
    assert len(receipt["checks"]) >= 300
    assert receipt["mutations"] == ["register", "start", "stop", "stop", "remove"]
    assert len(receipt["nativeInvocations"]) == 8
    assert receipt["powershell"].startswith("5.1.")
