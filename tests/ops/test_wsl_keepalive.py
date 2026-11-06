"""Exercise the Windows task boundary without creating tasks or starting WSL."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows PowerShell task-boundary fixture")
def test_keepalive_operator_and_task_boundaries(tmp_path):
    source = Path(__file__).resolve().parents[2] / "scripts/wsl-keepalive.ps1"
    fixture = tmp_path / "task fixture.ps1"
    fixture.write_text(r'''
param([string]$TargetScript)
$ErrorActionPreference = 'Stop'
. $TargetScript
$script:ExistingTask = $null
$script:Calls = New-Object 'System.Collections.Generic.List[string]'
$script:Checks = New-Object 'System.Collections.Generic.List[string]'
$script:QueryFails = $false
$script:Distros = @('Ubuntu')
function Assert($Condition, [string]$Name) {
    if (-not $Condition) { throw "assertion failed: $Name" }
    $script:Checks.Add($Name)
}
function MustRefuse([scriptblock]$Operation, [string]$Name) {
    $caught = $false
    try { & $Operation | Out-Null } catch { $caught = $true }
    Assert $caught $Name
}
function Get-OperatorSid { 'S-1-5-21-101-202-303-1001' }
function Get-WslDistributions { $script:Distros }
function Get-ScheduledTask {
    param($TaskPath, $ErrorAction)
    if ($script:QueryFails) { throw 'fixture query unavailable' }
    if ($script:ExistingTask) { $script:ExistingTask }
}
function New-ScheduledTaskAction {
    param($Execute, $Argument)
    [pscustomobject]@{Execute=$Execute; Arguments=$Argument}
}
function New-ScheduledTaskTrigger {
    param([switch]$AtLogOn, $User)
    Assert ([bool]$AtLogOn -and $User -eq (Get-OperatorSid)) 'only current-user logon'
    [pscustomobject]@{User=$User}
}
function New-ScheduledTaskPrincipal {
    param($UserId, $LogonType, $RunLevel)
    [pscustomobject]@{UserId=$UserId; LogonType=$LogonType; RunLevel=$RunLevel}
}
function New-ScheduledTaskSettingsSet {
    param([switch]$Hidden, $MultipleInstances, [TimeSpan]$ExecutionTimeLimit)
    Assert ([bool]$Hidden -and $MultipleInstances -eq 'IgnoreNew' -and
        $ExecutionTimeLimit -eq [TimeSpan]::Zero) 'hidden single task with explicit lifetime'
    [pscustomobject]@{Hidden=$true}
}
function New-ScheduledTask {
    param($Action, $Trigger, $Principal, $Settings, $Description)
    [pscustomobject]@{Actions=@($Action); Principal=$Principal; Description=$Description;
        State='Ready'; TaskName=''; TaskPath=''}
}
function Register-ScheduledTask {
    param($TaskName, $TaskPath, $InputObject)
    $script:Calls.Add('register')
    $InputObject.TaskName=$TaskName
    $InputObject.TaskPath=$TaskPath
    $script:ExistingTask=$InputObject
    $InputObject
}
function Start-ScheduledTask {
    param($InputObject)
    $script:Calls.Add('start')
    $InputObject.State='Running'
}
function Stop-ScheduledTask {
    param($InputObject)
    $script:Calls.Add('stop')
    $InputObject.State='Ready'
}
function Unregister-ScheduledTask {
    param($InputObject, [switch]$Confirm)
    Assert (-not $Confirm) 'explicit removal without prompt'
    $script:Calls.Add('remove')
    $script:ExistingTask=$null
}
$status = Invoke-KeepAlive Status Ubuntu
Assert (-not $status.Installed -and $script:Calls.Count -eq 0) 'status has no task mutation'
$plan = Invoke-KeepAlive Plan Ubuntu
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
$stopped=Invoke-KeepAlive Stop Ubuntu
Assert ($stopped.Installed -and $stopped.TaskState -eq 'Ready') 'stop retains task'
$removed=Invoke-KeepAlive Remove Ubuntu
Assert (-not $removed.Installed) 'remove deletes only owned task'
$repeat=Invoke-KeepAlive Remove Ubuntu
Assert (-not $repeat.Installed) 'absent removal is idempotent'
Assert (($script:Calls -join ',') -eq 'register,start,stop,stop,remove') 'exact mutation sequence'
@{checks=@($script:Checks); mutations=@($script:Calls)} | ConvertTo-Json -Depth 4 -Compress
''', encoding="utf-8", newline="\n")
    shell = Path(os.environ["WINDIR"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-File", str(fixture), str(source)],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = json.loads(result.stdout)
    assert len(receipt["checks"]) >= 25
    assert receipt["mutations"] == ["register", "start", "stop", "stop", "remove"]
