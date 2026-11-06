# Keep the local WSL test environment running

`scripts/wsl-keepalive.ps1` manages an optional Windows logon task that holds an
Ubuntu session open for the development cluster. It defaults to **Status** and
changes nothing until an explicit Install, Start, Stop or Remove action.

Run it from the stable Windows checkout, not a temporary worktree. The task keeps
the absolute script path; moving that checkout requires explicit removal and
reinstallation. Use the Windows account that owns the distribution. That Windows
account does not grant any Cyber Thunder application or target-system permission.

```powershell
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Status
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Plan
```

Plan verifies that `Ubuntu` is registered for the current user and shows the exact
task identity and command. Use `-Distribution NAME` for another distribution;
supported names contain letters, numbers, periods, underscores and hyphens, start
with a letter or number, and are at most 64 characters. Listing distributions is
bounded to ten seconds and does not start them. Status queries the task only.

Install the reviewed plan, then start it for this login:

```powershell
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Install
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Start
```

Install registers the task without starting WSL. The logon trigger applies to the
current Windows user only. It runs with that user's interactive token and limited
privileges, stores no password and does not request elevation. The wrapper window
is hidden, concurrent task instances are refused, and the task has no scheduler
execution-time limit. Existing Windows execution policy and default task battery
rules still apply; an unplugged laptop may stop or defer the task.

The helper does not edit `.wslconfig`, restart WSL, install a distribution, rebuild
the cluster or change network configuration. It holds `sleep infinity` in the
selected distribution. If an operator shuts down WSL, the session ends; it does
not immediately undo that shutdown. Start the task again when ready.

## Status and removal

Status reports whether the owned task exists and its Task Scheduler state. A
Running task does not prove Docker, Kubernetes or the application is healthy;
`ClusterHealth` is explicitly `Not checked`. Check the deployed application and
cluster separately using [DEPLOYMENT](DEPLOYMENT.md).

```powershell
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Stop
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Remove
```

Stop asks Task Scheduler to stop this task; Remove also unregisters it. Neither
command terminates the whole distribution or touches other tasks or sessions.
The distribution may remain running because another terminal or process uses it.
Removing an absent task is harmless. Reinstalling over an existing task is refused.

Before any task operation, the helper verifies the owner SID, description,
interactive/limited principal and exact command. A changed or conflicting task
requires inspection in Windows Task Scheduler; the helper does not overwrite or
delete it. If the checkout moved, inspect and remove the old task there before
installing from the new location. A failed task query is an error, not an absent
task. Use Task Scheduler's history and Last Run Result to diagnose startup issues.

## Verification and limits

Native Windows PowerShell command-boundary fixtures cover user ownership,
non-mutating Status/Plan, registration without launch, rejection of changed tasks,
explicit start/stop/removal, duplicate installation and failed queries. A read-only
check found the local Ubuntu distribution; native ScheduledTasks cmdlets built
the limited interactive definition without registering it. No persistent task was
installed during that check. Actual logoff/logon, reboot, sleep and battery
behavior still require a local deployment acceptance run. This helper is for a
developer's Windows test environment; it is not an application service manager.

The definition uses Microsoft's documented
[interactive task principal](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)
and [task settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset?view=windowsserver2025-ps).
