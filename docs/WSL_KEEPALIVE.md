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
Both listing streams are drained concurrently and limited to 65,536 characters
each. Cancellation allows up to one further second to confirm that the listing
process exited. A failed or oversized listing prevents installation and start.
Script paths containing percent signs or control characters are refused:
Task Scheduler can expand environment variables inside action arguments.

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
`LastRunTime` and `LastTaskResult` report Task Scheduler's most recent run
information. They may describe an earlier run while a new start is pending;
Start requests execution and does not wait for a healthy session. A nonzero WSL
exit makes the wrapper fail, with no retry or automatic restart.

```powershell
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Stop
powershell.exe -NoProfile -File C:\dev\cyber-thunder\scripts\wsl-keepalive.ps1 -Action Remove
```

Stop asks Task Scheduler to stop this task; Remove also unregisters it. Neither
command terminates the whole distribution or touches other tasks or sessions.
The distribution may remain running because another terminal or process uses it.
Removing an absent task is harmless. Reinstalling over an existing task is refused.

The helper selects the exact root folder and task name, detects case-only name
collisions, and verifies the owner SID, description, interactive/limited principal,
single command, user-specific logon trigger and safety settings (hidden window,
single instance, unlimited lifetime and no automatic restart). A changed or
conflicting task requires inspection in Windows Task Scheduler; the helper refuses
to operate on it. If the checkout moved, inspect and remove the old task there
before installing from the new location. A failed task query is an error, not an
absent task. Status, Stop and Remove do not depend on WSL being available.

Ownership is checked again after the distribution query and immediately before
each start, stop or removal. Registration must be observable, and removal must be
followed by a successful query confirming absence. A failure after a scheduler
operation may mean that operation already took effect; use Status and Task
Scheduler to inspect the result before retrying.

These checks narrow races but are not an atomic compare-and-change operation:
another process with permission to edit the same task could replace it between a
check and a scheduler call. Avoid concurrent task edits. The helper also executes
the script at the stored path; it does not pin that file's contents. It is not a
security boundary against another process running as the same user or an
administrator. Stop requests termination of the scheduler task; teardown of its
WSL session still needs deployment acceptance testing.

## Verification and limits

Native Windows PowerShell 5.1 fixtures construct real ScheduledTasks definitions
and mock scheduler queries and mutations. They cover ownership, case and folder
collisions, changed actions/triggers/settings, failed queries and operations,
replacement/disappearance between operations, and install/start separation.
Harmless local executable fixtures cover listing pipe pressure, output limits,
timeouts and cleanup, runtime exit handling and literal argument parsing.
Modules are imported before the scheduler mocks are defined, autoloading is
disabled, and the mocks are protected from replacement. The fixture keeps its
single Linux skip with reason
`native Windows PowerShell task-boundary fixture`; no new platform allowance is
needed.

An earlier read-only check found the local Ubuntu distribution. During review, an
initial fixture revision loaded ScheduledTasks after defining its mocks; module
autoload replaced a mock and registered the helper task unintentionally. The test
failed before Start. Its exact identity and never-run result were verified, it
was unregistered, and a fresh query confirmed absence. The corrected fixture
does not register tasks. This incident is not runtime acceptance evidence.
Actual logoff/logon, reboot, session teardown, sleep and battery behavior remain
open. This helper is for a developer's Windows test environment; it is not an
application service manager.

The definition uses Microsoft's documented
[interactive task principal](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtaskprincipal?view=windowsserver2025-ps)
and [task settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset?view=windowsserver2025-ps).
See also Microsoft's [action environment-variable behavior](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction)
and [redirected process output guidance](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.standardoutput?view=netframework-4.8.1).
