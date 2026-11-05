# Demo runbook (10 minutes)

Commands and clicks follow [UI.md](UI.md) and [API.md](API.md). The CLI commands below were run against the
merged build from a clean state directory. Run `python -m cyberthunder <cmd> --help` for exact flags.

## Before you go on stage

Run on the demo laptop, with the local model server already running and nothing else in the browser.

```bash
export CT_STATE_DIR="$HOME/ct-demo-state"
```

```bash
python -m cyberthunder demo reset
```

```bash
python -m cyberthunder demo load
```

```bash
python -m cyberthunder serve
```

Open <http://127.0.0.1:8000>. Settings: actor = your name and rank (for example `IT1 Smith`). Confirm the header
shows the green chain badge, the link indicator, and the model indicator. Have the STIG release file
(`tests/fixtures/windows/w11_subset-xccdf.xml`) and the bulletin JSON (`tests/fixtures/ingest/iavm_openssh.json`)
in a folder you can reach from the file picker. Keep a second terminal open in the
repo for the CLI steps.

## Timing

| Step | What | Minutes | Running |
|---|---|---|---|
| 1 | Throttled link, STIG release arrives as a delta | 1:00 | 1:00 |
| 2 | Discovery sweep, rogue device | 0:45 | 1:45 |
| 3 | Scan of the simulated range | 1:15 | 3:00 |
| 4 | Hunt panel, intrusion indicators | 0:45 | 3:45 |
| 5 | Explanations with citations | 0:45 | 4:30 |
| 6 | Approve two, deny one | 0:45 | 5:15 |
| 7 | Apply and verify | 0:45 | 6:00 |
| 8 | Forced verification failure, automatic rollback | 1:00 | 7:00 |
| 9 | Kill switch | 0:45 | 7:45 |
| 10 | Audit chain verified, then broken by hand | 1:15 | 9:00 |
| 11 | Commander one-pager and path to fleet | 1:00 | 10:00 |

## Steps

### 1. Explicit link test mode; a new STIG release arrives as a delta (1:00)

Two release pairs work for this step. The repository ships `tests/fixtures/windows/w11_subset-xccdf.xml` (old) and `tests/fixtures/ingest/w11_subset_new-xccdf.xml` (new). If `range/downloads/` holds the real DISA pair `U_MS_Windows_11_V1R3_STIG_SCAP_1-2_Benchmark.zip` and `U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.zip`, use those: the delta is 15 rules added, 204 changed, 6 removed; the full download is 1.4 MB (200 s at 56 kbps) and the compressed delta 27 KB (4.4 s), 51 times smaller.

Click: **Settings**, Link controls: explicitly choose test mode, then set 56 kbps, 500 ms and connected. In **STIG Library > Import / transfer**, import the new STIG release.
The delta summary shows rules added, removed and changed, and sizes: full download vs delta vs compressed, with
estimated transfer time under the configured test model for each. Normal production mode starts with unknown rate and does not impose those numbers. The **Rescan changed rules** button reruns only the changed
rules (you can press it here or fold it into step 3).

CLI equivalent:

```bash
python -m cyberthunder link set --mode test --kbps 56 --latency-ms 500 --connected true
```

```bash
python -m cyberthunder ingest stig tests/fixtures/windows/w11_subset-xccdf.xml
```

On a fresh state the first release has nothing to compare with, so the summary shows only added rules. To show
changed and removed rules, pass the previous release: `ingest stig <new.xml> --old <old.xml>`. The repository
ships the old and new subset pair named above; use that pair when the full releases are unavailable.

Say: "This demonstration models a 56 kilobit link. These are estimates, not measured network bandwidth.
The compressed delta is smaller and identifies changed rules for a targeted recheck."

This setting does not shape all host traffic. Content pacing also requires the explicit download pacing option;
actual range traffic shaping is a separate setup. Return to normal behavior after the demonstration with
`python -m cyberthunder link set --mode production`.

### 2. Discovery finds the enclave's assets and a rogue device (0:45)

Click: **Assets**. Inventory shows one asset per type, each with a simulated badge. In the **Discovery** card, Mode shows `simulated` (no scopes saved); click **Run sweep**. When the run shows `finished`, the Candidates table lists two `new` devices that are not in inventory: 192.168.56.66 (Raspberry Pi, `consumer/iot device`) and 192.168.56.3 (an unmanaged switch seen over CDP). The **Findings** tab shows `discovery:unknown_asset` (T1200, T1046), `discovery:consumer_device` and `discovery:new_listener` (tcp/4444). Optional: click **Accept** on 192.168.56.66, pick a type, choose **Out of scope**, give a reason, Accept. It joins the inventory but stays out of every scan.

```bash
python -m cyberthunder discover scopes --add 192.168.56.0/24 --reason "demo enclave"
```

```bash
python -m cyberthunder discover sweep --mode simulated --wait
```

```bash
python -m cyberthunder discover list --status new
```

A sweep refuses to run until a scope is saved, hence the first command. The list shows two new devices, one of
them a consumer/iot device.

Say: "Discovery is read-only. The inventory is the scope; nothing outside it is ever touched. The unknown
device is flagged for a human, not scanned."

### 3. Scan the simulated range (1:15)

Click: **Scans**, select all targets, modules check, hunt, cve, **Start scan**. Watch per-target progress.
Open **Findings**: Linux host, switch config, k3s cluster, container host, Windows host. Point at the CAT I
(red), II (amber), III (blue) badges and the rule id chips.

```bash
python -m cyberthunder scan
```

```bash
python -m cyberthunder ingest bulletin tests/fixtures/ingest/iavm_openssh.json
```

Ingest the bulletin after the scan: it matches against the package inventory the scan collected, and before a
scan it matches nothing. After a scan it reports the affected Linux host.

Say: "Real checks, not guesses. Every finding carries a STIG id, CCI, CVE or ATT&CK technique."

### 4. Hunt panel: the intrusion indicators (0:45)

Click: **Findings**, filter source = hunt. Expected indicators on the Linux host, as in
`range/answer_key/linux.json`: a second uid-0 account, an unknown key in root's authorized keys, a hidden cron
entry with a timestomped script, an unexpected listener on tcp/4444, a SUID copy of the shell, a sudoers
override. Open one: the evidence is shown and the citation is an ATT&CK technique.

Say: "Deterministic hunt checks found the seeded indicators. On a real system, an indicator needs investigation;
it does not by itself prove malice or justify deleting a workload."

### 5. Explanations with citations (0:45)

Click one CAT I finding to open the drawer; read the explanation panel (risk, impact, plan). Click a
citation chip. Point at the footnote: "generated by <model>" or "template".

Say: "Written for a commander. Every claim cites an identifier from the finding; anything the model cites that
is not on the finding is stripped. If the model is down, a template explains instead."

### 6. IT approves two fixes and denies one (0:45)

Click: **Decisions**. Read a card top to bottom (what is wrong, why it matters, what will change, could it break
something, how to undo). Keyboard: `j` to move, `a` to open the approval review, `d` to deny. Review dependency evidence,
unknowns and recovery limits; collecting a new assessment is an explicit action. Approve the SSH root login fix and the
duplicate uid-0 account removal; deny one with a note ("needs change window").

```bash
python -m cyberthunder proposals list
```

```bash
python -m cyberthunder proposals approve <proposal-id>
```

```bash
python -m cyberthunder proposals deny <proposal-id> --note "needs change window"
```

The scan already creates a proposal for every finding with a library fix. `proposals show <proposal-id>` prints
the `finding_id` to use with `explain` and `propose`.

Say: "The default flow waits for an operator decision. An assessment supplies advice and never authorizes a change."
The demonstration's typed acting name is attribution, not verified login identity. Direct CLI approval without an
assessment is recorded as unassessed; it is not equivalent to having reviewed a dependency receipt.

### 7. Apply, then verify (0:45)

Click **Apply** on an approved card. The timeline fills in: scope check, before-state captured, applied,
verified, each with a time and audit sequence number.

```bash
python -m cyberthunder apply <proposal-id>
```

Say: "Applied from the vetted library, then rescanned. Verified means the check now passes, not that the
command exited zero."

### 8. Forced verification failure, automatic rollback (1:00)

Click: **Settings**, Demo controls, turn on "force verification failure on next apply" (a demonstration control,
and say so). Back on **Decisions**, apply the second fix you approved in step 6. Timeline: applied, verification failed,
rolled back. Click **Diff** on the proposal card (also in the finding drawer's proposal history): before and after match, so the host is back where it started.

```bash
python -m cyberthunder apply <proposal-id> --simulate-verify-fail
```

```bash
python -m cyberthunder diff <proposal-id>
```

Say: "I rigged verification to fail. The system put the host back by itself and logged why. The Sailor never
has to trust the fix, only the rollback."

### 9. Kill switch with a queued action (0:45)

Approve one more proposal but do not apply it. Click the red **Kill switch**, enter a reason. The header turns
red. Click **Apply** on the queued card: refused (423), nothing runs. Release the switch with a reason.

```bash
python -m cyberthunder kill engage --reason "demo"
```

```bash
python -m cyberthunder kill release --reason "demo over"
```

```bash
python -m cyberthunder audit tail
```

Say: "One button stops the agent. The blocked attempt is in the log, so the pause is evidence too."

### 10. Audit chain verified, then tampered (1:15)

Click: **Audit**, **Verify chain**: green, record count, head hash. In the terminal, edit one line of the audit
file by hand (change any field value; this is the one deliberate edit in the demo).

```bash
python -m cyberthunder audit verify
```

The CLI and the header badge now report the break at the sequence number you edited. Reset afterwards (see
below).

Say: "Each record carries the hash of the one before. Change a line and the chain breaks at exactly that
record. The head hash is on every report, so deleting the tail is caught too."

### 11. Commander one-pager and path to fleet (1:00)

Click: **Reports**: the commander one-pager inline, then path to fleet, then the detection score card
(seeded vs found). Click **Queue for sync** and show the outbox entry waiting for reconnect. Toggle the link to
connected and click sync.

```bash
python -m cyberthunder report commander
```

Say: "Risk in terms a commander and a system owner can act on. Reports queue offline and sync when the link
returns. The one-page path to fleet names the owner and the 30, 60, 90, 180 day plan."

## Demonstrating against the real VM range

Everything above runs against the simulated range (the default; the header badge reads `simulated`). To put
the same demo on the real Rocky 9 VM, build and seed it first ([range/README.md](../range/README.md) and
[range/vmware/README.md](../range/vmware/README.md)), then:

1. Revert the VM to its seeded state and boot it headless:

```bash
vmrun -T ws revertToSnapshot C:\VM\acd-target-01\acd-target-01.vmx seeded
```

```bash
vmrun -T ws start C:\VM\acd-target-01\acd-target-01.vmx nogui
```

2. In a scratch `CT_STATE_DIR`, register the three real targets (the exact `targets add` commands are under
   [First real-host run](../range/README.md#first-real-host-run-from-the-laptop)), then start the server:

```bash
python -m cyberthunder serve
```

Open <http://127.0.0.1:8000>. The inventory now lists `acd-target-01`, `acd-containers` and `acd-k3s` with
no `simulated` badge; the chain, link and model badges in the header are the same as in the simulated demo.

What differs from the script above (the panels and the talking points are otherwise identical):

- **Step 3, scan.** The Linux target runs real OpenSCAP on the VM, so the scan takes a few minutes rather
  than seconds; Findings fill in the same way. On the Reports page the detection score reads 28 of 28 across
  the three built targets (Linux 12, containers 6, Kubernetes 10).
- **Step 2, discovery.** The sweep is simulated by default. On the enclave, add the VM's subnet as a scope
  and sweep it for a real rogue-device story, or keep the simulated sweep.
- **Steps 6-8, apply / verify / rollback.** These run over SSH on the real host: the before-state is captured
  and restored on the VM, and `audit verify` covers the real changes. The forced-failure control and the
  kill switch behave exactly as in the simulated run.
- **Link throttling is real here.** `sudo bash range/link_emulate.sh on 56 500` shapes the VM's NIC with
  `tc`/`netem`; set the same numbers in Cyber Thunder so its reported sizes and times match the wire
  ([range/README.md](../range/README.md#low-bandwidth-link-emulation)).

Between rehearsals, revert the VM to `seeded` again and reset the laptop side by pointing `CT_STATE_DIR` at a
fresh directory.

## Reset procedure

Between rehearsals, and after step 10 (the audit file was edited, so that state is not trustworthy):

```bash
python -m cyberthunder demo reset
```

This returns simulated hosts to their seeded state and is recorded in the audit log. If the audit chain is
broken, stop the server, point `CT_STATE_DIR` at a new empty directory, and run `demo load` again. Release
the kill switch if engaged. If you are running against the VM range, revert the VM snapshot to `seeded`
([range/README.md](../range/README.md)).

## Fallbacks

| Problem | Do this |
|---|---|
| Model server down or slow | Explanations fall back to templates; say so. Precompute runs after the scan |
| Server will not start | Same steps from the CLI; `report` and `audit verify` need no server |
| Range unreachable | Simulated range is the default demo mode; the badge says simulated |
| Time running short | Drop step 2 and the step 9 release, keep 8 and 10 |
