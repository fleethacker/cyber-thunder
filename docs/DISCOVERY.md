# Asset discovery

Discovery answers "what is actually on this enclave?" before anyone asks "is it compliant?". It sweeps
operator-defined address ranges, types every device it finds from evidence, compares the result with the
inventory, and puts the differences in front of the IT Sailor: unknown devices, devices that changed,
new listeners, and inventory entries that stopped answering.

Code: `cyberthunder/discovery/` (service, classifier, sources), API `cyberthunder/api/routes/discovery.py`,
CLI `cyberthunder discover ...`, tests `tests/discovery/`, answer key `range/answer_key/discovery.json`.

## Guardrail: discovery proposes, a person accepts

Discovery never adds anything to the inventory and never changes scope by itself.

| Rule | Where |
|---|---|
| Only `DiscoveryService.accept()` writes a discovered asset into the inventory | `service.py` |
| Accept needs a named human actor (`agent`, `llm`, `system` refused), an explicit in-scope decision and a reason | `require_human`, `accept` |
| Accept is audited as `inventory.add` (source `discovery`, asset, in_scope, reason) and, when in scope, `scope.change` `{target, before: null, after: true, reason}` | `accept` |
| An asset from a simulated sweep is accepted only as a simulated target (transport `simulated`, no credentials); it never becomes a live ssh/winrm target at an emulator address | `accept` |
| Inventory `credential_ref` is an opaque short reference, never a password or path. Verified execution selects a separate authorized account binding; legacy range environment lookup uses only `CT_CRED_<ref>` | `accept`, [account access](ACCOUNT_ACCESS.md) |
| Accept refuses an asset whose address or MAC an inventory target already holds, names that target and links the asset to it | `accept` |
| Sweeps run only inside saved scopes; public space needs `allow_public` and a reason | `DiscoveryScope.validate`, `_sweep_scopes` |
| Commands come from fixed tables; addresses on an nmap command line come from validated scopes or nmap's own ping sweep | `sources/nmap.py`, `render()` |
| Switches, clusters, domain controllers and hypervisors are asked only when they are in-scope inventory targets | `_inventory_sources` |
| Kill switch checked before the first scope, between scopes and before the inventory sources; a block writes `action.blocked` and the run ends `stopped` | `sweep`, `_collect` |
| Everything is audited: `discovery.scopes`, `discovery.start`, `discovery.finish`, `discovery.ignore`, `inventory.add`, `scope.change` | audit chain |

## Scopes

A scope is a CIDR plus who added it, when and why. Scopes are replaced as a set with one reason and
audited as `discovery.scopes` with the before and after lists. Limits:

* private, link-local or loopback space only, unless saved with `allow_public` and a reason
* no larger than a /16 (IPv4) or /112 (IPv6) per scope
* optional `scanner_target`: an in-scope inventory target (normally SSH to a Linux box inside the
  enclave) that runs nmap, so the sweep starts from inside the enclave rather than from the laptop

A sweep request may name part of a saved scope (`--scope 192.168.56.0/26`); anything outside every saved
scope is refused.

The [range editor](HOST_SCOPE.md#preview-and-save-discovery-ranges) additionally accepts individual IPs and inclusive start-end ranges, with exclusions. Its preview does no DNS or probing; save compiles the effective address space into these same CIDR scopes. Range-editor limits also bound total addresses and output networks. Search-range changes never change an inventory target's separate `in_scope` decision.

## Modes

| Mode | Sends packets | What runs |
|---|---|---|
| `quick` | yes, rate-limited | nmap ping sweep, then `-sV --top-ports 25 -T3 --max-rate 50` on live hosts |
| `full` | yes, rate-limited | ping sweep, then `-sV --top-ports 200 -T3 --max-rate 50 --script smb-os-discovery` (`-O` only when privileged) |
| `passive` | no | neighbor table (`ip neigh show`, `arp -an`, or `Get-NetNeighbor`), hosts file and SSH known_hosts on the scanner |
| `simulated` | no | the built-in simulated enclave (192.168.56.0/24) with three seeded surprises, for the demo and tests |

In quick, full and passive modes the inventory sources below are merged in as well.

## Sources

| Source | Command (fixed) | Asked when |
|---|---|---|
| nmap | ping sweep + service scan, one NSE script (`smb-os-discovery`, unauthenticated) in full mode | quick / full |
| neighbor caches, hosts, known_hosts | see passive mode; key material in known_hosts is never kept | passive |
| Cisco switch tables | `show cdp neighbors detail`, `show lldp neighbors detail`, `show ip arp`, `show mac address-table` | inventory has an in-scope `cisco_ios` target; failures are recorded on the run and the rest continue |
| Kubernetes nodes | `kubectl get nodes -o json` | inventory has an in-scope `kubernetes` target |
| Active Directory | `Get-ADComputer -Filter * -Properties ... \| ConvertTo-Json` | in-scope `windows` target with `options.directory_source: true` |
| Hyper-V | `Get-VM \| Select-Object Name,State,Generation,MAC,IP \| ConvertTo-Json` | in-scope target with `options.hypervisor: hyperv`; powered-off VMs are listed with `status offline` evidence and no ports |
| VMware Workstation | `vmrun list`, then each named `.vmx` read (displayName, guestOS, ethernet0 MAC) | in-scope target with `options.hypervisor: vmware` |

Anything a source reports outside the swept scopes is dropped, except powered-off VMs, which have no
address and come from a hypervisor that is already in scope.

vCenter/ESXi has a bounded read-only API source with explicit credentials and TLS trust.
The [vSphere account-access guide](VSPHERE_ACCOUNT_ACCESS.md) describes provisioning,
collection limits and saved-history ownership. The Assets [source-inventory view](VSPHERE_UI.md)
can collect one authorized source and read that account's saved collections without a global
sweep. Reported VMs do not become accepted targets and their addresses do not establish
reachability or guest access. Actual vCenter/ESXi deployment acceptance remains open in DIS-01.

Observations of one device (same MAC or same address) are merged before classification, so an asset can
carry `nmap`, `switch_arp` and `hyperv` evidence at once. Virtual NIC prefixes (VMware, Hyper-V, KVM,
VirtualBox) add `virtual:<platform>` to the evidence and notes.

## Classifier

Deterministic, no model. Each rule that fires adds a weight to one type and a line to the evidence
(`classify: windows +0.30: tcp/3389 open (RDP)`), so an operator can see why a host got its type.

1. Specific types (`cisco_ios`, `kubernetes`, `containers`, consumer/IoT) win at a score of 0.5
   (`DECISIVE`); several over the line go to the highest score, ties by precedence.
2. Otherwise the generic OS types (`windows`, `linux`) win at 0.5 (`MIN_TYPED`).
3. Otherwise the asset is `unknown` with "insufficient evidence".

Confidence is the winning score capped at 0.99. Printers and single-board computers are typed `unknown`
with the note `consumer/iot device`, because no adapter manages them.

## Reconcile and findings

Each sweep compares what answered with the inventory (by `address` or `options.address`) and with the
previous sweep:

| Status / change | Meaning | Finding (rule_id, severity, citation) |
|---|---|---|
| `new` | answered, not in the inventory, not ignored | `discovery:unknown_asset`, high, T1200, T1046 |
| consumer/IoT | printer or single-board computer present | `discovery:consumer_device`, medium, T1200 |
| `known` + type changed | evidence says a different type than the inventory | `discovery:type_changed`, medium, T1036 |
| `known` + new listener | a port open now that was closed in the previous sweep (also for `new` simulated assets, whose previous sweep is fixed) | `discovery:new_listener`, medium, T1571 |
| `missing` | inventory target inside a scope that was actually swept did not answer | `discovery:missing_asset`, low (informational), CCI-000366 |
| `ignored` | an operator marked it accounted for (audited, with reason) | none |

One inventory target keeps one asset record: when a device first seen by address is later identified by
its MAC (or goes missing after being seen by MAC), the older record is replaced, not left beside the new one.

A run ends `finished` when every scope was swept cleanly and `partial` when one was not. If the nmap port
phase fails or one host's XML cannot be read, the hosts the ping sweep reported are still kept and the
scope is `partial`. If the liveness sweep itself fails (nmap error or timeout, no neighbor table in
passive mode), the scope is `failed`: nobody in it is reported missing, because absence was never tested.
Either way the reason is in the run's `errors`. A run still marked `running` whose process has exited
(each sweep holds an OS lock on `runs/<id>.lock`) is closed as `failed` with an `interrupted` error and
audited the next time the service starts.

Devices that are not in the inventory are reported with host `discovered:<address>` and asset type
`unknown`. The simulated enclave seeds a rogue Raspberry Pi, an unmanaged switch seen over CDP and a new
tcp/4444 listener; `range/answer_key/discovery.json` lists them with the rule_id each must raise.

## API (`/api/v1/discovery`)

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET | `` | | scopes, last run, counts by status |
| PUT | `/scopes` | `{scopes: [{cidr, allow_public?, scanner_target?}], reason}` | saved scopes |
| POST | `/sweep` | `{scopes?, mode}` | 202 and the run (runs in the background) |
| GET | `/runs` | | runs, newest first |
| GET | `/runs/{id}` | | run with its asset snapshot |
| GET | `/assets` | `?status=new\|known\|ignored\|missing` | discovered assets |
| GET | `/assets/{id}` | | one asset with evidence |
| POST | `/assets/{id}/accept` | `{name?, asset_type?, transport?, username?, credential_ref?, in_scope, reason}` | the new Target |
| POST | `/assets/{id}/ignore` | `{reason}` | the asset |
| GET | `/findings` | `?run_id=` | findings of the latest (or given) run |
| GET | `/applicable` | `?benchmark=` or `?title=` or `?product=` | `[{target, name, asset_type, rule, basis, reason}]` |

Verified requests use the authenticated principal and current node/resource
grants; accepted targets do not acquire shared credentials or scope implicitly.
`X-Actor` is unverified attribution only in loopback development mode, where
empty and reserved machine actors are refused with 400. Other errors include
authentication 401, refused authorization 403, kill switch 423, bad input 400 and
unknown ID 404. See [account access](ACCOUNT_ACCESS.md).

## CLI

These local commands are development/replay commands. Use authenticated discovery
controls in the UI/API for verified mode; a typed local actor cannot bypass them.

```
cyberthunder discover scopes [--add CIDR --reason TEXT] [--allow-public]
cyberthunder discover sweep [--mode quick|full|passive|simulated] [--scope CIDR ...] [--wait]
cyberthunder discover list [--status new|known|ignored|missing]
cyberthunder discover accept <id> --name NAME --type TYPE (--in-scope|--out-of-scope) --reason TEXT [--transport T --username U --credential-ref REF]
cyberthunder discover ignore <id> --reason TEXT
cyberthunder discover findings [--run-id ID]
cyberthunder discover applicable --benchmark ID | --title TEXT | --product NAME
```

`discover sweep` always runs in the foreground and returns when the run ends (0 for `finished`, 1 for
`partial` or `failed`); `--wait` is still accepted. A background thread would die with the CLI process
and leave the run open.

`--actor` (or `CT_ACTOR`) names the operator, as for every other command. It is a top-level option, so it goes before the subcommand: `cyberthunder --actor bob discover accept ...`.

## Assets page: Discovery panel

What the UI should show on the Assets page:

* **Scopes bar**: saved CIDRs with who added them and why; "Edit scopes" asks for a reason before saving.
* **Run sweep**: mode selector (quick / full / passive / simulated) and an optional subset of the saved
  scopes; shows the running run and its counts (seen, new, known, changed, missing) when it finishes,
  plus any source errors (for example "LLDP not enabled on sw-core-01").
* **Candidate table**: address, MAC and vendor, hostname, type guess with confidence, open ports,
  sources, and badges `new`, `changed` (type changed or new listener, with the detail on hover) and
  `missing`; `virtual:<platform>` and `consumer/iot device` notes shown as chips. Expanding a row shows the
  full evidence list, including every `classify:` line.
* **Accept**: name (prefilled from hostname), asset type (prefilled from the guess; required when the
  guess is unknown), transport and username, an explicit **In scope** toggle with no default, and a
  required reason. The confirmation states that this adds the asset to the inventory and, if in scope,
  allows scans of it.
* **Ignore**: required reason; ignored devices stay ignored on later sweeps and drop out of findings.
* Findings from discovery appear in the normal findings list with source `discovery`.

## Applicability: feeding STIG deltas and bulletins

When a new STIG release or a vulnerability bulletin arrives over the link, ingest asks
`applicability.applicable_targets(ctx, benchmark_id | title | product)` which inventory targets it
touches. Each target is matched with the best facts available: the latest scan's collected facts, then
operator hints in `target.options` (`os`, `os_name`, `os_version`, `product`), then the discovery record
linked to the target (OS guess, CDP platform, kube node OS image), then asset type alone (reported as
"scan to confirm"). Scan facts and hints that contradict the rule exclude a target. A discovery guess
that names a different OS family does not exclude (nmap OS guesses are ranges), but one that names the
right family at a different major version does: a node reporting Rocky Linux 8.9 is left out of a RHEL 9
delta. Accepted assets record the discovery OS guess as `options.discovered_os`, never as a hint.
