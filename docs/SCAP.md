# Running DISA SCAP benchmarks

DISA publishes each STIG it can automate as a SCAP benchmark: one XML file (a SCAP 1.2 or 1.3 *source
datastream*) holding the XCCDF checklist, the OVAL definitions that decide every rule, and a CPE dictionary.
Cyber Thunder runs those benchmarks itself, so a node needs neither SCC nor Evaluate-STIG to produce
benchmark results, and every result comes with the item values that decided it.

## What runs where

| Asset | Who evaluates the benchmark | How the content gets there |
|---|---|---|
| Linux (RHEL, Rocky, Ubuntu) | OpenSCAP (`oscap xccdf eval`) on the host itself, over SSH | SSG content from the `scap-security-guide` package, or a DISA datastream copied to the host (`options.benchmark_path`) |
| Windows 10/11, Server 2019/2022 | Our OVAL evaluator (`cyberthunder/scap/`) on the operator node, from data one PowerShell script collects over WinRM (or from the simulated host) | The datastream stays on the operator node (`options.scap_datastream`) |
| Cisco IOS / IOS-XE, Kubernetes, containers | Native checks in each adapter (DISA publishes no SCAP benchmark for these) | n/a |

Native checks keep running alongside a benchmark. On Windows the two are merged by STIG ID and the benchmark
result wins (see "Merging" below); on Linux `checks.merge` does the same with OpenSCAP results.

## Windows

Set on the target (inventory options):

```json
{"scap_datastream": "C:\\cyberthunder\\content\\U_MS_Windows_11_V2R11_STIG_SCAP_1-3_Benchmark.xml",
 "scap_profile": "xccdf_mil.disa.stig_profile_MAC-1_Classified"}
```

`scap_profile` is optional; without it the benchmark's default selection is used (every rule, for DISA content).
`cyberthunder scan` then:

1. Loads the datastream and the rules the profile selects (`datastream.py`).
2. Plans collection (`windows_plan.py`): walks every OVAL definition those rules reach and asks each object's
   probe what it needs: registry keys and values, the `[System Access]` and `[Privilege Rights]` sections of
   `secedit /export`, `auditpol /get /category:* /r`, local users and groups, files, services, WQL queries.
3. Runs `cyberthunder/scap/windows_collect.ps1` once with that plan inserted as data (`$CtParams`, base64
   JSON). The script reads only; it prints one JSON document. Missing items are reported as absent, not as
   errors. Objects that can only be located from other objects' data (a registry key named by a local variable)
   cause one more run of the same script with a smaller plan, at most three runs in all.
4. Evaluates each rule (`benchmark.py`, `oval/evaluator.py`) and writes one finding per rule with the
   benchmark's title, severity, STIG ID, group ID, CCIs, fix text and the item values in the evidence.

Result mapping: OVAL `true` -> pass -> `not_a_finding`; `false` -> fail -> `open`; a rule whose CPE platform
does not apply (for example a domain-member rule on a standalone workstation) -> `not_applicable`; anything
the evaluator cannot decide (unknown, error, not evaluated, unsupported test type) -> `not_reviewed` with the
reason in the evidence. Nothing unsupported is ever reported as a pass.

### Merging with the native checks

The native Windows checks (`adapters/windows/checks.py`) cover the answer-key items and work without any
content. When a datastream is configured:

* a rule both cover: the benchmark's status, text and evidence win; the finding keeps the native finding's id,
  fix reference and check text, so proposals made before the datastream was configured still apply. If the
  benchmark could not decide the rule and the native check could, the native status is kept and the evidence
  says so.
* a rule only the benchmark covers: its own finding, source `windows-scap`; the fix library resolves fixes by
  STIG ID as usual.
* a native check the benchmark lacks: kept unchanged.

Verify after a fix re-collects and re-evaluates just that rule from the benchmark, falling back to the native
check when the benchmark lacks the rule.

### Commands

```
cyberthunder scap info <datastream> [--profile ID] [--json]   profiles, counts, supported vs unsupported rules
cyberthunder scap plan <datastream> [--profile ID] [--rule ID] the plan the collection script would receive
cyberthunder scap eval --target ID [--datastream PATH] [--profile ID] [--rule ID] [--out FILE]
cyberthunder scap subset <datastream> --rule ID [--rule ID ...] --out FILE
```

`scap eval` is read-only on the host, checks scope first and is audited (`scap.eval`). It writes a findings
JSON (default `<state>/scap/<target>-<time>.json`) but does not create proposals; use `cyberthunder scan` for
that. `scap subset` writes a valid datastream holding only the named rules and exactly the OVAL content they
reference: useful to send a handful of urgent rules over a constrained link instead of the whole benchmark.

## Supported OVAL subset

Language: OVAL 5.11 definitions, namespace-agnostic.

* **Definitions and criteria**: `criteria` with operators AND, OR, ONE, XOR; `negate` on criteria, criterion
  and `extend_definition`; class `compliance` (and `vulnerability`/`patch`, where true means fail).
* **Tests**: `check_existence` all_exist, any_exist, at_least_one_exists, none_exist, only_one_exists;
  `check` all, at least one, only one, none satisfy; several states combined with `state_operator`.
* **Objects**: entities with operations and `var_ref`; `set` with UNION, INTERSECTION, COMPLEMENT and nested
  sets; `filter` include/exclude (on sets and on objects).
* **States**: entity operator, `entity_check`, `var_check`; record datatype (wmi57 results).
* **Variables**: `constant_variable`; `local_variable` with literal_component, object_component (item_field,
  record_field), variable_component, concat, arithmetic (add, multiply), regex_capture, substring, begin, end,
  split, unique, count, escape_regex. `external_variable` evaluates to error (DISA benchmarks do not use it).
* **Operations**: equals, not equal, case insensitive equals / not equal, greater than (or equal), less than
  (or equal), pattern match, bitwise and, bitwise or, subset of, superset of.
* **Datatypes**: string, int (decimal or 0x hex), float, boolean (1/0/true/false), version (component-wise,
  numeric where numeric), evr_string and debian_evr_string (rpm segment comparison), binary (hex, case and
  spacing ignored), ios_version (as version), fileset_revision and anything else (as string).
* **Pattern match**: Python `re` search (unanchored, as OVAL specifies). Inline flag groups such as `(?i)`
  anywhere in the pattern apply to the whole pattern (Python only accepts them at the start; DISA content
  writes `^(?i)...`), and named groups `(?<name>...)` become `(?P<name>...)`. Other Perl/ECMAScript syntax is
  passed through; a pattern Python cannot compile makes the comparison an error, never a pass.
* **Results**: true, false, unknown, error, not evaluated, not applicable, with the OVAL operator tables.
  A state entity whose field the item does not have evaluates false.

### Windows test types

| Test | Collected from | Notes |
|---|---|---|
| `registry_test` | .NET `RegistryKey` (64-bit view), value kinds from `RegistryValueKind` | hive/key/name; key and name as literal or pattern; `name xsi:nil` = the key itself; key patterns enumerate subkeys below the literal prefix (at most 3 levels, or `behaviors max_depth`); other behaviors are logged and ignored; values: reg_dword/qword as unsigned int, reg_sz, reg_expand_sz (not expanded), reg_multi_sz as several values, reg_binary as hex |
| `passwordpolicy_test` | `secedit /export` [System Access], `net accounts` as fallback | ages in seconds as OVAL defines them |
| `lockoutpolicy_test` | same | durations in seconds; -1 kept for "until an administrator unlocks" |
| `auditeventpolicysubcategories_test` | `auditpol /get /category:* /r` | field names from the English subcategory names |
| `auditeventpolicy_test` | derived from subcategories | a category audits success (failure) when any of its subcategories does |
| `userright_test` | secedit [Privilege Rights], SIDs translated to names | a right held by nobody yields one item with empty trustee fields, which is how DISA content tests "must not be assigned"; names drop the BUILTIN and NT AUTHORITY domains |
| `accesstoken_test` | same | one item per principal holding any right |
| `sid_sid_test` | `Get-LocalUser`, `Get-LocalGroup` | local accounts and groups only |
| `user_sid55_test`, `user_sid_test` | same | enabled flag and group membership |
| `file_test` | `Get-Item`, `VersionInfo` | filepath or path + filename; filename patterns list one directory |
| `service_test` | `Win32_Service` | start_type and current_state as SERVICE_* constants |
| `wmi57_test`, `wmi_test` | `Get-CimInstance -Query` | only plain `SELECT ... FROM ... [WHERE ...]` queries in a `root\...` namespace are run; booleans become "1"/"0" |
| `family_test` (independent) | constant | windows |

Everything else is **unsupported** and the rule is reported `not_reviewed` with the test type named in the
evidence. In the Windows 11 V2R11 benchmark that is 6 of 219 rules:

* `fileeffectiverights53_test` (event log file permissions: WN11-AU-000515, -000520, -000525)
* `ntuser_test` (per-user registry hives: WN11-CC-000390, WN11-UC-000015, WN11-UC-000020)

Not implemented at all: `fileauditedpermissions53_test`, `regkeyeffectiverights53_test`,
`regkeyauditedpermissions53_test`, `lockoutpolicy` force-logoff semantics beyond the secedit flag, `group_test`,
`group_sid_test`, `user_test`, `process58_test`, `port_test`, `interface_test`, `cmdlet_test`, `activedirectory57_test`,
`sharedresource_test`, `textfilecontent54_test` on Windows, `variable_test`, `environmentvariable58_test`, and
every unix/linux test type (OpenSCAP evaluates those on the host).

## Linux

`LinuxAdapter` runs `oscap xccdf eval` on the host when `oscap` is installed. By default it finds the SSG
datastream under `/usr/share/xml/scap/ssg/content/` and picks its STIG profile. To run the DISA benchmark
instead, copy the datastream to the host and point the target at it:

```
scp U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml admin@host:/tmp/
ssh admin@host 'sudo install -m 0644 -D /tmp/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml \
    /var/lib/cyberthunder/scap/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml'
```

```json
{"benchmark_path": "/var/lib/cyberthunder/scap/U_RHEL_9_V2R10_STIG_SCAP_1-3_Benchmark.xml",
 "profile": "xccdf_mil.disa.stig_profile_MAC-1_Classified"}
```

Without `profile` the adapter reads `oscap info <datastream>` and picks the first DISA profile in the order
MAC-1 Classified, MAC-1 Sensitive, MAC-1 Public, MAC-2 ..., MAC-3 ... (MAC-1 Classified selects every rule);
for SSG content it keeps picking the STIG profile. The results file is parsed like any other oscap result and
merged with the native checks by STIG ID.

**Rocky Linux and other rebuilds:** DISA's RHEL benchmark declares the platform `cpe:/o:redhat:enterprise_linux:9.0`
and its applicability checks look for Red Hat Enterprise Linux itself, so on Rocky OpenSCAP reports the rules
`notapplicable` instead of evaluating them. Keep the SSG content (`ssg-rhel9-ds.xml` from `scap-security-guide`, which applies to
RHEL-compatible distributions) and its `stig` profile there; the rules map to the same STIG IDs.

## Getting a datastream onto a disconnected node

DISA posts benchmarks on the public cyber.mil STIG downloads page as `U_<product>_V<v>R<r>_STIG_SCAP_1-3_Benchmark.zip`.
In a disconnected or low-bandwidth enclave:

1. On a connected system, download the zip and verify it (hash published with the release, or compare with
   the copy your ISSM distributes).
2. Move it across with the rest of the update bundle (`cyberthunder ingest` handles STIG releases and their
   deltas over the emulated link). Only the XML inside the zip is needed.
3. Put the XML on the operator node, for example under `<state>/content/`, and set `scap_datastream` on the
   Windows targets. For Linux targets copy it to each host as above.
4. `cyberthunder scap info <file>` confirms the benchmark, release and profiles before the first scan.

When only a few rules matter (a new bulletin), `cyberthunder scap subset` produces a much smaller valid
datastream holding just those rules.

## Adding a Windows test type

1. In `cyberthunder/scap/oval/windows_probes.py` write `requests(obj, resolved)` (the `Request`s the object
   needs, with a stable `id`) and `items(obj, resolved, data)` (`(flag, [item dict])`, item fields named as
   in the OVAL item schema), and add a `Probe` to `PROBES`. `resolved` maps each object entity to its values
   after variables are resolved; use `ResolvedEntity.matches()` so operations behave the same everywhere.
2. If it needs new data, add the plan key in `Plan.to_params()` (`windows_plan.py`), the section in
   `windows_collect.ps1` (read-only; treat every plan value as data), and the same section in
   `adapters/windows/scap_sim.py` so the simulated host answers it.
3. Add tests under `tests/scap/` with hand-made collected items, and a rule in the fixture if a DISA rule
   uses the test type (`cyberthunder scap subset` builds the fixture from the downloaded benchmark).
4. Update the tables above.
