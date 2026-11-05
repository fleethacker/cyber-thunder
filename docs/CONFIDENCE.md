# Finding evidence strength

`cyberthunder.findings.confidence.assess(finding, *, now=None)` returns an
evidence-strength grade. It does not estimate probability, use severity, change
the scanner result, confirm a review, or grant approval. All rules are local and
deterministic; there are no external services or new dependencies.

## API and versions

The input is a `Finding` or its serialized dictionary. The return value has:

| Key | Meaning |
| --- | --- |
| `grade` | `high`, `medium`, `low`, or `unknown` |
| `reason` | Primary explanation for compact displays |
| `reasons` | Ordered explanations, including downgrades and missing provenance |
| `version` | Grading rules version, currently `1.1` |
| `assessed_at` | Assessment clock, ISO timestamp normalized to UTC |
| `observed_at` | Recorded observation time normalized to UTC, or `null` if unusable |
| `evidence` | Recorded facts, classification indicators, and explicit unknowns |

`now` accepts an aware `datetime` or an ISO timestamp with a timezone. Omitting it
uses the UTC clock. Passing the same finding and `now` returns the same result;
there is no random scoring, file access, inventory access, or mutation in `assess`.
An invalid or timezone-free explicit `now` raises `ValueError`.

Finding schema `1.1` adds optional `collection_provenance`, defaulting to `None`.
Existing constructors and `1.0` documents still load. JSON and SQLite retain the
entire dictionary through the existing findings store. This is an additive
schema change; old readers that reject unknown fields may need updating before
reading new documents. Grading changes require a new rules version independently
of the findings schema version.

Rules `1.1` add conservative recognition of legacy version fields, banners, and
port-only observations. ACAS/Nessus origin is now classified as `scanner`, never
as proof of direct or authenticated collection. Previously stored findings are
reassessed under these rules without reparsing exports or migrating documents.

## Rule order

The strongest restriction wins. All applicable explanations are retained.

1. **Unknown:** unresolved or erroneous scanner status; explicitly incomplete or
   failed collection; recorded collection errors; missing host/rule identity;
   or no usable observation. A source name, pass/fail label, port-only Nessus
   fallback, title, fix text, reference, or artifact path cannot replace evidence.
2. **Low:** simulated or replayed evidence, version-only matches, discovery or
   heuristic indicators, conflicts, partial evidence, inapplicable evidence,
   insufficient collection privilege, invalid provenance, unestablished direct
   collection method, or an unusable/stale observation timestamp.
3. **High:** useful direct evidence with every required provenance fact below,
   including a fresh explicit observation time, and no preceding restriction.
4. **Medium:** useful direct or substantive scanner evidence with a fresh recorded time, but insufficient
   explicit provenance for High. Existing scanner and native check results
   normally fall here when complete and supported by observations.

Only `open`, `not_a_finding`, and `not_applicable` are resolved scanner statuses.
`not_reviewed`, `error`, and all unrecognized serialized statuses remain Unknown.
A High grade on a scanner pass remains a scanner pass, not a human decision.
An Unknown grade never changes a finding to pass.

Freshness is **seven days inclusive**, a prototype operational default rather
than a mandated compliance interval. Any older observation is Low. Any future
observation, even slightly ahead of `now`, is Low; no clock skew is silently
accepted. Missing, invalid, and timezone-free observation times are Low when
otherwise usable evidence exists. Timezone offsets and `Z` normalize to UTC.
Invalid timestamps return `observed_at: null`; valid future/stale timestamps
remain visible with their corresponding `timestamp_status`.

`collection_provenance.observed_at` takes precedence whenever the key is present,
even when null or invalid. Otherwise the existing `collected_at` field is used,
and `observation_time_origin` is listed as unknown. Some parsers substitute import
time when the original scan time is absent, and `Finding` defaults to creation
time. This module cannot recover the original scan time. A fallback timestamp
can support Medium but cannot satisfy High's explicit observation-time rule.

## Structured collection provenance

Producers should record facts actually known during collection. Do not derive
authentication from a source name, transport name, configured credential, or
requested privilege. No credentials belong in this dictionary. Provenance is
recorded evidence, not cryptographically verified collector identity.

| Field | Type and meaning | Required for High |
| --- | --- | --- |
| `method` | `direct`, `scanner`, `command`, or `configuration` for direct evidence | Yes |
| `authenticated` | Actual successful collection authentication, boolean | `true` |
| `privilege` | Recorded effective context, e.g. `root` or a named role | Nonempty, known string |
| `privilege_sufficient` | Whether that context could perform this check, boolean | `true` |
| `complete` | Whether collection for this determination completed, boolean | `true` |
| `applicable` | Whether this evidence applies to this host/rule, boolean | `true` |
| `simulated` | Whether observations came from simulation/replay, boolean | Explicit `false` |
| `observed_at` | Actual observation ISO timestamp with timezone | Fresh, explicit |
| `detector` | Object containing detector `name` and implementation `version` | Both known strings |
| `content` | Object containing content `id` and `version` | Both known strings |

The existing `benchmark` and `benchmark_release` can supply missing `content.id`
and `content.version`. An explicitly supplied null or unknown value does not
fall back. `rule_version` is often a STIG identifier, so it never substitutes for
a detector or content version. Authentication, effective privilege, and detector
versions are never inferred. Boolean strings and numbers do not count as boolean
facts. Missing facts appear as null/empty recorded values and in `evidence.unknowns`.

Additional supported fields:

| Field | Effect |
| --- | --- |
| `observations` | Object/list containing actual values can supplement absent textual `Finding.evidence`; empty nested values, result labels and nonfinite numbers do not count, while explicit false/zero measurements do |
| `collection_status` | `partial` caps at Low; `incomplete`, `error`, `failed`, `not_reviewed`, `unknown` force Unknown |
| `errors` | Nonempty errors affecting this finding's own collection force Unknown |
| `collector_errors` | Optional record of wider collection problems; retained without affecting the grade of an independent completed check |
| `partial: true` | Available evidence is partial: Low |
| `version_only: true` | Version matching without confirmation: Low |
| `conflicts` | `true` or nonempty list/string/object records a conflict: Low |
| `conflicting: true` | Explicit conflict marker: Low |
| `transport` | `simulated`, `fixture`, or `replay` marks simulated/replayed evidence: Low |

`method` values `version`, `version_only`, `package_version`, `cpe`, or `banner`
mean version-only evidence; `discovery`, `heuristic`, or `inferred` mean an
indicator requiring verification. Hyphens and spaces in marker values normalize
to underscores. Other extension fields, including package/image metadata, are
retained unchanged in `evidence.collection_provenance` without guessing their meaning.

`complete: false` means a determination was not completed and forces Unknown.
Use `partial: true` or `collection_status: partial` for a usable completed result
with limited supporting evidence; those cap at Low. Missing `complete` alone
does not discard useful legacy scanner observations, but prevents High.

All completeness/error flags above describe **this finding's check**, not the
whole host scan. Do not stamp a host-wide `collected.errors` list as `errors`,
`complete: false`, or `partial` on every finding: other checks may have independent,
valid evidence. Wider issues may be retained separately as `collector_errors`.
Set `partial` only when the finding's own evidence is limited. A malformed
explicit `partial`, `version_only`, `conflicting`, or `conflicts` marker caps at
Low and appears in `evidence.invalid_markers`.

`evidence` exposes original source/host/rule/status, observation, tags, benchmark,
release and raw artifact reference; supplied collection provenance; normalized
authentication/privilege/content facts; timestamp origin/status/age; derived
`source_kind`, `version_only`, `partial`, `conflicting`, `inference_markers`, and simulation indicators;
unknowns; and `high_requirements_unmet`. Derived classification indicators are
rule interpretations, not claims that a collector verified their absence.
Artifact references are reported only; this module never opens them.

## Existing source defaults

| Source | Default interpretation with usable observations and a fresh timestamp |
| --- | --- |
| `native`, `windows-stig`, `windows-scap`, `kubernetes`, `containers`, `cisco_ios` | Direct native/configuration check: at most Medium without explicit provenance |
| `openscap`, `scc`, `evaluate-stig`, `powerstig`, `xccdf`, `cklb` | Direct scanner/checklist evidence: at most Medium without explicit provenance |
| `acas`, `nessus` | Scanner origin only; substantive observations can support Medium, but source/plugin names establish neither direct collection nor authentication |
| `trivy`, `cve`, `iavm` | Version/advisory matching: Low; installed versions do not establish backport or runtime applicability |
| `discovery`, `nmap` | Discovery indicators/guesses: Low |
| `hunt`, `hunt-*` | Heuristic intrusion indicators: Low pending direct verification |
| Anything else | Low unless an explicit direct method establishes the collection class |

A known source never independently qualifies for High. Version/discovery/hunt
source restrictions still apply when metadata claims a direct method. A new
producer with a direct method and all required facts can qualify for High.

### Legacy version, banner and port evidence

The rules inspect `Finding.evidence`, not plugin IDs, plugin names, report titles,
or the claimed credential policy. Recognition is case-insensitive, handles
multiline or whitespace-flattened parser output, and applies to any source:

- Labeled `Version`, `Installed version`, `Remote software version`, `Detected
  version`, `Fixed version`, and similar version fields followed by `:` or `=`
  mark version evidence. For example, `Installed version : 8.7p1 Fixed version :
  9.6p1 [22/tcp]` is Low with `source_kind: version_match`, `version_only: true`,
  and `inference_markers: [version_field]`. Package versions alone do not resolve
  backports or confirm vulnerability applicability.
- Labeled `Banner`, `Server`, and `X-Powered-By` values, or SSH identification
  strings such as `SSH-2.0-OpenSSH_8.7`, mark banner inference and cap at Low.
- Whole observations consisting of port/service presence, such as `22/tcp open
  ssh` or `Port 22 is open`, are Low with `source_kind: network_indicator`.
  The parser's bare `[22/tcp]` fallback stays Unknown because it has no usable
  observation. Both grades withhold standing approval through the policy guard.
- A port suffix on substantive output, such as `Encryption level not enforced.
  [3389/tcp]`, does not itself trigger a downgrade. This remains scanner evidence
  with authentication and collection method unknown unless explicitly recorded.

These are conservative restrictions. A recognized version field/banner remains
Low even alongside extra prose or metadata claiming a direct method or
`version_only: false`; those assertions do not establish independent applicability
verification. `evidence.inference_markers` exposes the matched format. Original
observations, source, timestamps, provenance and scanner status are preserved.
Unrecognized formats and arbitrary prose are not fully interpreted; producers
should still supply explicit `method`/`version_only` provenance. This module
neither compares version numbers nor claims a vulnerability was exploited.

Legacy tags `simulated`, `simulation`, `demo`, `fixture`, and `replay` distinguish
demonstration data; `version_only`, `version_match`, `banner`, and `cpe_match`
mark version inference; `conflict`/`conflicting` mark conflicts;
`partial`/`partial_evidence` and `scap:undecided` mark partial observations; and
`incomplete`/`collection_error` force Unknown. Existing `simulated sweep:` evidence
and explicit `version-only` wording are recognized conservatively. The existing
Linux native/OpenSCAP and Windows native/CKLB/SCAP merge formats are recognized
when they explicitly record differing statuses, and cap the result at Low.
Arbitrary prose is not parsed for logical contradictions or collection failures; producers
must record those in status/provenance. No host-name or file-path guessing is used.

## Context helper for legacy simulation data

`assess_for_context(ctx, finding, *, now=None)` wraps the pure rules for API and
report callers. When `collection_provenance.simulated` is absent, it makes one
normal `ctx.inventory.get(finding.host)` lookup and reads only `target.simulated`.
It performs no collection, network calls, writes, or additional file reads beyond
the inventory's normal lookup. Missing/unreadable inventory leaves the pure
assessment unchanged.

Any explicit `simulated` key takes precedence, including false, null, or malformed
values. Malformed provenance is not replaced. A current inventory flag of true
can downgrade legacy evidence to Low; an unresolved result stays Unknown. A
current false flag cannot promote evidence to High or establish historical
collection facts. Other simulation markers still apply.

The primary reason explicitly labels the inventory context. The returned
`evidence.simulation_context` records its source/value, while
`evidence.collection_provenance` remains exactly as supplied. The unknown
`simulation_at_collection` remains visible. No finding is mutated or persisted.
`Scanner._scan_target` stamps the actual target simulation flag into new observations.
Imported and older records without that flag retain the conservative context behavior above.

## Examples

```python
from cyberthunder.findings.confidence import assess
from cyberthunder.findings.schema import Finding

finding = Finding(
    host="range-01", source="native", rule_id="RHEL-09-255045",
    title="Disable direct root login", severity="high", status="open",
    evidence="sshd -T: permitrootlogin yes",
    collected_at="2026-11-05T14:00:00Z",
)
now = "2026-11-05T15:00:00Z"
assert assess(finding, now=now)["grade"] == "medium"

finding.collection_provenance = {
    "method": "command", "authenticated": True, "privilege": "root",
    "privilege_sufficient": True, "complete": True, "applicable": True,
    "simulated": False, "observed_at": "2026-11-05T14:00:00Z",
    "detector": {"name": "native-sshd", "version": "1"},
    "content": {"id": "RHEL_9_STIG", "version": "V2R3"},
}
assert assess(finding, now=now)["grade"] == "high"

finding.collection_provenance["conflicts"] = ["A second config observation disagrees"]
assert assess(finding, now=now)["grade"] == "low"
```

| Other observation | Grade | Explanation |
| --- | --- | --- |
| Complete CKLB check with finding details and recent timestamp, no authentication metadata | Medium | Useful scanner evidence, unknown provenance |
| Scanner says `not_reviewed` despite detailed output | Unknown | No completed determination |
| Direct check has no evidence or only `PASS` | Unknown | Source/status alone is insufficient |
| Trivy package match or bulletin version match | Low | Version matching needs applicability/backport verification |
| ACAS/Nessus output containing only installed/fixed version fields | Low | Version fields are recognized in fresh imports and legacy stored findings |
| Explicit simulated target with otherwise complete provenance | Low | Demonstration evidence is explicitly labeled |
| Nine-day-old command observation | Low | Stale evidence |
| Timestamp lacks timezone or is in the future | Low | Freshness cannot be established |
| Collection failed while trying to read a protected file | Unknown | Collection incomplete |
| Partially available observations or conflicting outputs | Low | Supporting evidence needs resolution |

## Focused validation

`tests/findings/test_confidence.py` covers the public contract, non-mutation,
required High provenance, source mappings, preserved scanner status, missing
observations, timestamps, simulations, version matching, conflicts, partial and
failed collection, parser fixtures, inventory fallback, and legacy/new document
round trips. The actual Nessus fixture regression checks deterministic version
grading, preserves substantive observations, and verifies that a matching policy
is withheld after restoring a legacy version-only finding. The shared `state_dir` fixture runs storage checks on both JSON and
SQLite. Run it together with `tests/test_schema_and_parsers.py` and
`tests/test_store.py`; no live hosts or network tests are needed.

This module does not retrofit collector metadata, validate artifact contents,
resolve conflicts, verify the truth of supplied provenance, or evaluate whether
a remediation is safe. Those remain separate collection, review, and approval
responsibilities.
