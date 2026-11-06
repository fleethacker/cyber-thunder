"""Findings queries against both public StateStore backends; no targets or scanners are contacted."""
from dataclasses import replace

import pytest

from cyberthunder.findings.schema import Finding, Reference, Severity, Status

URL = "/api/v1/findings"


def finding(id, **overrides):
    values = dict(id=id, host="alpha", source="native", rule_id=f"check:{id}", title=f"Check {id}",
                  severity=Severity.MEDIUM, status=Status.OPEN, asset_type="linux",
                  collected_at="2026-11-05T10:00:00Z")
    values.update(overrides)
    return Finding(**values)


def save(ctx, findings, sid="base", *, at="2026-11-05T10:00:00Z", trigger="manual", targets=None):
    ctx.store.save_scan_run({"id": sid, "started_at": at, "trigger": trigger, "status": "done",
                             "targets": sorted({f.host for f in findings}) if targets is None else targets})
    ctx.store.save_findings(sid, [replace(f, scan_id=sid) for f in findings])


def query(client, **params):
    response = client.get(URL, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def ids(result):
    return [f["id"] for f in result["findings"]]


@pytest.fixture
def catalog(ctx):
    records = [
        finding("stig", rule_id="SV-257985r925717_rule", rule_version="RHEL-09-255045", group_id="V-257985",
                title="SSH root login", benchmark="RHEL 9 STIG", benchmark_release="V2R1", severity="high"),
        finding("both", host="Bravo", source="openscap", rule_id="xccdf_custom_ssh", title="SSH update",
                references=[Reference("stig_id", "RHEL-09-211010"), Reference("cve", "CVE-2026-12345")],
                benchmark="RHEL 9 STIG", benchmark_release="V2R2"),
        finding("cve", host="bravo", source="trivy", rule_id="image:openssl:CVE-2026-99999", title="Library issue",
                asset_type="containers", severity="low"),
        finding("hunt", host="charlie", source="hunt", rule_id="hunt:linux:cron", title="Unexpected cron",
                references=[Reference("attack", "T1053.003")], severity="high"),
        finding("unsupported", source="custom-scanner", title="CVE STIG hunt words alone do not classify",
                status="not_reviewed", severity="unknown", asset_type=None, collected_at="invalid"),
        finding("error", source="custom-scanner", status="error", asset_type="new-platform",
                benchmark='Vendor "Policy", Edge', benchmark_release="Release 1, November"),
        finding("na", source="scc", status="not_applicable", benchmark="CIS Linux", severity="info"),
        finding("pass", source="powerstig", status="not_a_finding", severity="low", asset_type="windows"),
    ]
    save(ctx, records)
    return records


def test_categories_overlap_and_do_not_guess_from_title(client, catalog):
    result = query(client)
    assert set(ids(result)) == {f.id for f in catalog}
    categories = {f["id"]: f["categories"] for f in result["findings"]}
    assert categories == {"stig": ["stig"], "both": ["stig", "cve"], "cve": ["cve"], "hunt": ["hunt"],
                          "unsupported": ["other"], "error": ["other"], "na": ["other"], "pass": ["stig"]}
    assert set(ids(query(client, category="STIG,CVE"))) == {"stig", "both", "cve", "pass"}
    assert set(ids(query(client, category="other"))) == {"unsupported", "error", "na"}


def test_category_evidence_handles_case_and_multiple_provenance(client, ctx):
    save(ctx, [
        finding("mixed", source="HUNT", rule_id="image:cve-2026-12345", rule_version="rhel-09-255045"),
        finding("reference", references=[Reference("attack", "T1053.003")]),
        finding("identifier", rule_id="custom:hunt:persistence"),
        finding("group", group_id="V-257985"),
        finding("generic", source="openscap", references=[Reference("group", "system_settings")]),
    ])
    categories = {f["id"]: f["categories"] for f in query(client)["findings"]}
    assert categories == {"mixed": ["stig", "cve", "hunt"], "reference": ["hunt"],
                          "identifier": ["hunt"], "group": ["stig"], "generic": ["other"]}


def test_filter_combinations_or_within_and_across_axes(client, catalog):
    result = query(client, category="stig,cve", status="open", severity="CAT II,low", host="BRAVO",
                   asset_type="linux,containers", source="openscap,trivy", benchmark="RHEL 9 STIG",
                   benchmark_release="V2R2", q="2026-12345")
    assert ids(result) == ["both"]
    assert result["total"] == 1 and result["unfiltered_total"] == 8
    assert query(client, category="hunt", benchmark="RHEL 9 STIG")["total"] == 0
    assert ids(query(client, benchmark='"Vendor ""Policy"", Edge"', benchmark_release='"Release 1, November"')) == ["error"]
    # Unknown extensible values are valid, useful saved selections with no current matches.
    assert query(client, host="retired-host", source="future-scanner")["total"] == 0


@pytest.mark.parametrize(("term", "expected"), [
    ("cve-2026-12345", {"both"}), ("CVE-2026-99999", {"cve"}), ("rhel-09-211010", {"both"}),
    ("SV-257985", {"stig"}), ("V-257985", {"stig"}), ("BRAVO", {"both", "cve"}),
    ("SSH root", {"stig"}), ("T1053.003", {"hunt"}), ("V2R2", {"both"}),
])
def test_search_identifiers_references_title_and_machine(client, catalog, term, expected):
    assert set(ids(query(client, q=term))) == expected


def test_facets_cover_full_view_even_when_filters_match_nothing(client, catalog):
    all_results = query(client)
    empty = query(client, q="nothing matches", category="stig", limit=1, offset=20)
    assert empty["total"] == 0 and empty["unfiltered_total"] == 8
    assert empty["facets"] == all_results["facets"]
    facets = empty["facets"]
    assert {o["value"] for o in facets["status"]} == {s.value for s in Status}
    assert {o["value"]: o["count"] for o in facets["category"]} == {"stig": 3, "cve": 2, "hunt": 1, "other": 3}
    assert next(o for o in facets["host"] if o["value"] == "bravo")["count"] == 2
    assert {o["value"] for o in facets["asset_type"]} >= {"new-platform", "__missing__"}
    assert set(ids(query(client, asset_type="__missing__", severity="unknown"))) == {"unsupported"}
    assert set(ids(query(client, benchmark="__missing__", status="error,not_applicable"))) == set()


def test_facets_and_sort_are_not_limited_to_first_page(client, ctx):
    rows = [finding(f"item-{i:03}", title=f"Result {i:03}") for i in range(205)]
    rows[-1] = replace(rows[-1], host="last-machine", source="last-source", asset_type="last-type",
                       benchmark="Last STIG", benchmark_release="Last release", severity=Severity.HIGH)
    save(ctx, rows)
    first = query(client, sort_by="title", limit=200)
    assert len(first["findings"]) == 200 and first["total"] == 205
    for axis, value in (("host", "last-machine"), ("source", "last-source"), ("asset_type", "last-type"),
                        ("benchmark", "last stig"), ("benchmark_release", "last release")):
        assert value in {o["value"] for o in first["facets"][axis]}
    assert ids(query(client, sort_by="severity", sort_dir="desc", limit=1)) == ["item-204"]
    assert ids(query(client, category="stig", limit=1)) == ["item-204"]
    assert ids(query(client, sort_by="title", sort_dir="desc", limit=1, offset=1)) == ["item-203"]


@pytest.mark.parametrize("field", ["host", "asset_type", "source", "title", "rule_id", "rule_version", "benchmark", "benchmark_release"])
def test_text_sort_case_insensitive_stable_ties_and_missing_last(client, ctx, field):
    rows = [finding("z", **{field: "Alpha"}), finding("b", **{field: "alpha"}),
            finding("a", **{field: "Zulu"}), finding("m", **{field: ""})]
    save(ctx, rows)
    assert ids(query(client, sort_by=field)) == ["b", "z", "a", "m"]
    assert ids(query(client, sort_by=field, sort_dir="desc")) == ["a", "b", "z", "m"]
    save(ctx, list(reversed(rows)))
    assert ids(query(client, sort_by=field, limit=1, offset=1)) == ["z"]
    assert ids(query(client, sort_by=field, sort_dir="desc")) == ["a", "b", "z", "m"]


def test_severity_and_observation_time_sort(client, ctx):
    save(ctx, [finding("high", severity="high", collected_at="2026-11-05T11:00:00+01:00"),
               finding("info", severity="info", collected_at="2026-11-05T09:30:00"),
               finding("medium", severity="medium", collected_at="2026-11-05T10:30:00Z"),
               finding("unknown", severity="unknown", collected_at="broken"),
               finding("low", severity="low", collected_at="")])
    assert ids(query(client, sort_by="severity")) == ["info", "low", "medium", "high", "unknown"]
    assert ids(query(client, sort_by="severity", sort_dir="desc")) == ["high", "medium", "low", "info", "unknown"]
    assert ids(query(client, sort_by="collected_at")) == ["info", "high", "medium", "low", "unknown"]
    assert ids(query(client, sort_by="collected_at", sort_dir="desc")) == ["medium", "high", "info", "low", "unknown"]


def test_category_sort_and_default_priority_are_deterministic(client, catalog, ctx):
    ordered = ["cve", "both", "hunt", "error", "na", "unsupported", "pass", "stig"]
    assert ids(query(client, sort_by="category")) == ordered
    assert ids(query(client))[:2] == ["stig", "hunt"]
    save(ctx, [finding("z", title="Same"), finding("a", title="Same", rule_id="check:z")])
    assert ids(query(client)) == ["a", "z"]


def test_current_partial_overlays_and_explicit_historical_facets(client, ctx):
    old = finding("old", host="historical", benchmark="Old STIG", benchmark_release="V1R1")
    base = finding("base", rule_version="RHEL-09-255045", benchmark="Current STIG", benchmark_release="V2R1")
    untouched = finding("untouched", host="other-machine")
    save(ctx, [old], "older", at="2026-11-04T10:00:00Z")
    # This full scan checked the historical host too and found no remaining finding there.
    save(ctx, [base, untouched], targets=[old.host, base.host, untouched.host])
    save(ctx, [replace(base, status=Status.NOT_A_FINDING, benchmark_release="V2R2")], "rescan",
         at="2026-11-05T11:00:00Z", trigger="stig_delta")
    save(ctx, [finding("bulletin", source="iavm", references=[Reference("cve", "CVE-2026-12345")])],
         "bulletin", at="2026-11-05T12:00:00Z", trigger="bulletin")
    current = query(client)
    assert current["scan_id"] == "base" and current["view"] == "current"
    assert set(ids(current)) == {"base", "untouched", "bulletin"}
    assert ids(query(client, category="cve")) == ["bulletin"]
    assert query(client, category="stig", status="open")["total"] == 0
    assert {o["value"] for o in current["facets"]["benchmark_release"]} == {"v2r2", "__missing__"}
    explicit = query(client, scan_id="base", category="stig", status="open")
    assert ids(explicit) == ["base"] and explicit["view"] == "scan" and explicit["unfiltered_total"] == 2
    assert {o["value"] for o in explicit["facets"]["benchmark_release"]} == {"v2r1", "__missing__"}
    historical = query(client, scan_id="older")
    assert ids(historical) == ["old"] and historical["facets"]["host"][0]["value"] == "historical"
    assert ids(query(client, scan_id="bulletin")) == ["bulletin"]


def test_verified_fix_keeps_existing_effective_status_semantics(client, ctx):
    save(ctx, [finding("fixed", collected_at="2000-01-01T00:00:00Z")])
    p = ctx.gate.propose(actor="ITC Rivera", finding_id="fixed", host="alpha", title="Fix", fix_ref="test:fix",
                         fix_preview="test", rollback_plan="restore", risk="test", citations=[])
    ctx.gate.approve(p.id, "ITC Rivera")
    ctx.gate.start_apply(p.id, "ITC Rivera")
    ctx.gate.applied(p.id)
    ctx.gate.verified(p.id)
    result = query(client, status="not_a_finding")
    assert ids(result) == ["fixed"]
    assert result["findings"][0]["remediated"]["scan_status"] == "open"
    assert result["facets"]["status"] == [{"value": "not_a_finding", "label": "not_a_finding", "count": 1}]
    assert query(client, status="open")["total"] == 0
    assert ids(query(client, scan_id="base", status="not_a_finding")) == ["fixed"]


@pytest.mark.parametrize("params", [
    {"category": "patch"}, {"status": "approved"}, {"severity": "spicy"},
    {"sort_by": "evidence"}, {"sort_dir": "up"}, {"sort_dir": "desc"},
    {"host": "alpha,,bravo"}, {"benchmark": '"unclosed'}, {"category": "stig,"},
    {"limit": 0}, {"limit": 5001}, {"offset": -1},
])
def test_invalid_queries_fail_clearly_even_on_empty_view(client, params):
    response = client.get(URL, params=params)
    assert response.status_code == 400
    assert isinstance(response.json()["detail"], str) and response.json()["detail"]


def test_empty_view_unknown_scan_and_response_compatibility(client, ctx):
    result = query(client)
    assert result["findings"] == [] and result["total"] == result["unfiltered_total"] == 0
    assert result["scan_id"] is None and result["view"] == "current"
    assert result["limit"] == 200 and result["offset"] == 0
    assert result["summary"]["total"] == 0
    assert all(not choices for choices in result["facets"].values())
    assert client.get(URL, params={"scan_id": "unknown"}).status_code == 404
    save(ctx, [finding("partial")], trigger="bulletin")
    assert ids(query(client)) == ["partial"]
