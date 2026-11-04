import csv
import io
import json
from types import SimpleNamespace

import pytest

from cyberthunder.cli import main
from cyberthunder.report.poam import COLUMNS
from cyberthunder.report.render import ReportError
from cyberthunder.report.service import ReportService

from .conftest import FIX, SCAN


def svc(node) -> ReportService:
    return ReportService(node)


def last_render(node, kind):
    recs = [r for r in node.audit.records() if r["action"] == "report.render" and r["details"]["kind"] == kind]
    return recs[-1]


# -- commander ----------------------------------------------------------------------------
def test_commander_html_has_the_facts_and_the_head_hash(node):
    head = node.audit.head
    html = svc(node).commander(SCAN, "html")
    assert "USS Example" in html and SCAN in html and "stig_delta" in html
    assert head in html and "intact" in html
    assert "T1053.003" in html and "T1136.001" in html           # intrusion indicators with ATT&CK ids
    assert "Anyone with the root password" in html               # explanation.risk is quoted
    assert "No explanation generated yet" in html                # and missing ones are said so
    assert "sailor1" in html and "SSH permits root login" in html   # verified change and its approver
    assert "Pending 1" in html and "Verified 1" in html and "Rolled back 1" in html and "Denied 1" in html
    assert "BLUF" in html and "Reproduce:" in html and "report commander" in html
    assert 'src="http' not in html and 'href="http' not in html   # no external assets
    assert "{{" not in html and "{%" not in html


def test_commander_counts_by_host_and_cat(node):
    md = svc(node).commander(SCAN, "md")
    assert "| rhel-01 | 4 | 2 | 0 | 6 | 2 |" in md
    assert "| sw-01 | 0 | 0 | 1 | 1 | 0 |" in md
    assert "7 open finding(s) on 2 host(s): 4 CAT I, 2 CAT II, 1 CAT III." in md


def test_commander_md_has_head_and_sections(node):
    head = node.audit.head
    md = svc(node).commander(SCAN, "md")
    assert head in md and "## Top risks" in md and "## Next actions" in md
    assert "Approve or deny 1 pending proposal(s)" in md
    assert "Review intrusion indicators on rhel-01" in md


def test_commander_default_is_latest_scan_and_errors_are_clear(node):
    assert SCAN in svc(node).commander(None, "md")
    with pytest.raises(ReportError, match="not found"):
        svc(node).commander("nope", "md")
    with pytest.raises(ReportError, match="format"):
        svc(node).commander(SCAN, "pdf")


def test_commander_without_any_scan_says_what_to_do(state_dir):
    from cyberthunder.config import Settings
    from cyberthunder.context import AppContext
    ctx = AppContext(Settings.from_env(state_dir=state_dir))
    with pytest.raises(ReportError, match="run a scan first"):
        ReportService(ctx).commander()


def test_commander_flags_a_broken_audit_chain(node):
    path = node.store.audit_log
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("sailor1", "sailorX", 1), encoding="utf-8")
    html = svc(node).commander(SCAN, "html")
    assert "BROKEN" in html and "Investigate the audit chain" in html


def test_commander_link_line_when_ingest_exists(node):
    node.ingest = None
    assert "Link " not in svc(node).commander(SCAN, "md")
    node.ingest = SimpleNamespace(outbox=SimpleNamespace(pending=lambda: ["a", "b"]),
                                  link=SimpleNamespace(status=lambda: {"kbps": 28.8, "connected": False}))
    md = svc(node).commander(SCAN, "md")
    assert "Link disconnected at 28.8 kbps. Outbox: 2 item(s) waiting to sync (will send on reconnect)." in md


# -- audit ----------------------------------------------------------------------------------
def test_every_render_is_audited_with_the_embedded_head_and_the_chain_verifies(node):
    s = svc(node)
    head = node.audit.head
    s.commander(SCAN, "html")
    rec = last_render(node, "commander")
    assert rec["details"]["audit_head"] == head and rec["details"]["scan_id"] == SCAN
    s.poam_csv(SCAN)
    s.checklist_cklb(SCAN, "rhel-01")
    s.fleet("md")
    s.friction("md")
    s.score(SCAN, str(FIX / "answer_key"))
    kinds = [r["details"]["kind"] for r in node.audit.records() if r["action"] == "report.render"]
    assert kinds == ["commander", "poam", "checklist", "fleet", "friction", "score"]
    assert node.audit.verify().ok


# -- POA&M ----------------------------------------------------------------------------------
def test_poam_csv_columns_and_rows(node):
    text = svc(node).poam_csv(SCAN)
    rows = list(csv.DictReader(io.StringIO(text, newline="")))
    assert list(rows[0].keys()) == COLUMNS
    ids = {r["Finding ID"]: r for r in rows}
    f = node.findings
    assert f["shadow"].id not in ids                              # passing checks are not POA&M items
    assert ids[f["root"].id]["Status"] == "Completed" and ids[f["root"].id]["Scheduled Completion"] == ""
    assert ids[f["root"].id]["STIG ID"] == "RHEL-09-255045" and ids[f["root"].id]["Severity (CAT)"] == "CAT I"
    assert ids[f["empty"].id]["Proposal State"] == "proposed"
    assert ids[f["empty"].id]["Milestone"] == "Approve or deny proposal"
    assert ids[f["world"].id]["Status"] == "Open" and ids[f["world"].id]["Proposal State"] == "rolled_back"
    assert ids[f["cron"].id]["Citations"].count("T1053.003") == 1
    assert ids[f["cve"].id]["Proposed Fix"] == "" and "manual remediation" in ids[f["cve"].id]["Resources Required"]
    assert len(rows) == 7
    assert rows[0]["Severity (CAT)"] == "CAT I"                    # worst first


def test_poam_survives_unicode_and_commas(node):
    f = node.findings["cve"]
    f.title = 'Café, "quoted" title'
    node.store.save_findings(SCAN, list(node.findings.values()))
    rows = list(csv.DictReader(io.StringIO(svc(node).poam_csv(SCAN), newline="")))
    assert any(r["Title"] == f.title for r in rows)


# -- checklist ------------------------------------------------------------------------------
def test_checklist_synthesised_statuses(node):
    doc = svc(node).checklist_cklb(SCAN, "rhel-01")
    assert doc["target_data"]["host_name"] == "rhel-01" and doc["cklb_version"] == "1.0"
    rules = {r["rule_version"] or r["rule_id"]: r for s in doc["stigs"] for r in s["rules"]}
    assert rules["RHEL-09-255045"]["status"] == "not_a_finding"       # verified change closes it
    assert "approved by sailor1" in rules["RHEL-09-255045"]["comments"]
    assert rules["RHEL-09-255040"]["status"] == "open"
    assert rules["RHEL-09-232245"]["status"] == "not_a_finding"        # scanner pass
    assert rules["RHEL-09-232261"]["status"] == "open" and "rolled_back" in rules["RHEL-09-232261"]["comments"]
    assert rules["hunt:cron_beacon"]["status"] == "open"
    assert all(r["finding_details"] for r in rules.values())
    json.dumps(doc)


def test_checklist_needs_a_host_when_scan_has_several(node):
    with pytest.raises(ReportError, match="pass a host"):
        svc(node).checklist_cklb(SCAN)
    with pytest.raises(ReportError, match="no findings for host"):
        svc(node).checklist_cklb(SCAN, "ghost")
    assert svc(node).checklist_cklb(SCAN, "sw-01")["target_data"]["host_name"] == "sw-01"


def test_checklist_reuses_input_cklb(node, raw_cklb):
    before = raw_cklb.read_text(encoding="utf-8")
    doc = svc(node).checklist_cklb(SCAN, "rhel-01")
    rules = {r["rule_version"]: r for r in doc["stigs"][0]["rules"]}
    assert doc["id"] == "11111111-1111-1111-1111-111111111111"          # the input document, not a new one
    assert rules["RHEL-09-255045"]["status"] == "not_a_finding"
    assert rules["RHEL-09-255045"]["comments"].startswith("reviewer text")   # reviewer text kept
    assert "Fixed by approved change" in rules["RHEL-09-255045"]["comments"]
    assert rules["RHEL-09-255040"]["status"] == "open"
    assert rules["RHEL-09-255040"]["finding_details"] == "evidence for SSH permits empty passwords"
    assert rules["RHEL-09-999999"]["status"] == "not_reviewed" and rules["RHEL-09-999999"]["comments"] == "keep"
    assert raw_cklb.read_text(encoding="utf-8") == before                # the scanner artifact is never modified


# -- path to fleet and friction ---------------------------------------------------------------
@pytest.mark.parametrize("fmt", ["html", "md"])
def test_fleet_page(node, fmt):
    head = node.audit.head
    out = svc(node).fleet(fmt).lower()
    for needle in ("NAVIFOR / Naval Network Warfare Command", "NIWC Atlantic", "Iron Bank", "DADMS",
                   "no approved offline model runtime", "Day 180" if fmt == "md" else "30 / 60 / 90 / 180", head):
        assert needle.lower() in out, needle
    for key in ("May", "Never", "Requires approval", "Logged", "Stopped"):
        assert key.lower() in out


@pytest.mark.parametrize("fmt", ["html", "md"])
def test_friction_log(node, fmt):
    out = svc(node).friction(fmt)
    for i in range(1, 9):
        assert f"F{i}" in out
    assert "DADMS" in out and "4 GB of VRAM" in out and "cloud-synced" in out


def test_friction_yaml_is_valid():
    from cyberthunder.report.friction import AREAS, load_friction
    entries = load_friction(None)
    assert len(entries) == 8 and {e["area"] for e in entries} <= set(AREAS)


def test_site_docs_override_repo_docs(node):
    d = node.store.root / "docs"
    d.mkdir()
    (d / "friction.yaml").write_text(
        "entries:\n  - {id: X1, area: range, what: w, impact: i, workaround: k, ask: a}\n", encoding="utf-8")
    out = svc(node).friction("md")
    assert "X1" in out and "F1" not in out
    (d / "friction.yaml").write_text(
        "entries:\n  - {id: X2, area: nonsense, what: w, impact: i, workaround: k, ask: a}\n", encoding="utf-8")
    with pytest.raises(ReportError, match="unknown area"):
        svc(node).friction("md")


# -- score ------------------------------------------------------------------------------------
def test_score_against_answer_key(node, key_dir):
    res = svc(node).score(SCAN, str(key_dir))
    by = {i["id"]: i for i in res["items"]}
    assert res["seeded"] == 7 and res["found"] == 6 and res["share"] == round(6 / 7, 4)
    assert by["M1"]["found"] and by["M1"]["finding_ids"] == [node.findings["root"].id]      # check_id == rule_version
    assert by["M2"]["found"]                                                                 # older schema: stig_id
    assert not by["M3"]["found"]                                                             # scanner reported pass
    assert by["M6"]["found"] and by["M6"]["finding_ids"] == [node.findings["world"].id]     # RHEL-09-232xxx wildcard
    assert by["V1"]["found"]                                                                 # CVE in citations
    assert by["I1"]["found"]                                                                 # detector prefix
    assert by["I3"]["found"]                                                                 # ATT&CK in citations
    assert res["by_kind"]["misconfig"] == {"seeded": 4, "found": 3, "share": 0.75}
    assert res["by_kind"]["intrusion"]["found"] == 2 and res["by_kind"]["vuln"]["share"] == 1.0
    assert isinstance(res["time_to_plan_s"], float) and res["time_to_plan_s"] >= 0


def test_score_only_counts_findings_on_the_keyed_host(node, tmp_path):
    d = tmp_path / "keys"
    d.mkdir()
    (d / "a.json").write_text(json.dumps({"target": "sw-01", "items": [
        {"id": "S1", "kind": "misconfig", "check_id": "CCI-000196", "what": "x"},
        {"id": "S2", "kind": "misconfig", "check_id": "RHEL-09-255045", "what": "on another host"}]}), encoding="utf-8")
    res = svc(node).score(SCAN, str(d))
    assert [i["found"] for i in res["items"]] == [True, False]


def test_score_errors(node, tmp_path):
    with pytest.raises(ReportError, match="not found"):
        svc(node).score(SCAN, str(tmp_path / "missing"))
    (tmp_path / "empty").mkdir()
    with pytest.raises(ReportError, match="no answer key"):
        svc(node).score(SCAN, str(tmp_path / "empty"))


# -- queue and CLI ----------------------------------------------------------------------------
def test_queue_requires_an_outbox(node):
    node.ingest = None
    with pytest.raises(ReportError, match="outbox is not available"):
        svc(node).queue("commander", SCAN)


def test_queue_puts_the_render_in_the_outbox_and_audits(node):
    got = []

    class Outbox:
        def enqueue(self, kind, name, content, meta=None):
            got.append((kind, name, content, meta))
            return "item-1"

    node.ingest = SimpleNamespace(outbox=Outbox())
    res = svc(node).queue("poam", SCAN)
    assert res["queued"] and res["outbox"] == "item-1" and res["filename"].endswith(".csv")
    assert got[0][0] == "report.poam" and got[0][2].startswith("Host,Asset Type") and got[0][3]["scan_id"] == SCAN
    assert [r for r in node.audit.records() if r["action"] == "report.queue"]
    assert node.audit.verify().ok
    with pytest.raises(ReportError, match="unknown report kind"):
        svc(node).queue("nonsense", SCAN)


def test_cli_commands(node, key_dir, tmp_path, capsys):
    base = ["--state-dir", str(node.store.root), "report"]
    out = tmp_path / "poam.csv"
    assert main([*base, "poam", "--out", str(out)]) == 0
    assert out.read_bytes().startswith(b"Host,Asset Type")
    assert main([*base, "commander", "--format", "md", "--scan-id", SCAN]) == 0
    assert "Commander one-pager" in capsys.readouterr().out
    assert main([*base, "checklist", "--host", "sw-01"]) == 0
    assert json.loads(capsys.readouterr().out)["target_data"]["host_name"] == "sw-01"
    assert main([*base, "score", "--key-dir", str(key_dir)]) == 0
    assert json.loads(capsys.readouterr().out)["found"] == 6
    assert main([*base, "checklist"]) == 2                    # two hosts, no --host
    assert "pass a host" in capsys.readouterr().err
    assert main([*base, "fleet", "--format", "md"]) == 0 and main([*base, "friction"]) == 0
