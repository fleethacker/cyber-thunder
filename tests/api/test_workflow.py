"""Workflow routes: receive, discover, scan, explain, propose, apply, report, rollback."""
from __future__ import annotations

import time

from tests.api.conftest import ACTOR, SSH_ROOT, add_target, wait_state

API = "/api/v1"


def _wait_scan(client, scan_id, timeout=5.0):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = client.get(f"{API}/scans/{scan_id}").json()
        if last["status"] in ("done", "error", "stopped"):
            return last
        time.sleep(0.05)
    raise AssertionError(last)


def test_receive_lists_cves_and_stigs_newest_first(client, ctx):
    assert client.get(f"{API}/receive/cve").json() == {"cves": []}
    assert client.get(f"{API}/receive/stig").json() == {"stigs": []}
    ctx.store.write_json(ctx.store.ingest_dir / "bulletins" / "old.json", {
        "id": "IAVM-2026-001", "title": "OpenSSH", "severity": "high", "cves": ["CVE-2024-6387"],
        "source": "iavm", "ingested_at": "2026-11-01T00:00:00Z", "hosts_affected": ["web01"], "findings": 1,
        "scan_id": "scan-old", "notes": "drop me",
    })
    ctx.store.write_json(ctx.store.ingest_dir / "bulletins" / "new.json", {
        "id": "IAVM-2026-002", "title": "kernel", "severity": "medium", "cves": ["CVE-2026-1"],
        "ingested_at": "2026-11-04T00:00:00Z",
    })
    ctx.store.write_json(ctx.store.ingest_dir / "deltas" / "stig.json", {
        "id": "delta-1", "benchmark_id": "RHEL_9_STIG", "old_release": "V1R1", "new_release": "V1R2",
        "counts": {"added": 2}, "created_at": "2026-11-04T00:00:00Z", "rules_added": [{"rule_id": "x"}],
    })
    cves = client.get(f"{API}/receive/cve").json()["cves"]
    assert [c["id"] for c in cves] == ["IAVM-2026-002", "IAVM-2026-001"]
    assert "notes" not in cves[1] and cves[1]["cves"] == ["CVE-2024-6387"]
    stigs = client.get(f"{API}/receive/stig").json()["stigs"]
    assert stigs[0]["benchmark_id"] == "RHEL_9_STIG" and stigs[0]["new_release"] == "V1R2"
    assert "rules_added" not in stigs[0]


def test_discover_returns_the_system_and_its_targets(client):
    add_target(client, "web01")
    add_target(client, "db01", options={"fixture_dir": str(__import__("pathlib").Path(__file__).resolve().parents[1] / "fixtures" / "api" / "host1"),
                                       "system": "web01"})
    add_target(client, "spare", in_scope=False, options={"system": "web01"})
    body = client.post(f"{API}/discover", json={"system": "web01"}, headers=ACTOR)
    assert body.status_code == 200, body.text
    targets = body.json()["targets"]
    assert [t["id"] for t in targets] == ["web01", "db01"]
    assert targets[0]["facts"]["hostname"] == "rocky9-web01"
    assert "facts" not in targets[1]
    assert client.post(f"{API}/discover", json={"target": "missing"}, headers=ACTOR).status_code == 404
    client.put(f"{API}/targets/web01", json={"in_scope": False}, headers=ACTOR)
    assert client.post(f"{API}/discover", json={"system": "web01"}, headers=ACTOR).status_code == 403
    assert client.post(f"{API}/discover", json={}, headers=ACTOR).status_code == 400


def test_scan_one_target_returns_its_results(client):
    add_target(client)
    r = client.post(f"{API}/scan", json={"target": "web01"}, headers=ACTOR)
    assert r.status_code == 202, r.text
    row = r.json()["results"]["web01"]
    assert row["target"] == "web01" and row["scan_id"]
    run = _wait_scan(client, row["scan_id"])
    assert run["status"] == "done" and run["targets"] == ["web01"] and run["findings_count"] > 0
    assert client.post(f"{API}/scan", json={"target": "ghost"}, headers=ACTOR).status_code == 404
    assert client.post(f"{API}/scan", json={}, headers=ACTOR).status_code == 400


def test_generate_explains_and_proposes_from_scan_results(client):
    add_target(client)
    started = client.post(f"{API}/scan", json={"target": "web01"}, headers=ACTOR).json()
    _wait_scan(client, started["results"]["web01"]["scan_id"])
    explained = client.post(f"{API}/generate/explain", json={"results": started}, headers=ACTOR)
    assert explained.status_code == 200, explained.text
    explanations = explained.json()["explanations"]
    assert explanations and all(e["risk"] for e in explanations)
    assert explained.json()["truncated"] == 0
    proposed = client.post(f"{API}/generate/propose", json={"results": started}, headers=ACTOR)
    assert proposed.status_code == 200, proposed.text
    titles = [p["title"] for p in proposed.json()["proposals"]]
    assert titles == ["Disable SSH root login"]
    assert proposed.json()["skipped"]
    again = client.post(f"{API}/generate/propose", json={"results": {"target": "web01"}}, headers=ACTOR)
    assert again.json()["proposals"] == []
    assert any("live proposal" in s["reason"] for s in again.json()["skipped"])
    assert client.post(f"{API}/generate/explain", json={}, headers=ACTOR).status_code == 400


def test_apply_only_approved_checklist_items_and_rollback_by_version(client):
    add_target(client)
    started = client.post(f"{API}/scan", json={"target": "web01"}, headers=ACTOR).json()
    _wait_scan(client, started["results"]["web01"]["scan_id"])
    proposed = client.post(f"{API}/generate/propose", json={"results": started}, headers=ACTOR).json()["proposals"][0]
    refused = client.post(f"{API}/apply", json={"targets": ["web01"], "checklists": [SSH_ROOT]}, headers=ACTOR)
    assert refused.status_code == 200, refused.text
    assert refused.json()["results"]["web01"]["applied"] == []
    assert "approve" in refused.json()["results"]["web01"]["skipped"][0]["reason"]
    assert client.get(f"{API}/proposals/{proposed['id']}").json()["state"] == "proposed"

    client.post(f"{API}/proposals/{proposed['id']}/approve", json={"note": "window"}, headers=ACTOR)
    applied = client.post(f"{API}/apply", json={"targets": ["web01"], "checklists": [SSH_ROOT]}, headers=ACTOR)
    assert applied.status_code == 200, applied.text
    change = applied.json()["results"]["web01"]["applied"][0]
    assert change["proposal_id"] == proposed["id"]
    assert wait_state(client, proposed["id"], {"verified"})["state"] == "verified"

    rolled = client.post(f"{API}/rollback", json={"targets": ["web01"], "version": proposed["id"]}, headers=ACTOR)
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["results"]["web01"]["rolled_back"][0]["proposal_id"] == proposed["id"]
    assert wait_state(client, proposed["id"], {"rolled_back"})["state"] == "rolled_back"

    missed = client.post(f"{API}/rollback", json={"targets": ["web01"], "versions": ["no-such-release"]}, headers=ACTOR)
    assert missed.json()["results"]["web01"]["ok"] is False
    assert missed.json()["results"]["web01"]["skipped"][0]["id"] == "no-such-release"


def test_kill_switch_blocks_apply_and_rollback(client, approved):
    client.post(f"{API}/kill/engage", json={"reason": "drill"}, headers=ACTOR)
    blocked = client.post(f"{API}/apply", json={"targets": ["web01"], "checklists": [SSH_ROOT]}, headers=ACTOR)
    assert blocked.status_code == 423, blocked.text
    assert client.get(f"{API}/proposals/{approved['id']}").json()["state"] == "approved"
    client.post(f"{API}/kill/release", json={"reason": "drill over"}, headers=ACTOR)
    client.post(f"{API}/proposals/{approved['id']}/apply", headers=ACTOR)
    assert wait_state(client, approved["id"], {"verified"})["state"] == "verified"
    client.post(f"{API}/kill/engage", json={"reason": "drill"}, headers=ACTOR)
    assert client.post(f"{API}/rollback", json={"targets": ["web01"], "versions": [approved["id"]]}, headers=ACTOR).status_code == 423


def test_target_report_round_trip_and_fixed_report_paths_stay_put(client):
    add_target(client)
    assert client.get(f"{API}/reports/web01").status_code == 404
    # the fixed report routes are matched before /reports/{target}
    assert client.get(f"{API}/reports/commander").status_code == 501
    written = client.post(f"{API}/reports", json={"target": "web01"}, headers=ACTOR)
    assert written.status_code == 200, written.text
    assert written.json()["target"]["id"] == "web01"
    assert written.json()["findings"] == 0 and written.json()["checklist"] is None
    assert client.get(f"{API}/reports/web01").json()["generated_by"] == ACTOR["X-Actor"]
    assert client.get(f"{API}/reports/ghost").status_code == 404
    assert client.post(f"{API}/reports", json={}, headers=ACTOR).status_code == 400


def test_report_attaches_a_checklist_after_a_scan(client, ctx):
    from cyberthunder.report.service import ReportService
    ctx.reports = ReportService(ctx)
    add_target(client)
    started = client.post(f"{API}/scan", json={"target": "web01"}, headers=ACTOR).json()
    _wait_scan(client, started["results"]["web01"]["scan_id"])
    doc = client.post(f"{API}/reports", json={"target": "web01"}, headers=ACTOR).json()
    assert doc["open"] >= 1 and doc["checklist"]["target_data"]["host_name"] == "web01"
    assert doc["checklist_error"] is None
