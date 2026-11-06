"""Namespace coverage stays explicit through serial and bounded collection."""
import json
from dataclasses import replace

import pytest

from cyberthunder.adapters.kubernetes import scope
from cyberthunder.control.principal import principal_scope
from cyberthunder.report.checklist import build_checklist
from tests.kubernetes.test_namespace_scope import scoped_account
from tests.security.test_kubernetes_account_integration import selected_cluster, assert_selected
from tests.security.test_kube_credentials import cert_material, write


@pytest.mark.parametrize("workers", [1, 3])
def test_namespace_coverage_survives_collection_scheduler(scoped_account, workers):
    ctx, target, person, config, policy_path, calls = scoped_account
    ctx.settings.scan_max_workers = workers
    ctx.settings.scan_host_budget_s = 0
    policy = json.loads(policy_path.read_text())
    policy["entries"][0]["grants"][0]["actions"].append("export")
    policy["entries"][0]["node_actions"] = ["audit", "export"]
    write(policy_path, json.dumps(policy).encode())
    person = replace(person, roles=(*person.roles, "auditor"))
    try:
        with principal_scope(person):
            run = ctx.scanner.start([target.id], modules=["check", "hunt"],
                                    requested_by=person.actor, background=False)
            expected_status = "done" if workers == 1 else "partial"
            assert run.status == expected_status
            assert run.results[target.id].status == expected_status
            assert run.coverage_incomplete is True
            assert run.results[target.id].errors == [
                "Namespace coverage only; cluster-scoped inputs and node configuration unavailable by scope."
            ]
            findings = ctx.store.load_findings(run.id)
            checklist = build_checklist(ctx, run.id, target.id)
            collected = ctx.store.read_json(ctx.store.scan_dir(run.id) / "raw" / target.id / "collected.json")
        assert len(calls) == 7
        assert_selected(calls, config)
        assert collected["raw"][scope.SCOPE_KEY]["namespaces"] == ["work"]
        assert run.results[target.id].facts["extra"]["node_count"] is None
        assert findings and all(f.collection_provenance[scope.SCOPE_KEY]["read_only"] for f in findings)
        assert "Namespace coverage: work; cluster coverage incomplete" in json.dumps(checklist)
        assert '"status": "not_a_finding"' not in json.dumps(checklist)
        assert any(f.is_open and f.rule_version == "k8s:cis:5.2.2" for f in findings)
        if workers > 1:
            assert run.scheduling["partial_targets"] == [target.id]
            assert run.scheduling["unavailable_targets"] == []
            assert run.scheduling["omitted_observations"] == "retain_without_revalidation"
            assert target.last_scan is None
    finally:
        assert ctx.close()
