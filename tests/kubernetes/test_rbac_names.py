"""RBAC objects carry path-segment names with colons (system:controller:bootstrap-signer in kube-system).

The first scan of a real cluster aborted check_rbac and hunt_admin_bindings on such a RoleBinding; both the
object-reference rule and the binding iteration must take them in stride.
"""
import pytest

from cyberthunder.adapters.base import Collected
from cyberthunder.adapters.kubernetes import checks, hunt
from cyberthunder.adapters.kubernetes.checks import KubeData
from cyberthunder.adapters.kubernetes.kubectl import ObjRef
from cyberthunder.inventory.targets import Target


def _binding(kind, name, role, subjects, namespace=None):
    md = {"name": name}
    if namespace:
        md["namespace"] = namespace
    return {"kind": kind, "metadata": md, "roleRef": {"kind": "ClusterRole" if kind == "ClusterRoleBinding" else "Role",
                                                     "name": role}, "subjects": subjects}


@pytest.fixture
def target():
    return Target(id="k8s-lab", name="lab cluster", asset_type="kubernetes", transport="kubeconfig",
                  options={"kubeconfig": "unused"})


@pytest.fixture
def data(tmp_path):
    col = Collected(target_id="k8s-lab", asset_type="kubernetes", workdir=str(tmp_path))
    col.raw["clusterrolebindings"] = {"items": [
        _binding("ClusterRoleBinding", "system:public-info-viewer", "system:public-info-viewer",
                 [{"kind": "Group", "name": "system:unauthenticated"}]),
        _binding("ClusterRoleBinding", "velero-server", "cluster-admin",
                 [{"kind": "ServiceAccount", "name": "velero-server", "namespace": "velero"}]),
    ]}
    col.raw["rolebindings"] = {"items": [
        _binding("RoleBinding", "system:controller:bootstrap-signer", "system:controller:bootstrap-signer",
                 [{"kind": "ServiceAccount", "name": "bootstrap-signer", "namespace": "kube-system"}],
                 namespace="kube-system"),
        # an object the reference rule cannot address is skipped, never fatal
        _binding("RoleBinding", "odd", "edit", [{"kind": "User", "name": "x"}], namespace="Not A Namespace"),
    ]}
    return KubeData(col)


def test_rbac_names_with_colons_are_addressable():
    ref = ObjRef("kube-system", "rolebinding", "system:controller:bootstrap-signer")
    assert ref.name == "system:controller:bootstrap-signer" and ref.namespace == "kube-system"
    assert ObjRef(None, "clusterrole", "system:aggregate-to-view").namespace is None
    with pytest.raises(ValueError):
        ObjRef("default", "pod", "bad:name")          # ordinary objects stay DNS-1123 names


def test_bindings_skip_unaddressable_objects(data):
    names = [ref.name for ref, _ in checks.bindings(data)]
    assert "system:controller:bootstrap-signer" in names
    assert "odd" not in names


def test_check_rbac_and_hunt_survive_colon_names(target, data):
    found = checks.check_rbac(target, data)
    titles = {f.title for f in found}
    assert any("anonymous" in t.lower() for t in titles), titles
    assert any("cluster-admin" in t for t in titles), titles
    assert all(f.references for f in found)
    assert hunt.hunt_admin_bindings(target, data) == []
