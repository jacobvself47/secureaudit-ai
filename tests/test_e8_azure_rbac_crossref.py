"""
Tests for E8 — Azure RBAC cross-reference (dual K8s+Azure path detection).

Verifies severity escalation, best-grant selection, and negative cases.
"""
import sys
import os

_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "risk-agent", "scripts")
_SHARED = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "shared")
sys.path.insert(0, os.path.normpath(_SCRIPTS))
sys.path.insert(0, os.path.normpath(_SHARED))

from analyze import run_checks  # noqa: E402


def _make_grant(subject_name="alice@example.com", subject_kind="User", scope="cluster", scope_namespace=None):
    return {
        "subject_kind": subject_kind,
        "subject_name": subject_name,
        "subject_namespace": None,
        "binding": f"test-binding-{subject_name}-{scope}",
        "binding_kind": "ClusterRoleBinding" if scope == "cluster" else "RoleBinding",
        "role": "view",
        "role_kind": "ClusterRole",
        "scope": scope,
        "scope_namespace": scope_namespace,
        "rules": [],
    }


def _make_user_entra(subject_name="alice@example.com", azure_roles=None):
    return {
        "subject_name": subject_name,
        "object_id": "oid-alice",
        "kind": "User",
        "display_name": subject_name,
        "azure_rbac_roles": [{"role": r} for r in (azure_roles or [])],
    }


def _make_group_entra(object_id="grp-oid-1", display_name="ops-team", azure_roles=None):
    return {
        "object_id": object_id,
        "display_name": display_name,
        "azure_rbac_roles": [{"role": r} for r in (azure_roles or [])],
        "orphaned": False,
    }


def _e8(grants, entra):
    findings, _, _ = run_checks(grants, entra=entra)
    return [f for f in findings if f["check"] == "E8"]


# --- User severity tests ---

def test_user_cluster_user_role_is_high():
    """User with Cluster User Role + K8s grant → HIGH."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=["Azure Kubernetes Service Cluster User Role"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_user_cluster_admin_role_is_critical():
    """User with Cluster Admin Role + K8s grant → CRITICAL."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=["Azure Kubernetes Service Cluster Admin Role"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_user_owner_role_is_critical():
    """User with Owner + K8s grant → CRITICAL."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=["Owner"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_user_user_access_administrator_is_critical():
    """User with User Access Administrator + K8s grant → CRITICAL."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=["User Access Administrator"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


# --- Group severity tests ---

def test_group_any_aks_role_is_critical():
    """Group with Cluster User Role + K8s grant → CRITICAL (groups always critical)."""
    grants = [_make_grant(subject_name="grp-oid-1", subject_kind="Group")]
    entra = {
        "users": [],
        "groups": [_make_group_entra(azure_roles=["Azure Kubernetes Service Cluster User Role"])],
    }
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


# --- Negative tests ---

def test_user_with_azure_role_but_no_k8s_grant():
    """User has AKS Azure role but no K8s grant → 0 E8 findings."""
    entra = {"users": [_make_user_entra(azure_roles=["Azure Kubernetes Service Cluster Admin Role"])], "groups": []}
    findings = _e8([], entra)
    assert len(findings) == 0


def test_user_with_k8s_grant_but_no_azure_role():
    """User has K8s grant but empty azure_rbac_roles → 0 E8 findings."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=[])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 0


def test_user_with_non_aks_azure_role():
    """User has Storage Blob Data Reader (non-AKS) + K8s grant → 0 E8 findings."""
    grants = [_make_grant()]
    entra = {"users": [_make_user_entra(azure_roles=["Storage Blob Data Reader"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 0


def test_aks_system_subject_skipped():
    """system:serviceaccount:kube-system subjects must be skipped."""
    subject = "system:serviceaccount:kube-system:coredns"
    grants = [_make_grant(subject_name=subject)]
    entra = {
        "users": [_make_user_entra(subject_name=subject, azure_roles=["Azure Kubernetes Service Cluster Admin Role"])],
        "groups": [],
    }
    findings = _e8(grants, entra)
    assert len(findings) == 0


# --- Best-grant selection ---

def test_cluster_scoped_grant_preferred_over_namespace():
    """When user has both cluster-scoped and namespace-scoped grants, cluster-scoped is reported."""
    ns_grant = _make_grant(scope="namespace", scope_namespace="staging")
    cluster_grant = _make_grant(scope="cluster")
    # Put namespace grant first to confirm preference logic, not list order
    grants = [ns_grant, cluster_grant]
    entra = {"users": [_make_user_entra(azure_roles=["Azure Kubernetes Service Cluster User Role"])], "groups": []}
    findings = _e8(grants, entra)
    assert len(findings) == 1
    assert findings[0]["grant"]["scope"] == "cluster"
