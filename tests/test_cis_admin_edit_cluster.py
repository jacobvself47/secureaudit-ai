"""
Tests for admin/edit ClusterRoleBinding → CRITICAL finding check (Gap 2).

Verifies that built-in 'admin' and 'edit' roles bound cluster-wide via
ClusterRoleBinding produce a CRITICAL CIS-5.1.1 finding, while the same
roles bound namespace-scoped via RoleBinding produce no such finding.
"""
import sys
import os

_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "risk-agent", "scripts")
_SHARED = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "shared")
sys.path.insert(0, os.path.normpath(_SCRIPTS))
sys.path.insert(0, os.path.normpath(_SHARED))

from analyze import run_checks  # noqa: E402


def _make_grant(role, scope, binding_kind, subject_name="test-user", scope_namespace=None):
    return {
        "subject_kind": "User",
        "subject_name": subject_name,
        "subject_namespace": None,
        "binding": f"test-binding-{role}-{scope}",
        "binding_kind": binding_kind,
        "role": role,
        "role_kind": "ClusterRole",
        "scope": scope,
        "scope_namespace": scope_namespace,
        "rules": [],
    }


def _511_findings(grants):
    findings, _, _ = run_checks(grants, entra=None)
    return [f for f in findings if f["check"] == "CIS-5.1.1"]


def test_admin_clusterrolebinding_is_critical():
    """'admin' bound cluster-wide must produce a CRITICAL CIS-5.1.1 finding."""
    grant = _make_grant("admin", "cluster", "ClusterRoleBinding")
    findings = _511_findings([grant])
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_edit_clusterrolebinding_is_critical():
    """'edit' bound cluster-wide must produce a CRITICAL CIS-5.1.1 finding."""
    grant = _make_grant("edit", "cluster", "ClusterRoleBinding")
    findings = _511_findings([grant])
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


def test_admin_rolebinding_namespace_no_finding():
    """'admin' bound namespace-scoped via RoleBinding must NOT produce a CIS-5.1.1 finding."""
    grant = _make_grant("admin", "namespace", "RoleBinding", scope_namespace="staging")
    assert len(_511_findings([grant])) == 0


def test_edit_rolebinding_namespace_no_finding():
    """'edit' bound namespace-scoped via RoleBinding must NOT produce a CIS-5.1.1 finding."""
    grant = _make_grant("edit", "namespace", "RoleBinding", scope_namespace="staging")
    assert len(_511_findings([grant])) == 0


def test_admin_finding_structure_no_extra_fields():
    """Finding for admin ClusterRoleBinding must contain all standard fields and no extras."""
    grant = _make_grant("admin", "cluster", "ClusterRoleBinding")
    findings = _511_findings([grant])
    assert len(findings) == 1
    f = findings[0]
    expected_fields = {
        "id", "check", "severity", "severity_source", "title",
        "subject", "grant", "matched_rules", "aks_infra",
        "entra_context", "needs_investigation", "investigation_reasons",
        "suggested_tool",
    }
    assert set(f.keys()) == expected_fields


def test_cluster_admin_still_fires_independently():
    """cluster-admin check must still fire even when admin/edit check exists."""
    grant = _make_grant("cluster-admin", "cluster", "ClusterRoleBinding")
    findings = _511_findings([grant])
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
