"""
Tests for CIS-5.1.4 — pods/exec and pods/log subresource detection (Gap 1).

Verifies that the resource match `any(r == "pods" or r.startswith("pods/") for r in resources)`
fires correctly for pod subresource notation, and that summarize_rules() sets
has_pod_create for subresource entries.
"""
import sys
import os

_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "risk-agent", "scripts")
_SHARED = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills", "shared")
sys.path.insert(0, os.path.normpath(_SCRIPTS))
sys.path.insert(0, os.path.normpath(_SHARED))

from analyze import run_checks  # noqa: E402
from lib.grants import summarize_rules  # noqa: E402


def _make_grant(role, scope, binding_kind, resources, verbs, subject_name="test-user",
                scope_namespace=None):
    return {
        "subject_kind": "User",
        "subject_name": subject_name,
        "subject_namespace": None,
        "binding": f"test-binding-{role}",
        "binding_kind": binding_kind,
        "role": role,
        "role_kind": "ClusterRole",
        "scope": scope,
        "scope_namespace": scope_namespace,
        "rules": [
            {
                "api_groups": [""],
                "resources": resources,
                "verbs": verbs,
                "resource_names": [],
            }
        ],
    }


def _514_findings(grants):
    findings, _, _ = run_checks(grants, entra=None)
    return [f for f in findings if f["check"] == "CIS-5.1.4"]


# --- summarize_rules() unit tests ---

def test_summarize_pods_sets_has_pod_create():
    rules = [{"verbs": ["create"], "resources": ["pods"], "api_groups": [], "resource_names": []}]
    assert summarize_rules(rules)["has_pod_create"] is True


def test_summarize_pods_exec_sets_has_pod_create():
    rules = [{"verbs": ["create"], "resources": ["pods/exec"], "api_groups": [], "resource_names": []}]
    assert summarize_rules(rules)["has_pod_create"] is True


def test_summarize_pods_log_sets_has_pod_create():
    rules = [{"verbs": ["create"], "resources": ["pods/log"], "api_groups": [], "resource_names": []}]
    assert summarize_rules(rules)["has_pod_create"] is True


def test_summarize_deployments_no_pod_create():
    rules = [{"verbs": ["create"], "resources": ["deployments"], "api_groups": [], "resource_names": []}]
    assert summarize_rules(rules)["has_pod_create"] is False


# --- run_checks() integration tests ---

def test_pods_exact_triggers_514():
    """'pods' resource with create verb must trigger CIS-5.1.4 (regression guard)."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["pods"], ["create"])
    assert len(_514_findings([grant])) == 1


def test_pods_exec_triggers_514():
    """'pods/exec' with create verb must trigger CIS-5.1.4."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["pods/exec"], ["create"])
    assert len(_514_findings([grant])) == 1


def test_pods_log_triggers_514():
    """'pods/log' with create verb must trigger CIS-5.1.4."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["pods/log"], ["create"])
    assert len(_514_findings([grant])) == 1


def test_pods_exec_wildcard_verb_triggers_514():
    """'pods/exec' with wildcard verb must trigger CIS-5.1.4."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["pods/exec"], ["*"])
    assert len(_514_findings([grant])) == 1


def test_unrelated_resource_no_514():
    """A grant with no pod resource must not produce a CIS-5.1.4 finding."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["deployments"], ["create"])
    assert len(_514_findings([grant])) == 0


def test_pods_exec_get_verb_no_514():
    """'pods/exec' with only get/list verbs must not trigger CIS-5.1.4 (no create)."""
    grant = _make_grant("custom-role", "namespace", "RoleBinding", ["pods/exec"], ["get", "list"])
    assert len(_514_findings([grant])) == 0


def test_cluster_admin_excluded_from_514():
    """cluster-admin is caught by CIS-5.1.1 and must not additionally emit CIS-5.1.4."""
    grant = _make_grant("cluster-admin", "cluster", "ClusterRoleBinding", ["pods", "pods/exec"], ["*"])
    assert len(_514_findings([grant])) == 0
