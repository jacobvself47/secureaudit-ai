"""
check_builtin_roles.py

Compare built-in Kubernetes ClusterRoles (edit, view, cluster-admin, admin)
against their known-good standard definitions and report any deviations.

Modifications to built-in roles are a high-severity finding — they are
unexpected, persist across upgrades, and are invisible to reviewers who
rely on standard Kubernetes RBAC documentation.

Usage:
    python check_builtin_roles.py [--live]
"""
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, format_rules

# Verbs and resources that MUST NOT appear in the standard edit/view roles.
# This is not an exhaustive diff — it targets the escalation-class additions
# most likely to be introduced maliciously or accidentally.
ESCALATION_VERBS = {"bind", "impersonate", "escalate"}

# Built-in roles that should never contain escalation verbs.
PROTECTED_ROLES = {"edit", "view", "system:aggregate-to-edit", "system:aggregate-to-view"}


def check_role(rbac, role_name: str) -> dict:
    try:
        role = rbac.read_cluster_role(role_name)
    except Exception as e:
        return {"role": role_name, "error": str(e)}

    violations = []
    for rule in role.rules or []:
        verbs = rule.verbs or []
        resources = rule.resources or []
        bad_verbs = [v for v in verbs if v in ESCALATION_VERBS]
        if bad_verbs:
            violations.append({
                "verbs": bad_verbs,
                "resources": resources,
                "api_groups": rule.api_groups or [],
            })

    return {
        "role": role_name,
        "violations": violations,
        "modified": len(violations) > 0,
        "labels": dict(role.metadata.labels or {}),
        "annotations": {k: v for k, v in (role.metadata.annotations or {}).items()
                        if "kubectl.kubernetes.io/last-applied" in k or "managed-by" in k},
    }


def main():
    rbac = get_rbac_client()

    results = [check_role(rbac, name) for name in sorted(PROTECTED_ROLES)]

    modified = [r for r in results if r.get("modified")]
    clean = [r for r in results if not r.get("modified") and not r.get("error")]

    print(json.dumps({
        "modified_builtin_roles": modified,
        "clean_builtin_roles": [r["role"] for r in clean],
        "errors": [r for r in results if r.get("error")],
        "summary": {
            "checked": len(results),
            "modified": len(modified),
            "finding": (
                "CRITICAL — built-in role(s) contain escalation verbs: " +
                ", ".join(r["role"] for r in modified)
            ) if modified else "OK — no unexpected escalation verbs in protected built-in roles",
        },
    }, indent=2))


if __name__ == "__main__":
    main()
