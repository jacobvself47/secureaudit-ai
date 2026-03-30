"""
check_unbound_roles.py

Scan all ClusterRoles for dangerous permissions regardless of whether they
are currently bound to any subject. Unbound dangerous roles are latent risk —
they can be exploited the moment someone creates a binding.

Usage:
    python check_unbound_roles.py
"""
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, format_rules, summarize_rules, is_aks_system

# ClusterRoles that are expected to be "dangerous" by design — skip them.
EXPECTED_DANGEROUS = {
    "cluster-admin", "admin", "edit",
    "system:aggregate-to-admin", "system:aggregate-to-edit",
}


def get_bound_role_names(rbac) -> set:
    bound = set()
    for b in rbac.list_cluster_role_binding().items:
        bound.add(b.role_ref.name)
    for b in rbac.list_role_binding_for_all_namespaces().items:
        bound.add(b.role_ref.name)
    return bound


def main():
    rbac = get_rbac_client()
    bound_names = get_bound_role_names(rbac)

    dangerous_unbound = []

    for role in rbac.list_cluster_role().items:
        name = role.metadata.name
        if name in bound_names:
            continue
        if name in EXPECTED_DANGEROUS:
            continue
        if is_aks_system(name) or name.startswith("system:"):
            continue

        rules = format_rules(role.rules)
        s = summarize_rules(rules)

        flags = []
        if s["effectively_cluster_admin"]:
            flags.append("EFFECTIVELY_CLUSTER_ADMIN")
        if s["has_escalation_verbs"]:
            flags.append(f"ESCALATION_VERBS:{','.join(s['escalation_verbs'])}")
        if s["has_wildcard_verbs"] or s["has_wildcard_resources"]:
            flags.append("WILDCARDS")
        if s["has_secrets_access"]:
            flags.append("SECRETS_ACCESS")

        if flags:
            dangerous_unbound.append({
                "name": name,
                "flags": flags,
                "rules": rules,
                "created": role.metadata.creation_timestamp.isoformat()
                if role.metadata.creation_timestamp else None,
            })

    print(json.dumps({
        "dangerous_unbound_roles": dangerous_unbound,
        "summary": {
            "count": len(dangerous_unbound),
            "finding": (
                f"{len(dangerous_unbound)} dangerous unbound ClusterRole(s) — "
                "can be exploited by creating a binding: " +
                ", ".join(r["name"] for r in dangerous_unbound)
            ) if dangerous_unbound else "OK — no dangerous unbound ClusterRoles found",
        },
    }, indent=2))


if __name__ == "__main__":
    main()
