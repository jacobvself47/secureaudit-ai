"""
get_role.py <role_name> [--kind ClusterRole|Role] [--namespace <ns>] [--live]

Decode what a ClusterRole or Role actually grants: verbs, resources,
escalation verbs, secrets access, wildcards, and which subjects are bound to it.
Queries K8s live.
"""
import argparse
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, format_rules, summarize_rules, kubectl


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role_name")
    parser.add_argument("--kind", choices=["ClusterRole", "Role"], default="ClusterRole")
    parser.add_argument("--namespace")
    args = parser.parse_args()

    rbac = get_rbac_client()

    rules = []
    source = "live"
    try:
        if args.kind == "ClusterRole":
            role_obj = rbac.read_cluster_role(args.role_name)
        else:
            ns = args.namespace or "default"
            role_obj = rbac.read_namespaced_role(args.role_name, ns)
        rules = format_rules(role_obj.rules)
    except Exception as e:
        cmd_args = ["get", args.kind.lower(), args.role_name]
        if args.namespace:
            cmd_args += ["-n", args.namespace]
        ok, data = kubectl(*cmd_args)
        if ok:
            raw_rules = data.get("rules") or []
            rules = [
                {
                    "api_groups": r.get("apiGroups", []),
                    "resources": r.get("resources", []),
                    "verbs": r.get("verbs", []),
                    "resource_names": r.get("resourceNames", []),
                }
                for r in raw_rules
            ]
        else:
            print(json.dumps({"error": f"Role not found: {e}", "role_name": args.role_name}))
            sys.exit(1)

    analysis = summarize_rules(rules)

    all_grants = iter_all_grants(rbac)
    bound_to = [
        {
            "subject_kind": g["subject_kind"],
            "subject_name": g["subject_name"],
            "binding": g["binding"],
            "scope": g["scope"],
            "scope_namespace": g.get("scope_namespace"),
        }
        for g in all_grants
        if g["role"] == args.role_name and g["role_kind"] == args.kind
    ]

    print(json.dumps({
        "role_name": args.role_name,
        "role_kind": args.kind,
        "namespace": args.namespace,
        "source": source,
        "rules": rules,
        "analysis": analysis,
        "bound_to": bound_to,
        "bound_to_count": len(bound_to),
    }, indent=2))


if __name__ == "__main__":
    main()
