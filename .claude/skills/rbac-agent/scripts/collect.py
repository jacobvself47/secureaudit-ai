"""
collect.py — RBAC Agent: enumerate all Kubernetes RBAC grants.

Queries the cluster live via the Kubernetes Python client and writes
rbac-grants.json conforming to contracts/rbac-grants.schema.json.

This is the only agent with kubectl/K8s client access. All downstream
agents (entra-agent, risk-agent) read from the artifact it produces.

Usage:
    python collect.py [--output rbac-grants.json]
"""
import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, get_cluster_name, iter_all_grants

from kubernetes import config as kconfig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="rbac-grants.json")
    args = parser.parse_args()

    print("Connecting to Kubernetes cluster...", file=sys.stderr)
    try:
        kconfig.load_kube_config()
        contexts, active = kconfig.list_kube_config_contexts()
        context_name = active.get("name", "unknown") if active else "unknown"
        rbac = get_rbac_client()
        cluster = get_cluster_name()
    except Exception as e:
        print(f"Error connecting to cluster: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  Context: {context_name}, cluster: {cluster}", file=sys.stderr)
    print("Enumerating RBAC grants...", file=sys.stderr)

    grants = iter_all_grants(rbac)
    print(f"  {len(grants)} grants", file=sys.stderr)

    subject_counts = dict(Counter(g["subject_kind"] for g in grants))
    namespaces = sorted({g["scope_namespace"] for g in grants if g.get("scope_namespace")})

    for kind, count in subject_counts.items():
        print(f"    {kind}: {count}", file=sys.stderr)
    print(f"    Namespaces with bindings: {len(namespaces)}", file=sys.stderr)

    output = {
        "meta": {
            "cluster": cluster,
            "context": context_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "grant_count": len(grants),
            "subject_counts": subject_counts,
            "namespace_count": len(namespaces),
            "namespaces": namespaces,
        },
        "grants": grants,
    }

    dest = sys.stdout if args.output == "-" else open(args.output, "w")
    json.dump(output, dest, indent=2)
    if args.output != "-":
        dest.close()
        print(f"  Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
