"""
get_workload_identity.py <sa_name> <namespace> [--live]

Trace the full Azure identity chain for a ServiceAccount:
annotations → managed identity → Azure RBAC roles.
Cache-first, --live forces fresh kubectl + az queries.
"""
import argparse
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, load_entra_cache, find_entra_wi, summarize_rules, az, kubectl, is_aks_system

BROAD_ROLES = {"Contributor", "Owner", "User Access Administrator"}


def resolve_mi_live(client_id: str) -> dict:
    result = {"client_id": client_id, "status": "unresolved"}
    ok, identities = az("identity", "list")
    if not ok:
        result["error"] = identities
        return result
    for identity in identities:
        if identity.get("clientId") == client_id:
            principal_id = identity.get("principalId")
            azure_rbac = []
            if principal_id:
                ok2, assignments = az("role", "assignment", "list", "--assignee", principal_id, "--all")
                if ok2:
                    azure_rbac = [
                        {
                            "role": a.get("roleDefinitionName"),
                            "scope": a.get("scope"),
                            "resource_group": a.get("resourceGroup"),
                            "is_broad": a.get("roleDefinitionName") in BROAD_ROLES,
                        }
                        for a in assignments
                    ]
            result.update({
                "status": "resolved",
                "name": identity.get("name"),
                "resource_group": identity.get("resourceGroup"),
                "principal_id": principal_id,
                "azure_rbac_roles": azure_rbac,
            })
            return result
    result["error"] = f"No managed identity with clientId {client_id}"
    return result


def get_sa_annotations_live(sa_name: str, namespace: str) -> tuple[dict, list]:
    ok, data = kubectl("get", "serviceaccount", sa_name, "-n", namespace)
    if not ok:
        return {}, [data]
    return (data.get("metadata") or {}).get("annotations") or {}, []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("sa_name")
    parser.add_argument("namespace")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--entra-file", default="entra-context.json")
    args = parser.parse_args()

    entra = load_entra_cache(args.entra_file)
    errors = []

    if not args.live and entra:
        cached_wi = find_entra_wi(entra, args.sa_name, args.namespace)
        if cached_wi:
            azure_identity = {
                "binding_type": cached_wi.get("binding_type"),
                "client_id": cached_wi.get("client_id"),
                "tenant_id": cached_wi.get("tenant_id"),
                "pod_identity_binding": cached_wi.get("pod_identity_binding"),
                "managed_identity": cached_wi.get("managed_identity", {}),
                "source": "cache",
            }
        else:
            annotations, errs = get_sa_annotations_live(args.sa_name, args.namespace)
            errors.extend(errs)
            client_id = annotations.get("azure.workload.identity/client-id")
            pod_identity = annotations.get("aadpodidbinding")
            if client_id:
                azure_identity = {
                    "binding_type": "workload-identity",
                    "client_id": client_id,
                    "tenant_id": annotations.get("azure.workload.identity/tenant-id"),
                    "managed_identity": resolve_mi_live(client_id),
                    "source": "live",
                }
            elif pod_identity:
                azure_identity = {
                    "binding_type": "pod-identity-legacy",
                    "pod_identity_binding": pod_identity,
                    "managed_identity": {"status": "legacy-binding", "note": "Migrate to Workload Identity"},
                    "source": "live",
                }
            else:
                azure_identity = {"binding_type": "none", "managed_identity": {"status": "none"}, "source": "live"}
    else:
        annotations, errs = get_sa_annotations_live(args.sa_name, args.namespace)
        errors.extend(errs)
        client_id = annotations.get("azure.workload.identity/client-id")
        pod_identity = annotations.get("aadpodidbinding")
        if client_id:
            azure_identity = {
                "binding_type": "workload-identity",
                "client_id": client_id,
                "tenant_id": annotations.get("azure.workload.identity/tenant-id"),
                "managed_identity": resolve_mi_live(client_id),
                "source": "live",
            }
        elif pod_identity:
            azure_identity = {
                "binding_type": "pod-identity-legacy",
                "pod_identity_binding": pod_identity,
                "managed_identity": {"status": "legacy-binding"},
                "source": "live",
            }
        else:
            azure_identity = {"binding_type": "none", "managed_identity": {"status": "none"}, "source": "live"}

    k8s_grants = []
    try:
        rbac = get_rbac_client()
        all_grants = iter_all_grants(rbac)
        for g in all_grants:
            if (g["subject_kind"] == "ServiceAccount"
                    and g["subject_name"] == args.sa_name
                    and not is_aks_system(args.sa_name)):
                k8s_grants.append({
                    "binding": g["binding"],
                    "role": g["role"],
                    "scope": g["scope"],
                    "scope_namespace": g.get("scope_namespace"),
                    "rules_summary": summarize_rules(g.get("rules", [])),
                })
    except Exception as e:
        errors.append(str(e))

    risk_flags = []
    mi = azure_identity.get("managed_identity", {})
    if azure_identity.get("binding_type") == "pod-identity-legacy":
        risk_flags.append("LEGACY_POD_IDENTITY")
    if mi.get("status") == "unresolved":
        risk_flags.append("UNRESOLVED_MI")
    if any(r.get("is_broad") for r in mi.get("azure_rbac_roles", [])):
        risk_flags.append("BROAD_AZURE_ROLE")
    if any(g["rules_summary"].get("has_escalation_verbs") for g in k8s_grants if "rules_summary" in g):
        risk_flags.append("ESCALATION_VERBS")

    print(json.dumps({
        "sa_name": args.sa_name,
        "namespace": args.namespace,
        "k8s_grants": k8s_grants,
        "azure_identity": azure_identity,
        "risk_flags": risk_flags,
        "errors": errors,
    }, indent=2))


if __name__ == "__main__":
    main()
