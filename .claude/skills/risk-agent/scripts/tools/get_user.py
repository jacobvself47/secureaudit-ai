"""
get_user.py <identifier> [--live]

Resolve a User subject: display name, guest/disabled status, all cluster
access paths (direct grants + group memberships). Cache-first, --live forces
fresh az CLI query.
"""
import argparse
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, load_entra_cache, find_entra_user, az, is_aks_system


def query_live(identifier: str) -> dict:
    result = {"identifier": identifier, "source": "live"}

    ok, data = az("ad", "user", "show", "--id", identifier)
    if ok:
        result.update({
            "kind": "User",
            "display_name": data.get("displayName"),
            "upn": data.get("userPrincipalName"),
            "object_id": data.get("id"),
            "user_type": data.get("userType"),
            "account_enabled": data.get("accountEnabled"),
        })
        flags = []
        if data.get("userType") == "Guest": flags.append("GUEST")
        if data.get("accountEnabled") is False: flags.append("DISABLED")
        result["flags"] = flags
        return result

    ok2, sp = az("ad", "sp", "show", "--id", identifier)
    if ok2:
        result.update({
            "kind": "ServicePrincipal",
            "display_name": sp.get("displayName"),
            "app_id": sp.get("appId"),
            "object_id": sp.get("id"),
            "flags": [],
        })
        return result

    result["kind"] = None
    result["error"] = "not found in Entra ID (may be AKS managed identity or cert-authn subject)"
    result["flags"] = []
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("identifier")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--entra-file", default="entra-context.json")
    args = parser.parse_args()

    entra = load_entra_cache(args.entra_file)

    if not args.live and entra:
        cached = find_entra_user(entra, args.identifier)
        if cached and not cached.get("error"):
            user_data = {**cached, "source": "cache", "identifier": args.identifier}
            flags = []
            if cached.get("user_type") == "Guest": flags.append("GUEST")
            if cached.get("account_enabled") is False: flags.append("DISABLED")
            user_data["flags"] = flags
        else:
            user_data = query_live(args.identifier)
    else:
        user_data = query_live(args.identifier)

    direct_grants = []
    group_memberships = []
    try:
        rbac = get_rbac_client()
        all_grants = iter_all_grants(rbac)

        for g in all_grants:
            if g["subject_kind"] == "User" and g["subject_name"] == args.identifier and not is_aks_system(args.identifier):
                direct_grants.append({"binding": g["binding"], "role": g["role"], "scope": g["scope"], "scope_namespace": g.get("scope_namespace")})

        if entra:
            upn = user_data.get("upn") or args.identifier
            for group in entra.get("groups", []):
                for member in group.get("members", []):
                    if member.get("upn") == upn or member.get("display_name") == upn:
                        group_grants = [
                            {"binding": g["binding"], "role": g["role"], "scope": g["scope"], "scope_namespace": g.get("scope_namespace")}
                            for g in all_grants
                            if g["subject_kind"] == "Group" and g["subject_name"] == group["object_id"] and not is_aks_system(group["object_id"])
                        ]
                        if group_grants:
                            group_memberships.append({
                                "group_id": group["object_id"],
                                "group_display_name": group.get("display_name"),
                                "grants_via_group": group_grants,
                            })
    except Exception as e:
        user_data["k8s_error"] = str(e)

    user_data["direct_grants"] = direct_grants
    user_data["group_memberships_with_cluster_access"] = group_memberships
    user_data.setdefault("errors", [])

    print(json.dumps(user_data, indent=2))


if __name__ == "__main__":
    main()
