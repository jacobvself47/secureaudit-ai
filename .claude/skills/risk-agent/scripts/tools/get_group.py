"""
get_group.py <group_id> [--live]

Resolve an AAD group: display name, owners, members with guest/disabled flags,
sub-groups, and which cluster grants it holds. Checks entra-context.json cache
first; --live forces a fresh az CLI query.
"""
import argparse
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, load_entra_cache, find_entra_group, az, is_aks_system


def query_live(group_id: str) -> dict:
    result = {"object_id": group_id, "source": "live", "orphaned": False}

    ok, data = az("ad", "group", "show", "--group", group_id)
    if not ok:
        result["orphaned"] = True
        result["error"] = data
        return result

    result["display_name"] = data.get("displayName")

    ok2, owners = az("ad", "group", "owner", "list", "--group", group_id)
    result["owners"] = [
        {"display_name": o.get("displayName"), "upn": o.get("userPrincipalName"), "object_id": o.get("id")}
        for o in (owners if ok2 else [])
    ]

    ok3, members = az("ad", "group", "member", "list", "--group", group_id)
    if not ok3:
        result["members"] = []
        result["errors"] = [members]
        return result

    parsed = []
    sub_groups = []
    for m in members:
        odata = m.get("@odata.type", "")
        kind = "User" if "user" in odata.lower() else "ServicePrincipal" if "serviceprincipal" in odata.lower() else "Group" if "group" in odata.lower() else "Unknown"
        member = {
            "kind": kind,
            "display_name": m.get("displayName"),
            "upn": m.get("userPrincipalName"),
            "object_id": m.get("id"),
            "app_id": m.get("appId"),
        }
        if kind == "User":
            member["user_type"] = m.get("userType")
            member["account_enabled"] = m.get("accountEnabled")
            flags = []
            if m.get("userType") == "Guest": flags.append("GUEST")
            if m.get("accountEnabled") is False: flags.append("DISABLED")
            member["flags"] = flags
        if kind == "Group":
            sub_groups.append({"object_id": m.get("id"), "display_name": m.get("displayName")})
        parsed.append(member)

    result["members"] = parsed
    result["member_count"] = len(parsed)
    result["sub_groups"] = sub_groups
    from collections import Counter
    result["member_type_counts"] = dict(Counter(m["kind"] for m in parsed))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("group_id")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--entra-file", default="entra-context.json")
    args = parser.parse_args()

    entra = load_entra_cache(args.entra_file)

    if not args.live and entra:
        cached = find_entra_group(entra, args.group_id)
        if cached:
            group_data = {**cached, "source": "cache"}
        else:
            group_data = query_live(args.group_id)
    else:
        group_data = query_live(args.group_id)

    grants_via = []
    try:
        rbac = get_rbac_client()
        all_grants = iter_all_grants(rbac)
        for g in all_grants:
            if g["subject_kind"] == "Group" and g["subject_name"] == args.group_id and not is_aks_system(args.group_id):
                grants_via.append({"binding": g["binding"], "role": g["role"], "scope": g["scope"], "scope_namespace": g.get("scope_namespace")})
    except Exception as e:
        grants_via = [{"error": str(e)}]

    multi_path = []
    if entra:
        mp = entra.get("multi_path_access", {})
        for upn, paths in mp.items():
            group_ids = [p.get("group_id") for p in paths]
            if args.group_id in group_ids:
                other = [p.get("group_name") or p.get("group_id") for p in paths if p.get("group_id") != args.group_id]
                multi_path.append({"upn": upn, "display_name": paths[0].get("display_name"), "also_in_groups": other})

    group_data["grants_via_this_group"] = grants_via
    group_data["member_multi_path"] = multi_path
    group_data.setdefault("errors", [])

    print(json.dumps(group_data, indent=2))


if __name__ == "__main__":
    main()
