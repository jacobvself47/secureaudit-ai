"""
blast_radius.py

Compute the full human blast radius: distinct people with cluster access,
broken down by permission level. Reads K8s live + entra-context.json cache.
"""
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, load_entra_cache, find_entra_group, summarize_rules, is_aks_system


def main():
    entra = load_entra_cache()

    rbac = get_rbac_client()
    all_grants = iter_all_grants(rbac)

    direct_users = {}
    for g in all_grants:
        if g["subject_kind"] == "User" and not is_aks_system(g["subject_name"]):
            name = g["subject_name"]
            if name not in direct_users:
                direct_users[name] = {"subject_name": name, "display_name": None, "roles": []}
            direct_users[name]["roles"].append(g["role"])

    if entra:
        for u in entra.get("users", []):
            n = u.get("subject_name")
            if n in direct_users and u.get("display_name"):
                direct_users[n]["display_name"] = u["display_name"]
                direct_users[n]["user_type"] = u.get("user_type")
                direct_users[n]["account_enabled"] = u.get("account_enabled")

    group_entries = []
    all_members_by_upn = {}

    for g in all_grants:
        if g["subject_kind"] != "Group" or is_aks_system(g["subject_name"]):
            continue
        eg = find_entra_group(entra, g["subject_name"]) if entra else None
        entry = {
            "subject_name": g["subject_name"],
            "display_name": eg.get("display_name") if eg else None,
            "orphaned": eg.get("orphaned", False) if eg else (entra is not None),
            "member_count_resolved": eg.get("member_count", 0) if eg and not (eg.get("orphaned")) else 0,
            "member_count_unknown": 0 if (eg and not eg.get("orphaned")) else 1,
            "roles": [g["role"]],
        }
        group_entries.append(entry)

        if eg and not eg.get("orphaned"):
            for m in eg.get("members", []):
                if m["kind"] == "User" and m.get("upn"):
                    upn = m["upn"]
                    if upn not in all_members_by_upn:
                        all_members_by_upn[upn] = {"display_name": m.get("display_name"), "roles": [], "user_type": m.get("user_type"), "account_enabled": m.get("account_enabled")}
                    all_members_by_upn[upn]["roles"].append(g["role"])

    def subjects_with_role(role_name):
        out = []
        for name, info in direct_users.items():
            if role_name in info["roles"]:
                out.append({"kind": "User", "name": name, "display_name": info.get("display_name"), "via": "direct"})
        for upn, info in all_members_by_upn.items():
            if role_name in info["roles"]:
                out.append({"kind": "User", "name": upn, "display_name": info.get("display_name"), "via": "group membership"})
        return out

    def subjects_with_flag(flag_fn):
        out = []
        for name, info in direct_users.items():
            if flag_fn(info):
                out.append({"name": name, "display_name": info.get("display_name"), "via": "direct"})
        for upn, info in all_members_by_upn.items():
            if flag_fn(info):
                out.append({"name": upn, "display_name": info.get("display_name"), "via": "group membership"})
        return out

    impersonate_subjects = []
    for g in all_grants:
        if is_aks_system(g["subject_name"]):
            continue
        s = summarize_rules(g.get("rules", []))
        if "impersonate" in s["escalation_verbs"]:
            impersonate_subjects.append({"kind": g["subject_kind"], "name": g["subject_name"], "via": "direct"})

    resolved_human_count = len(set(list(direct_users.keys()) + list(all_members_by_upn.keys())))

    print(json.dumps({
        "entra_available": entra is not None,
        "direct_user_bindings": len(direct_users),
        "direct_users": list(direct_users.values()),
        "group_bindings": len(group_entries),
        "groups": group_entries,
        "resolved_human_count": resolved_human_count,
        "unresolved_human_count": sum(1 for e in group_entries if e["member_count_unknown"]),
        "permission_breakdown": {
            "cluster_admin": {
                "count": len(subjects_with_role("cluster-admin")),
                "subjects": subjects_with_role("cluster-admin"),
            },
            "impersonate": {
                "count": len(impersonate_subjects),
                "subjects": impersonate_subjects,
            },
        },
        "guest_users": subjects_with_flag(lambda u: u.get("user_type") == "Guest"),
        "disabled_accounts": subjects_with_flag(lambda u: u.get("account_enabled") is False),
        "note": None if entra else "entra-context.json not found — group member counts unknown. Run entra-agent for full blast radius.",
    }, indent=2))


if __name__ == "__main__":
    main()
