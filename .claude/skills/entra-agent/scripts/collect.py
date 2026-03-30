"""
collect.py — Entra Agent: resolve RBAC principals against Entra ID.

Reads rbac-grants.json (produced by rbac-agent) to get the list of
subjects, then queries Entra ID for each and writes entra-context.json
conforming to contracts/entra-context.schema.json.

This agent has no Kubernetes API access — it reads only from the
rbac-grants.json artifact.

Usage:
    python collect.py [--grants rbac-grants.json] [--output entra-context.json]
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import is_aks_system, az, kubectl


# ---------------------------------------------------------------------------
# Read subjects from rbac-grants.json artifact
# ---------------------------------------------------------------------------

def get_subjects_from_grants(grants_path: str, errors: list) -> tuple[set, set, set]:
    """Read rbac-grants.json and return (user_subjects, group_ids, service_accounts)."""
    try:
        with open(grants_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        errors.append({"context": f"read {grants_path}", "error": "File not found — run rbac-agent first"})
        sys.exit(1)
    except json.JSONDecodeError as e:
        errors.append({"context": f"parse {grants_path}", "error": str(e)})
        sys.exit(1)

    user_subjects, group_ids, service_accounts = set(), set(), set()
    for g in data.get("grants", []):
        kind, name = g["subject_kind"], g["subject_name"]
        if is_aks_system(name):
            continue
        if kind == "User":
            user_subjects.add(name)
        elif kind == "Group":
            group_ids.add(name)
        elif kind == "ServiceAccount":
            ns = g.get("subject_namespace") or g.get("scope_namespace") or "default"
            service_accounts.add((name, ns))

    return user_subjects, group_ids, service_accounts


# ---------------------------------------------------------------------------
# User resolution
# ---------------------------------------------------------------------------

def resolve_user(subject_name: str, errors: list) -> dict:
    result = {"subject_name": subject_name}
    ok, data = az("ad", "user", "show", "--id", subject_name)
    if ok:
        object_id = data.get("id")
        azure_rbac = []
        if object_id:
            ok_rbac, assignments = az("role", "assignment", "list", "--assignee", object_id, "--all")
            if ok_rbac:
                azure_rbac = [{"role": a.get("roleDefinitionName"), "scope": a.get("scope"), "resource_group": a.get("resourceGroup")} for a in assignments]
        result.update({
            "kind": "User",
            "display_name": data.get("displayName"),
            "upn": data.get("userPrincipalName"),
            "object_id": object_id,
            "user_type": data.get("userType"),
            "account_enabled": data.get("accountEnabled"),
            "azure_rbac_roles": azure_rbac,
        })
        return result
    ok2, sp = az("ad", "sp", "show", "--id", subject_name)
    if ok2:
        app_id = sp.get("appId")
        object_id = sp.get("id")
        # E9: check for OIDC federation — absence means client-secret auth
        oidc_federation = []
        if app_id:
            ok_fc, fed_creds = az("ad", "app", "federated-credential", "list", "--id", app_id)
            if ok_fc:
                oidc_federation = fed_creds
        azure_rbac = []
        if object_id:
            ok_rbac, assignments = az("role", "assignment", "list", "--assignee", object_id, "--all")
            if ok_rbac:
                azure_rbac = [{"role": a.get("roleDefinitionName"), "scope": a.get("scope"), "resource_group": a.get("resourceGroup")} for a in assignments]
        result.update({
            "kind": "ServicePrincipal",
            "display_name": sp.get("displayName"),
            "app_id": app_id,
            "object_id": object_id,
            "oidc_federation": oidc_federation,
            "azure_rbac_roles": azure_rbac,
        })
        return result
    errors.append({"context": f"user/sp show {subject_name}", "error": data})
    result["error"] = "not found in Entra ID"
    return result


# ---------------------------------------------------------------------------
# Group resolution
# ---------------------------------------------------------------------------

def resolve_group(object_id: str, errors: list) -> dict:
    result = {"object_id": object_id, "display_name": None, "orphaned": False, "owners": [], "members": [], "sub_groups": [], "member_count": 0, "member_type_counts": {}}

    ok, data = az("ad", "group", "show", "--group", object_id)
    if not ok:
        result["orphaned"] = True
        errors.append({"context": f"group show {object_id}", "error": data})
        return result

    result["display_name"] = data.get("displayName")

    # E8: Azure RBAC roles assigned to this group
    azure_rbac = []
    ok_rbac, assignments = az("role", "assignment", "list", "--assignee", object_id, "--all")
    if ok_rbac:
        azure_rbac = [{"role": a.get("roleDefinitionName"), "scope": a.get("scope"), "resource_group": a.get("resourceGroup")} for a in assignments]
    result["azure_rbac_roles"] = azure_rbac

    ok2, owners = az("ad", "group", "owner", "list", "--group", object_id)
    result["owners"] = [{"display_name": o.get("displayName"), "upn": o.get("userPrincipalName"), "object_id": o.get("id")} for o in (owners if ok2 else [])]

    ok3, members = az("ad", "group", "member", "list", "--group", object_id)
    if not ok3:
        errors.append({"context": f"group member list {object_id}", "error": members})
        return result

    parsed, sub_groups = [], []
    for m in members:
        odata = m.get("@odata.type", "")
        kind = "User" if "user" in odata.lower() else "ServicePrincipal" if "serviceprincipal" in odata.lower() else "Group" if "group" in odata.lower() else "Unknown"
        member = {"kind": kind, "display_name": m.get("displayName"), "upn": m.get("userPrincipalName"), "object_id": m.get("id"), "app_id": m.get("appId")}
        if kind == "User":
            member["user_type"] = m.get("userType")
            member["account_enabled"] = m.get("accountEnabled")
        if kind == "Group":
            sub_groups.append({"object_id": m.get("id"), "display_name": m.get("displayName")})
        parsed.append(member)

    result["members"] = parsed
    result["member_count"] = len(parsed)
    result["sub_groups"] = sub_groups
    by_type: dict = {}
    for m in parsed:
        by_type[m["kind"]] = by_type.get(m["kind"], 0) + 1
    result["member_type_counts"] = by_type
    return result


# ---------------------------------------------------------------------------
# Workload identity resolution
# ---------------------------------------------------------------------------

def resolve_sa(sa_name: str, namespace: str, errors: list) -> dict | None:
    ns = namespace or "default"
    ok, data = kubectl("get", "serviceaccount", sa_name, "-n", ns)
    if not ok:
        errors.append({"context": f"get sa {ns}/{sa_name}", "error": data})
        return None

    annotations = (data.get("metadata") or {}).get("annotations") or {}
    client_id = annotations.get("azure.workload.identity/client-id")
    pod_identity = annotations.get("aadpodidbinding")

    if client_id:
        mi = resolve_mi(client_id, errors)
        return {"sa_name": sa_name, "namespace": ns, "binding_type": "workload-identity", "client_id": client_id, "tenant_id": annotations.get("azure.workload.identity/tenant-id"), "managed_identity": mi}
    if pod_identity:
        return {"sa_name": sa_name, "namespace": ns, "binding_type": "pod-identity-legacy", "pod_identity_binding": pod_identity, "managed_identity": {"status": "legacy-binding"}}
    return None


def resolve_mi(client_id: str, errors: list) -> dict:
    result = {"client_id": client_id, "status": "unresolved"}
    ok, identities = az("identity", "list")
    if not ok:
        errors.append({"context": f"identity list {client_id}", "error": identities})
        return result
    for identity in identities:
        if identity.get("clientId") == client_id:
            principal_id = identity.get("principalId")
            azure_rbac = []
            if principal_id:
                ok2, assignments = az("role", "assignment", "list", "--assignee", principal_id, "--all")
                if ok2:
                    azure_rbac = [{"role": a.get("roleDefinitionName"), "scope": a.get("scope"), "resource_group": a.get("resourceGroup")} for a in assignments]
            result.update({"status": "resolved", "name": identity.get("name"), "resource_group": identity.get("resourceGroup"), "subscription_id": (identity.get("id") or "").split("/")[2] if identity.get("id") else None, "principal_id": principal_id, "azure_rbac_roles": azure_rbac})
            return result
    result["error"] = f"No managed identity with clientId {client_id}"
    return result


# ---------------------------------------------------------------------------
# Multi-path
# ---------------------------------------------------------------------------

def build_multi_path(group_results: list) -> dict:
    user_groups: dict = defaultdict(list)
    for g in group_results:
        if g.get("orphaned"):
            continue
        for m in g.get("members", []):
            if m["kind"] == "User" and m.get("upn"):
                user_groups[m["upn"]].append({"group_id": g["object_id"], "group_name": g.get("display_name"), "display_name": m.get("display_name")})
    return {upn: paths for upn, paths in user_groups.items() if len(paths) > 1}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--grants", default="rbac-grants.json", help="Path to rbac-grants.json from rbac-agent")
    parser.add_argument("--output", default="entra-context.json")
    args = parser.parse_args()

    errors = []

    print(f"Reading subjects from {args.grants}...", file=sys.stderr)
    user_subjects, group_ids, service_accounts = get_subjects_from_grants(args.grants, errors)
    print(f"  {len(user_subjects)} users, {len(group_ids)} groups, {len(service_accounts)} SAs to resolve", file=sys.stderr)

    # Get cluster name from grants file for metadata
    try:
        with open(args.grants) as f:
            grants_meta = json.load(f).get("meta", {})
        cluster = grants_meta.get("cluster", "unknown")
    except Exception:
        cluster = "unknown"

    print(f"Resolving principals against Entra ID...", file=sys.stderr)
    user_results = [resolve_user(n, errors) for n in sorted(user_subjects)]
    group_results = [resolve_group(oid, errors) for oid in sorted(group_ids)]
    sa_results = [r for n, ns in sorted(service_accounts) if (r := resolve_sa(n, ns, errors)) is not None]
    multi_path = build_multi_path(group_results)

    ok, account = az("account", "show")

    output = {
        "meta": {"timestamp": datetime.now(timezone.utc).isoformat(), "cluster": cluster},
        "azure_context": account if ok else {"error": account},
        "summary": {
            "orphaned_groups": sum(1 for g in group_results if g.get("orphaned")),
            "guest_users_in_groups": sum(1 for g in group_results for m in g.get("members", []) if m.get("user_type") == "Guest"),
            "disabled_accounts_in_groups": sum(1 for g in group_results for m in g.get("members", []) if m.get("account_enabled") is False),
            "users_with_multi_path_access": len(multi_path),
            "workload_identity_bindings": len(sa_results),
            "unresolved_managed_identities": sum(1 for sa in sa_results if sa.get("managed_identity", {}).get("status") == "unresolved"),
        },
        "users": user_results,
        "groups": group_results,
        "workload_identities": sa_results,
        "multi_path_access": multi_path,
        "errors": errors,
    }

    dest = sys.stdout if args.output == "-" else open(args.output, "w")
    json.dump(output, dest, indent=2)
    if args.output != "-":
        dest.close()

    print(f"  Written to {args.output} ({len(errors)} errors)", file=sys.stderr)
    if output["summary"]["orphaned_groups"]:
        print(f"  WARNING: {output['summary']['orphaned_groups']} orphaned groups", file=sys.stderr)
    if output["summary"]["guest_users_in_groups"]:
        print(f"  WARNING: {output['summary']['guest_users_in_groups']} guest users in groups", file=sys.stderr)


if __name__ == "__main__":
    main()
