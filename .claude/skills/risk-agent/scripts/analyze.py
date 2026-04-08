"""
analyze.py — Risk Agent: deterministic CIS + Entra detection engine.

Reads rbac-grants.json (from rbac-agent) and optionally entra-context.json
(from entra-agent), runs all CIS 5.1.x and E1–E7 checks, and writes
audit-findings.json conforming to contracts/audit-findings.schema.json.

This agent does not query Kubernetes or Entra ID live — it reads only from
the artifacts produced by rbac-agent and entra-agent.

Usage:
    python analyze.py [--grants rbac-grants.json] [--entra-file entra-context.json] [--output audit-findings.json]
"""
import argparse
import hashlib
import json
import sys
import os
from datetime import datetime, timezone

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import (
    is_aks_system, looks_like_cicd, summarize_rules,
    load_entra_cache, find_entra_group, find_entra_user, find_entra_wi,
    CICD_PATTERNS,
)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def finding_id(check: str, subject_kind: str, subject_name: str,
               binding: str, scope_namespace: str | None) -> str:
    key = f"{check}:{subject_kind}:{subject_name}:{binding}:{scope_namespace}"
    return f"{check}-{hashlib.md5(key.encode()).hexdigest()[:6].upper()}"


def make_finding(check, severity, title, grant, matched_rules,
                 entra_context=None, escalation_note=None,
                 needs_investigation=False, investigation_reasons=None,
                 suggested_tool=None, aks_infra=False):
    return {
        "id": finding_id(check, grant["subject_kind"], grant["subject_name"],
                         grant["binding"], grant.get("scope_namespace")),
        "check": check,
        "severity": severity,
        "severity_source": escalation_note or f"base {severity}",
        "title": title,
        "subject": {
            "kind": grant["subject_kind"],
            "name": grant["subject_name"],
            "namespace": grant.get("subject_namespace"),
        },
        "grant": {
            "binding": grant["binding"],
            "binding_kind": grant["binding_kind"],
            "role": grant["role"],
            "role_kind": grant["role_kind"],
            "scope": grant["scope"],
            "scope_namespace": grant.get("scope_namespace"),
        },
        "matched_rules": matched_rules,
        "aks_infra": aks_infra,
        "entra_context": entra_context or {"available": False},
        "needs_investigation": needs_investigation,
        "investigation_reasons": investigation_reasons or [],
        "suggested_tool": suggested_tool,
    }


def build_entra_context_for_group(name, entra):
    if entra is None:
        return None
    g = find_entra_group(entra, name)
    if g is None:
        return {
            "available": True,
            "for_group": None,
            "missing": True,
        }
    return {
        "available": True,
        "for_group": {
            "display_name": g.get("display_name"),
            "orphaned": g.get("orphaned", False),
            "owners": g.get("owners", []),
            "member_count": g.get("member_count", 0),
            "member_type_counts": g.get("member_type_counts", {}),
            "members": g.get("members", []),
            "sub_groups": g.get("sub_groups", []),
        }
    }


def build_entra_context_for_user(name, entra, multi_path_map=None):
    if entra is None:
        return None
    u = find_entra_user(entra, name)
    multi = []
    if multi_path_map:
        for path in multi_path_map.get(name, []):
            multi.append(path.get("group_name") or path.get("group_id"))
    ctx = {"available": True}
    if u:
        ctx["for_user"] = {
            "display_name": u.get("display_name"),
            "upn": u.get("upn"),
            "user_type": u.get("user_type"),
            "account_enabled": u.get("account_enabled"),
            "multi_path_groups": multi,
        }
    else:
        ctx["for_user"] = None
        ctx["not_found"] = True
    return ctx


def build_entra_context_for_sa(name, ns, entra):
    if entra is None:
        return None
    wi = find_entra_wi(entra, name, ns or "default")
    ctx = {"available": True}
    if wi:
        mi = wi.get("managed_identity", {})
        ctx["for_service_account"] = {
            "binding_type": wi.get("binding_type"),
            "client_id": wi.get("client_id"),
            "managed_identity_status": mi.get("status"),
            "managed_identity_name": mi.get("name"),
            "resource_group": mi.get("resource_group"),
            "azure_rbac_roles": mi.get("azure_rbac_roles", []),
        }
    else:
        ctx["for_service_account"] = {
            "binding_type": "none",
            "managed_identity_status": "none",
        }
    return ctx


def needs_investigation_for(grant, entra, reason_list):
    """Populate reason_list and return (needs_investigation, suggested_tool)."""
    kind = grant["subject_kind"]
    name = grant["subject_name"]
    ns = grant.get("subject_namespace") or grant.get("scope_namespace") or "default"

    if entra is None:
        if kind == "Group":
            reason_list.append(f"Group subject — membership unknown (no entra-context.json)")
            return True, f"get_group.py {name}"
        if kind == "User":
            reason_list.append(f"User subject — identity unknown (no entra-context.json)")
            return True, f"get_user.py {name}"

    if kind == "Group":
        g = find_entra_group(entra, name) if entra else None
        if g is None:
            reason_list.append(f"Group {name} not in entra-context.json — may be orphaned or newly added")
            return True, f"get_group.py {name}"
        if g.get("orphaned"):
            reason_list.append(f"Group {name} is ORPHANED (deleted from Entra ID)")
            return True, f"get_group.py {name}"

    if kind == "User":
        u = find_entra_user(entra, name) if entra else None
        if u is None or u.get("error"):
            reason_list.append(f"User {name} not found in Entra ID — may be AKS managed identity or stale binding")
            return True, f"get_user.py {name}"
        if u.get("user_type") == "Guest":
            reason_list.append(f"User {name} is a GUEST account")
            return True, f"get_user.py {name}"
        if u.get("account_enabled") is False:
            reason_list.append(f"User {name} account is DISABLED")
            return True, f"get_user.py {name}"

    if kind == "ServiceAccount":
        wi = find_entra_wi(entra, name, ns) if entra else None
        if wi and wi.get("managed_identity", {}).get("status") == "unresolved":
            reason_list.append(f"Managed identity unresolved for {ns}/{name}")
            return True, f"get_workload_identity.py {name} {ns}"

    return False, None


# Standard Kubernetes built-in roles that should never contain escalation verbs.
# If resolved rules for these roles include escalation verbs, the role has been tampered with.
_PROTECTED_BUILTIN_ROLES = {"edit", "view"}
_ESCALATION_VERBS = {"bind", "impersonate", "escalate"}


def _check_builtin_role_tampering(grants: list) -> list:
    """
    Detect modifications to built-in ClusterRoles by inspecting resolved rules
    in the grants artifact. Fires once per tampered role, not per binding.
    """
    findings = []
    seen_roles = set()

    for g in grants:
        role = g["role"]
        if role not in _PROTECTED_BUILTIN_ROLES or role in seen_roles:
            continue
        rules = g.get("rules", [])
        tampered_rules = [
            r for r in rules
            if set(r.get("verbs", [])) & _ESCALATION_VERBS
        ]
        if not tampered_rules:
            continue
        seen_roles.add(role)
        verbs_found = sorted({v for r in tampered_rules for v in r.get("verbs", []) if v in _ESCALATION_VERBS})
        # Synthesise a representative grant for the finding (use the first matching one)
        findings.append(make_finding(
            "CIS-5.1.3",
            "CRITICAL",
            f"Built-in '{role}' ClusterRole has been modified to include escalation verbs: {verbs_found}",
            g,
            tampered_rules,
            escalation_note=(
                f"CRITICAL: standard '{role}' ClusterRole should never contain {verbs_found}. "
                "Modification is likely via an aggregation ClusterRole — check roles with "
                f"label 'rbac.authorization.k8s.io/aggregate-to-{role}: true'."
            ),
            needs_investigation=True,
            investigation_reasons=[
                f"Built-in '{role}' role contains {verbs_found} — not present in upstream Kubernetes definition. "
                "This affects every subject currently bound to this role."
            ],
            suggested_tool="check_builtin_roles.py",
            aks_infra=False,
        ))

    return findings


def run_checks(grants: list, entra: dict | None) -> list:
    findings = []
    multi_path = (entra or {}).get("multi_path_access", {})

    # Built-in role tampering — check once before per-grant loop
    findings.extend(_check_builtin_role_tampering(grants))

    for g in grants:
        name = g["subject_name"]
        kind = g["subject_kind"]
        ns = g.get("subject_namespace") or g.get("scope_namespace") or "default"
        role = g["role"]
        rules = g.get("rules", [])
        summary = summarize_rules(rules)
        sys_flag = is_aks_system(name)
        scope = g.get("scope", "cluster")

        reasons = []

        # --- CIS 5.1.1: cluster-admin ---
        if role == "cluster-admin":
            sev = "CRITICAL"
            note = "base CRITICAL"
            if kind == "ServiceAccount":
                note += "; ServiceAccount with cluster-admin is extreme over-grant"
            needs, tool = needs_investigation_for(g, entra, reasons)
            findings.append(make_finding(
                "CIS-5.1.1", sev,
                f"cluster-admin bound to {kind}/{name}",
                g, [{"role": "cluster-admin", "note": "full cluster access"}],
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.1 (admin/edit cluster-wide): near-cluster-admin via built-in roles ---
        # admin and edit bound via ClusterRoleBinding grant near-unrestricted namespace access
        # across every namespace — effectively cluster-admin without wildcards in rules.
        if role in ("admin", "edit") and scope == "cluster":
            sev = "CRITICAL"
            note = f"base CRITICAL: built-in '{role}' ClusterRoleBinding = near-unrestricted cluster access"
            if kind == "Group":
                note += "; Group subject multiplies blast radius"
            reasons_ae = []
            needs, tool = needs_investigation_for(g, entra, reasons_ae)
            findings.append(make_finding(
                "CIS-5.1.1", sev,
                f"Built-in '{role}' role bound cluster-wide — {kind}/{name}",
                g, rules,
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons_ae,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.2: unscoped secrets access ---
        secrets_rules = [
            r for r in rules
            if ("secrets" in r.get("resources", []) or "*" in r.get("resources", []))
            and (set(r.get("verbs", [])) & {"get", "list", "watch", "*"})
            and not r.get("resource_names")
        ]
        if secrets_rules and role != "cluster-admin":
            sev = "HIGH"
            note = "base HIGH"
            if scope == "cluster":
                sev = "CRITICAL" if kind in ("Group", "ServiceAccount") else "HIGH"
                note += "; cluster-scoped"
            reasons2 = []
            needs, tool = needs_investigation_for(g, entra, reasons2)
            findings.append(make_finding(
                "CIS-5.1.2", sev,
                f"Unscoped cluster-wide secrets access — {kind}/{name}",
                g, secrets_rules,
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons2,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.3: wildcards ---
        wildcard_rules = [
            r for r in rules
            if "*" in r.get("verbs", []) or "*" in r.get("resources", []) or "*" in r.get("api_groups", [])
        ]
        if wildcard_rules and role != "cluster-admin":
            sev = "HIGH"
            note = "base HIGH"
            if summary["effectively_cluster_admin"]:
                sev = "CRITICAL"
                note = "escalated to CRITICAL: wildcard verbs + resources = effective cluster-admin"
            reasons3 = []
            needs, tool = needs_investigation_for(g, entra, reasons3)
            findings.append(make_finding(
                "CIS-5.1.3", sev,
                f"Wildcard permissions — {kind}/{name}",
                g, wildcard_rules,
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons3,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.4: pod create (includes pods/exec and other subresources) ---
        pod_rules = [
            r for r in rules
            if any(res == "pods" or res == "*" or res.startswith("pods/") for res in r.get("resources", []))
            and ("create" in r.get("verbs", []) or "*" in r.get("verbs", []))
        ]
        if pod_rules and role != "cluster-admin":
            sev = "HIGH"
            note = "base HIGH"
            if summary["has_secrets_access"] or summary["has_escalation_verbs"]:
                sev = "CRITICAL"
                note = "escalated to CRITICAL: pod create + secrets/escalation = full escalation chain"
            reasons4 = []
            needs, tool = needs_investigation_for(g, entra, reasons4)
            findings.append(make_finding(
                "CIS-5.1.4", sev,
                f"Pod creation rights — {kind}/{name}",
                g, pod_rules,
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons4,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.5: default SA with grants ---
        if kind == "ServiceAccount" and name == "default" and rules:
            findings.append(make_finding(
                "CIS-5.1.5", "MEDIUM",
                f"default ServiceAccount has active grants in {g.get('scope_namespace', 'cluster')}",
                g, rules,
                entra_context=build_entra_context_for_sa(name, ns, entra),
                aks_infra=sys_flag,
            ))

        # --- CIS 5.1.7: system:masters ---
        if kind == "Group" and name == "system:masters":
            findings.append(make_finding(
                "CIS-5.1.7", "CRITICAL",
                "system:masters group binding — bypasses RBAC entirely",
                g, [],
                aks_infra=True,
            ))

        # --- CIS 5.1.8: escalation verbs ---
        esc_rules = [
            r for r in rules
            if set(r.get("verbs", [])) & {"bind", "impersonate", "escalate"}
        ]
        if esc_rules:
            present = set()
            for r in esc_rules:
                present |= set(r.get("verbs", [])) & {"bind", "impersonate", "escalate"}
            sev = "CRITICAL"
            note = f"escalation verbs present: {sorted(present)}"
            reasons5 = []
            needs, tool = needs_investigation_for(g, entra, reasons5)
            findings.append(make_finding(
                "CIS-5.1.8", sev,
                f"Escalation verbs ({', '.join(sorted(present))}) — {kind}/{name}",
                g, esc_rules,
                entra_context=(
                    build_entra_context_for_group(name, entra) if kind == "Group" else
                    build_entra_context_for_user(name, entra, multi_path) if kind == "User" else
                    build_entra_context_for_sa(name, ns, entra)
                ),
                escalation_note=note,
                needs_investigation=needs,
                investigation_reasons=reasons5,
                suggested_tool=tool,
                aks_infra=sys_flag,
            ))

    # --- Entra-specific checks (require entra cache) ---
    if entra:
        # E1: Orphaned group bindings
        for g in grants:
            if g["subject_kind"] != "Group" or is_aks_system(g["subject_name"]):
                continue
            eg = find_entra_group(entra, g["subject_name"])
            if eg and eg.get("orphaned"):
                findings.append(make_finding(
                    "E1", "CRITICAL",
                    f"Orphaned RBAC binding — group {g['subject_name']} deleted from Entra ID",
                    g, [],
                    entra_context={"available": True, "for_group": eg},
                    needs_investigation=True,
                    investigation_reasons=["Group no longer exists in Entra ID — binding is inert but unauditable"],
                    suggested_tool=f"get_group.py {g['subject_name']}",
                ))

        # E2: Guest users with cluster access
        for u in entra.get("users", []):
            if u.get("user_type") == "Guest" and not u.get("error"):
                for g in grants:
                    if g["subject_name"] == u["subject_name"] and not is_aks_system(g["subject_name"]):
                        sev = "CRITICAL" if g["role"] in ("cluster-admin",) or summarize_rules(g.get("rules", []))["has_escalation_verbs"] else "HIGH"
                        findings.append(make_finding(
                            "E2", sev,
                            f"Guest user with cluster access — {u['subject_name']}",
                            g, [],
                            entra_context={"available": True, "for_user": u},
                            needs_investigation=True,
                            investigation_reasons=["Guest (external) account has persistent cluster access"],
                            suggested_tool=f"get_user.py {u['subject_name']}",
                        ))
                        break

        # E3: Disabled accounts with active grants
        for u in entra.get("users", []):
            if u.get("account_enabled") is False and not u.get("error"):
                for g in grants:
                    if g["subject_name"] == u["subject_name"] and not is_aks_system(g["subject_name"]):
                        findings.append(make_finding(
                            "E3", "HIGH",
                            f"Disabled account with active grant — {u['subject_name']}",
                            g, [],
                            entra_context={"available": True, "for_user": u},
                            needs_investigation=True,
                            investigation_reasons=["Account is disabled but RBAC binding persists"],
                            suggested_tool=f"get_user.py {u['subject_name']}",
                        ))
                        break

        # E4: Unresolved workload identity
        for wi in entra.get("workload_identities", []):
            mi = wi.get("managed_identity", {})
            if mi.get("status") == "unresolved":
                for g in grants:
                    if (g["subject_kind"] == "ServiceAccount"
                            and g["subject_name"] == wi["sa_name"]
                            and (g.get("subject_namespace") or g.get("scope_namespace")) == wi["namespace"]):
                        sev = "CRITICAL" if g["role"] == "cluster-admin" or summarize_rules(g.get("rules", []))["has_escalation_verbs"] else "HIGH"
                        findings.append(make_finding(
                            "E4", sev,
                            f"Unresolved workload identity — {wi['namespace']}/{wi['sa_name']}",
                            g, [],
                            entra_context={"available": True, "for_service_account": {"binding_type": wi.get("binding_type"), "managed_identity_status": "unresolved", "client_id": wi.get("client_id")}},
                            needs_investigation=True,
                            investigation_reasons=[f"client_id {wi.get('client_id')} not found in Azure — identity chain is broken"],
                            suggested_tool=f"get_workload_identity.py {wi['sa_name']} {wi['namespace']}",
                        ))
                        break

        # E5: CI/CD SA over-privilege
        seen_e5 = set()
        for g in grants:
            if g["subject_kind"] != "ServiceAccount" or is_aks_system(g["subject_name"]):
                continue
            if not looks_like_cicd(g["subject_name"]):
                continue
            s = summarize_rules(g.get("rules", []))
            key = g["subject_name"]
            if key in seen_e5:
                continue
            if g["role"] == "cluster-admin" or s["effectively_cluster_admin"]:
                seen_e5.add(key)
                findings.append(make_finding(
                    "E5", "CRITICAL",
                    f"CI/CD ServiceAccount with cluster-admin — {g['subject_name']}",
                    g, g.get("rules", []),
                    entra_context=build_entra_context_for_sa(g["subject_name"], g.get("subject_namespace") or g.get("scope_namespace") or "default", entra),
                    needs_investigation=True,
                    investigation_reasons=["CI/CD SA with cluster-admin is a high-value supply chain target"],
                    suggested_tool=f"get_workload_identity.py {g['subject_name']} {g.get('subject_namespace') or 'default'}",
                ))
            elif s["has_escalation_verbs"] or s["has_wildcard_verbs"]:
                seen_e5.add(key)
                findings.append(make_finding(
                    "E5", "HIGH",
                    f"CI/CD ServiceAccount with over-broad permissions — {g['subject_name']}",
                    g, g.get("rules", []),
                    entra_context=build_entra_context_for_sa(g["subject_name"], g.get("subject_namespace") or g.get("scope_namespace") or "default", entra),
                    needs_investigation=True,
                    investigation_reasons=["CI/CD SA holds escalation verbs or wildcards"],
                    suggested_tool=f"get_workload_identity.py {g['subject_name']} {g.get('subject_namespace') or 'default'}",
                ))

        # E6: Legacy pod identity
        for wi in entra.get("workload_identities", []):
            if wi.get("binding_type") == "pod-identity-legacy":
                for g in grants:
                    if g["subject_kind"] == "ServiceAccount" and g["subject_name"] == wi["sa_name"]:
                        findings.append(make_finding(
                            "E6", "MEDIUM",
                            f"Legacy AAD Pod Identity — {wi['namespace']}/{wi['sa_name']}",
                            g, [],
                            entra_context={"available": True, "for_service_account": wi},
                            needs_investigation=False,
                            investigation_reasons=["Migrate to AKS Workload Identity"],
                        ))
                        break

        # E8: Azure RBAC cluster access path
        # Subjects with both K8s RBAC bindings AND Azure RBAC roles that provide cluster access
        AKS_AZURE_ROLES = {
            "Azure Kubernetes Service Cluster Admin Role",
            "Azure Kubernetes Service Cluster User Role",
            "Azure Kubernetes Service RBAC Admin",
            "Azure Kubernetes Service RBAC Cluster Admin",
            "Azure Kubernetes Service RBAC Reader",
            "Azure Kubernetes Service RBAC Writer",
            "Contributor", "Owner", "User Access Administrator",
        }
        # Roles that grant admin-level cluster access — used to escalate User findings to CRITICAL
        E8_CRITICAL_AZURE_ROLES = {
            "Azure Kubernetes Service Cluster Admin Role",
            "Azure Kubernetes Service RBAC Cluster Admin",
            "Owner",
            "User Access Administrator",
        }
        for u in entra.get("users", []):
            if u.get("error") or not u.get("azure_rbac_roles"):
                continue
            aks_roles = [r for r in u["azure_rbac_roles"] if r.get("role") in AKS_AZURE_ROLES]
            if not aks_roles:
                continue
            subject_grants = [
                g for g in grants
                if g["subject_name"] == u["subject_name"] and not is_aks_system(g["subject_name"])
            ]
            if subject_grants:
                best = next((g for g in subject_grants if g["scope"] == "cluster"), subject_grants[0])
                sev = "CRITICAL" if any(r["role"] in E8_CRITICAL_AZURE_ROLES for r in aks_roles) else "HIGH"
                findings.append(make_finding(
                    "E8", sev,
                    f"Dual K8s+Azure RBAC cluster access — {u['subject_name']}",
                    best, [],
                    entra_context={"available": True, "for_user": u, "azure_rbac_path": aks_roles},
                    needs_investigation=True,
                    investigation_reasons=[f"Subject has both K8s RBAC binding and Azure RBAC path: {[r['role'] for r in aks_roles]}"],
                    suggested_tool=f"get_user.py {u['subject_name']}",
                ))
        for grp in entra.get("groups", []):
            if grp.get("orphaned") or not grp.get("azure_rbac_roles"):
                continue
            aks_roles = [r for r in grp["azure_rbac_roles"] if r.get("role") in AKS_AZURE_ROLES]
            if not aks_roles:
                continue
            subject_grants = [
                g for g in grants
                if g["subject_kind"] == "Group" and g["subject_name"] == grp["object_id"]
                and not is_aks_system(grp["object_id"])
            ]
            if subject_grants:
                best = next((g for g in subject_grants if g["scope"] == "cluster"), subject_grants[0])
                # Groups always CRITICAL: a group-held Azure admin path affects all members
                findings.append(make_finding(
                    "E8", "CRITICAL",
                    f"Dual K8s+Azure RBAC cluster access — group {grp.get('display_name') or grp['object_id']}",
                    best, [],
                    entra_context={"available": True, "for_group": grp, "azure_rbac_path": aks_roles},
                    needs_investigation=True,
                    investigation_reasons=[f"Group has both K8s RBAC binding and Azure RBAC path: {[r['role'] for r in aks_roles]}"],
                    suggested_tool=f"get_group.py {grp['object_id']}",
                ))

        # E9: CI/CD identity authenticating via client secret (no OIDC federation)
        for u in entra.get("users", []):
            if u.get("kind") != "ServicePrincipal":
                continue
            if not looks_like_cicd(u.get("subject_name", "")):
                continue
            if u.get("oidc_federation"):
                continue  # has federation — OK
            for g in grants:
                if g["subject_name"] == u["subject_name"] and not is_aks_system(g["subject_name"]):
                    s = summarize_rules(g.get("rules", []))
                    sev = "CRITICAL" if g["role"] == "cluster-admin" or s["effectively_cluster_admin"] else "HIGH"
                    findings.append(make_finding(
                        "E9", sev,
                        f"CI/CD identity without OIDC federation — {u['subject_name']}",
                        g, [],
                        entra_context={"available": True, "for_user": u},
                        needs_investigation=True,
                        investigation_reasons=["ServicePrincipal uses client-secret auth — no workload identity federation detected. Long-lived secret is a supply-chain risk."],
                        suggested_tool=f"get_user.py {u['subject_name']}",
                    ))
                    break

        # E7: Multi-path access
        for upn, paths in entra.get("multi_path_access", {}).items():
            paths_with_grants = []
            for path in paths:
                gid = path.get("group_id")
                for g in grants:
                    if g["subject_kind"] == "Group" and g["subject_name"] == gid and not is_aks_system(gid):
                        paths_with_grants.append({**path, "role": g["role"], "scope": g.get("scope")})
                        break
            if len(paths_with_grants) >= 2:
                rep_grant = next(
                    (g for g in grants if g["subject_kind"] == "Group"
                     and g["subject_name"] == paths_with_grants[0]["group_id"]), None
                )
                if rep_grant:
                    has_admin = any(p.get("role") == "cluster-admin" for p in paths_with_grants)
                    sev = "HIGH" if has_admin else "MEDIUM"
                    findings.append(make_finding(
                        "E7", sev,
                        f"Multi-path cluster access — {upn}",
                        rep_grant, [],
                        entra_context={"available": True, "multi_path": {"upn": upn, "paths": paths_with_grants}},
                        needs_investigation=True,
                        investigation_reasons=[
                            f"User reachable via {len(paths_with_grants)} groups: " +
                            ", ".join(p.get("group_name") or p.get("group_id") for p in paths_with_grants)
                        ],
                        suggested_tool=f"get_user.py {upn}",
                    ))

    return findings, _collect_groups_with_access(grants, entra), _collect_users_with_access(grants, entra)


def _collect_users_with_access(grants: list, entra: dict | None) -> list:
    """All non-system User subjects with cluster access, for LLM judgment in report-agent."""
    seen = {}
    for g in grants:
        if g["subject_kind"] != "User" or is_aks_system(g["subject_name"]):
            continue
        name = g["subject_name"]
        if name not in seen:
            eu = find_entra_user(entra, name) if entra else None
            seen[name] = {
                "subject_name": name,
                "display_name": eu.get("display_name") if eu else None,
                "upn": eu.get("upn") if eu else None,
                "user_type": eu.get("user_type") if eu else None,
                "account_enabled": eu.get("account_enabled") if eu else None,
                "roles": [],
                "bindings": [],
            }
        seen[name]["roles"].append(g["role"])
        seen[name]["bindings"].append({
            "binding": g["binding"],
            "scope": g.get("scope"),
            "scope_namespace": g.get("scope_namespace"),
        })

    for entry in seen.values():
        entry["roles"] = sorted(set(entry["roles"]))

    return list(seen.values())


def _collect_groups_with_access(grants: list, entra: dict | None) -> list:
    """All non-system Group subjects with cluster access, for LLM judgment in report-agent."""
    seen = {}
    for g in grants:
        if g["subject_kind"] != "Group" or is_aks_system(g["subject_name"]):
            continue
        gid = g["subject_name"]
        if gid not in seen:
            eg = find_entra_group(entra, gid) if entra else None
            seen[gid] = {
                "object_id": gid,
                "display_name": eg.get("display_name") if eg else None,
                "orphaned": eg.get("orphaned", False) if eg else None,
                "member_count": eg.get("member_count", 0) if eg else None,
                "members": eg.get("members", []) if eg else [],
                "roles": [],
                "bindings": [],
            }
        seen[gid]["roles"].append(g["role"])
        seen[gid]["bindings"].append({
            "binding": g["binding"],
            "scope": g.get("scope"),
            "scope_namespace": g.get("scope_namespace"),
        })

    for entry in seen.values():
        entry["roles"] = sorted(set(entry["roles"]))

    return list(seen.values())


def compute_summary(findings: list, grants: list, entra: dict | None, cluster: str) -> dict:
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if not f["aks_infra"]:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    needs_inv = sum(1 for f in findings if f.get("needs_investigation") and not f["aks_infra"])

    direct_users = {g["subject_name"] for g in grants if g["subject_kind"] == "User" and not is_aks_system(g["subject_name"])}
    group_subjects = {g["subject_name"] for g in grants if g["subject_kind"] == "Group" and not is_aks_system(g["subject_name"])}

    ca_subjects = []
    for g in grants:
        if g["role"] == "cluster-admin" and not is_aks_system(g["subject_name"]):
            if g["subject_kind"] == "Group" and entra:
                eg = find_entra_group(entra, g["subject_name"])
                if eg and not eg.get("orphaned"):
                    for m in eg.get("members", []):
                        if m["kind"] == "User" and m.get("display_name"):
                            ca_subjects.append(m.get("display_name") or m.get("upn"))
            else:
                ca_subjects.append(g["subject_name"])

    imp_subjects = []
    for g in grants:
        s = summarize_rules(g.get("rules", []))
        if s["has_escalation_verbs"] and "impersonate" in s["escalation_verbs"] and not is_aks_system(g["subject_name"]):
            if g["subject_kind"] == "Group" and entra:
                eg = find_entra_group(entra, g["subject_name"])
                if eg:
                    for m in eg.get("members", []):
                        imp_subjects.append(m.get("display_name") or m.get("upn"))
            else:
                imp_subjects.append(g["subject_name"])

    return {
        "cluster": cluster,
        "total_findings": len([f for f in findings if not f["aks_infra"]]),
        "by_severity": by_sev,
        "needs_investigation_count": needs_inv,
        "blast_radius": {
            "direct_user_bindings": len(direct_users),
            "group_bindings": len(group_subjects),
            "humans_with_cluster_admin": sorted(set(ca_subjects)),
            "humans_with_impersonate": sorted(set(imp_subjects)),
            "note": None if entra else "Entra not available — group member counts unknown. Run with entra-context.json for full blast radius.",
        },
    }


def load_grants(grants_path: str) -> tuple[list, str]:
    """Load grants from rbac-grants.json artifact."""
    try:
        with open(grants_path) as f:
            data = json.load(f)
        return data.get("grants", []), data.get("meta", {}).get("cluster", "unknown")
    except FileNotFoundError:
        print(f"Error: {grants_path} not found — run rbac-agent first", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing {grants_path}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Run CIS + Entra detection against RBAC artifacts")
    parser.add_argument("--grants", default="rbac-grants.json")
    parser.add_argument("--entra-file", default="entra-context.json")
    parser.add_argument("--output", default="audit-findings.json")
    args = parser.parse_args()

    print(f"Loading grants from {args.grants}...", file=sys.stderr)
    grants, cluster = load_grants(args.grants)
    print(f"  {len(grants)} grants from {cluster}", file=sys.stderr)

    entra = load_entra_cache(args.entra_file)
    if entra:
        print(f"  Entra context loaded from {args.entra_file}", file=sys.stderr)
    else:
        print(f"  No Entra context (run entra-agent for identity findings)", file=sys.stderr)

    print("Running checks...", file=sys.stderr)
    findings, groups_with_access, users_with_access = run_checks(grants, entra)

    actionable = [f for f in findings if not f["aks_infra"]]
    infra = [f for f in findings if f["aks_infra"]]

    actionable.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                   0 if f["grant"]["scope"] == "cluster" else 1))

    summary = compute_summary(findings, grants, entra, cluster)

    output = {
        "meta": {
            "cluster": cluster,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entra_available": entra is not None,
            "total_grants_analyzed": len(grants),
            "grants_filtered_as_aks_system": sum(1 for g in grants if is_aks_system(g["subject_name"])),
        },
        "summary": summary,
        "findings": actionable,
        "aks_infra_findings": infra,
        "groups_with_access": groups_with_access,
        "users_with_access": users_with_access,
    }

    dest = sys.stdout if args.output == "-" else open(args.output, "w")
    json.dump(output, dest, indent=2)
    if args.output != "-":
        dest.close()

    crit = summary["by_severity"]["CRITICAL"]
    high = summary["by_severity"]["HIGH"]
    print(f"  {len(actionable)} findings ({crit} CRITICAL, {high} HIGH), {summary['needs_investigation_count']} need investigation", file=sys.stderr)
    print(f"  Written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
