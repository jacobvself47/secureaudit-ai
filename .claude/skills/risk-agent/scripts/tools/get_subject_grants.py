"""
get_subject_grants.py <subject_name> [--kind User|Group|ServiceAccount]

Returns all grants held by a subject plus a rules summary.
Queries K8s live. Use when a subject appears in multiple findings
and you want the full picture before writing narrative.
"""
import argparse
import json
import os
import sys

_SHARED = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared")
sys.path.insert(0, os.path.normpath(_SHARED))
from lib.grants import get_rbac_client, iter_all_grants, summarize_rules, load_entra_cache, find_entra_group, find_entra_user, find_entra_wi


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("subject_name")
    parser.add_argument("--kind", choices=["User", "Group", "ServiceAccount"])
    parser.add_argument("--entra-file", default="entra-context.json")
    args = parser.parse_args()

    rbac = get_rbac_client()
    all_grants = iter_all_grants(rbac)

    matched = [
        g for g in all_grants
        if g["subject_name"] == args.subject_name
        and (args.kind is None or g["subject_kind"] == args.kind)
    ]

    entra = load_entra_cache(args.entra_file)

    grants_out = []
    for g in matched:
        s = summarize_rules(g.get("rules", []))
        grants_out.append({
            "binding": g["binding"],
            "binding_kind": g["binding_kind"],
            "role": g["role"],
            "scope": g["scope"],
            "scope_namespace": g.get("scope_namespace"),
            "rules_summary": s,
        })

    kind = matched[0]["subject_kind"] if matched else args.kind or "unknown"
    ns = next((g.get("subject_namespace") or g.get("scope_namespace") or "default" for g in matched), "default")

    entra_ctx = None
    if entra:
        if kind == "Group":
            eg = find_entra_group(entra, args.subject_name)
            entra_ctx = eg
        elif kind == "User":
            entra_ctx = find_entra_user(entra, args.subject_name)
        elif kind == "ServiceAccount":
            entra_ctx = find_entra_wi(entra, args.subject_name, ns)

    finding_ids = []
    try:
        with open("audit-findings.json") as f:
            af = json.load(f)
        for finding in af.get("findings", []):
            if finding["subject"]["name"] == args.subject_name:
                finding_ids.append(finding["id"])
    except FileNotFoundError:
        pass

    print(json.dumps({
        "subject_name": args.subject_name,
        "subject_kind": kind,
        "grant_count": len(matched),
        "grants": grants_out,
        "entra_context": {"available": entra is not None, "data": entra_ctx},
        "finding_ids": finding_ids,
    }, indent=2))


if __name__ == "__main__":
    main()
