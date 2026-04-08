# Stage 2 Spec: E8 — Azure RBAC Cross-Reference Finalization

## Goal

Finalize E8 (dual K8s+Azure RBAC path detection). The core plumbing is already in place:
`collect.py` already fetches `azure_rbac_roles` for Users, ServicePrincipals, and Groups, and
`analyze.py` already has the E8 detection loop. What's missing: severity escalation, best-grant
selection, tests, and removing the stale CLAUDE.md gap entry.

---

## Gap 1 — Severity Escalation

### Problem
E8 always emits `HIGH` regardless of how powerful the Azure RBAC role is. Per the escalation
rules (cluster-scoped > namespace-scoped, group subjects escalate), the severity should reflect
the actual risk of the Azure RBAC path.

### Fix
Add a `E8_CRITICAL_AZURE_ROLES` constant at the start of the E8 block in `analyze.py`:

```python
E8_CRITICAL_AZURE_ROLES = {
    "Azure Kubernetes Service Cluster Admin Role",
    "Azure Kubernetes Service RBAC Cluster Admin",
    "Owner",
    "User Access Administrator",
}
```

Derive severity before calling `make_finding`:
- For **Users**: `"CRITICAL"` if any matched Azure role is in `E8_CRITICAL_AZURE_ROLES`, else `"HIGH"`
- For **Groups**: always `"CRITICAL"` — a group-held Azure admin path affects all members

### Files In Scope
- `.claude/skills/risk-agent/scripts/analyze.py` — E8 block only (lines ~562–608)
- `tests/test_e8_azure_rbac_crossref.py` — new test file

---

## Gap 2 — Best-Grant Selection

### Problem
The current E8 loops break on the first matching grant for a subject. If the subject has both
a cluster-scoped and a namespace-scoped K8s binding, the namespace-scoped one may be reported,
understating the risk.

### Fix
Replace the `for g in grants: ... break` pattern in both the user and group E8 loops with a
cluster-scope preference:

```python
subject_grants = [
    g for g in grants
    if g["subject_name"] == subject_name and not is_aks_system(subject_name)
]
if subject_grants:
    best = next((g for g in subject_grants if g["scope"] == "cluster"), subject_grants[0])
    findings.append(make_finding("E8", sev, ..., best, ...))
```

Apply the same pattern for the groups loop (match on `subject_kind == "Group"`).

### Files In Scope
- `.claude/skills/risk-agent/scripts/analyze.py` — E8 block only

---

## Gap 3 — Tests

### Test File
`tests/test_e8_azure_rbac_crossref.py`

Follow the exact pattern from `tests/test_cis_admin_edit_cluster.py`:
- Import `run_checks` from `analyze`
- Build minimal grant dicts and entra dicts in-memory (no external calls)
- Call `run_checks(grants, entra=entra)` and filter for `check == "E8"`

### Required Test Cases

| Test | Expected |
|------|----------|
| User with `Azure Kubernetes Service Cluster User Role` + K8s grant | 1 E8 finding, severity `HIGH` |
| User with `Azure Kubernetes Service Cluster Admin Role` + K8s grant | 1 E8 finding, severity `CRITICAL` |
| User with `Owner` + K8s grant | 1 E8 finding, severity `CRITICAL` |
| Group with any AKS Azure role + K8s grant | 1 E8 finding, severity `CRITICAL` |
| User with AKS Azure role but no K8s grant in grants list | 0 E8 findings |
| User with K8s grant but no Azure role (`azure_rbac_roles: []`) | 0 E8 findings |
| User with non-AKS Azure role (e.g. `"Storage Blob Data Reader"`) + K8s grant | 0 E8 findings |
| AKS system subject (`system:serviceaccount:kube-system:...`) skipped | 0 E8 findings |
| User with both cluster-scoped and namespace-scoped grants → cluster-scoped selected | `grant.scope == "cluster"` |

---

## Gap 4 — CLAUDE.md Cleanup

Remove item 3 from the Known Gaps section in `.claude/CLAUDE.md` (the E8 entry). Renumber
the remaining gaps so they are sequential (current 4→3, current 5→4).

---

## Files In Scope
- `.claude/skills/risk-agent/scripts/analyze.py` — E8 block (lines ~562–608) only
- `tests/test_e8_azure_rbac_crossref.py` — new file
- `.claude/CLAUDE.md` — remove stale gap entry

## Files Off-Limits
- `.claude/skills/contracts/` — schemas are frozen, do not touch
- `.claude/skills/entra-agent/` — collect.py is already complete, no changes needed
- Any CIS detection rules — out of scope for this stage

---

## Success Criteria

Self-evaluate all of the following before signaling completion:

- [ ] E8 emits `CRITICAL` when Azure role is `Azure Kubernetes Service Cluster Admin Role`
- [ ] E8 emits `CRITICAL` when Azure role is `Owner`
- [ ] E8 emits `CRITICAL` when Azure role is `User Access Administrator`
- [ ] E8 emits `HIGH` when Azure role is `Azure Kubernetes Service Cluster User Role`
- [ ] E8 emits `CRITICAL` for Group subjects regardless of which AKS Azure role
- [ ] E8 selects cluster-scoped K8s grant when subject has both cluster and namespace bindings
- [ ] No E8 when subject has Azure role but no K8s binding
- [ ] No E8 when subject has K8s binding but no AKS-relevant Azure role
- [ ] AKS system subjects are skipped
- [ ] All new test cases pass
- [ ] All existing tests still pass (`tests/test_cis514_subresource.py`, `tests/test_cis_admin_edit_cluster.py`)
- [ ] CLAUDE.md Known Gaps no longer lists E8
- [ ] No files outside the in-scope list were modified

---

## Constraints
- Do not modify artifact contract schemas
- Do not modify entra-agent (`collect.py` is already complete)
- Do not add new dependencies to `requirements.txt`
- Append all non-obvious decisions to `.claude/DECISIONS.md`

---

## Definition of Done
All success criteria checked and passing. Commit message:
`"feat: finalize E8 — severity escalation, best-grant selection, and tests"`
