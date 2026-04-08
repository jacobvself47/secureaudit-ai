# Stage 1 Spec: CIS Detection Rule Fixes

## Goal
Fix two known gaps in the deterministic detection logic. Both fixes
are isolated to `analyze.py` in the rbac-agent. No schema changes,
no new agents, no external API calls.

---

## Gap 1 — pods/exec Subresource Missing from CIS-5.1.4

### Problem
CIS-5.1.4 checks whether a subject has pod creation rights by matching
`"pods"` in the resources list. It misses grants expressed as
`"pods/exec"`, `"pods/log"`, or other subresource variants because
string equality fails on subresource notation.

### Fix
In `summarize_rules()` and the CIS-5.1.4 check in `analyze.py`,
replace the resource match logic with:

```python
any(r == "pods" or r.startswith("pods/") for r in resources)
```

Apply this pattern consistently wherever pod resource matching occurs.

### Files In Scope
- `agents/rbac-agent/analyze.py` — detection logic only
- `tests/` — add or update a test case covering `pods/exec`

### Files Off-Limits
- `.claude/skills/contracts/` — do not touch schemas
- `agents/entra-agent/` — out of scope for this stage
- `agents/risk-agent/` — out of scope for this stage
- `agents/report-agent/` — out of scope for this stage

---

## Gap 2 — admin/edit ClusterRole Cluster-Wide Binding

### Problem
The existing cluster-admin check (CIS-5.1.1) only catches explicit
`cluster-admin` bindings. The built-in `admin` and `edit` ClusterRoles
bound via ClusterRoleBinding give near-equivalent permissions cluster-wide
but contain no wildcard resources, so current rules produce no finding.

### Fix
Add a new CRITICAL severity check in `analyze.py`:

```python
if role in ("admin", "edit") and scope == "cluster":
    # Emit CRITICAL finding — near-cluster-admin access
```

This check must:
- Fire only on ClusterRoleBinding scope (not RoleBinding)
- Produce a CRITICAL severity finding
- Include the subject, role, and binding name in the finding output
- Follow the existing finding structure exactly — do not invent new fields

### Files In Scope
- `agents/rbac-agent/analyze.py` — detection logic only
- `tests/` — add a test case for admin and edit cluster-scoped bindings

### Files Off-Limits
- Same as Gap 1

---

## Success Criteria
Self-evaluate all of the following before signaling completion:

- [ ] `pods/exec` subresource now triggers CIS-5.1.4 finding
- [ ] `pods/log` subresource now triggers CIS-5.1.4 finding
- [ ] `"pods"` alone still triggers CIS-5.1.4 (no regression)
- [ ] `admin` bound via ClusterRoleBinding produces a CRITICAL finding
- [ ] `edit` bound via ClusterRoleBinding produces a CRITICAL finding
- [ ] `admin` bound via RoleBinding (namespace-scoped) produces no finding
- [ ] New findings follow existing finding structure — no new fields added
- [ ] All existing tests still pass
- [ ] New test cases added for each of the above scenarios
- [ ] No files outside `agents/rbac-agent/` were modified
- [ ] `.claude/skills/contracts/` schemas are unchanged

---

## Constraints
- Do not modify artifact contract schemas
- Do not modify any Entra ID detection rules (E1-E9)
- Do not add new dependencies to `requirements.txt`
- Commit after each gap is complete — two atomic commits minimum
- Append all non-obvious decisions to `.claude/DECISIONS.md`

---

## Definition of Done
All success criteria checked and passing. Final commit message:
`"feat: fix CIS-5.1.4 subresource gap and add admin/edit cluster binding check"`
