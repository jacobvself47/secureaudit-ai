# Decisions Log

## Gap 1 — pods/exec Subresource (CIS-5.1.4)

**Fix applied in two places:** `grants.py:summarize_rules()` sets `has_pod_create` using the
`r.startswith("pods/")` pattern, and `analyze.py` duplicates the same predicate when building
`pod_rules`. The duplication is intentional: `summarize_rules()` is used for cross-check
flags (escalation chain detection), while the `pod_rules` list in `analyze.py` drives the
actual finding and populates `matched_rules`. Both must agree or the severity escalation logic
breaks silently.

**`r == "*"` retained alongside `r.startswith("pods/")`:** Wildcard resource entries (`"*"`)
would match any resource including pods, so they must continue to set `has_pod_create`. This
was already present in `grants.py`; kept to avoid regression on wildcard roles.

---

## Gap 2 — admin/edit ClusterRoleBinding (CIS-5.1.1)

**Filed under CIS-5.1.1, not a new check ID:** The SPEC specified producing a "CIS-5.1.1
finding". `admin`/`edit` bound cluster-wide is categorically the same threat class as
`cluster-admin` — unrestricted access to every namespace — so the same check ID is correct.
Creating a new check ID would fragment reporting without adding signal.

**Condition is `scope == "cluster"`, not `binding_kind == "ClusterRoleBinding"`:** In practice
these are equivalent for our data model (cluster scope → ClusterRoleBinding), but checking
`scope` is semantically cleaner: it matches the escalation rule in CLAUDE.md ("cluster-scoped >
namespace-scoped") and makes the intent explicit in code review.

**`rules` passed as `matched_rules` (not a synthetic entry):** For `cluster-admin` the rules
list is empty (the role is built-in and not expanded), so `matched_rules` gets a synthetic
`[{"role": "cluster-admin", "note": "..."}]` entry. For `admin`/`edit` the rules are present
in the grants artifact, so we pass them through directly. This is more informative and avoids
inventing structure.
