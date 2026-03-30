# CIS Kubernetes Benchmark v1.9 — RBAC Controls (Section 5.1)

Use these controls when analyzing RBAC grants. Each control includes detection logic expressed in terms of the flat grants schema.

---

## 5.1.1 — Cluster-admin role used only where required

**Severity:** CRITICAL
**Description:** The `cluster-admin` ClusterRole grants unrestricted access to the entire cluster. It should only be bound to human administrators who explicitly require it.

**Detection:** Any grant where `role == "cluster-admin"`, especially:
- Subjects of kind `ServiceAccount`
- Subjects of kind `Group` that are not `system:masters` (which is AKS infrastructure)
- Users who are not explicitly known cluster administrators

**Note:** AKS system bindings (`cluster-admin` → `system:masters`, `kubeadm:cluster-admins`) are expected infrastructure — flag them but mark as likely-benign unless confirmed otherwise.

---

## 5.1.2 — Minimize access to secrets

**Severity:** HIGH
**Description:** Secrets contain credentials, tokens, and keys. Access should be restricted to only what is necessary, using `resourceNames` to scope to specific secrets where possible.

**Detection:** Any grant where:
- `rules[].resources` contains `"secrets"` or `"*"`
- `rules[].verbs` contains any of: `"get"`, `"list"`, `"watch"`, `"*"`
- `rules[].resource_names` is empty (meaning all secrets, not specific ones)

Cluster-scoped secrets access is more severe than namespace-scoped.

---

## 5.1.3 — Minimize wildcard use in Roles and ClusterRoles

**Severity:** HIGH
**Description:** Wildcards (`*`) in verbs or resources grant broad permissions that are hard to audit and often grant more than intended.

**Detection:** Any grant where:
- `rules[].verbs` contains `"*"`, OR
- `rules[].resources` contains `"*"`, OR
- `rules[].api_groups` contains `"*"`

A grant with all three wildcards is equivalent to cluster-admin for that scope.

---

## 5.1.4 — Minimize access to create pods

**Severity:** HIGH
**Description:** Pod creation rights can be used for privilege escalation — a subject can create a pod mounting sensitive host paths, using a privileged security context, or with a service account token.

**Detection:** Any grant where:
- `rules[].resources` contains `"pods"` or `"*"`
- `rules[].verbs` contains `"create"` or `"*"`

Escalate severity if the subject also has access to service accounts or secrets.

---

## 5.1.5 — Default service accounts not bound to active roles

**Severity:** MEDIUM
**Description:** The `default` ServiceAccount in every namespace should not have any non-trivial RBAC grants. Applications that need permissions should use dedicated service accounts.

**Detection:** Any grant where:
- `subject_kind == "ServiceAccount"`
- `subject_name == "default"`
- `rules` is non-empty (i.e., the binding actually grants permissions)

---

## 5.1.6 — Service account token auto-mounting

**Severity:** LOW (informational — not detectable from RBAC data alone)
**Description:** Service accounts automatically mount tokens into pods. If a service account has elevated privileges, any pod using it is exposed.

**Note:** Flag service accounts with significant grants and note that token auto-mounting amplifies the risk — remediations should include `automountServiceAccountToken: false`.

---

## 5.1.7 — Avoid use of system:masters group

**Severity:** CRITICAL
**Description:** Members of `system:masters` bypass RBAC authorization entirely (handled at the authenticator level). No RBAC policy can restrict a `system:masters` member.

**Detection:** Any grant where:
- `subject_kind == "Group"`
- `subject_name == "system:masters"`

AKS itself creates one such binding — flag it as infrastructure but note the risk.

---

## 5.1.8 — Limit bind, impersonate, and escalate permissions

**Severity:** CRITICAL
**Description:** These verbs allow privilege escalation beyond what is directly granted:
- `bind` — allows binding roles to subjects, potentially granting higher privileges
- `impersonate` — allows acting as other users or service accounts
- `escalate` — allows modifying roles to grant additional permissions

**Detection:** Any grant where `rules[].verbs` contains `"bind"`, `"impersonate"`, or `"escalate"`.

---

## Severity escalation rules

Apply these when a control matches:

| Condition | Escalate by |
|---|---|
| Cluster-scoped (`scope == "cluster"`) vs namespace-scoped | +1 severity level |
| Subject is a ServiceAccount (automated, persistent access) | +1 severity level for wildcards/secrets |
| Subject is a Group (affects many principals) | +1 severity level |
| Multiple controls violated by the same grant | Severity = highest applicable |
| `resource_names` is non-empty (scoped to specific resources) | -1 severity level |
