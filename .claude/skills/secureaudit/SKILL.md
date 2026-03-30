---
name: secureaudit
description: Orchestrator for the full Kubernetes RBAC security audit pipeline. Routes work across rbac-agent, entra-agent, risk-agent, and report-agent. Use when the user wants a complete audit, security scan, or compliance check on a cluster.
compatibility: Requires kubectl configured with an active cluster context and Python in .venv. The --with-entra flag additionally requires az CLI authenticated via `az login`.
allowed-tools: Bash(source *) Bash(python .claude/skills/rbac-agent/scripts/*) Bash(python .claude/skills/entra-agent/scripts/*) Bash(python .claude/skills/risk-agent/scripts/*) Bash(kubectl *) Bash(az *) Read
---

# SecureAudit — Orchestrator

Routes work across four specialized agents. Each agent has a single domain:

| Agent | Domain | Input → Output |
|---|---|---|
| `rbac-agent` | What grants exist? | cluster → `rbac-grants.json` |
| `entra-agent` | Who are these principals? | `rbac-grants.json` → `entra-context.json` |
| `risk-agent` | What does this mean? | artifacts → `audit-findings.json` |
| `report-agent` | What should the team do? | `audit-findings.json` → report |

## Flags

| Flag | Description |
|---|---|
| `--with-entra` | Run entra-agent after rbac-agent. Resolves group membership, user guest/disabled status, managed identities, and multi-path access. Requires `az login`. |

## Argument parsing

- Any word not starting with `--` is a kubectl context name
- `--with-entra` enables Entra enrichment

---

## Step 1 — Confirm context

**If a context argument was provided**, switch first:
```
kubectl config use-context <argument>
```
If the context does not exist, list available contexts with `kubectl config get-contexts -o name` and ask the user to choose.

Confirm the active context with the user before proceeding. If `--with-entra`, also show `az account show --query "{subscription:name, tenantId:tenantId}" -o table` and confirm the Azure account.

---

## Step 2 — rbac-agent: enumerate grants

```
source .venv/bin/activate && python .claude/skills/rbac-agent/scripts/collect.py
```

Report to the user:
- Cluster name and context
- Total grants; breakdown by subject kind (User / Group / ServiceAccount)
- Namespaces with bindings
- Any immediately obvious signal (e.g. number of cluster-admin bindings, presence of Group subjects)

---

## Step 3 — entra-agent: resolve principals *(only if `--with-entra`)*

```
source .venv/bin/activate && python .claude/skills/entra-agent/scripts/collect.py
```

Report to the user:
- Groups resolved vs orphaned
- Guest users found (direct + via groups)
- Disabled accounts found
- Users with multi-path access
- Workload identity bindings: resolved vs unresolved

If any `errors[]` entries are present, list which lookups failed — a partial result is still usable.

**If `--with-entra` was not passed**, skip this step entirely.

---

## Step 4 — risk-agent: detect and investigate

Run detection:
```
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/analyze.py
```

With Entra context (if Step 3 ran):
```
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/analyze.py --entra-file entra-context.json
```

Also run the two cluster-level integrity checks (always, every audit):
```
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/tools/check_builtin_roles.py
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/tools/check_unbound_roles.py
```
- If `modified_builtin_roles` is non-empty: CRITICAL finding. Standard built-in roles (`edit`, `view`) should never contain escalation verbs. Note whether the change came via direct modification or an aggregation ClusterRole (the more subtle path).
- If `dangerous_unbound_roles` is non-empty: HIGH finding. List each role, its dangerous flags, and note that anyone with `bind` permission can activate it immediately.

Then follow the full `risk-agent` skill — Phase 2 (investigate `needs_investigation` findings) and Phase 3 (report).

**Critical reminder:** Every finding that mentions a Group, User, or ServiceAccount subject **must** include an Entra Context block when `entra-context.json` is available. This is not optional. Do not summarise group data vaguely — list the actual member names, UPNs, guest flags, and disabled flags inline in each finding.

---

## Step 5 — report-agent: write the report

Follow the full `report-agent` skill for report structure and per-finding format.

---

## Step 6 — Closing summary

After the full report:

1. **Top priority** — the single most important remediation and why (consider: blast radius, exploitation likelihood, ease of fix)
2. **Quick wins** — findings that are easy to fix and eliminate a disproportionate amount of risk
3. **Next steps** — re-running after remediations, enabling audit logging, reviewing specific namespaces

**If `--with-entra` was not passed** and Group subjects appeared in findings:
> Run `/secureaudit --with-entra` to resolve group membership, guest users, and managed identities. True blast radius is unknown until Entra data is collected.
