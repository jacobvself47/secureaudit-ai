# SecureAudit AI

AI-powered Kubernetes RBAC security audit system. Combines deterministic CIS Benchmark detection with LLM-driven risk analysis and identity enrichment from Entra ID.

---

## Architecture

Multi-agent system. Each agent owns exactly one domain and communicates only through JSON artifact files.

```
secureaudit (orchestrator)
    │
    ├── rbac-agent       "What grants exist?"         cluster → rbac-grants.json
    ├── entra-agent      "Who are these principals?"  rbac-grants.json → entra-context.json
    ├── risk-agent       "What does this mean?"       artifacts → audit-findings.json
    └── report-agent     "What should the team do?"  audit-findings.json → report
```

**Design principle:** Scripts handle facts deterministically. The LLM handles meaning, judgment, and narrative. Never conflate these — a detection rule should never require LLM reasoning, and the LLM should never re-implement detection logic.

---

## Artifact Contracts

Schemas live in `.claude/skills/contracts/`. These are the interfaces between agents — treat them as an API.
Artifact schemas in .claude/skills/contracts/ are frozen. Never modify them.

| File | Producer | Consumers |
|---|---|---|
| `rbac-grants.json` | rbac-agent | entra-agent, risk-agent |
| `entra-context.json` | entra-agent | risk-agent |
| `audit-findings.json` | risk-agent | report-agent |

---

## Agent Boundaries

| Agent | Allowed access | Never does |
|---|---|---|
| rbac-agent | kubectl, Kubernetes Python client | Touches Azure/Entra |
| entra-agent | az CLI, reads rbac-grants.json | Queries Kubernetes directly |
| risk-agent | Read artifacts, kubectl + az for investigation tools | Writes to cluster or Azure |
| report-agent | Read only | Runs scripts or tools |

---

## Skills

Invoke via Claude Code slash commands:

```
/secureaudit                  # Full audit, current context
/secureaudit --with-entra     # Full audit + Entra ID enrichment
/secureaudit prod             # Switch to 'prod' context first
```

Individual agents can also be invoked directly:
- `/rbac-agent` — enumerate grants only
- `/entra-agent` — resolve principals only (requires rbac-grants.json)
- `/risk-agent` — detect and investigate (requires rbac-grants.json)

Skill definitions: `.claude/skills/`

---

## Environment

- Python 3.11+ with `.venv` (not `venv`)
- Activate: `source .venv/bin/activate`
- Install deps: `pip install -r requirements.txt`
- Kubernetes: kubectl configured, active context is AKS
> Note for autonomous development runs: if you need to execute a test audit to validate new code, use the kind-secureaudit-local context, not the active AKS context.
Never run against AKS to test code changes.
- Azure: `az login` required for `--with-entra`
- Shared library: `.claude/skills/shared/lib/grants.py`

---

## Detection Rules

**CIS Kubernetes Benchmark v1.9 (section 5.1):**
- 5.1.1 cluster-admin bindings
- 5.1.2 unscoped secrets access
- 5.1.3 wildcard permissions
- 5.1.4 pod creation rights
- 5.1.5 default ServiceAccount with grants
- 5.1.7 system:masters group
- 5.1.8 escalation verbs (bind, impersonate, escalate)

**Entra ID checks (E1–E9):**
- E1 Orphaned group bindings
- E2 Guest users with cluster access
- E3 Disabled accounts with active grants
- E4 Unresolved workload identity
- E5 CI/CD SA over-privilege
- E6 Legacy AAD pod identity
- E7 Multi-path access (user reachable via 2+ groups)
- E8 Azure RBAC cluster access path (dual K8s+Azure path to cluster)
- E9 CI/CD identity with no OIDC federation (client-secret auth)

**LLM judgment (report-agent):**
- Group access appropriateness — every non-system Group with cluster or namespace access is reviewed for business justification. The LLM reasons about whether the access makes sense given group name, namespace, and role. This is intentionally not a deterministic rule.
- User access appropriateness - every user with cluster or namespace access is reviewed for business justification.  The LLM reasons about whether the access makes sense given group name, namespace, and role.  This is intentionally not a deterministic rule.

---

## Known Gaps (implement next)

1. **`pods/exec` subresource** — CIS-5.1.4 misses container exec grants because `"pods/exec"` doesn't match `"pods"` in a list. Fix: `any(r == "pods" or r.startswith("pods/") for r in resources)` in `summarize_rules()` and the CIS-5.1.4 check in `analyze.py`.

2. **`admin`/`edit` ClusterRole cluster-wide** — Built-in `admin` bound via ClusterRoleBinding is functionally near-cluster-admin but has no wildcard resources, so existing rules miss it. Fix: new CRITICAL check in `analyze.py` for `role in ("admin", "edit")` with `scope == "cluster"`.

3. **Azure RBAC cross-reference (E8)** — entra-agent already fetches Azure RBAC for managed identities. Extend it to also call `az role assignment list --assignee <object-id> --all` for Groups and Users, storing AKS-relevant roles in `entra-context.json`. risk-agent then emits E8 when a K8s subject also has an Azure RBAC path to the cluster.

4. **OIDC federation check (E9)** — When a subject resolves to a ServicePrincipal, call `az ad app federated-credential list --id <app-id>`. If empty, the SP authenticates via client secret. Add E9 finding for CI/CD identities without workload identity federation.

5. **Group access appropriateness** — Add `groups_with_access[]` to `audit-findings.json` (all non-system Groups with any binding, even clean ones). report-agent reasons about each one.

---

## Severity Levels

`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

Escalation rules:
- Cluster-scoped > namespace-scoped
- Group subject (affects many principals) escalates severity
- ServiceAccount subject (persistent, automated) escalates for wildcards/secrets
- pod create + secrets/escalation = CRITICAL escalation chain
- `resourceNames` scoping reduces severity

---

## Code Style

- PEP 8, type hints on all functions
- No docstrings on obvious functions; comments only where logic isn't self-evident
- All scripts output JSON to stdout, status to stderr
- `sys.path.insert` pattern for shared lib import (no package installs needed)
- Severity as string constants, not enums
