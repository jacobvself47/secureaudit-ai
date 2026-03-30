# SecureAudit AI

AI-powered Kubernetes RBAC security audit system for AKS clusters. Combines deterministic detection of CIS Benchmark violations with LLM-driven investigation and identity enrichment from Azure Entra ID, producing a human-readable report suitable for GRC access reviews.

---

## What it does

Running `/secureaudit` against a cluster produces a full security report covering:

- **Who has access** — every ClusterRoleBinding and RoleBinding, resolved to named individuals via Entra ID group membership
- **What they can do** — effective permissions including escalation paths, secrets access, pod execution rights
- **Whether they should** — CIS Benchmark violations, over-privileged CI/CD identities, orphaned accounts, guest users, disabled accounts, and dual K8s+Azure RBAC access paths
- **What to do about it** — exact `kubectl` and `az` remediation commands, severity-ranked, written for a GRC reviewer rather than a security engineer

A typical audit produces findings at CRITICAL, HIGH, MEDIUM, and LOW severity, an access review section where a reviewer signs off on each group and direct user binding, and a closing summary with prioritised next steps.

---

## How it works

The system is a pipeline of four Claude Code agents, each owning exactly one domain. Agents communicate only through JSON artifact files — no agent calls another directly.

```
/secureaudit
    │
    ├── rbac-agent       Enumerates all grants from the live cluster
    │                    Output: rbac-grants.json
    │
    ├── entra-agent      Resolves principals against Azure Entra ID
    │   (optional)       Output: entra-context.json
    │
    ├── risk-agent       Runs CIS + Entra checks, investigates findings
    │                    Output: audit-findings.json
    │
    └── report-agent     Writes the human-readable report
                         Output: audit-report.md
```

**Design principle:** Scripts handle facts deterministically. The LLM handles meaning, judgment, and narrative. A detection rule never requires LLM reasoning; the LLM never re-implements detection logic.

---

## Quick start

### Prerequisites

- Python 3.11+ with a `.venv` virtual environment
- `kubectl` configured with an active AKS context
- `az login` completed (required for `--with-entra`)

```bash
# Install dependencies
source .venv/bin/activate
pip install -r requirements.txt
```

### Run a full audit

```bash
# Audit the current kubectl context
/secureaudit

# Audit with Entra ID identity resolution (recommended)
/secureaudit --with-entra

# Switch to a specific context first
/secureaudit prod --with-entra
```

The report is written to `audit-report.md` in the project directory and displayed in the conversation.

### Run individual agents

```bash
# Enumerate RBAC grants only
/rbac-agent

# Resolve principals against Entra ID (requires rbac-grants.json)
/entra-agent

# Run detection and investigation (requires rbac-grants.json)
/risk-agent
```

---

## Detection coverage

### CIS Kubernetes Benchmark v1.9 — Section 5.1

| Check | Description |
|---|---|
| 5.1.1 | `cluster-admin` bindings |
| 5.1.2 | Unscoped Secrets access |
| 5.1.3 | Wildcard permissions |
| 5.1.4 | Pod creation rights |
| 5.1.5 | Default ServiceAccount with grants |
| 5.1.7 | `system:masters` group membership |
| 5.1.8 | Escalation verbs (`bind`, `impersonate`, `escalate`) |

### Entra ID checks (E1–E9)

| Check | Description |
|---|---|
| E1 | Orphaned group bindings (group deleted from directory) |
| E2 | Guest users with cluster access |
| E3 | Disabled accounts with active grants |
| E4 | Unresolved workload identity (managed identity not found) |
| E5 | CI/CD service account over-privilege |
| E6 | Legacy AAD pod identity bindings |
| E7 | Multi-path access (user reachable via 2+ groups) |
| E8 | Dual K8s + Azure RBAC access path to same cluster |
| E9 | CI/CD identity without OIDC federation (client-secret auth) |

### Cluster integrity checks (always run)

- **Modified built-in roles** — detects escalation verbs added to standard ClusterRoles (`edit`, `view`) directly or via aggregation
- **Dangerous unbound roles** — finds ClusterRoles with wildcard or escalation permissions that are not currently bound but can be activated instantly by anyone with the `bind` verb

### LLM judgment

Every non-system Group with cluster access is reviewed for business justification. The LLM reasons about whether the access makes sense given the group name, role, and namespace. This is intentionally not a deterministic rule.

---

## Artifact files

These files are produced at runtime and gitignored — they contain live cluster and identity data and must not be committed.

| File | Produced by | Consumed by |
|---|---|---|
| `rbac-grants.json` | rbac-agent | entra-agent, risk-agent |
| `entra-context.json` | entra-agent | risk-agent |
| `audit-findings.json` | risk-agent | report-agent |
| `audit-report.md` | report-agent | — (final output) |

JSON schemas for all artifact contracts are in `.claude/skills/contracts/`.

---

## Severity levels

`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

Escalation rules:
- Cluster-scoped findings rank higher than namespace-scoped
- Group subjects escalate severity (one binding affects many people)
- ServiceAccount subjects escalate for wildcards and secrets (persistent, automated access)
- Pod create + secrets or escalation verbs = CRITICAL escalation chain
- `resourceNames` scoping reduces severity

---

## Project structure

```
.claude/skills/
├── secureaudit/          Orchestrator skill (/secureaudit)
├── rbac-agent/           Kubernetes RBAC enumeration
│   └── scripts/
│       └── collect.py
├── entra-agent/          Entra ID principal resolution
│   └── scripts/
│       └── collect.py
├── risk-agent/           Detection, scoring, and investigation
│   ├── scripts/
│   │   ├── analyze.py
│   │   └── tools/        On-demand investigation tools
│   └── references/
│       └── cis-benchmark.md
├── report-agent/         Report writing
├── shared/
│   └── lib/
│       └── grants.py     Shared utilities (kubectl/az wrappers, parsing)
└── contracts/            JSON schemas for artifact interfaces
```
