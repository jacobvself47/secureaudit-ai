---
name: risk-agent
description: Risk assessment domain agent. Reads RBAC and Entra artifacts, runs deterministic CIS 5.1.x and Entra E1-E7 checks, investigates flagged findings with on-demand query tools, and produces audit-findings.json. Use when you need to analyze, score, or audit security posture.
compatibility: Requires rbac-grants.json in the working directory. For Entra findings, also requires entra-context.json. Investigation tools need kubectl and optionally az CLI.
allowed-tools: Bash(source *) Bash(python .claude/skills/risk-agent/scripts/*) Bash(kubectl *) Bash(az *) Read
---

# Risk Agent

**Domain:** What does this mean from a security perspective?
**Input:** `rbac-grants.json` + (optional) `entra-context.json`
**Output:** `audit-findings.json` — see `contracts/audit-findings.schema.json`

## Phase 1 — Detect

```
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/analyze.py
```

With Entra context:
```
source .venv/bin/activate && python .claude/skills/risk-agent/scripts/analyze.py --entra-file entra-context.json
```

Read the stderr summary: total findings by severity and `needs_investigation_count`.

## Phase 2 — Investigate

Read `audit-findings.json`. For every finding where `needs_investigation == true`, use the `suggested_tool` field as your starting point. Call tools in parallel when investigations are independent.

**Tool reference:**

| Tool | When to call |
|---|---|
| `tools/get_subject_grants.py <name>` | Subject appears in multiple findings — get the full picture before writing |
| `tools/get_group.py <group_id>` | Group membership missing or orphan status unclear |
| `tools/get_user.py <identifier>` | User not found in Entra, guest, disabled, or multi-path suspected |
| `tools/get_workload_identity.py <sa_name> <namespace>` | Managed identity unresolved or SA is CI/CD-named |
| `tools/get_role.py <role_name>` | Unfamiliar role name — need to understand effective permissions |
| `tools/blast_radius.py` | Call once at the end to get exact human access counts |
| `tools/check_builtin_roles.py` | Always call once per audit — live cluster check for modified built-in ClusterRoles; confirms which aggregation role introduced the change |
| `tools/check_unbound_roles.py` | Always call once per audit — finds dangerous ClusterRoles (wildcards, escalation verbs) not currently bound to any subject |

Add `--live` to any Entra tool to bypass cache and force fresh az CLI queries.

Stop investigating when all `needs_investigation` findings are addressed or tools return `not_found` with no further options.

## Phase 3 — Report

Write the full findings report using data from `audit-findings.json` plus Phase 2 tool output.

Follow the full report format in `report-agent` — or hand off to `report-agent` for the reporting step.

## Boundary

This agent does not:
- Write to the cluster or Azure
- Run bulk Entra collection (that is entra-agent's job)
- Own the human-readable report format (that is report-agent's job)

Reference material: `references/cis-benchmark.md`
