---
name: entra-agent
description: Entra ID domain agent. Resolves Kubernetes RBAC principals (users, groups, service accounts) against Azure Active Directory. Reads rbac-grants.json and writes entra-context.json. This is the only agent with az CLI access.
compatibility: Requires az CLI authenticated via `az login` and rbac-grants.json present in the working directory (produced by rbac-agent).
allowed-tools: Bash(source .venv/*) Bash(python .claude/skills/entra-agent/scripts/*) Bash(az ad *) Bash(az role assignment list *) Bash(az identity list*) Bash(az account show*) Read
---

# Entra Agent

**Domain:** Who are these principals?
**Input:** `rbac-grants.json` (from rbac-agent)
**Output:** `entra-context.json` — see `contracts/entra-context.schema.json`

## Run

```
source .venv/bin/activate && python .claude/skills/entra-agent/scripts/collect.py
```

To use a non-default grants file:
```
source .venv/bin/activate && python .claude/skills/entra-agent/scripts/collect.py --grants rbac-grants.json
```

## Report

From stderr output, tell the user:
- Groups resolved vs orphaned
- Guest users found (direct + via groups)
- Disabled accounts found
- Users with multi-path access
- Workload identity bindings: resolved vs unresolved

If any `errors[]` entries are present, list which lookups failed — a partial result is still usable.

## Boundary

This agent does not:
- Query the Kubernetes API directly (reads only from rbac-grants.json artifact)
- Analyze findings or assign severity
- Write to Entra ID / Azure

If `rbac-grants.json` is missing, instruct the user to run rbac-agent first.
