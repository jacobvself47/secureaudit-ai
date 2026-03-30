---
name: rbac-agent
description: Kubernetes RBAC domain agent. Enumerates all ClusterRoleBindings and RoleBindings from a live cluster and writes rbac-grants.json. This is the only agent with kubectl/Kubernetes API access. All other agents read from the artifact it produces.
compatibility: Requires kubectl configured with an active cluster context and Python in .venv.
allowed-tools: Bash(source *) Bash(python .claude/skills/rbac-agent/scripts/*) Bash(kubectl *)
---

# RBAC Agent

**Domain:** What grants exist in the cluster?
**Input:** Live Kubernetes cluster (kubectl context)
**Output:** `rbac-grants.json` — see `contracts/rbac-grants.schema.json`

## Run

```
source .venv/bin/activate && python .claude/skills/rbac-agent/scripts/collect.py
```

## Report

From stderr output, tell the user:
- Cluster name and context
- Total grants
- Subject counts: User / Group / ServiceAccount
- Number of namespaces with bindings; list the namespaces
- Any immediately obvious signal (e.g. number of cluster-admin bindings, presence of Group subjects)

## Boundary

This agent does not:
- Query Entra ID / Azure
- Analyze findings or assign severity
- Write to the cluster

If kubectl context is wrong, list available contexts:
```
kubectl config get-contexts -o name
```
