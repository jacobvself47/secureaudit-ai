"""
Shared utilities for all secureaudit agent scripts.
"""
import json
import subprocess
from kubernetes import client, config

# ---------------------------------------------------------------------------
# AKS system noise filter
# ---------------------------------------------------------------------------

AKS_SYSTEM_NAMES = {
    "system:masters", "clusterrole-aggregation-controller", "daemon-set-controller",
    "job-controller", "persistent-volume-binder", "disruption-controller",
    "generic-garbage-collector", "horizontal-pod-autoscaler", "node-controller",
    "replicaset-controller", "replication-controller", "statefulset-controller",
    "ttl-controller", "ttl-after-finished-controller", "expand-controller",
    "resourcequota-controller", "namespace-controller", "service-account-controller",
    "endpoint-controller", "endpointslice-controller", "ephemeral-volume-controller",
    "root-ca-cert-publisher", "pvc-protection-controller", "pv-protection-controller",
    "certificate-controller", "token-cleaner", "bootstrap-signer",
    "attachdetach-controller", "cronjob-controller", "csrapproving-controller",
    "csrcleaner-controller", "csrsigning-controller", "cloud-node-manager",
    "azure-cloud-provider", "selinux-warning-controller", "service-controller",
    "route-controller", "leader-election-controller", "kube-scheduler",
    "kube-dns", "cloud-provider",
}

CICD_PATTERNS = {
    "pipeline", "deploy", "actions", "ci", "cd", "builder",
    "runner", "argo", "flux", "tekton", "jenkins", "drone",
}


def is_aks_system(name: str) -> bool:
    return (
        name in AKS_SYSTEM_NAMES
        or name.startswith("system:")
        or name.startswith("aks:")
    )


def looks_like_cicd(name: str) -> bool:
    lower = name.lower()
    return any(p in lower for p in CICD_PATTERNS)


# ---------------------------------------------------------------------------
# Rule analysis
# ---------------------------------------------------------------------------

def summarize_rules(rules: list) -> dict:
    """Compute boolean risk flags from a list of role rules."""
    has_wildcard_verbs = False
    has_wildcard_resources = False
    has_wildcard_api_groups = False
    has_secrets_access = False
    has_pod_create = False
    escalation_verbs = set()
    secrets_verbs = set()

    for rule in rules:
        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])
        api_groups = rule.get("api_groups", [])
        resource_names = rule.get("resource_names", [])

        if "*" in verbs:
            has_wildcard_verbs = True
        if "*" in resources:
            has_wildcard_resources = True
        if "*" in api_groups:
            has_wildcard_api_groups = True

        ev = set(verbs) & {"bind", "impersonate", "escalate"}
        if ev:
            escalation_verbs |= ev

        if ("secrets" in resources or "*" in resources) and not resource_names:
            sv = set(verbs) & {"get", "list", "watch", "*"}
            if sv:
                has_secrets_access = True
                secrets_verbs |= sv

        if any(r == "pods" or r == "*" or r.startswith("pods/") for r in resources):
            if "create" in verbs or "*" in verbs:
                has_pod_create = True

    return {
        "has_wildcard_verbs": has_wildcard_verbs,
        "has_wildcard_resources": has_wildcard_resources,
        "has_wildcard_api_groups": has_wildcard_api_groups,
        "effectively_cluster_admin": has_wildcard_verbs and has_wildcard_resources,
        "has_secrets_access": has_secrets_access,
        "secrets_verbs": sorted(secrets_verbs),
        "has_pod_create": has_pod_create,
        "has_escalation_verbs": bool(escalation_verbs),
        "escalation_verbs": sorted(escalation_verbs),
    }


# ---------------------------------------------------------------------------
# Kubernetes client
# ---------------------------------------------------------------------------

def get_rbac_client() -> client.RbacAuthorizationV1Api:
    config.load_kube_config()
    return client.RbacAuthorizationV1Api()


def get_cluster_name() -> str:
    _, ctx = config.list_kube_config_contexts()
    return ctx.get("context", {}).get("cluster", "unknown")


def format_rules(rules) -> list:
    if not rules:
        return []
    return [
        {
            "api_groups": rule.api_groups or [],
            "resources": rule.resources or [],
            "verbs": rule.verbs or [],
            "resource_names": rule.resource_names or [],
        }
        for rule in rules
    ]


def get_role_rules(rbac: client.RbacAuthorizationV1Api, role_name: str,
                   role_kind: str = "ClusterRole", namespace: str = None) -> list:
    try:
        if role_kind == "ClusterRole":
            return format_rules(rbac.read_cluster_role(role_name).rules)
        else:
            return format_rules(rbac.read_namespaced_role(role_name, namespace).rules)
    except Exception:
        return []


def iter_all_grants(rbac: client.RbacAuthorizationV1Api) -> list:
    """Enumerate every grant from the cluster as a flat list of dicts."""
    grants = []

    for binding in rbac.list_cluster_role_binding().items:
        role_name = binding.role_ref.name
        rules = get_role_rules(rbac, role_name)
        for subject in binding.subjects or []:
            grants.append({
                "subject_kind": subject.kind,
                "subject_name": subject.name,
                "subject_namespace": subject.namespace,
                "binding": binding.metadata.name,
                "binding_kind": "ClusterRoleBinding",
                "role": role_name,
                "role_kind": "ClusterRole",
                "scope": "cluster",
                "scope_namespace": None,
                "rules": rules,
            })

    for binding in rbac.list_role_binding_for_all_namespaces().items:
        role_name = binding.role_ref.name
        role_kind = binding.role_ref.kind
        ns = binding.metadata.namespace
        rules = get_role_rules(rbac, role_name, role_kind, ns)
        for subject in binding.subjects or []:
            grants.append({
                "subject_kind": subject.kind,
                "subject_name": subject.name,
                "subject_namespace": subject.namespace,
                "binding": binding.metadata.name,
                "binding_kind": "RoleBinding",
                "role": role_name,
                "role_kind": role_kind,
                "scope": "namespace",
                "scope_namespace": ns,
                "rules": rules,
            })

    return grants


# ---------------------------------------------------------------------------
# Entra cache
# ---------------------------------------------------------------------------

def load_entra_cache(path: str = "entra-context.json") -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def find_entra_group(entra: dict, object_id: str) -> dict | None:
    for g in entra.get("groups", []):
        if g.get("object_id") == object_id:
            return g
    return None


def find_entra_user(entra: dict, subject_name: str) -> dict | None:
    for u in entra.get("users", []):
        if u.get("subject_name") == subject_name:
            return u
    return None


def find_entra_wi(entra: dict, sa_name: str, namespace: str) -> dict | None:
    for wi in entra.get("workload_identities", []):
        if wi.get("sa_name") == sa_name and wi.get("namespace") == namespace:
            return wi
    return None


# ---------------------------------------------------------------------------
# az CLI / kubectl helpers
# ---------------------------------------------------------------------------

def az(*args) -> tuple[bool, any]:
    cmd = ["az"] + list(args) + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False, result.stderr.strip()
    try:
        return True, json.loads(result.stdout)
    except json.JSONDecodeError:
        return False, f"JSON parse error: {result.stdout[:200]}"


def kubectl(*args) -> tuple[bool, any]:
    cmd = ["kubectl"] + list(args) + ["-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return False, result.stderr.strip()
    try:
        return True, json.loads(result.stdout)
    except json.JSONDecodeError:
        return False, f"JSON parse error: {result.stdout[:200]}"
