"""
Discovery Agent - Extracts RBAC configuration from Kubernetes cluster
"""
from kubernetes import client, config
import json
from typing import Dict, List
from datetime import datetime

class RBACDiscoveryAgent:
    def __init__(self, kubeconfig_path: str = None):
        """Initialize Kubernetes client"""
        if kubeconfig_path:
            config.load_kube_config(config_file=kubeconfig_path)
        else:
            config.load_kube_config()

        self.rbac_api = client.RbacAuthorizationV1Api()
        self.core_api = client.CoreV1Api()

    def discover_cluster_roles(self) -> List[Dict]:
        """Get all ClusterRoles"""
        cluster_roles = self.rbac_api.list_cluster_role()
        return [{
            'name': role.metadata.name,
            'rules': self._format_rules(role.rules),
            'created': role.metadata.creation_timestamp.isoformat() if role.metadata.creation_timestamp else None
        } for role in cluster_roles.items]

    def discover_cluster_role_bindings(self) -> List[Dict]:
        """Get all ClusterRoleBindings"""
        bindings = self.rbac_api.list_cluster_role_binding()
        return [{
            'name': binding.metadata.name,
            'role_name': binding.role_ref.name,
            'subjects': self._format_subjects(binding.subjects),
            'created': binding.metadata.creation_timestamp.isoformat() if binding.metadata.creation_timestamp else None
        } for binding in bindings.items]

    def discover_roles(self) -> List[Dict]:
        """Get all namespaced Roles"""
        roles = self.rbac_api.list_role_for_all_namespaces()
        return [{
            'name': role.metadata.name,
            'namespace': role.metadata.namespace,
            'rules': self._format_rules(role.rules),
            'created': role.metadata.creation_timestamp.isoformat() if role.metadata.creation_timestamp else None
        } for role in roles.items]

    def discover_role_bindings(self) -> List[Dict]:
        """Get all namespaced RoleBindings"""
        bindings = self.rbac_api.list_role_binding_for_all_namespaces()
        return [{
            'name': binding.metadata.name,
            'namespace': binding.metadata.namespace,
            'role_name': binding.role_ref.name,
            'subjects': self._format_subjects(binding.subjects),
            'created': binding.metadata.creation_timestamp.isoformat() if binding.metadata.creation_timestamp else None
        } for binding in bindings.items]

    def _format_rules(self, rules) -> List[Dict]:
        """Format RBAC rules into dict"""
        if not rules:
            return []
        return [{
            'apiGroups': rule.api_groups or [],
            'resources': rule.resources or [],
            'verbs': rule.verbs or [],
            'resourceNames': rule.resource_names or []
        } for rule in rules]

    def _format_subjects(self, subjects) -> List[Dict]:
        """Format subjects into dict"""
        if not subjects:
            return []
        return [{
            'kind': subj.kind,
            'name': subj.name,
            'namespace': subj.namespace
        } for subj in subjects]

    def run_full_discovery(self) -> Dict:
        """Run complete RBAC discovery"""
        print("🔍 Starting RBAC discovery...")

        discovery_data = {
            'timestamp': datetime.now().isoformat(),
            'cluster_roles': self.discover_cluster_roles(),
            'cluster_role_bindings': self.discover_cluster_role_bindings(),
            'roles': self.discover_roles(),
            'role_bindings': self.discover_role_bindings()
        }

        print(f"✅ Discovery complete!")
        print(f"   - Found {len(discovery_data['cluster_roles'])} ClusterRoles")
        print(f"   - Found {len(discovery_data['cluster_role_bindings'])} ClusterRoleBindings")
        print(f"   - Found {len(discovery_data['roles'])} Roles")
        print(f"   - Found {len(discovery_data['role_bindings'])} RoleBindings")

        return discovery_data


if __name__ == "__main__":
    # Quick test
    agent = RBACDiscoveryAgent()
    data = agent.run_full_discovery()

    # Save to file
    with open('rbac_discovery_output.json', 'w') as f:
        json.dump(data, f, indent=2)

    print("\n💾 Output saved to rbac_discovery_output.json")
