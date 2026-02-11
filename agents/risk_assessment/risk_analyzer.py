"""
Risk Assessment Agent - Analyzes RBAC configurations for security issues

Combines rule-based detection with AI-powered analysis for comprehensive
security assessments of Kubernetes RBAC configurations.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from dotenv import load_dotenv
import anthropic

# Load .env from project root
_project_root = Path(__file__).parent.parent.parent
load_dotenv(_project_root / ".env")


class RiskAssessmentAgent:
    """Analyzes RBAC configurations for security violations.

    Uses rule-based detection for critical security patterns, with optional
    AI enrichment for natural language explanations and remediation guidance.

    Args:
        discovery_data: RBAC data from the discovery agent.
        enable_ai: Enable AI-powered analysis enrichment. Defaults to True.
    """

    def __init__(self, discovery_data: Dict, enable_ai: bool = True):
        self.data = discovery_data
        self.findings: List[Dict] = []
        self.enable_ai = enable_ai
        self._client: Optional[anthropic.Anthropic] = None

        if enable_ai:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                print("⚠️  ANTHROPIC_API_KEY not set - AI enrichment disabled")
                self.enable_ai = False
            else:
                self._client = anthropic.Anthropic()

    def check_cluster_admin_bindings(self):
        """Flag any cluster-admin bindings (CRITICAL)"""
        for binding in self.data['cluster_role_bindings']:
            if binding['role_name'] == 'cluster-admin':
                self.findings.append({
                    'severity': 'CRITICAL',
                    'title': 'Cluster Admin Binding Detected',
                    'resource': binding['name'],
                    'resource_type': 'ClusterRoleBinding',
                    'description': f"ClusterRoleBinding '{binding['name']}' grants cluster-admin privileges",
                    'subjects': binding['subjects'],
                    'recommendation': 'Review if cluster-admin access is truly necessary. Consider using more restrictive roles.'
                })

    def check_wildcard_permissions(self):
        """Flag roles with wildcard (*) permissions (HIGH)"""
        # Check ClusterRoles
        for role in self.data['cluster_roles']:
            for rule in role['rules']:
                if '*' in rule['verbs'] or '*' in rule['resources']:
                    self.findings.append({
                        'severity': 'HIGH',
                        'title': 'Wildcard Permissions Detected',
                        'resource': role['name'],
                        'resource_type': 'ClusterRole',
                        'description': f"ClusterRole '{role['name']}' uses wildcard permissions",
                        'details': {
                            'apiGroups': rule['apiGroups'],
                            'resources': rule['resources'],
                            'verbs': rule['verbs']
                        },
                        'recommendation': 'Replace wildcard permissions with explicit resource and verb definitions.'
                    })

        # Check namespaced Roles
        for role in self.data['roles']:
            for rule in role['rules']:
                if '*' in rule['verbs'] or '*' in rule['resources']:
                    self.findings.append({
                        'severity': 'HIGH',
                        'title': 'Wildcard Permissions Detected',
                        'resource': f"{role['namespace']}/{role['name']}",
                        'resource_type': 'Role',
                        'description': f"Role '{role['name']}' in namespace '{role['namespace']}' uses wildcard permissions",
                        'details': {
                            'apiGroups': rule['apiGroups'],
                            'resources': rule['resources'],
                            'verbs': rule['verbs']
                        },
                        'recommendation': 'Replace wildcard permissions with explicit resource and verb definitions.'
                    })

    def check_secrets_access(self):
        """Flag roles with secrets access (MEDIUM-HIGH)"""
        dangerous_verbs = ['get', 'list', 'watch', '*']

        # Check ClusterRoles
        for role in self.data['cluster_roles']:
            for rule in role['rules']:
                if 'secrets' in rule['resources']:
                    if any(verb in dangerous_verbs for verb in rule['verbs']):
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'title': 'Secrets Access Detected',
                            'resource': role['name'],
                            'resource_type': 'ClusterRole',
                            'description': f"ClusterRole '{role['name']}' has access to secrets",
                            'details': {
                                'verbs': rule['verbs']
                            },
                            'recommendation': 'Limit secrets access to only what is necessary. Consider using specific resourceNames.'
                        })

        # Check namespaced Roles
        for role in self.data['roles']:
            for rule in role['rules']:
                if 'secrets' in rule['resources']:
                    if any(verb in dangerous_verbs for verb in rule['verbs']):
                        self.findings.append({
                            'severity': 'MEDIUM',
                            'title': 'Secrets Access Detected',
                            'resource': f"{role['namespace']}/{role['name']}",
                            'resource_type': 'Role',
                            'description': f"Role '{role['name']}' in namespace '{role['namespace']}' has access to secrets",
                            'details': {
                                'verbs': rule['verbs']
                            },
                            'recommendation': 'Limit secrets access to only what is necessary.'
                        })

    def _format_finding_compact(self, idx: int, finding: Dict) -> str:
        """Format a finding as a compact single line for the AI prompt.

        Args:
            idx: Finding number for reference.
            finding: The finding dictionary.

        Returns:
            Compact string representation.
        """
        parts = [f"#{idx}", f"[{finding['severity']}]", finding['resource_type'], finding['resource']]

        # Add subjects if present
        subjects = finding.get('subjects', [])
        if subjects:
            subject_names = [s.get('name', '?') for s in subjects[:2]]
            parts.append(f"-> {','.join(subject_names)}")

        # Add key details
        details = finding.get('details', {})
        if 'verbs' in details:
            parts.append(f"verbs:{details['verbs']}")
        if 'resources' in details:
            parts.append(f"resources:{details['resources']}")

        return " ".join(parts)

    def _parse_ai_response(self, response_text: str) -> List[Dict]:
        """Extract and parse JSON array from AI response.

        Args:
            response_text: Raw response text from API.

        Returns:
            Parsed list of analysis objects.
        """
        # Handle markdown code blocks
        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0]
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0]

        # Extract JSON array
        start_idx = response_text.find("[")
        end_idx = response_text.rfind("]") + 1
        if start_idx != -1 and end_idx > start_idx:
            response_text = response_text[start_idx:end_idx]

        return json.loads(response_text)

    def _enrich_batch(self, batch: List[tuple], batch_num: int, total_batches: int) -> int:
        """Process a single batch of findings through the AI.

        Args:
            batch: List of (original_index, finding) tuples.
            batch_num: Current batch number.
            total_batches: Total number of batches.

        Returns:
            Number of findings successfully enriched.
        """
        findings_text = "\n".join([
            self._format_finding_compact(i + 1, f) for i, (_, f) in enumerate(batch)
        ])

        prompt = f"""You are a Kubernetes security expert. Analyze these {len(batch)} RBAC security findings:

{findings_text}

Respond with a JSON array of {len(batch)} objects (in order) with these fields:
- "explanation": 2-3 sentence technical explanation of why this is a security risk
- "attack_scenario": A realistic attack scenario exploiting this misconfiguration
- "remediation_steps": Array of 2-4 specific remediation steps
- "priority_score": Integer 1-10 based on exploitability and impact (10 = most critical)

Return ONLY the JSON array, no other text."""

        try:
            message = self._client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}]
            )

            ai_analyses = self._parse_ai_response(message.content[0].text)

            if len(ai_analyses) != len(batch):
                print(f"   ⚠️  Batch {batch_num}: expected {len(batch)}, got {len(ai_analyses)}")

            enriched = 0
            for i, analysis in enumerate(ai_analyses):
                if i < len(batch):
                    original_idx = batch[i][0]
                    self.findings[original_idx]['ai_analysis'] = analysis
                    enriched += 1
            return enriched

        except json.JSONDecodeError as e:
            print(f"   ⚠️  Batch {batch_num}/{total_batches}: parse error - {e}")
            return 0
        except anthropic.APIError as e:
            print(f"   ⚠️  Batch {batch_num}/{total_batches}: API error - {e}")
            return 0

    def _enrich_findings_with_ai(self, batch_size: int = 10) -> None:
        """Enrich findings with AI-generated analysis in batches.

        Processes findings in batches to manage context window limits
        and provide resilience against partial failures.

        Args:
            batch_size: Findings per API call. Default 10.
        """
        if not self.findings or not self._client:
            return

        # Create batches preserving original indices
        indexed_findings = list(enumerate(self.findings))
        batches = [
            indexed_findings[i:i + batch_size]
            for i in range(0, len(indexed_findings), batch_size)
        ]

        total_enriched = 0
        for batch_num, batch in enumerate(batches, 1):
            print(f"   Batch {batch_num}/{len(batches)} ({len(batch)} findings)...")
            total_enriched += self._enrich_batch(batch, batch_num, len(batches))

        print(f"   ✓ Enriched {total_enriched}/{len(self.findings)} findings")

    def run_assessment(self) -> List[Dict]:
        """Run all risk checks with optional AI enrichment.

        Executes rule-based security checks, then optionally enriches
        findings with AI-generated analysis for better context.

        Returns:
            List of findings sorted by severity, optionally enriched with AI analysis.
        """
        print("🔍 Running risk assessment...")

        # Rule-based detection
        self.check_cluster_admin_bindings()
        self.check_wildcard_permissions()
        self.check_secrets_access()

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.findings.sort(key=lambda x: severity_order.get(x['severity'], 999))

        # AI enrichment layer
        if self.enable_ai and self.findings:
            print("🤖 Enriching findings with AI analysis...")
            self._enrich_findings_with_ai()

        print("✅ Assessment complete!")
        print(f"   - Found {len([f for f in self.findings if f['severity'] == 'CRITICAL'])} CRITICAL findings")
        print(f"   - Found {len([f for f in self.findings if f['severity'] == 'HIGH'])} HIGH findings")
        print(f"   - Found {len([f for f in self.findings if f['severity'] == 'MEDIUM'])} MEDIUM findings")
        if self.enable_ai:
            enriched = len([f for f in self.findings if 'ai_analysis' in f])
            print(f"   - AI enriched: {enriched}/{len(self.findings)} findings")

        return self.findings


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run RBAC risk assessment")
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI enrichment (rule-based only)"
    )
    parser.add_argument(
        "--input",
        default="../../agents/discovery/rbac_discovery_output.json",
        help="Path to discovery data JSON"
    )
    args = parser.parse_args()

    # Load discovery data
    with open(args.input, 'r') as f:
        discovery_data = json.load(f)

    # Run assessment
    agent = RiskAssessmentAgent(discovery_data, enable_ai=not args.no_ai)
    findings = agent.run_assessment()

    # Generate report
    report = {
        'timestamp': datetime.now().isoformat(),
        'ai_enabled': agent.enable_ai,
        'summary': {
            'total_findings': len(findings),
            'critical': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'high': len([f for f in findings if f['severity'] == 'HIGH']),
            'medium': len([f for f in findings if f['severity'] == 'MEDIUM']),
            'ai_enriched': len([f for f in findings if 'ai_analysis' in f])
        },
        'findings': findings
    }

    # Save report
    with open('risk_assessment_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    print("\n💾 Report saved to risk_assessment_report.json")
    print("\n📊 Top findings:")
    for finding in findings[:5]:
        print(f"\n   [{finding['severity']}] {finding['title']}: {finding['resource']}")
        if 'ai_analysis' in finding:
            print(f"   💡 {finding['ai_analysis'].get('explanation', '')[:100]}...")
            print(f"   🎯 Priority: {finding['ai_analysis'].get('priority_score', 'N/A')}/10")
