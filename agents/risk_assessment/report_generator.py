"""
HTML Report Generator - Creates polished security reports from assessment data.
"""
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def generate_html_report(report_data: Dict) -> str:
    """Generate a styled HTML security report.

    Args:
        report_data: The risk assessment report dictionary.

    Returns:
        Complete HTML document as a string.
    """
    summary = report_data['summary']
    findings = report_data['findings']
    timestamp = report_data.get('timestamp', datetime.now().isoformat())

    # Group findings by severity
    by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
    for f in findings:
        sev = f.get('severity', 'LOW')
        if sev in by_severity:
            by_severity[sev].append(f)

    findings_html = _generate_findings_html(findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RBAC Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e4e4e7;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .logo {{
            font-size: 3rem;
            margin-bottom: 0.5rem;
        }}

        h1 {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: #a1a1aa;
            font-size: 0.95rem;
        }}

        .timestamp {{
            color: #71717a;
            font-size: 0.85rem;
            margin-top: 1rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 3rem;
        }}

        .summary-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .summary-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
        }}

        .summary-card.critical {{
            border-color: rgba(239, 68, 68, 0.5);
            background: rgba(239, 68, 68, 0.1);
        }}

        .summary-card.high {{
            border-color: rgba(249, 115, 22, 0.5);
            background: rgba(249, 115, 22, 0.1);
        }}

        .summary-card.medium {{
            border-color: rgba(234, 179, 8, 0.5);
            background: rgba(234, 179, 8, 0.1);
        }}

        .summary-card.total {{
            border-color: rgba(96, 165, 250, 0.5);
            background: rgba(96, 165, 250, 0.1);
        }}

        .summary-number {{
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .summary-card.critical .summary-number {{ color: #ef4444; }}
        .summary-card.high .summary-number {{ color: #f97316; }}
        .summary-card.medium .summary-number {{ color: #eab308; }}
        .summary-card.total .summary-number {{ color: #60a5fa; }}

        .summary-label {{
            color: #a1a1aa;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .findings-section {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 16px;
            padding: 2rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .findings-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .findings-header h2 {{
            font-size: 1.25rem;
            color: #e4e4e7;
        }}

        .ai-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: linear-gradient(90deg, rgba(167, 139, 250, 0.2), rgba(96, 165, 250, 0.2));
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            color: #a78bfa;
            border: 1px solid rgba(167, 139, 250, 0.3);
        }}

        .finding {{
            background: rgba(0, 0, 0, 0.2);
            border-radius: 12px;
            margin-bottom: 1rem;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.5rem;
            cursor: pointer;
            transition: background 0.2s;
        }}

        .finding-header:hover {{
            background: rgba(255, 255, 255, 0.03);
        }}

        .severity-badge {{
            padding: 0.35rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .severity-badge.critical {{
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }}

        .severity-badge.high {{
            background: rgba(249, 115, 22, 0.2);
            color: #fdba74;
            border: 1px solid rgba(249, 115, 22, 0.4);
        }}

        .severity-badge.medium {{
            background: rgba(234, 179, 8, 0.2);
            color: #fde047;
            border: 1px solid rgba(234, 179, 8, 0.4);
        }}

        .severity-badge.low {{
            background: rgba(34, 197, 94, 0.2);
            color: #86efac;
            border: 1px solid rgba(34, 197, 94, 0.4);
        }}

        .finding-title {{
            flex: 1;
            font-weight: 500;
        }}

        .finding-resource {{
            color: #71717a;
            font-size: 0.85rem;
            font-family: 'SF Mono', Monaco, 'Courier New', monospace;
        }}

        .priority-score {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            color: #a1a1aa;
            font-size: 0.85rem;
        }}

        .priority-score .score {{
            font-weight: 700;
            color: #f97316;
        }}

        .finding-details {{
            padding: 0 1.5rem 1.5rem 1.5rem;
            display: none;
        }}

        .finding.expanded .finding-details {{
            display: block;
        }}

        .finding-section {{
            margin-bottom: 1.25rem;
        }}

        .finding-section:last-child {{
            margin-bottom: 0;
        }}

        .finding-section-title {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #71717a;
            margin-bottom: 0.5rem;
        }}

        .finding-section p {{
            color: #d4d4d8;
            font-size: 0.95rem;
        }}

        .remediation-list {{
            list-style: none;
        }}

        .remediation-list li {{
            position: relative;
            padding-left: 1.5rem;
            margin-bottom: 0.5rem;
            color: #d4d4d8;
            font-size: 0.95rem;
        }}

        .remediation-list li::before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #60a5fa;
        }}

        .expand-icon {{
            color: #71717a;
            transition: transform 0.2s;
        }}

        .finding.expanded .expand-icon {{
            transform: rotate(180deg);
        }}

        footer {{
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: #71717a;
            font-size: 0.85rem;
        }}

        footer a {{
            color: #60a5fa;
            text-decoration: none;
        }}

        .powered-by {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            .summary-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .finding-header {{
                flex-wrap: wrap;
            }}

            .finding-resource {{
                width: 100%;
                margin-top: 0.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️</div>
            <h1>Kubernetes RBAC Security Assessment</h1>
            <p class="subtitle">AI-Enhanced Risk Analysis Report</p>
            <p class="timestamp">Generated: {_format_timestamp(timestamp)}</p>
        </header>

        <div class="summary-grid">
            <div class="summary-card total">
                <div class="summary-number">{summary['total_findings']}</div>
                <div class="summary-label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-number">{summary['critical']}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-number">{summary['high']}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-number">{summary['medium']}</div>
                <div class="summary-label">Medium</div>
            </div>
        </div>

        <div class="findings-section">
            <div class="findings-header">
                <h2>Security Findings</h2>
                <div class="ai-badge">
                    <span>✨</span>
                    <span>AI-Enhanced Analysis</span>
                </div>
            </div>

            {findings_html}
        </div>

        <footer>
            <p>SecureAudit AI - Kubernetes RBAC Compliance Analysis</p>
            <div class="powered-by">
                Powered by <a href="https://anthropic.com/claude" target="_blank">Claude AI</a>
            </div>
        </footer>
    </div>

    <script>
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.parentElement.classList.toggle('expanded');
            }});
        }});
    </script>
</body>
</html>"""

    return html


def _format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_timestamp)
        return dt.strftime("%B %d, %Y at %I:%M %p")
    except (ValueError, TypeError):
        return iso_timestamp


def _generate_findings_html(findings: List[Dict]) -> str:
    """Generate HTML for all findings."""
    html_parts = []

    for finding in findings:
        severity = finding.get('severity', 'LOW').lower()
        ai = finding.get('ai_analysis', {})
        priority = ai.get('priority_score', 'N/A')
        explanation = ai.get('explanation', finding.get('description', ''))
        attack = ai.get('attack_scenario', '')
        remediation = ai.get('remediation_steps', [])

        # Use recommendation as fallback
        if not remediation and finding.get('recommendation'):
            remediation = [finding['recommendation']]

        remediation_html = ""
        if remediation:
            items = "".join([f"<li>{step}</li>" for step in remediation])
            remediation_html = f"""
            <div class="finding-section">
                <div class="finding-section-title">Remediation Steps</div>
                <ul class="remediation-list">{items}</ul>
            </div>"""

        attack_html = ""
        if attack:
            attack_html = f"""
            <div class="finding-section">
                <div class="finding-section-title">Attack Scenario</div>
                <p>{attack}</p>
            </div>"""

        html_parts.append(f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity-badge {severity}">{finding['severity']}</span>
                    <span class="finding-title">{finding['title']}</span>
                    <span class="finding-resource">{finding['resource']}</span>
                    <span class="priority-score">Priority: <span class="score">{priority}/10</span></span>
                    <span class="expand-icon">▼</span>
                </div>
                <div class="finding-details">
                    <div class="finding-section">
                        <div class="finding-section-title">Analysis</div>
                        <p>{explanation}</p>
                    </div>
                    {attack_html}
                    {remediation_html}
                </div>
            </div>""")

    return "\n".join(html_parts)


def main():
    """Generate HTML report from assessment JSON."""
    parser = argparse.ArgumentParser(description="Generate HTML security report")
    parser.add_argument(
        "--input",
        default="risk_assessment_report.json",
        help="Path to assessment JSON file"
    )
    parser.add_argument(
        "--output",
        default="security_report.html",
        help="Output HTML file path"
    )
    args = parser.parse_args()

    # Load report data
    with open(args.input, 'r') as f:
        report_data = json.load(f)

    # Generate HTML
    html = generate_html_report(report_data)

    # Write output
    with open(args.output, 'w') as f:
        f.write(html)

    print(f"✅ Report generated: {args.output}")
    print(f"   Open in browser: file://{Path(args.output).absolute()}")


if __name__ == "__main__":
    main()
